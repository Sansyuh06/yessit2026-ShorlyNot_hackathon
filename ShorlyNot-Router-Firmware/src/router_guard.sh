#!/bin/sh
# =============================================================================
# ShorlyNot Router Guard
# =============================================================================
# Polls KMS /link_status endpoint and enforces nftables firewall rules.
#
# The router is a semi-trusted enforcer: it never holds key material.
# It simply receives GREEN/YELLOW/RED status from the KMS and blocks
# the relay port (TCP/8765) when the link is RED.
#
# Configuration priority: CLI flags > environment variables > defaults
# =============================================================================

VERSION="1.0.0"

# ---- Defaults (overridden by env vars, then by CLI flags) -------------------
KMS_URL="${KMS_URL:-http://192.168.1.2:8000}"
RELAY_PORT="${RELAY_PORT:-8765}"
POLL_INTERVAL="${POLL_INTERVAL:-3}"
MAX_FAILURES="${MAX_FAILURES:-5}"
FAIL_ACTION="${FAIL_ACTION:-block}"          # "block" or "allow" on KMS failure
PID_FILE="${PID_FILE:-/var/run/router_guard.pid}"
STATE_FILE="${STATE_FILE:-/tmp/router_guard.state}"
LOG_TAG="router_guard"
DRY_RUN=0

# ---- Load UCI config if available (OpenWrt) ---------------------------------
# (Loaded BEFORE CLI flags so that CLI flags correctly override UCI settings)
if [ -f "/etc/config/router_guard" ] && command -v uci >/dev/null 2>&1; then
    _val=$(uci -q get router_guard.main.kms_host)
    _port=$(uci -q get router_guard.main.kms_port)
    if [ -n "$_val" ] && [ -n "$_port" ]; then
        KMS_URL="http://${_val}:${_port}"
    fi
    _val=$(uci -q get router_guard.main.relay_port)
    [ -n "$_val" ] && RELAY_PORT="$_val"
    _val=$(uci -q get router_guard.main.poll_interval)
    [ -n "$_val" ] && POLL_INTERVAL="$_val"
    _val=$(uci -q get router_guard.main.max_failures)
    [ -n "$_val" ] && MAX_FAILURES="$_val"
    _val=$(uci -q get router_guard.main.fail_action)
    [ -n "$_val" ] && FAIL_ACTION="$_val"
fi

# ---- Parse CLI arguments (override env vars and UCI) ------------------------
show_help() {
    cat <<EOF
ShorlyNot Router Guard v${VERSION}

Usage: router_guard.sh [OPTIONS]

Options:
  --kms-url URL        KMS base URL         (default: $KMS_URL)
  --relay-port PORT    Relay port to guard   (default: $RELAY_PORT)
  --poll-interval SEC  Polling interval      (default: $POLL_INTERVAL)
  --max-failures N     Failures before block (default: $MAX_FAILURES)
  --fail-action ACT    On failure: block|allow (default: $FAIL_ACTION)
  --pid-file PATH      PID file location     (default: $PID_FILE)
  --state-file PATH    State file location   (default: $STATE_FILE)
  --dry-run            Log nftables commands without executing
  --status             Print current state from state file and exit
  --version            Print version and exit
  --help               Show this help

Environment variables: KMS_URL, RELAY_PORT, POLL_INTERVAL, MAX_FAILURES,
                       FAIL_ACTION, PID_FILE, STATE_FILE
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --kms-url)       KMS_URL="$2";       shift 2 ;;
        --relay-port)    RELAY_PORT="$2";     shift 2 ;;
        --poll-interval) POLL_INTERVAL="$2";  shift 2 ;;
        --max-failures)  MAX_FAILURES="$2";   shift 2 ;;
        --fail-action)   FAIL_ACTION="$2";    shift 2 ;;
        --pid-file)      PID_FILE="$2";       shift 2 ;;
        --state-file)    STATE_FILE="$2";     shift 2 ;;
        --dry-run)       DRY_RUN=1;           shift   ;;
        --status)
            if [ -f "${STATE_FILE}" ]; then
                cat "${STATE_FILE}"
                exit 0
            else
                echo "UNKNOWN (router_guard not running)"
                exit 1
            fi
            ;;
        --version)       echo "router_guard v${VERSION}"; exit 0 ;;
        --help|-h)       show_help; exit 0 ;;
        *)               echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
done


# ---- Logging ----------------------------------------------------------------
log_info() {
    logger -t "$LOG_TAG" -p daemon.info "$1" 2>/dev/null
    echo "[INFO]  $1"
}

log_warn() {
    logger -t "$LOG_TAG" -p daemon.warning "$1" 2>/dev/null
    echo "[WARN]  $1"
}

log_err() {
    logger -t "$LOG_TAG" -p daemon.err "$1" 2>/dev/null
    echo "[ERROR] $1" >&2
}

# ---- nftables wrapper (supports --dry-run) ----------------------------------
fw_exec() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[DRY-RUN] nft $*"
        case "$1" in
            list) return 1 ;;
            *)    return 0 ;;
        esac
    else
        nft "$@"
    fi
}

# ---- Firewall enforcement ---------------------------------------------------
# The chain 'router_guard_forward' is declared statically in
# /etc/firewall.router_guard and owned by fw4's declarative config.
# This means it survives 'fw4 reload' automatically.
# router_guard.sh only manages the tcp dport DROP rule inside the chain.

init_firewall() {
    # Verify the chain is actually present (it should be, since fw4 owns it).
    # If somehow it's missing (e.g. fw4 hasn't started yet), log and abort.
    if ! nft list chain inet fw4 router_guard_forward >/dev/null 2>&1; then
        log_warn "router_guard_forward chain not found in inet fw4 — fw4 may not be ready yet"
        return 1
    fi
    return 0
}

enforce_drop() {
    init_firewall || return 1
    if ! nft list chain inet fw4 router_guard_forward 2>/dev/null | grep -q "dport $RELAY_PORT drop"; then
        log_warn "BLOCK relay port $RELAY_PORT (status=RED)"
        fw_exec add rule inet fw4 router_guard_forward tcp dport "$RELAY_PORT" drop
    fi
}

enforce_allow() {
    if nft list chain inet fw4 router_guard_forward >/dev/null 2>&1; then
        log_info "ALLOW relay port $RELAY_PORT (removing DROP rule)"
        fw_exec flush chain inet fw4 router_guard_forward 2>/dev/null || true
    fi
}

# ---- HTTP fetch -------------------------------------------------------------
fetch_status() {
    _resp=""
    if command -v curl >/dev/null 2>&1; then
        _resp=$(curl -sf --connect-timeout 2 --max-time 5 \
                "${KMS_URL}/link_status" 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        _resp=$(wget -qO- --timeout=5 \
                "${KMS_URL}/link_status" 2>/dev/null) || _resp=""
    else
        log_err "No HTTP client (curl or wget) available"
        return 1
    fi

    [ -z "$_resp" ] && return 1
    echo "$_resp"
    return 0
}

# ---- JSON parsing -----------------------------------------------------------
parse_status() {
    _json="$1"
    _status=""

    if command -v jq >/dev/null 2>&1; then
        _status=$(printf '%s' "$_json" | jq -r '.status // empty' 2>/dev/null)
    elif command -v jsonfilter >/dev/null 2>&1; then
        _status=$(printf '%s' "$_json" | jsonfilter -e '@.status' 2>/dev/null)
    else
        # grep/awk fallback (works with BusyBox)
        _status=$(printf '%s' "$_json" | \
            grep -o '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | \
            head -1 | \
            sed 's/.*"\([^"]*\)"$/\1/')
    fi

    # Validate: must be GREEN, YELLOW, or RED
    case "$_status" in
        GREEN|YELLOW|RED) echo "$_status" ;;
        *) return 1 ;;
    esac
}

# ---- Cleanup on exit --------------------------------------------------------
cleanup() {
    log_info "Shutting down router_guard"
    if [ "$FAIL_ACTION" = "block" ]; then
        # Fail-secure: leave the DROP rule active on shutdown so the relay
        # stays blocked until the guard is explicitly restarted.
        # (Matches the intent of FAIL_ACTION=block for daemon termination.)
        log_warn "FAIL_ACTION=block — keeping DROP rule active on shutdown"
    else
        enforce_allow
    fi
    rm -f "$PID_FILE"
    rm -f "$STATE_FILE"
    exit 0
}

trap cleanup INT TERM

# =============================================================================
# Main loop
# =============================================================================

log_info "Starting router_guard v${VERSION}"
log_info "  KMS URL      : ${KMS_URL}"
log_info "  Relay port   : ${RELAY_PORT}"
log_info "  Poll interval: ${POLL_INTERVAL}s"
log_info "  Max failures : ${MAX_FAILURES}"
log_info "  Fail action  : ${FAIL_ACTION}"
[ "$DRY_RUN" -eq 1 ] && log_info "  *** DRY-RUN MODE ***"

# Write PID file
echo "$$" > "$PID_FILE" 2>/dev/null

# Fail-closed boot policy: default to blocking until verified KMS poll
if [ "$FAIL_ACTION" = "block" ]; then
    log_info "Fail-closed boot policy active: enforcing DROP on relay port $RELAY_PORT until KMS link is verified"
    enforce_drop
    current_state="RED"
else
    enforce_allow
    current_state="INIT"
fi

fail_count=0
echo "$current_state" > "$STATE_FILE" 2>/dev/null

while true; do
    resp=$(fetch_status)
    fetch_ok=$?

    if [ $fetch_ok -ne 0 ] || [ -z "$resp" ]; then
        # KMS unreachable or empty response
        fail_count=$((fail_count + 1))

        if [ "$fail_count" -ge "$MAX_FAILURES" ]; then
            if [ "$FAIL_ACTION" = "block" ]; then
                new_state="RED"
                log_warn "KMS unreachable for $fail_count polls — fail-safe BLOCK"
            else
                new_state="$current_state"
                log_warn "KMS unreachable for $fail_count polls — fail-open (keeping $current_state)"
            fi
        else
            new_state="$current_state"
            log_warn "KMS unreachable (failure $fail_count/$MAX_FAILURES)"
        fi
    else
        # Got a response — try to parse it
        parsed=$(parse_status "$resp")
        if [ $? -eq 0 ] && [ -n "$parsed" ]; then
            fail_count=0
            new_state="$parsed"
        else
            # Valid HTTP response but unparseable or unknown status
            fail_count=$((fail_count + 1))
            log_warn "Unparseable KMS response (failure $fail_count/$MAX_FAILURES)"
            if [ "$fail_count" -ge "$MAX_FAILURES" ] && [ "$FAIL_ACTION" = "block" ]; then
                new_state="RED"
            else
                new_state="$current_state"
            fi
        fi
    fi

    # Apply state transition
    if [ "$new_state" != "$current_state" ]; then
        log_info "State transition: $current_state -> $new_state"
        current_state="$new_state"
        echo "$current_state" > "$STATE_FILE" 2>/dev/null

        case "$current_state" in
            GREEN|YELLOW)
                enforce_allow
                ;;
            RED)
                enforce_drop
                ;;
            *)
                log_err "Unexpected state: $current_state"
                ;;
        esac
    else
        # No state transition this cycle — but if we're in RED, verify the
        # drop rule is still present (a 'fw4 reload' can silently flush it).
        if [ "$current_state" = "RED" ]; then
            if ! nft list chain inet fw4 router_guard_forward 2>/dev/null | grep -q "dport $RELAY_PORT drop"; then
                log_warn "Drop rule missing after firewall reload — re-applying RED enforcement"
                enforce_drop
            fi
        fi
    fi

    sleep "$POLL_INTERVAL"
done
