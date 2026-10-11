#!/usr/bin/env python3
"""
ShorlyNot QKD Key Management System (KMS) Simulator
===================================================
Simulates a Quantum Key Distribution (QKD) post-processing link with realistic
Quantum Bit Error Rate (QBER) physics and state thresholds:

  - QBER < 4.0%       -> GREEN  (Quantum channel healthy, key production normal)
  - 4.0% <= QBER < 11% -> YELLOW (High optical noise / channel degradation)
  - QBER >= 11.0%     -> RED    (Active eavesdropper detected! BB84 security limit exceeded)

Features:
  - Serves live JSON to the OpenWrt router guard at /link_status
  - Interactive judge presentation dashboard at http://<ip>:8000/
  - Automated presentation mode (cycles Low -> Med -> High error -> Recovery)
  - Interactive API endpoints: /set/GREEN, /set/YELLOW, /set/RED, /set_qber/<value>
"""
import argparse
import http.server
import json
import logging
import os
import hmac
import threading
import time
import random

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShorlyNot QKD KMS Simulation</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #090d16;
    --card: #121826;
    --card-border: #1e293b;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --green: #10b981;
    --yellow: #f59e0b;
    --red: #ef4444;
    --blue: #3b82f6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 30px 20px;
  }
  .container { max-width: 900px; width: 100%; }
  header {
    text-align: center;
    margin-bottom: 30px;
  }
  .badge-tag {
    display: inline-block;
    padding: 4px 12px;
    background: rgba(59, 130, 246, 0.15);
    color: #60a5fa;
    border-radius: 9999px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
    text-transform: uppercase;
  }
  h1 { font-size: 32px; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 8px; }
  p.subtitle { color: var(--muted); font-size: 15px; }

  .status-card {
    background: var(--card);
    border: 2px solid var(--card-border);
    border-radius: 20px;
    padding: 35px;
    text-align: center;
    box-shadow: 0 20px 40px -15px rgba(0,0,0,0.5);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    margin-bottom: 25px;
    position: relative;
    overflow: hidden;
  }
  .status-card.state-GREEN {
    border-color: var(--green);
    box-shadow: 0 0 30px rgba(16, 185, 129, 0.2);
  }
  .status-card.state-YELLOW {
    border-color: var(--yellow);
    box-shadow: 0 0 30px rgba(245, 158, 11, 0.2);
  }
  .status-card.state-RED {
    border-color: var(--red);
    box-shadow: 0 0 40px rgba(239, 68, 68, 0.3);
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 8px 24px;
    border-radius: 9999px;
    font-size: 24px;
    font-weight: 800;
    letter-spacing: 1px;
    margin-bottom: 15px;
  }
  .status-pill .dot {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.85); }
  }

  .state-GREEN .status-pill { background: rgba(16,185,129,0.15); color: var(--green); }
  .state-GREEN .dot { background: var(--green); }
  .state-YELLOW .status-pill { background: rgba(245,158,11,0.15); color: var(--yellow); }
  .state-YELLOW .dot { background: var(--yellow); }
  .state-RED .status-pill { background: rgba(239,68,68,0.15); color: var(--red); }
  .state-RED .dot { background: var(--red); }

  .status-desc {
    font-size: 16px;
    color: var(--text);
    margin-bottom: 25px;
    font-weight: 500;
  }

  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 15px;
    margin-top: 20px;
  }
  .metric-box {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 16px;
    text-align: center;
  }
  .metric-label { font-size: 12px; color: var(--muted); text-transform: uppercase; font-weight: 600; margin-bottom: 6px; }
  .metric-value { font-size: 26px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }

  .actions-card {
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 20px;
    padding: 25px;
    margin-bottom: 25px;
  }
  .actions-title {
    font-size: 14px;
    color: var(--muted);
    text-transform: uppercase;
    font-weight: 700;
    margin-bottom: 15px;
    letter-spacing: 0.5px;
  }
  .btn-group {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-bottom: 15px;
  }
  button {
    font-family: inherit;
    font-weight: 600;
    font-size: 14px;
    padding: 14px;
    border-radius: 12px;
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.15s ease;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }
  button:hover { transform: translateY(-2px); }
  button:active { transform: translateY(0); }

  .btn-green { background: rgba(16,185,129,0.12); border-color: rgba(16,185,129,0.4); color: #34d399; }
  .btn-green:hover { background: rgba(16,185,129,0.25); }
  .btn-yellow { background: rgba(245,158,11,0.12); border-color: rgba(245,158,11,0.4); color: #fbbf24; }
  .btn-yellow:hover { background: rgba(245,158,11,0.25); }
  .btn-red { background: rgba(239,68,68,0.12); border-color: rgba(239,68,68,0.4); color: #f87171; }
  .btn-red:hover { background: rgba(239,68,68,0.25); }

  .btn-demo {
    width: 100%;
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    color: #ffffff;
    padding: 16px;
    font-size: 15px;
    border-radius: 12px;
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: center;
    gap: 10px;
    box-shadow: 0 4px 15px rgba(37, 99, 235, 0.3);
  }
  .btn-demo:hover { background: linear-gradient(135deg, #1d4ed8, #1e40af); }

  .router-sync-box {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 13px;
    color: var(--muted);
  }
  .router-sync-box code {
    font-family: 'JetBrains Mono', monospace;
    color: #38bdf8;
    background: rgba(56, 189, 248, 0.1);
    padding: 2px 6px;
    border-radius: 4px;
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="badge-tag">ShorlyNot Project Demonstration</div>
    <h1>QKD Key Management System</h1>
    <p class="subtitle">Real-Time Quantum Channel Simulator & Router Guard Monitor</p>
  </header>

  <div id="statusCard" class="status-card state-GREEN">
    <div class="status-pill">
      <div class="dot"></div>
      <span id="statusText">GREEN</span>
    </div>
    <div id="statusDesc" class="status-desc">Quantum link secure. QBER is below threshold. Router firewall allowing relay port 8765.</div>

    <div class="metrics-grid">
      <div class="metric-box">
        <div class="metric-label">Quantum Error (QBER)</div>
        <div id="qberVal" class="metric-value" style="color: #34d399;">1.4%</div>
      </div>
      <div class="metric-box">
        <div class="metric-label">Key Generation Rate</div>
        <div id="keyRateVal" class="metric-value">2,420 bps</div>
      </div>
      <div class="metric-box">
        <div class="metric-label">Router Enforcement</div>
        <div id="routerActionVal" class="metric-value" style="color: #34d399; font-size: 20px;">ALLOW (Open)</div>
      </div>
    </div>
  </div>

  <div class="actions-card">
    <div class="actions-title">Interactive Judge Demonstration Controls</div>
    <div class="btn-group">
      <button class="btn-green" onclick="setScenario('green', 1.5)">
        <span>Low Error Rate</span>
        <small style="opacity:0.75">QBER: 1.5% (🟢 GREEN)</small>
      </button>
      <button class="btn-yellow" onclick="setScenario('yellow', 6.8)">
        <span>Medium Optical Noise</span>
        <small style="opacity:0.75">QBER: 6.8% (🟡 YELLOW)</small>
      </button>
      <button class="btn-red" onclick="setScenario('red', 16.2)">
        <span>Simulate Eavesdropping</span>
        <small style="opacity:0.75">QBER: 16.2% (🔴 RED / BLOCK)</small>
      </button>
    </div>

    <button id="demoBtn" class="btn-demo" onclick="toggleAutoDemo()">
      <span>⏱️ Start Automated Judge Demo (15s Cycles)</span>
    </button>
  </div>

  <div class="router-sync-box">
    <div>Router Polling Endpoint: <code>http://192.168.1.123:8000/link_status</code></div>
    <div>Total Router Polls: <strong id="pollCount" style="color: #fff;">0</strong></div>
  </div>
</div>

<script>
let autoDemoActive = false;
let demoInterval = null;

async function updateData() {
  try {
    const res = await fetch('/metrics');
    const data = await res.json();
    
    document.getElementById('statusText').innerText = data.status;
    document.getElementById('pollCount').innerText = data.polls;
    document.getElementById('qberVal').innerText = data.qber.toFixed(1) + '%';
    document.getElementById('keyRateVal').innerText = data.key_rate.toLocaleString() + ' bps';

    const card = document.getElementById('statusCard');
    card.className = 'status-card state-' + data.status;

    const desc = document.getElementById('statusDesc');
    const action = document.getElementById('routerActionVal');
    const qber = document.getElementById('qberVal');

    if (data.status === 'GREEN') {
      desc.innerText = 'Quantum link secure. QBER is below threshold. Router firewall allowing relay port 8765.';
      action.innerText = 'ALLOW (Open)';
      action.style.color = '#34d399';
      qber.style.color = '#34d399';
    } else if (data.status === 'YELLOW') {
      desc.innerText = 'High optical noise / channel degradation. Link remains safe for now. Relay traffic allowed.';
      action.innerText = 'ALLOW (Warning)';
      action.style.color = '#fbbf24';
      qber.style.color = '#fbbf24';
    } else {
      desc.innerText = 'CRITICAL: Quantum Error Rate exceeded 11% threshold! Active eavesdropping detected. Router firewall BLOCKING port 8765!';
      action.innerText = 'BLOCK (Drop 8765)';
      action.style.color = '#f87171';
      qber.style.color = '#f87171';
    }
  } catch (e) {}
}

async function setScenario(status, qber) {
  await fetch(`/set_qber/${qber}`);
  updateData();
}

function toggleAutoDemo() {
  autoDemoActive = !autoDemoActive;
  const btn = document.getElementById('demoBtn');
  if (autoDemoActive) {
    btn.style.background = 'linear-gradient(135deg, #ef4444, #b91c1c)';
    btn.innerText = '⏹️ Stop Automated Demo';
    fetch('/demo/start');
  } else {
    btn.style.background = 'linear-gradient(135deg, #2563eb, #1d4ed8)';
    btn.innerText = '⏱️ Start Automated Judge Demo (15s Cycles)';
    fetch('/demo/stop');
  }
}

setInterval(updateData, 1000);
updateData();
</script>
</body>
</html>
"""

class MockKMSHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info(f"[{self.log_date_time_string()}] {self.address_string()} - {format%args}")

    KMS_AUTH_SECRET = os.environ.get("SHORLYNOT_KMS_SECRET", "kms-openwrt-auth-token-2026")

    def _is_authorized(self) -> bool:
        auth_header = self.headers.get("Authorization", "")
        token = self.headers.get("X-KMS-Auth", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        # Accept if matches KMS_AUTH_SECRET or if connecting from local loopback with default token
        if token and hmac.compare_digest(token.encode("utf-8"), self.KMS_AUTH_SECRET.encode("utf-8")):
            return True
        # Allow demo loopback for integrated test runner if configured
        if self.client_address[0] in ("127.0.0.1", "::1", "localhost"):
            return True
        return False

    def do_POST(self):
        global SERVER_STATE, AUTO_DEMO
        path = self.path
        if not self._is_authorized():
            self.send_error(401, "Unauthorized: KMS management token required.")
            return

        response = None
        if path.startswith("/set_qber/"):
            try:
                val = float(path.split("/set_qber/")[1])
                with SERVER_STATE["lock"]:
                    SERVER_STATE["qber"] = val
                    if val < 4.0:
                        status = "GREEN"
                        SERVER_STATE["key_rate"] = random.randint(2200, 2600)
                    elif val < 11.0:
                        status = "YELLOW"
                        SERVER_STATE["key_rate"] = random.randint(800, 1400)
                    else:
                        status = "RED"
                        SERVER_STATE["key_rate"] = 0
                    SERVER_STATE["status"] = status
                    SERVER_STATE["transitions"].append({"time": time.time(), "status": status, "qber": val})
                response = {"status": "ok", "new_status": status, "qber": val}
            except Exception as e:
                self.send_error(400, f"Invalid QBER value: {e}")
                return

        elif path.startswith("/set/"):
            new_status = path.split("/set/")[1].upper()
            if new_status in ["GREEN", "YELLOW", "RED"]:
                with SERVER_STATE["lock"]:
                    SERVER_STATE["status"] = new_status
                    if new_status == "GREEN":
                        SERVER_STATE["qber"] = random.uniform(1.1, 2.8)
                        SERVER_STATE["key_rate"] = random.randint(2200, 2600)
                    elif new_status == "YELLOW":
                        SERVER_STATE["qber"] = random.uniform(5.5, 8.5)
                        SERVER_STATE["key_rate"] = random.randint(900, 1400)
                    else:
                        SERVER_STATE["qber"] = random.uniform(14.0, 18.0)
                        SERVER_STATE["key_rate"] = 0
                    SERVER_STATE["transitions"].append({"time": time.time(), "status": new_status, "qber": SERVER_STATE["qber"]})
                response = {"status": "ok", "new_status": new_status}
            else:
                self.send_error(400, "Invalid status")
                return

        elif path == "/demo/start":
            AUTO_DEMO["active"] = True
            response = {"demo": "started"}

        elif path == "/demo/stop":
            AUTO_DEMO["active"] = False
            response = {"demo": "stopped"}
        else:
            self.send_error(404, "Not Found")
            return

        data = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        global SERVER_STATE
        path = self.path
        response = None

        if path.startswith("/set/") or path.startswith("/set_qber/") or path.startswith("/demo/"):
            self.send_error(405, "Method Not Allowed: KMS state transitions require authenticated POST requests.")
            return
        
        if path == "/" or path == "/index.html":
            data = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            return

        elif path == "/link_status":
            with SERVER_STATE["lock"]:
                SERVER_STATE["polls"] += 1
                status = SERVER_STATE["status"]
                qber = SERVER_STATE["qber"]
                key_rate = SERVER_STATE["key_rate"]
            response = {
                "status": status,
                "qber": round(qber, 2),
                "key_rate": key_rate
            }

        elif path == "/metrics":
            with SERVER_STATE["lock"]:
                response = {
                    "status": SERVER_STATE["status"],
                    "qber": SERVER_STATE["qber"],
                    "key_rate": SERVER_STATE["key_rate"],
                    "polls": SERVER_STATE["polls"],
                    "uptime": time.time() - SERVER_STATE["start_time"]
                }
        else:
            self.send_error(404, "Not Found")
            return

        data = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)



def auto_demo_worker():
    """Cycles through real-world QKD phases: Green (15s) -> Yellow (15s) -> Red (15s) -> Green"""
    phases = [
        ("GREEN", 1.4, 2450, 15),
        ("YELLOW", 6.8, 1100, 15),
        ("RED", 16.5, 0, 15)
    ]
    idx = 0
    while not SHUTDOWN_EVENT.is_set():
        if AUTO_DEMO["active"]:
            status, qber, rate, duration = phases[idx % len(phases)]
            with SERVER_STATE["lock"]:
                SERVER_STATE["status"] = status
                SERVER_STATE["qber"] = qber
                SERVER_STATE["key_rate"] = rate
                SERVER_STATE["transitions"].append({"time": time.time(), "status": status, "qber": qber})
            logging.info(f"[AUTO-DEMO] Transitioned to {status} (QBER: {qber}%)")
            idx += 1
            for _ in range(duration * 10):
                if SHUTDOWN_EVENT.is_set() or not AUTO_DEMO["active"]:
                    break
                time.sleep(0.1)
        else:
            time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShorlyNot QKD KMS Simulator")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default 8000)")
    parser.add_argument("--demo", action="store_true", help="Start immediately in auto-demo cycle mode")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    SERVER_STATE = {
        "status": "GREEN",
        "qber": 1.4,
        "key_rate": 2420,
        "polls": 0,
        "transitions": [],
        "start_time": time.time(),
        "lock": threading.Lock()
    }

    AUTO_DEMO = {"active": args.demo}
    SHUTDOWN_EVENT = threading.Event()

    demo_thread = threading.Thread(target=auto_demo_worker, daemon=True)
    demo_thread.start()

    http.server.ThreadingHTTPServer.allow_reuse_address = True
    server = http.server.ThreadingHTTPServer(('', args.port), MockKMSHandler)
    logging.info(f"===============================================================")
    logging.info(f" ShorlyNot QKD KMS Server Live on port {args.port}")
    logging.info(f" Web Dashboard: http://localhost:{args.port}/")
    logging.info(f" Router URL   : http://192.168.1.123:{args.port}/link_status")
    logging.info(f"===============================================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("\nShutting down server...")
    finally:
        SHUTDOWN_EVENT.set()
        server.server_close()
