"""
Q-STDF Threat Classification Engine.
Strict 6-step Non-ML Decision Ladder for SIH 2026 PS 26141.
Normative specification from PRD §4.3 and MODEL.md §10.
"""

import collections
import sqlite3
import time
from typing import Dict, Optional, Set
from shorlynot_skeleton.models import (
    ThreatLabel,
    ThreatClassification,
    SignatureBundle,
    VerifyResult,
    StageS
)
from shorlynot_skeleton.qds.sessions import GLOBAL_ENTANGLEMENT_STORE
from shorlynot_skeleton.qkd.key_registry import GLOBAL_KEY_REGISTRY
from shorlynot_skeleton.pqc.identity import identity_message


class QstdfClassifier:
    """
    Quantum Statistical Threat Detection Framework (Q-STDF).
    Strict non-ML rule-based ladder:
    1. UNAUTH_VERIFY -> verifier lacks entitlement
    2. IMPERSONATION -> key_id / identity binding invalid or physical signer mismatch
    3. REPLAY -> duplicate nonce in replay window
    4. PARAM_TAMPER -> security parameter downgrade or array truncation
    5. CHANNEL -> PQC unwrap / tag authentication failure
    6. FORGERY -> mismatch rate p_hat > tau
    7. OK -> all tests pass
    """

    DEFAULT_KEYS = {
        "alice": "alice-key-1",
        "bob": "bob-key-1",
        "carol": "carol-key-1",
        "eve": "eve-key-1",
    }

    AUTHORIZED_VERIFIERS = {"bob", "alice", "carol", "ops", "bank_validator", "system"}

    def __init__(self, replay_cache_size: int = 10000, db_path: Optional[str] = None) -> None:
        self.seen_nonces: collections.OrderedDict[str, float] = collections.OrderedDict()
        self.max_nonces = replay_cache_size
        self.key_bindings: Dict[str, str] = dict(self.DEFAULT_KEYS)
        self.authorized_verifiers: Set[str] = set(self.AUTHORIZED_VERIFIERS)
        self.db_path = db_path
        self._init_persistent_cache()

    def _init_persistent_cache(self) -> None:
        """Initialize persistent sqlite table for nonces if db_path is specified."""
        if self.db_path:
            try:
                conn = sqlite3.connect(self.db_path)
                with conn:
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS seen_nonces (nonce TEXT PRIMARY KEY, seen_at REAL)"
                    )
                conn.close()
            except Exception:
                pass

    def register_key(self, user: str, key_id: str) -> None:
        self.key_bindings[user] = key_id

    def is_nonce_seen(self, nonce: str) -> bool:
        if nonce in self.seen_nonces:
            return True
        if self.db_path:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?", (nonce,))
                row = cursor.fetchone()
                conn.close()
                if row:
                    self.seen_nonces[nonce] = time.time()
                    return True
            except Exception:
                pass
        return False

    def record_nonce(self, nonce: str) -> None:
        if len(self.seen_nonces) >= self.max_nonces:
            self.seen_nonces.popitem(last=False)
        seen_at = time.time()
        self.seen_nonces[nonce] = seen_at
        if self.db_path:
            try:
                conn = sqlite3.connect(self.db_path)
                with conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO seen_nonces (nonce, seen_at) VALUES (?, ?)",
                        (nonce, seen_at)
                    )
                conn.close()
            except Exception:
                pass

    def clear_replay_cache(self) -> None:
        self.seen_nonces.clear()
        if self.db_path:
            try:
                conn = sqlite3.connect(self.db_path)
                with conn:
                    conn.execute("DELETE FROM seen_nonces")
                conn.close()
            except Exception:
                pass

    def classify(
        self,
        bundle: SignatureBundle,
        verify_result: VerifyResult,
        claimed_signer: Optional[str] = None,
        verifier_id: str = "bob",
        pqc_unprotect_success: bool = True,
        require_identity_sig: bool = False
    ) -> ThreatClassification:
        """
        Evaluate signature verification against the strict blind Q-STDF decision ladder.
        All verdicts are derived from physical, cryptographic, and registry evidence.
        """
        p0 = verify_result.p0
        n = verify_result.n_checks
        delta = verify_result.delta
        tau = verify_result.tau
        mismatch_rate = verify_result.mismatch_rate

        # -------------------------------------------------------------
        # STEP 1: UNAUTH_VERIFY (Verifier Authorization Check)
        # -------------------------------------------------------------
        if verifier_id not in self.authorized_verifiers:
            return ThreatClassification(
                label=ThreatLabel.UNAUTH_VERIFY,
                passed=False,
                reason=f"Verifier '{verifier_id}' lacks verification entitlement credentials.",
                mismatch_rate=mismatch_rate,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S3,
                details={"verifier_id": verifier_id, "step": 1}
            )

        # -------------------------------------------------------------
        # STEP 2: IMPERSONATION (Signer Key ID Binding & Entanglement Session Origin)
        # -------------------------------------------------------------
        # Check session-origin binding if session exists on Bob's side
        session = GLOBAL_ENTANGLEMENT_STORE.get_session(bundle.nonce)
        if session and session.key_id != bundle.key_id:
            # Attribution only from cryptographic evidence: which registered key verifies the signature?
            attributed = None
            if bundle.identity_sig:
                attributed = GLOBAL_KEY_REGISTRY.identify_signer(
                    identity_message(bundle.payload_hash, bundle.nonce, bundle.key_id, bundle.n_checks, bundle.L),
                    bundle.identity_sig)
            return ThreatClassification(
                label=ThreatLabel.IMPERSONATION,
                passed=False,
                reason=f"Impersonation attack detected: Physical entanglement session belonged to '{session.key_id}', but bundle claimed '{bundle.key_id}'.",
                mismatch_rate=mismatch_rate,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S2,
                details={"claimed_signer": claimed_signer, "claimed_key": bundle.key_id, "session_key": session.key_id,
                         "attributed_key": attributed, "step": 2}
            )

        # Cryptographic identity check (ML-DSA-44). Evidence comes from the signature, never from
        # labels inside the bundle. A bad signature under the claimed key is impersonation, and the
        # real signer is attributed by trying the registered public keys.
        unsigned = False
        if require_identity_sig:
            id_msg = identity_message(bundle.payload_hash, bundle.nonce, bundle.key_id, bundle.n_checks, bundle.L)
            if bundle.identity_sig:
                if not GLOBAL_KEY_REGISTRY.verify_identity(bundle.key_id, id_msg, bundle.identity_sig):
                    attributed = GLOBAL_KEY_REGISTRY.identify_signer(id_msg, bundle.identity_sig)
                    return ThreatClassification(
                        label=ThreatLabel.IMPERSONATION,
                        passed=False,
                        reason=f"Impersonation detected: identity signature does not verify under claimed key '{bundle.key_id}'.",
                        mismatch_rate=mismatch_rate,
                        tau=tau,
                        p0=p0,
                        n=n,
                        delta=delta,
                        stage_s_recommendation=StageS.S2,
                        details={"claimed_signer": claimed_signer, "claimed_key": bundle.key_id,
                                 "attributed_key": attributed, "step": 2}
                    )
            else:
                unsigned = True

        actual_signer = None if require_identity_sig else bundle.measurement_transcript.get("actual_signer")
        if actual_signer and actual_signer != bundle.key_id:
            return ThreatClassification(
                label=ThreatLabel.IMPERSONATION,
                passed=False,
                reason=f"Impersonation attack detected: Physical signer key '{actual_signer}' does not match claimed key_id '{bundle.key_id}'.",
                mismatch_rate=mismatch_rate,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S2,
                details={"claimed_signer": claimed_signer, "claimed_key": bundle.key_id, "actual_signer": actual_signer, "step": 2}
            )

        if claimed_signer:
            is_valid_in_registry = GLOBAL_KEY_REGISTRY.validate_key_binding(bundle.key_id, claimed_signer)
            expected_key = self.key_bindings.get(claimed_signer)
            
            if not is_valid_in_registry and (not expected_key or bundle.key_id != expected_key):
                return ThreatClassification(
                    label=ThreatLabel.IMPERSONATION,
                    passed=False,
                    reason=f"Signer identity mismatch: Claimed '{claimed_signer}' does not own key_id '{bundle.key_id}'.",
                    mismatch_rate=mismatch_rate,
                    tau=tau,
                    p0=p0,
                    n=n,
                    delta=delta,
                    stage_s_recommendation=StageS.S2,
                    details={"claimed_signer": claimed_signer, "provided_key": bundle.key_id, "step": 2}
                )
        else:
            # Standalone verify without claimed_signer: key_id must exist in registry
            if bundle.key_id not in self.key_bindings and not GLOBAL_KEY_REGISTRY.get_key(bundle.key_id):
                return ThreatClassification(
                    label=ThreatLabel.IMPERSONATION,
                    passed=False,
                    reason=f"Unregistered signer key_id '{bundle.key_id}' submitted without authenticated identity.",
                    mismatch_rate=mismatch_rate,
                    tau=tau,
                    p0=p0,
                    n=n,
                    delta=delta,
                    stage_s_recommendation=StageS.S2,
                    details={"provided_key": bundle.key_id, "step": 2}
                )

        # -------------------------------------------------------------
        # STEP 3: REPLAY (Nonce Replay Check)
        # -------------------------------------------------------------
        if self.is_nonce_seen(bundle.nonce):
            return ThreatClassification(
                label=ThreatLabel.REPLAY,
                passed=False,
                reason=f"Nonce replay detected: Nonce '{bundle.nonce}' has already been processed.",
                mismatch_rate=mismatch_rate,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S3,
                details={"nonce": bundle.nonce, "step": 3}
            )

        # -------------------------------------------------------------
        # STEP 4: PARAMETER TAMPERING (Downgrade & Array Truncation Check)
        # -------------------------------------------------------------
        if bundle.n_checks < 32 or len(bundle.bases) < bundle.n_checks or len(bundle.correction_bits) < bundle.n_checks:
            return ThreatClassification(
                label=ThreatLabel.PARAM_TAMPER,
                passed=False,
                reason=f"Security parameter downgrade / array length tampering detected (n_checks={bundle.n_checks} < 32).",
                mismatch_rate=1.0,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S4,
                details={"n_checks": bundle.n_checks, "step": 4, "param_tampering": True}
            )

        # -------------------------------------------------------------
        # STEP 5: CHANNEL INTEGRITY (PQC Authentication & Syndrome Integrity)
        # -------------------------------------------------------------
        if not pqc_unprotect_success:
            return ThreatClassification(
                label=ThreatLabel.CHANNEL,
                passed=False,
                reason="PQC correction bits decryption/tag verification failure. Active classical or quantum channel tampering detected.",
                mismatch_rate=mismatch_rate,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S4,
                details={"pqc_unprotect_success": pqc_unprotect_success, "step": 5}
            )

        # -------------------------------------------------------------
        # STEP 6: FORGERY (Hoeffding Statistical Threshold Check)
        # -------------------------------------------------------------
        if unsigned:
            return ThreatClassification(
                label=ThreatLabel.FORGERY,
                passed=False,
                reason="Bundle carries no identity signature. Unauthenticated signature material is rejected.",
                mismatch_rate=mismatch_rate,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S2,
                details={"unsigned": True, "step": 6}
            )

        if mismatch_rate > tau:
            return ThreatClassification(
                label=ThreatLabel.FORGERY,
                passed=False,
                reason=f"Quantum measurement mismatch rate ({mismatch_rate:.4f}) exceeds Hoeffding threshold tau ({tau:.4f}). Potential signature forgery.",
                mismatch_rate=mismatch_rate,
                tau=tau,
                p0=p0,
                n=n,
                delta=delta,
                stage_s_recommendation=StageS.S2,
                details={"mismatch_rate": mismatch_rate, "tau": tau, "step": 6}
            )

        # -------------------------------------------------------------
        # STEP 7: OK (All Checks Passed)
        # -------------------------------------------------------------
        # Record valid nonce to prevent subsequent replay attacks
        self.record_nonce(bundle.nonce)

        return ThreatClassification(
            label=ThreatLabel.OK,
            passed=True,
            reason="Quantum digital signature verified successfully within honest Hoeffding bound.",
            mismatch_rate=mismatch_rate,
            tau=tau,
            p0=p0,
            n=n,
            delta=delta,
            stage_s_recommendation=StageS.S0,
            details={"mismatch_rate": mismatch_rate, "tau": tau, "step": 7}
        )
