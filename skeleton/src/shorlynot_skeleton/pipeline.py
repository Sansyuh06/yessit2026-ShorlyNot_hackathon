"""
Atomic Quantum Security Transfer Pipeline for ShorlyNot.
Orchestrates QKD Session -> QDS Sign -> PQC Protect -> QDS Verify -> Q-STDF Classify -> Stage Update -> Bank Enforcement.
Normative specification from PRD §4.2.
"""

import hashlib
import os
import time
from typing import Optional

from shorlynot_skeleton.models import (
    TransferPipelineRequest,
    PipelineResult,
    ThreatClassification,
    ThreatLabel,
    StageS,
    StageQ
)
from shorlynot_skeleton.qds.protocol import QdsT1Protocol
from shorlynot_skeleton.qkd.bb84 import Bb84Simulator
from shorlynot_skeleton.pqc.protect import CorrectionBitProtector
from shorlynot_skeleton.detect.classifier import QstdfClassifier
from shorlynot_skeleton.detect.tau import TauCalculator
from shorlynot_skeleton.stages.state_machine import StageStateMachine
from shorlynot_skeleton.attacks.forgery import ForgeryAttack
from shorlynot_skeleton.attacks.impersonation import ImpersonationAttack
from shorlynot_skeleton.qkd.key_registry import GLOBAL_KEY_REGISTRY
from shorlynot_skeleton.pqc.kem_interface import MlKem768Interface
from shorlynot_skeleton.pqc.hybrid import derive_hybrid_key
from shorlynot_skeleton.pqc.identity import identity_message
from shorlynot_skeleton.attacks.unauth_verify import UnauthVerifyAttack
from shorlynot_skeleton.attacks.channel import ChannelTamperingAttack
from shorlynot_skeleton.attacks.param_tamper import ParameterTamperingAttack


class QuantumTransferPipeline:
    """
    Unified end-to-end security pipeline combining QDS-T1, Q-STDF, BB84, and PQC.
    """

    def __init__(
        self,
        qds_protocol: Optional[QdsT1Protocol] = None,
        qkd_simulator: Optional[Bb84Simulator] = None,
        classifier: Optional[QstdfClassifier] = None,
        stage_machine: Optional[StageStateMachine] = None
    ):
        self.qds = qds_protocol or QdsT1Protocol(p0=0.02, default_delta=0.01)
        self.qkd = qkd_simulator or Bb84Simulator(baseline_qber=0.025)
        _nonce_db = os.environ.get("SHORLYNOT_NONCE_DB") or "shorlynot_nonces.db"
        self.classifier = classifier or QstdfClassifier(db_path=_nonce_db)
        self.stage_machine = stage_machine or StageStateMachine()
        # Verifier's long-term ML-KEM-768 keypair (FIPS 203). Signer encapsulates per transfer.
        self._kem_pk, self._kem_sk = MlKem768Interface.keypair()

    def execute_transfer(self, request: TransferPipelineRequest) -> PipelineResult:
        """
        Execute full quantum-signed transfer workflow.
        simulate_attack only constructs malicious bundles for the demo harness; it is never read by the verifier or classifier — detection is blind.
        """
        t_start = time.perf_counter()
        tx = request.transaction
        canonical_json = tx.canonical_json()
        payload_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        # Step 1: QKD Session Negotiation
        inject_eve = (request.simulate_attack == "channel")
        # Full interception for the channel-compromise scenario: a tapped
        # link means Eve reads every qubit (expected QBER ≈ 25% -> Q4).
        qkd_result = self.qkd.negotiate_session(
            inject_eavesdropper=inject_eve,
            eve_intercept_prob=1.0 if inject_eve else 0.0
        )
        self.stage_machine.update_qber(qkd_result.qber)
        stage_q = self.stage_machine.stage_q

        # Check if active transfers allowed under current stage S
        current_state = self.stage_machine.get_state()
        actor = tx.from_user
        if self.stage_machine.is_actor_blocked(actor, request.source_id):
            t_end = time.perf_counter()
            if current_state.lock_scope == "account":
                reason = f"Account quarantine active for {actor} (Stage S{current_state.stage_s.value})"
            else:
                reason = "Bank security lockdown active (Stage S4)" if current_state.bank_locked else "New transfers suspended by security policy (Stage S2+)"
            return PipelineResult(
                success=False,
                status_code=423 if current_state.bank_locked else 403,
                message=reason,
                tx_id=tx.tx_id,
                payload_hash=payload_hash,
                qkd_session_id=qkd_result.session_id,
                qber=qkd_result.qber,
                stage_q=stage_q,
                threat_classification=ThreatClassification(
                    label=self.stage_machine.last_threat,
                    passed=False,
                    reason=reason,
                    mismatch_rate=self.stage_machine.last_mismatch,
                    tau=current_state.tau,
                    p0=current_state.p0,
                    n=current_state.n,
                    delta=current_state.delta,
                    stage_s_recommendation=self.stage_machine.stage_s
                ),
                stage_s=self.stage_machine.stage_s,
                bank_lock_status="bank_locked" if current_state.bank_locked else "transfers_blocked",
                total_time_ms=round((t_end - t_start) * 1000, 3)
            )

        # Step 2: QDS-T1 Signing
        claimed_signer = tx.from_user
        signer_key = request.signer_key_id

        # Generate honest signature
        bundle = self.qds.sign(
            payload_hash=payload_hash,
            key_id=signer_key,
            n_checks=64,
            L=128,
            backend=request.backend
        )

        # Identity binding: ML-DSA-44 signature over the bundle header, under the signer's registered key
        bundle.identity_sig = GLOBAL_KEY_REGISTRY.sign_identity(
            signer_key,
            identity_message(bundle.payload_hash, bundle.nonce, bundle.key_id, bundle.n_checks, bundle.L)
        )

        # Step 3: PQC Wrap of Pauli correction bits.
        # Wrap key = HKDF(BB84 key || ML-KEM-768 shared secret): secure if either ingredient holds.
        kem_ct, kem_ss_signer = MlKem768Interface.encapsulate(self._kem_pk)
        wrap_key_signer = derive_hybrid_key(qkd_result.session_key, kem_ss_signer)
        protected_corrections = CorrectionBitProtector.protect(bundle.correction_bits, wrap_key_signer)
        bundle.protected_corrections = protected_corrections
        bundle.pqc_mode = "ml-kem-768+bb84+aes-256-gcm"
        bundle.measurement_transcript["kem_ciphertext_hex"] = kem_ct.hex()

        # Handle Attack Injections for Live Demonstrations
        verifier_id = request.verifier_id
        if request.simulate_attack == "unauth_verify" and verifier_id in ("bob", "alice", "carol", "ops", "bank_validator", "system"):
            verifier_id = UnauthVerifyAttack.get_unauthorized_verifier_id()

        if request.simulate_attack == "forgery":
            bundle = ForgeryAttack.generate_forged_bundle(payload_hash=payload_hash, claimed_key_id=signer_key)
        elif request.simulate_attack == "impersonation":
            bundle = ImpersonationAttack.generate_impersonated_bundle(
                payload_hash=payload_hash,
                claimed_key_id=signer_key,
                attacker_key_id="eve-key-1",
                qds_protocol=self.qds
            )
        elif request.simulate_attack == "replay":
            # Replay by pre-registering nonce
            self.classifier.record_nonce(bundle.nonce)
        elif request.simulate_attack == "channel":
            bundle = ChannelTamperingAttack.tamper_correction_bits(bundle)
            bundle = ChannelTamperingAttack.corrupt_pqc_ciphertext(bundle)
        elif request.simulate_attack in ("param_tamper", "param_downgrade"):
            bundle = ParameterTamperingAttack.generate_downgraded_bundle(
                payload_hash=payload_hash,
                claimed_key_id=signer_key,
                tampered_n=1
            )

        # Step 4: PQC Unwrap & Verification (Pure evidence, zero oracles)
        pqc_success = True
        unwrapped_bits = bundle.correction_bits
        if bundle.protected_corrections:
            # Verifier side: decapsulate the transmitted KEM ciphertext, rebuild the hybrid key.
            try:
                kem_ss_verifier = MlKem768Interface.decapsulate(
                    bytes.fromhex(bundle.measurement_transcript.get("kem_ciphertext_hex", "")),
                    self._kem_sk
                )
                wrap_key_verifier = derive_hybrid_key(qkd_result.session_key, kem_ss_verifier)
            except Exception:
                wrap_key_verifier = b"\x00" * 32  # unwrap will fail authentication
            pqc_success, unwrapped = CorrectionBitProtector.unprotect(
                bundle.protected_corrections,
                wrap_key_verifier
            )
            if pqc_success and unwrapped is not None:
                unwrapped_bits = unwrapped
            else:
                pqc_success = False

        # Step 5: QDS-T1 Projective Verification
        delta_budget = TauCalculator.PRESETS[request.tau_preset]["delta"]
        verify_result = self.qds.verify(
            bundle=bundle,
            verifier_id=verifier_id,
            delta=delta_budget,
            override_syndromes=unwrapped_bits if pqc_success else bundle.correction_bits
        )

        # Step 6: Q-STDF Threat Classification (Strict Non-ML Ladder)
        classification = self.classifier.classify(
            bundle=bundle,
            verify_result=verify_result,
            claimed_signer=claimed_signer,
            verifier_id=verifier_id,
            pqc_unprotect_success=pqc_success,
            require_identity_sig=True
        )

        # Step 7: Update Security Stage State Machine
        # Response policy: punish only what the evidence proves.
        #  - attributed_actor: an account whose registered ML-DSA key verifiably produced the bundle
        #    (e.g. the real signer behind an impersonation). Never the claimed victim.
        #  - source_id: the network/session origin of the request.
        #  - link_evidence: elevated QBER measured on the physical link (not sender-controlled).
        attributed_actor = None
        if classification.label == ThreatLabel.IMPERSONATION:
            attributed_key = (classification.details or {}).get("attributed_key")
            if attributed_key:
                reg_record = GLOBAL_KEY_REGISTRY.get_key(attributed_key)
                attributed_actor = reg_record.user_id if reg_record else attributed_key

        stage_s = self.stage_machine.process_threat_verdict(
            label=classification.label,
            mismatch_rate=verify_result.mismatch_rate,
            tau=verify_result.tau,
            tx_id=tx.tx_id,
            actor=claimed_signer,
            details=f"Tx ₹{tx.amount} to {tx.to_user}: {classification.reason}",
            attributed_actor=attributed_actor,
            source_id=request.source_id,
            link_evidence=stage_q.value >= StageQ.Q3.value
        )

        t_end = time.perf_counter()
        total_time_ms = round((t_end - t_start) * 1000, 3)

        # Step 8: Final Bank Authorization Decision
        success = classification.passed and not self.stage_machine.is_actor_blocked(claimed_signer, request.source_id)
        status_code = 200 if success else (403 if stage_s.value < StageS.S4.value else 423)
        message = "Transfer successfully signed, verified, and committed to ledger." if success else classification.reason

        bank_lock_status = "active" if success else ("bank_locked" if stage_s.value >= StageS.S4.value else "transfers_blocked")

        return PipelineResult(
            success=success,
            status_code=status_code,
            message=message,
            tx_id=tx.tx_id,
            payload_hash=payload_hash,
            qkd_session_id=qkd_result.session_id,
            qber=qkd_result.qber,
            stage_q=stage_q,
            signature_bundle=bundle,
            verify_result=verify_result,
            threat_classification=classification,
            stage_s=stage_s,
            bank_lock_status=bank_lock_status,
            total_time_ms=total_time_ms
        )
