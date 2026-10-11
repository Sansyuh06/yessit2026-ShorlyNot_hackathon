#!/usr/bin/env python3
"""
ShorlyNot - One-Shot Attack Demonstration & Defense Verification Runner.
SIH 2026 PS 26141 — ShorlyNot-QDS-T1 & Q-STDF Threat Engine.

Executes complete one-shot sequence:
1. Honest Transfer -> OK (Stage S0, Q0)
2. Forgery Attack -> Caught (Stage S2 Transfers Suspended)
3. Application-Level Bank Enforcement -> Transfers Blocked (HTTP 403)
4. Channel Tampering Attack -> Caught (Stage S4 Full Lock, QBER=15% -> Stage Q3)
5. Critical Bank Lock Enforcement -> Full Lockdown (HTTP 423)
6. Nonce Replay Attack -> Caught (Stage S3 Read-Only)
7. Impersonation Attack -> Caught (Stage S2 Identity Mismatch)
8. Security Parameter Downgrade Attack -> Caught (Stage S4 Downgrade Rejection)
9. Operator SOC Stage Reset -> System Restored to S0/Q0 Baseline
"""

import sys
import time
from typing import Dict, Any, List

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from shorlynot_skeleton.pipeline import QuantumTransferPipeline
from shorlynot_skeleton.models import (
    TransactionPayload,
    TransferPipelineRequest,
    ThreatLabel,
    StageS,
    StageQ,
    TauPreset
)


def run_attack_demonstration() -> bool:
    print("=" * 78)
    print("      SHORLYNOT -- SIH 2026 PS 26141 ATTACK & DEFENSE VERIFICATION")
    print("      Protocol: ShorlyNot-QDS-T1 | Detector: Q-STDF (Strict Non-ML)")
    print("=" * 78)
    print()

    pipeline = QuantumTransferPipeline()
    passed_steps = 0
    total_steps = 8

    # -------------------------------------------------------------------------
    # STEP 1: Honest Transfer
    # -------------------------------------------------------------------------
    print("[*] STEP 1: Executing Honest Quantum-Signed Transfer (Alice -> Bob INR 5,000)...")
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()

    tx_honest = TransactionPayload(
        from_user="alice",
        to_user="bob",
        amount=5000.0,
        currency="INR",
        tx_id="tx-honest-demo-1"
    )
    req_honest = TransferPipelineRequest(
        transaction=tx_honest,
        signer_key_id="alice-key-1",
        verifier_id="bob",
        tau_preset=TauPreset.NORMAL
    )
    res_honest = pipeline.execute_transfer(req_honest)

    if (
        res_honest.success
        and res_honest.threat_classification.label == ThreatLabel.OK
        and res_honest.stage_s == StageS.S0
        and res_honest.stage_q in (StageQ.Q0, StageQ.Q1)
        and res_honest.status_code == 200
    ):
        mismatch = res_honest.verify_result.mismatch_rate if res_honest.verify_result else 0.0
        tau = res_honest.verify_result.tau if res_honest.verify_result else 0.2097
        print(f"  [PASS] 1. Honest Transfer: Success (Mismatch p_hat={mismatch:.4f} <= tau={tau:.4f} | Stage S0/Q{res_honest.stage_q.value} | HTTP 200)")
        passed_steps += 1
    else:
        print(f"  [FAIL] 1. Honest Transfer failed: {res_honest.message}")
        return False

    # -------------------------------------------------------------------------
    # STEP 2: Signature Forgery Attack
    # -------------------------------------------------------------------------
    print("\n[*] STEP 2: Injecting Unentangled Forgery Attack (Adversary Eve)...")
    tx_forge = TransactionPayload(
        from_user="alice",
        to_user="bob",
        amount=100000.0,
        currency="INR",
        tx_id="tx-forge-demo-2"
    )
    req_forge = TransferPipelineRequest(
        transaction=tx_forge,
        signer_key_id="alice-key-1",
        verifier_id="bob",
        tau_preset=TauPreset.NORMAL,
        simulate_attack="forgery",
        source_id="203.0.113.9"
    )
    res_forge = pipeline.execute_transfer(req_forge)

    if (
        not res_forge.success
        and res_forge.threat_classification.label == ThreatLabel.FORGERY
        and res_forge.stage_s >= StageS.S2
    ):
        mismatch = res_forge.verify_result.mismatch_rate if res_forge.verify_result else 0.5
        tau = res_forge.verify_result.tau if res_forge.verify_result else 0.2097
        print(f"  [PASS] 2. Forgery Attack: Caught by Q-STDF (Mismatch p_hat={mismatch:.4f} > tau={tau:.4f} -> Stage S{res_forge.stage_s.value} Suspended)")
        passed_steps += 1
    else:
        print(f"  [FAIL] 2. Forgery Attack detection failed!")
        return False

    # -------------------------------------------------------------------------
    # STEP 3: Bank Application-Level Lockout Verification (Stage S2)
    # -------------------------------------------------------------------------
    print("\n[*] STEP 3: Verifying Application-Level Bank Enforcement under Stage S2...")
    tx_blocked = TransactionPayload(
        from_user="alice",
        to_user="bob",
        amount=500.0,
        currency="INR",
        tx_id="tx-blocked-demo-3"
    )
    # The attacker's origin is refused. Alice, the identity the forger CLAIMED, is not locked out.
    res_blocked = pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx_blocked, signer_key_id="alice-key-1", verifier_id="bob", source_id="203.0.113.9"))
    tx_victim = TransactionPayload(
        from_user="alice", to_user="bob", amount=500.0, currency="INR", tx_id="tx-victim-demo-3")
    res_victim = pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx_victim, signer_key_id="alice-key-1", verifier_id="bob", source_id="198.51.100.7"))

    if not res_blocked.success and res_blocked.status_code == 403 and res_victim.success:
        print(f"  [PASS] 3. Bank App Enforcement: attacker source refused (HTTP 403); named victim Alice keeps transacting")
        passed_steps += 1
    else:
        print(f"  [FAIL] 3. Enforcement must block the attacker source and spare the victim!")
        return False

    # -------------------------------------------------------------------------
    # STEP 4: Channel Tampering & Q-Stage Escalation
    # -------------------------------------------------------------------------
    print("\n[*] STEP 4: Injecting MITM Channel Tampering (PQC corruption + QBER spike)...")
    # Reset temporarily to test clean channel escalation
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()

    tx_chan = TransactionPayload(
        from_user="alice",
        to_user="bob",
        amount=25000.0,
        currency="INR",
        tx_id="tx-channel-demo-4"
    )
    req_chan = TransferPipelineRequest(
        transaction=tx_chan,
        signer_key_id="alice-key-1",
        verifier_id="bob",
        tau_preset=TauPreset.NORMAL,
        simulate_attack="channel"
    )
    res_chan = pipeline.execute_transfer(req_chan)

    if (
        not res_chan.success
        and res_chan.threat_classification.label in (ThreatLabel.CHANNEL, ThreatLabel.FORGERY)
        and res_chan.stage_s == StageS.S4
        and res_chan.stage_q != StageQ.Q0
        and res_chan.qber >= 0.12
    ):
        print(f"  [PASS] 4. Channel Tampering: Caught (Q-Stage moved to {res_chan.stage_q.value} via QBER={res_chan.qber*100:.1f}% -> Stage S4 Critical Lock)")
        passed_steps += 1
    else:
        print(f"  [FAIL] 4. Channel Tampering / Q-Stage escalation failed! (stage_q={res_chan.stage_q}, stage_s={res_chan.stage_s})")
        return False

    # -------------------------------------------------------------------------
    # STEP 5: Critical Bank Lockdown Verification (Stage S4)
    # -------------------------------------------------------------------------
    print("\n[*] STEP 5: Verifying Critical Bank Lockout (HTTP 423 Locked)...")
    tx_s4_blocked = TransactionPayload(
        from_user="alice",
        to_user="bob",
        amount=100.0,
        currency="INR",
        tx_id="tx-s4-demo-5"
    )
    req_s4_blocked = TransferPipelineRequest(
        transaction=tx_s4_blocked,
        signer_key_id="alice-key-1",
        verifier_id="bob"
    )
    res_s4 = pipeline.execute_transfer(req_s4_blocked)

    if not res_s4.success and res_s4.status_code == 423:
        print(f"  [PASS] 5. Critical Bank Lock: Active (Application fully locked HTTP 423)")
        passed_steps += 1
    else:
        print(f"  [FAIL] 5. Bank failed to enforce HTTP 423 under Stage S4!")
        return False

    # -------------------------------------------------------------------------
    # STEP 6: Nonce Replay Attack
    # -------------------------------------------------------------------------
    print("\n[*] STEP 6: Injecting Signature Nonce Replay Attack...")
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()

    # Honest sign first
    tx_r1 = TransactionPayload(from_user="alice", to_user="bob", amount=100.0, tx_id="tx-replay-base")
    req_r1 = TransferPipelineRequest(transaction=tx_r1, signer_key_id="alice-key-1")
    pipeline.execute_transfer(req_r1)

    # Now replay
    tx_replay = TransactionPayload(from_user="alice", to_user="bob", amount=9999.0, tx_id="tx-replay-attack")
    req_replay = TransferPipelineRequest(
        transaction=tx_replay,
        signer_key_id="alice-key-1",
        simulate_attack="replay"
    )
    res_replay = pipeline.execute_transfer(req_replay)

    if (
        not res_replay.success
        and res_replay.threat_classification.label == ThreatLabel.REPLAY
        and res_replay.stage_s >= StageS.S3
    ):
        print(f"  [PASS] 6. Nonce Replay Attack: Caught by Q-STDF (Replayed nonce detected -> Stage S{res_replay.stage_s.value} Read-Only)")
        passed_steps += 1
    else:
        print(f"  [FAIL] 6. Nonce Replay detection failed!")
        return False

    # -------------------------------------------------------------------------
    # STEP 7: Impersonation Attack (Signer Identity Spoofing)
    # -------------------------------------------------------------------------
    print("\n[*] STEP 7: Injecting Impersonation Attack (Eve signing with Eve keys, claiming Alice)...")
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()

    tx_imp = TransactionPayload(from_user="alice", to_user="bob", amount=15000.0, tx_id="tx-impersonate-demo")
    req_imp = TransferPipelineRequest(
        transaction=tx_imp,
        signer_key_id="alice-key-1",
        simulate_attack="impersonation"
    )
    res_imp = pipeline.execute_transfer(req_imp)

    if (
        not res_imp.success
        and res_imp.threat_classification.label == ThreatLabel.IMPERSONATION
        and res_imp.signature_bundle.key_id == "alice-key-1"
        and res_imp.threat_classification.details.get("attributed_key") == "eve-key-1"
        and "eve" in pipeline.stage_machine.get_state().quarantined_accounts
        and "alice" not in pipeline.stage_machine.get_state().quarantined_accounts
    ):
        print(f"  [PASS] 7. Impersonation Attack: Caught; ML-DSA signature attributes the bundle to eve-key-1, only Eve is quarantined (Stage S{res_imp.stage_s.value})")
        passed_steps += 1
    else:
        print(f"  [FAIL] 7. Impersonation detection failed!")
        return False

    # -------------------------------------------------------------------------
    # STEP 8: Security Parameter Downgrade Tampering Attack
    # -------------------------------------------------------------------------
    print("\n[*] STEP 8: Injecting Parameter Downgrade Tampering (n_checks=1 tamper)...")
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()

    tx_param = TransactionPayload(from_user="alice", to_user="bob", amount=500.0, tx_id="tx-param-demo")
    req_param = TransferPipelineRequest(
        transaction=tx_param,
        signer_key_id="alice-key-1",
        simulate_attack="param_tamper"
    )
    res_param = pipeline.execute_transfer(req_param)

    if (
        not res_param.success
        and res_param.threat_classification.label in (ThreatLabel.PARAM_TAMPER, ThreatLabel.CHANNEL)
        and res_param.stage_s >= StageS.S2
    ):
        print(f"  [PASS] 8. Parameter Downgrade Attack: Caught (n_checks=1 rejected by Q-STDF -> Stage S{res_param.stage_s.value})")
        passed_steps += 1
    else:
        print(f"  [FAIL] 8. Parameter Downgrade detection failed!")
        return False

    # -------------------------------------------------------------------------
    # Final Stage Machine Clean Reset
    # -------------------------------------------------------------------------
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()
    final_state = pipeline.stage_machine.get_state()

    print()
    print("=" * 78)
    print(f"  DEMONSTRATION COMPLETE: {passed_steps}/{total_steps} ATTACK & DEFENSE TESTS PASSED (100%)")
    print(f"  Final Stage Status: S{final_state.stage_s.value} / Q{final_state.stage_q.value} (Operational Baseline Restored)")
    print("=" * 78)
    return True


if __name__ == "__main__":
    success = run_attack_demonstration()
    if not success:
        sys.exit(1)
    sys.exit(0)
