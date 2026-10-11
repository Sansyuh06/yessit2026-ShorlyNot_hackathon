"""
Tests for the 5 attack simulation vectors.
"""

from shorlynot_skeleton.pipeline import QuantumTransferPipeline
from shorlynot_skeleton.models import (
    TransactionPayload,
    TransferPipelineRequest,
    ThreatLabel,
    StageS,
    StageQ,
    TauPreset
)


def test_forgery_attack_vector():
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-forgery-1")
    req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        simulate_attack="forgery"
    )
    res = pipeline.execute_transfer(req)
    assert res.success is False
    assert res.threat_classification.label == ThreatLabel.FORGERY
    assert res.stage_s >= StageS.S2


def test_impersonation_attack_vector():
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-impersonate-1")
    req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        simulate_attack="impersonation"
    )
    res = pipeline.execute_transfer(req)
    assert res.success is False
    assert res.threat_classification.label == ThreatLabel.IMPERSONATION
    assert res.signature_bundle.key_id == "alice-key-1"
    # Detection is blind: no self-reported label exists in the bundle, and the real signer is
    # attributed cryptographically from the ML-DSA signature.
    assert "actual_signer" not in res.signature_bundle.measurement_transcript
    assert res.stage_s >= StageS.S2


def test_replay_attack_vector():
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-replay-1")
    req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        simulate_attack="replay"
    )
    res = pipeline.execute_transfer(req)
    assert res.success is False
    assert res.threat_classification.label == ThreatLabel.REPLAY
    assert res.stage_s >= StageS.S3


def test_unauth_verify_attack_vector():
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-unauth-1")
    req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        simulate_attack="unauth_verify"
    )
    res = pipeline.execute_transfer(req)
    assert res.success is False
    assert res.threat_classification.label == ThreatLabel.UNAUTH_VERIFY
    assert res.stage_s >= StageS.S3


def test_channel_attack_vector():
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-channel-1")
    req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        simulate_attack="channel"
    )
    res = pipeline.execute_transfer(req)
    assert res.success is False
    assert res.threat_classification.label in (ThreatLabel.CHANNEL, ThreatLabel.FORGERY)
    assert res.stage_s >= StageS.S2
    assert res.qber >= 0.12
    assert res.stage_q != StageQ.Q0


def test_parameter_tampering_downgrade_attack_vector():
    """
    Test that an adversary attempting to tamper with security parameters (e.g. n_checks=1)
    is caught immediately by Q-STDF and rejected.
    """
    from shorlynot_skeleton.attacks.param_tamper import ParameterTamperingAttack
    from shorlynot_skeleton.qds.protocol import QdsT1Protocol
    from shorlynot_skeleton.detect.classifier import QstdfClassifier

    protocol = QdsT1Protocol()
    classifier = QstdfClassifier()

    downgraded_bundle = ParameterTamperingAttack.generate_downgraded_bundle(
        payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        claimed_key_id="alice-key-1",
        tampered_n=1
    )

    verify_res = protocol.verify(downgraded_bundle, verifier_id="bob")
    assert verify_res.candidate_accepted is False
    assert verify_res.mismatch_rate == 1.0

    classification = classifier.classify(
        bundle=downgraded_bundle,
        verify_result=verify_res,
        verifier_id="bob",
        claimed_signer="alice"
    )
    assert classification.passed is False
    assert classification.label == ThreatLabel.PARAM_TAMPER
    assert classification.stage_s_recommendation == StageS.S4

    # Also test via full pipeline execution
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-tamper-1")
    req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        simulate_attack="param_tamper"
    )
    pipeline_res = pipeline.execute_transfer(req)
    assert pipeline_res.success is False
    assert pipeline_res.threat_classification.label == ThreatLabel.PARAM_TAMPER
    assert pipeline_res.stage_s >= StageS.S2


def test_payload_tamper_after_sign_rejected():
    """
    Test that modifying transaction payload amount after signing causes
    mismatch rate p_hat to jump to ~0.50 and leads to immediate blind rejection as FORGERY.
    Zero cooperation or self-labeling from attacker.
    """
    import hashlib
    from shorlynot_skeleton.qds.protocol import QdsT1Protocol
    from shorlynot_skeleton.detect.classifier import QstdfClassifier

    protocol = QdsT1Protocol()
    classifier = QstdfClassifier()

    # Alice honestly signs a transfer for Rs 5,000
    tx_original = TransactionPayload(from_user="alice", to_user="bob", amount=5000.0, tx_id="tx-honest-5k")
    hash_original = hashlib.sha256(tx_original.canonical_json().encode("utf-8")).hexdigest()
    bundle = protocol.sign(payload_hash=hash_original, key_id="alice-key-1")

    # Attacker tampers with amount (5,000 -> 500,000)
    tx_tampered = TransactionPayload(from_user="alice", to_user="bob", amount=500000.0, tx_id="tx-honest-5k")
    hash_tampered = hashlib.sha256(tx_tampered.canonical_json().encode("utf-8")).hexdigest()
    tampered_bundle = bundle.model_copy(update={"payload_hash": hash_tampered})

    # Verifier verifies tampered bundle against expected payload hash
    verify_res = protocol.verify(tampered_bundle, verifier_id="bob")
    assert verify_res.candidate_accepted is False
    # Empirical mismatch rate jumps around 0.50 (uncorrelated basis states) >> tau ~0.2097
    assert verify_res.mismatch_rate > verify_res.tau

    classification = classifier.classify(
        bundle=tampered_bundle,
        verify_result=verify_res,
        claimed_signer="alice",
        verifier_id="bob"
    )
    assert classification.passed is False
    assert classification.label == ThreatLabel.FORGERY


def test_bb84_deterministic_seed_and_eavesdropper_detection():
    from shorlynot_skeleton.qkd.bb84 import Bb84Simulator
    sim = Bb84Simulator(baseline_qber=0.02, raw_bits_count=512)

    # Deterministic runs with same seed produce identical QBER and bit counts
    res1 = sim.negotiate_session(inject_eavesdropper=False, seed=42)
    res2 = sim.negotiate_session(inject_eavesdropper=False, seed=42)
    assert res1.qber == res2.qber
    assert res1.sifted_bits_count == res2.sifted_bits_count
    assert res1.channel_status == "healthy"

    # Eavesdropper injection escalates QBER significantly above baseline
    res_eve = sim.negotiate_session(inject_eavesdropper=True, eve_intercept_prob=1.0, seed=42)
    assert res_eve.qber > 0.15
    assert res_eve.channel_status == "intercepted"

