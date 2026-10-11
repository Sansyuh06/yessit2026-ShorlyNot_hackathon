"""
Tests for end-to-end atomic transfer pipeline.
"""

from shorlynot_skeleton.pipeline import QuantumTransferPipeline
from shorlynot_skeleton.models import (
    TransactionPayload,
    TransferPipelineRequest,
    ThreatLabel,
    StageS,
    TauPreset
)


def test_honest_pipeline_transfer_success():
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=2500.0, currency="INR", tx_id="tx-honest-success")
    req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        verifier_id="bob",
        tau_preset=TauPreset.NORMAL
    )
    result = pipeline.execute_transfer(req)

    assert result.success is True
    assert result.status_code == 200
    assert result.threat_classification.label == ThreatLabel.OK
    assert result.verify_result.candidate_accepted is True
    assert result.verify_result.mismatch_rate <= result.verify_result.tau
    assert result.bank_lock_status == "active"
    assert result.stage_s == StageS.S0


def test_attacker_source_blocked_but_victim_unaffected():
    """A forged bundle that NAMES alice must block the attacker's source, never alice."""
    pipeline = QuantumTransferPipeline()

    tx_attack = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-atk-stage")
    res_attack = pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx_attack, signer_key_id="alice-key-1", simulate_attack="forgery",
        source_id="203.0.113.9"))
    assert res_attack.stage_s >= StageS.S2

    # Alice's legitimate transfer from her own origin still succeeds
    tx_legit = TransactionPayload(from_user="alice", to_user="bob", amount=500.0, tx_id="tx-legit-ok")
    res_legit = pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx_legit, signer_key_id="alice-key-1", source_id="198.51.100.7"))
    assert res_legit.success is True

    # The attacker's origin is refused
    tx_bad = TransactionPayload(from_user="alice", to_user="bob", amount=500.0, tx_id="tx-atk-again")
    res_bad = pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx_bad, signer_key_id="alice-key-1", source_id="203.0.113.9"))
    assert res_bad.success is False
    assert res_bad.bank_lock_status == "transfers_blocked"


def test_unauthenticated_forgeries_cannot_lock_victim_or_bank():
    """Regression for the lock-out weapon: repeated forgeries naming alice, with no attribution,
    never quarantine alice and never reach global scope."""
    pipeline = QuantumTransferPipeline()
    for i in range(6):
        tx = TransactionPayload(from_user="alice", to_user="bob", amount=1.0, tx_id=f"tx-spam-{i}")
        pipeline.execute_transfer(TransferPipelineRequest(
            transaction=tx, signer_key_id="alice-key-1", simulate_attack="forgery",
            source_id=f"10.0.0.{i}"))
    state = pipeline.stage_machine.get_state()
    assert "alice" not in state.quarantined_accounts
    assert state.lock_scope == "account" and state.bank_locked is False

    tx = TransactionPayload(from_user="alice", to_user="bob", amount=10.0, tx_id="tx-alice-after-spam")
    res = pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx, signer_key_id="alice-key-1", source_id="198.51.100.7"))
    assert res.success is True


def test_impersonator_account_is_quarantined_not_the_victim():
    """Eve signs with her own key but claims alice. The ML-DSA signature attributes the bundle to eve."""
    pipeline = QuantumTransferPipeline()
    tx = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-imp-attrib")
    pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx, signer_key_id="alice-key-1", simulate_attack="impersonation"))
    state = pipeline.stage_machine.get_state()
    assert "eve" in state.quarantined_accounts
    assert "alice" not in state.quarantined_accounts

    tx_a = TransactionPayload(from_user="alice", to_user="bob", amount=100.0, tx_id="tx-alice-fine")
    assert pipeline.execute_transfer(TransferPipelineRequest(
        transaction=tx_a, signer_key_id="alice-key-1")).success is True

    tx_e = TransactionPayload(from_user="eve", to_user="bob", amount=100.0, tx_id="tx-eve-blocked")
    res_e = pipeline.execute_transfer(TransferPipelineRequest(transaction=tx_e, signer_key_id="eve-key-1"))
    assert res_e.success is False and "quarantine" in res_e.message.lower()


def test_global_lock_blocks_everyone():
    """Regression: channel attack escalates to S4 global scope -> everyone blocked."""
    pipeline = QuantumTransferPipeline()

    tx_attack = TransactionPayload(from_user="alice", to_user="bob", amount=1000.0, tx_id="tx-atk-global")
    pipeline.execute_transfer(
        TransferPipelineRequest(transaction=tx_attack, signer_key_id="alice-key-1", simulate_attack="channel")
    )
    assert pipeline.stage_machine.get_state().lock_scope == "global"

    for actor, key in (("alice", "alice-key-1"), ("bob", "bob-key-1"), ("carol", "carol-key-1")):
        tx = TransactionPayload(from_user=actor, to_user="dave", amount=10.0, tx_id=f"tx-blocked-{actor}")
        res = pipeline.execute_transfer(TransferPipelineRequest(transaction=tx, signer_key_id=key))
        assert res.success is False, f"{actor} should be blocked under global lock"

