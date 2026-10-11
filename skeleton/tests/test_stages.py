"""
Tests for security stage machine and QBER thresholds.
"""

from shorlynot_skeleton.stages.state_machine import StageStateMachine
from shorlynot_skeleton.models import StageS, StageQ, ThreatLabel


def test_stage_state_machine_transitions():
    sm = StageStateMachine()
    assert sm.stage_s == StageS.S0
    assert sm.stage_q == StageQ.Q0

    # Forgery escalates to S2
    s = sm.process_threat_verdict(ThreatLabel.FORGERY, 0.45, 0.21, tx_id="tx-1")
    assert s == StageS.S2
    assert sm.get_state().active_transfers_allowed is False

    # Replay escalates to S3
    s = sm.process_threat_verdict(ThreatLabel.REPLAY, 0.01, 0.21, tx_id="tx-2")
    assert s == StageS.S3

    # Channel tampering WITHOUT physical-link evidence is sender-controlled: capped below full lock
    s = sm.process_threat_verdict(ThreatLabel.CHANNEL, 0.0, 0.21, tx_id="tx-3")
    assert s == StageS.S3 and sm.get_state().bank_locked is False

    # Channel tampering WITH measured link evidence (elevated QBER) escalates to S4 (Full Bank Lock)
    s = sm.process_threat_verdict(ThreatLabel.CHANNEL, 0.0, 0.21, tx_id="tx-4", link_evidence=True)
    assert s == StageS.S4
    assert sm.get_state().bank_locked is True

    # Admin reset restores S0
    sm.reset()
    assert sm.stage_s == StageS.S0
    assert sm.get_state().active_transfers_allowed is True
    assert sm.get_state().bank_locked is False


def test_q_stage_qber_bands():
    sm = StageStateMachine()
    assert sm.calculate_q_stage(0.03) == StageQ.Q0
    assert sm.calculate_q_stage(0.06) == StageQ.Q1
    assert sm.calculate_q_stage(0.09) == StageQ.Q2
    assert sm.calculate_q_stage(0.15) == StageQ.Q3
    assert sm.calculate_q_stage(0.25) == StageQ.Q4


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_trust_decay_steps_stage_down_and_expires_quarantine():
    clock = FakeClock()
    sm = StageStateMachine(decay_seconds=60, clock=clock)
    sm.process_threat_verdict(ThreatLabel.FORGERY, 0.5, 0.21, attributed_actor="eve", source_id="1.2.3.4")
    assert sm.stage_s == StageS.S2 and sm.is_actor_blocked("eve")
    clock.t += 59
    assert sm.stage_s == StageS.S2
    clock.t += 2   # 61s since the last threat: S2 -> S1, quarantine expires below S2
    assert sm.stage_s == StageS.S1
    assert not sm.is_actor_blocked("eve", "1.2.3.4")
    assert sm.get_state().quarantined_accounts == []
    clock.t += 61
    assert sm.stage_s == StageS.S0 and sm.get_state().lock_scope == "none"
    assert any(e.event_type == "TRUST_DECAY" for e in sm.get_events())


def test_global_lock_decays_to_account_scope_first():
    clock = FakeClock()
    sm = StageStateMachine(decay_seconds=60, clock=clock)
    sm.process_threat_verdict(ThreatLabel.CHANNEL, 0.0, 0.21, link_evidence=True)
    assert sm.stage_s == StageS.S4 and sm.is_actor_blocked("anyone")
    clock.t += 61
    assert sm.stage_s == StageS.S3
    assert sm.get_state().lock_scope == "account" and not sm.is_actor_blocked("anyone")


def test_new_threat_resets_decay_timer():
    clock = FakeClock()
    sm = StageStateMachine(decay_seconds=60, clock=clock)
    sm.process_threat_verdict(ThreatLabel.FORGERY, 0.5, 0.21, source_id="a")
    clock.t += 50
    sm.process_threat_verdict(ThreatLabel.FORGERY, 0.5, 0.21, source_id="a")
    clock.t += 50
    assert sm.stage_s.value >= StageS.S2.value


def test_unattributed_events_never_reach_global_scope():
    sm = StageStateMachine(decay_seconds=0)
    for i in range(10):
        sm.process_threat_verdict(ThreatLabel.FORGERY, 0.5, 0.21, actor="alice", source_id=f"s{i}")
        sm.process_threat_verdict(ThreatLabel.REPLAY, 0.0, 0.21, actor="alice", source_id=f"s{i}")
    st = sm.get_state()
    assert st.lock_scope == "account" and not st.bank_locked
    assert "alice" not in st.quarantined_accounts
    assert not sm.is_actor_blocked("alice", "clean-source")


def test_attributed_streak_can_escalate_to_global():
    sm = StageStateMachine(decay_seconds=0)
    for _ in range(4):
        sm.process_threat_verdict(ThreatLabel.IMPERSONATION, 0.5, 0.21, attributed_actor="eve")
    assert sm.get_state().lock_scope == "global" and sm.get_state().bank_locked
