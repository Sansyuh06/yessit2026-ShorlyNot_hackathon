"""Hash-chained audit log: tamper evidence for stage events."""
import json

from shorlynot_skeleton.audit.chain import HashChainedLog
from shorlynot_skeleton.models import ThreatLabel
from shorlynot_skeleton.stages.state_machine import StageStateMachine


def _filled(n=5):
    log = HashChainedLog()
    for i in range(n):
        log.append({"event": i, "who": "x"})
    return log


def test_clean_chain_verifies():
    assert _filled().verify() == (True, None)


def test_edit_is_detected_at_the_edited_entry():
    log = _filled()
    log._entries[2]["payload"]["who"] = "someone-else"
    assert log.verify() == (False, 2)


def test_deletion_in_the_middle_is_detected():
    log = _filled()
    del log._entries[2]
    ok, idx = log.verify()
    assert ok is False and idx == 2


def test_reordering_is_detected():
    log = _filled()
    log._entries[1], log._entries[2] = log._entries[2], log._entries[1]
    assert log.verify()[0] is False


def test_tail_truncation_needs_an_anchor():
    log = _filled()
    anchor = log.head()
    del log._entries[-1]
    assert log.verify() == (True, None)           # looks valid without an anchor
    assert log.verify(expected_head=anchor)[0] is False   # caught with one


def test_persistence_roundtrip_and_tamper_on_disk(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = HashChainedLog(str(path))
    for i in range(3):
        log.append({"i": i})
    assert HashChainedLog(str(path)).verify() == (True, None)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["payload"]["i"] = 99
    lines[1] = json.dumps(rec, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    assert HashChainedLog(str(path)).verify() == (False, 1)


def test_state_machine_events_are_chained():
    sm = StageStateMachine(decay_seconds=0)
    sm.process_threat_verdict(ThreatLabel.FORGERY, 0.5, 0.21, source_id="a")
    sm.process_threat_verdict(ThreatLabel.OK, 0.0, 0.21)
    sm.reset()
    assert len(sm.audit) == 3 and sm.audit.verify() == (True, None)
    sm.audit._entries[0]["payload"]["actor"] = "forged"
    assert sm.audit.verify() == (False, 0)
