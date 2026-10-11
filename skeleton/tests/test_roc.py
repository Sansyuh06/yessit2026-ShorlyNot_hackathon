"""Attack-strength ROC analysis: closed forms agree with the verifier model; exact threshold is tighter."""
from shorlynot_skeleton.analysis import roc
from shorlynot_skeleton.detect.tau import TauCalculator
from shorlynot_skeleton.qds.protocol import QdsT1Protocol


def test_closed_forms_match_engine_model():
    v = roc.validate_against_engine(n=64, p0=0.02, trials=100)
    for k in ("honest", "guess", "partial", "tamper"):
        assert abs(v[f"{k}_measured"] - v[f"{k}_theory"]) < 0.03, k


def test_exact_threshold_keeps_false_reject_budget():
    for n in (32, 64, 128):
        tau = TauCalculator.calculate_tau_exact(p0=0.02, delta=0.01, n=n)
        assert 1.0 - roc.accept_probability(0.01, tau, n) <= 0.01
        assert tau < TauCalculator.calculate_tau(p0=0.02, delta=0.01, n=n)


def test_exact_threshold_demands_more_attacker_information():
    t = roc.tolerated_information(64, 0.02, 0.01)
    assert t["exact"]["f_needed"] > t["hoeffding"]["f_needed"] + 0.2
    assert t["exact"]["r_tolerated"] < t["hoeffding"]["r_tolerated"]


def test_exact_threshold_fragile_under_noise_misspecification():
    nz = roc.frr_vs_true_noise(64, 0.02, 0.01, [0.02, 0.10])
    assert nz["frr_exact"][1] > 0.2 and nz["frr_hoeffding"][1] < 1e-3


def test_verify_exact_mode_accepts_honest_signature():
    p = QdsT1Protocol(p0=0.02)
    accepted = 0
    for i in range(40):
        b = p.sign(payload_hash=f"{i:064x}", key_id="alice-key-1", n_checks=64, L=128)
        r = p.verify(b, threshold_mode="exact")
        assert r.tau == TauCalculator.calculate_tau_exact(0.02, 0.01, 64).__round__(4)
        accepted += r.candidate_accepted
    assert accepted >= 38
