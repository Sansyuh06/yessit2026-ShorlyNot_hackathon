"""
Attack-strength ROC analysis for the Q-STDF detector.

The honest-vs-forger split is only interesting when the attacker has partial information.
Two attacker families are modelled, both with exact binomial math (no simulation noise):

1. Partial-information forger: knows each true syndrome with probability f and guesses the rest.
   Per-position mismatch probability: q = f * p0/2 + (1 - f) * 1/2.
2. In-flight tamperer (man in the middle): flips each syndrome bit of an honest bundle w.p. r.
   The measured bit flips only if the component relevant to the basis flips:
   q = (1 - r) * p0/2 + r * (1 - p0/2).

A bundle is accepted when mismatches <= floor(tau * n). Acceptance probability is the binomial CDF.
`validate_against_engine` cross-checks the closed forms against the project's own verifier model.
"""

from typing import Callable, Dict, List

import numpy as np
from scipy.stats import binom

from shorlynot_skeleton.detect.tau import TauCalculator


def q_partial_info(f: float, p0: float) -> float:
    return f * p0 / 2.0 + (1.0 - f) * 0.5


def q_tamper(r: float, p0: float) -> float:
    return (1.0 - r) * p0 / 2.0 + r * (1.0 - p0 / 2.0)


def accept_probability(q: float, tau: float, n: int) -> float:
    """P(mismatches <= floor(tau * n)) when each position mismatches w.p. q."""
    return float(binom.cdf(int(np.floor(tau * n + 1e-9)), n, q))


def thresholds(n: int, p0: float, delta: float) -> Dict[str, float]:
    return {
        "hoeffding": TauCalculator.calculate_tau(p0=p0, delta=delta, n=n),
        "exact": TauCalculator.calculate_tau_exact(p0=p0, delta=delta, n=n),
    }


def sweep(n: int = 64, p0: float = 0.02, delta: float = 0.01, points: int = 101) -> Dict[str, List]:
    taus = thresholds(n, p0, delta)
    xs = np.linspace(0.0, 1.0, points)
    out: Dict[str, List] = {"x": xs.tolist(), "tau": taus}
    for name, tau in taus.items():
        out[f"partial_info_{name}"] = [accept_probability(q_partial_info(f, p0), tau, n) for f in xs]
        out[f"tamper_{name}"] = [accept_probability(q_tamper(r, p0), tau, n) for r in xs]
    return out


def frr_vs_true_noise(n: int = 64, assumed_p0: float = 0.02, delta: float = 0.01,
                      true_p0s: List[float] = None) -> Dict[str, List]:
    """False-reject rate of honest signatures when real hardware noise differs from the assumed p0."""
    true_p0s = true_p0s if true_p0s is not None else [0.0, 0.02, 0.05, 0.1, 0.15, 0.2, 0.3]
    taus = thresholds(n, assumed_p0, delta)
    out: Dict[str, List] = {"true_p0": true_p0s, "tau": taus}
    for name, tau in taus.items():
        out[f"frr_{name}"] = [1.0 - accept_probability(TauCalculator.honest_mismatch_rate(p), tau, n)
                              for p in true_p0s]
    return out


def tolerated_information(n: int, p0: float, delta: float, target_accept: float = 0.5) -> Dict[str, Dict[str, float]]:
    """f_needed: smallest fraction of true syndromes a forger must know to be accepted with probability
    >= target_accept (higher is better for the defender). r_tolerated: largest syndrome-flip rate a
    man in the middle can apply and still be accepted with probability >= target_accept (lower is better)."""
    taus = thresholds(n, p0, delta)
    xs = np.linspace(0, 1, 2001)
    res: Dict[str, Dict[str, float]] = {}
    for name, tau in taus.items():
        f_star = next((float(f) for f in xs if accept_probability(q_partial_info(f, p0), tau, n) >= target_accept), 1.0)
        r_star = next((float(r) for r in xs[::-1] if accept_probability(q_tamper(r, p0), tau, n) >= target_accept), 0.0)
        res[name] = {"tau": tau, "f_needed": f_star, "r_tolerated": r_star}
    return res


def validate_against_engine(n: int = 64, p0: float = 0.02, trials: int = 300, seed: int = 7) -> Dict[str, float]:
    """Monte Carlo through QiskitAerEngine.simulate_bob_verification (the project's own verifier model)
    to check the closed-form per-position mismatch probabilities."""
    from shorlynot_skeleton.engines.qiskit_aer import QiskitAerEngine
    rng = np.random.default_rng(seed)
    np.random.seed(seed)
    eng = QiskitAerEngine(p0=p0)

    def measured_rate(provided_fn: Callable[[tuple], tuple]) -> float:
        wrong = 0
        total = n * trials
        for _ in range(trials):
            for _ in range(n):
                bit = int(rng.integers(0, 2))
                basis = int(rng.integers(0, 2))
                true_syn = (int(rng.integers(0, 2)), int(rng.integers(0, 2)))
                prov = provided_fn(true_syn)
                wrong += int(eng.simulate_bob_verification(bit, basis, true_syn, prov, True) != bit)
        return wrong / total

    f, r = 0.5, 0.3

    def guess(t):
        return (int(rng.integers(0, 2)), int(rng.integers(0, 2)))

    def partial(t):
        return t if rng.random() < f else guess(t)

    def tamper(t):
        return (t[0] ^ int(rng.random() < r), t[1] ^ int(rng.random() < r))
    return {
        "honest_measured": measured_rate(lambda t: t), "honest_theory": p0 / 2,
        "guess_measured": measured_rate(guess), "guess_theory": 0.5,
        "partial_measured": measured_rate(partial), "partial_theory": q_partial_info(f, p0),
        "tamper_measured": measured_rate(tamper), "tamper_theory": q_tamper(r, p0),
    }
