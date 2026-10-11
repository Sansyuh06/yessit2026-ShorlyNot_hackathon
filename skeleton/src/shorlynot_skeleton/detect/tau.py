"""
Hoeffding Statistical Threshold Calculation for Q-STDF.
Normative specification from PRD §3.10 and MODEL.md §7 & §8.
"""

from typing import Dict, Any
import numpy as np
from scipy.stats import binom

from shorlynot_skeleton.models import TauPreset


class TauCalculator:
    """
    Computes statistical threshold tau using Hoeffding's Inequality:
    tau = p0 + sqrt(ln(1/delta) / (2n))
    """

    PRESETS: Dict[TauPreset, Dict[str, Any]] = {
        TauPreset.STRICT: {
            "delta": 0.001,
            "p0": 0.02,
            "n": 64,
            "tau": 0.2523,  # 0.02 + sqrt(ln(1000)/128)
            "description": "High security, false-reject budget delta=0.001"
        },
        TauPreset.NORMAL: {
            "delta": 0.01,
            "p0": 0.02,
            "n": 64,
            "tau": 0.2097,  # 0.02 + sqrt(ln(100)/128) ~ 0.210
            "description": "Standard banking operations, delta=0.01"
        },
        TauPreset.LENIENT: {
            "delta": 0.05,
            "p0": 0.02,
            "n": 64,
            "tau": 0.1730,  # 0.02 + sqrt(ln(20)/128) ~ 0.173
            "description": "High noise tolerance, delta=0.05"
        }
    }

    @staticmethod
    def calculate_tau(p0: float = 0.02, delta: float = 0.01, n: int = 64) -> float:
        """
        Exact Hoeffding acceptance threshold.
        """
        if delta <= 0 or delta >= 1:
            raise ValueError(f"Delta budget must be in (0, 1), got {delta}")
        if n <= 0:
            raise ValueError(f"Check count n must be > 0, got {n}")
        if p0 < 0:
            raise ValueError(f"Noise floor p0 must be >= 0, got {p0}")

        t = np.sqrt(np.log(1.0 / delta) / (2.0 * n))
        return float(p0 + t)

    @staticmethod
    def honest_mismatch_rate(p0: float) -> float:
        """Per-position honest mismatch probability under depolarizing noise p0.
        The model gives P(wrong bit) = p0 / 2 (the depolarizing channel randomises the bit w.p. p0)."""
        return p0 / 2.0

    @classmethod
    def calculate_tau_exact(cls, p0: float = 0.02, delta: float = 0.01, n: int = 64) -> float:
        """
        Exact-binomial acceptance threshold: the smallest k such that an honest signature
        (mismatches ~ Binomial(n, p0/2)) exceeds k with probability <= delta, returned as k / n.
        Same false-reject guarantee as Hoeffding, but far tighter, because Hoeffding ignores the
        low variance of a rare-event binomial.
        """
        if delta <= 0 or delta >= 1:
            raise ValueError(f"Delta budget must be in (0, 1), got {delta}")
        if n <= 0:
            raise ValueError(f"Check count n must be > 0, got {n}")
        q = cls.honest_mismatch_rate(p0)
        k = int(binom.ppf(1.0 - delta, n, q))
        while binom.sf(k, n, q) > delta:
            k += 1
        return k / n

    @classmethod
    def get_preset_tau(cls, preset: TauPreset, n: int = 64, p0: float = 0.02) -> float:
        config = cls.PRESETS.get(preset, cls.PRESETS[TauPreset.NORMAL])
        delta = config["delta"]
        return cls.calculate_tau(p0=p0, delta=delta, n=n)

    @staticmethod
    def calculate_theoretical_p_forge(tau: float, n: int = 64) -> float:
        """
        Calculates theoretical random forgery acceptance probability:
        P_forge = sum_{k=0}^{\\lfloor tau * n \\rfloor} binom(n, k) * (0.5)^n
        """
        max_errors = int(np.floor(tau * n))
        # Cumulative distribution function for Binomial(n, 0.5) up to max_errors
        p_forge = float(binom.cdf(max_errors, n, 0.5))
        return p_forge
