"""
ShorlyNot-QDS-T1 Protocol Implementation.
Teleportation Profile T1 (MVP) for SIH 2026 PS 26141.
Normative specification from PRD §3 and MODEL.md.

ALL Bell measurements come from real Qiskit Aer circuits.
"""

import time
import uuid
from typing import List, Optional, Tuple
import numpy as np

from shorlynot_skeleton.models import SignatureBundle, VerifyResult, QuantumBackend, QuantumEngine
from shorlynot_skeleton.qds.encoding import PauliEncoding
from shorlynot_skeleton.engines.qiskit_aer import QiskitAerEngine
from shorlynot_skeleton.qds.sessions import GLOBAL_ENTANGLEMENT_STORE


MIN_SECURE_N: int = 32
DEFAULT_VERIFIER_N: int = 64


class QdsT1Protocol:
    """
    ShorlyNot-QDS-T1 Protocol Manager.
    Performs quantum digital signature generation and verification using Bell-state teleportation
    and Pauli eigenstate projective measurements.

    Sign path: runs N real teleportation circuits on AerSimulator to get Bell syndromes.
    Verify path: uses statevector math to check if provided syndromes recover original state.
    """

    def __init__(self, p0: float = 0.02, default_delta: float = 0.01):
        self.p0 = p0
        self.default_delta = default_delta
        self.engine = QiskitAerEngine(p0=p0)

    def sign(
        self,
        payload_hash: str,
        key_id: str,
        bases: Optional[List[int]] = None,
        n_checks: int = 64,
        L: int = 128,
        backend: QuantumBackend = QuantumBackend.SIM,
        nonce: Optional[str] = None
    ) -> SignatureBundle:
        """
        Sign a payload hash using ShorlyNot-QDS-T1 teleportation-based protocol.
        Each check position runs a REAL Qiskit Aer teleportation circuit.
        """
        t_start = time.perf_counter()

        effective_n = n_checks
        effective_L = max(L, effective_n)

        # 1. Derive payload bits
        bits = PauliEncoding.derive_payload_bits(payload_hash, length=effective_L)

        # 2. Select bases for all L positions (0 = Z basis, 1 = X basis)
        if bases is None:
            bases = [int(np.random.randint(0, 2)) for _ in range(effective_L)]
        else:
            if len(bases) < effective_L:
                bases = bases + [int(np.random.randint(0, 2)) for _ in range(effective_L - len(bases))]
            bases = bases[:effective_L]

        # 3. Nonce generation
        tx_nonce = nonce or str(uuid.uuid4())

        # 4. Run real teleportation circuits for each check position
        syndromes = []
        circuit_results = []

        for i in range(effective_n):
            bit = bits[i]
            beta = bases[i]

            # Run real circuit on AerSimulator
            result = self.engine.run_teleportation_circuit(bit, beta, shots=1)
            syndromes.append([result["m1"], result["m2"]])
            circuit_results.append({
                "pos": i,
                "bit": bit,
                "basis": beta,
                "m1": result["m1"],
                "m2": result["m2"],
                "bob_bit": result["bob_bit"]
            })

        # 5. Record Bob-side entanglement ground truth in the session store
        # With real hardware, Bob's Bell-half is the ground truth; the store simulates Bob's side.
        GLOBAL_ENTANGLEMENT_STORE.record_session(
            nonce=tx_nonce,
            key_id=key_id,
            alice_bell_measurements=[list(s) for s in syndromes],
            bases=bases,
            payload_hash=payload_hash,
            n_checks=effective_n,
            L=effective_L
        )

        t_end = time.perf_counter()

        telemetry = {
            "sign_latency_ms": round((t_end - t_start) * 1000, 3),
            "check_positions": effective_n,
            "bell_pair_type": "Phi+",
            "state_preparation": "Pauli-Eigenstates",
            "circuit_backend": "qiskit_aer",
            "real_circuits": True,
            "circuit_verification_results": circuit_results
        }

        bundle = SignatureBundle(
            payload_hash=payload_hash,
            key_id=key_id,
            nonce=tx_nonce,
            profile="T1",
            bases=bases,
            correction_bits=syndromes,
            measurement_transcript=telemetry,
            backend=backend,
            engine=QuantumEngine.QISKIT,
            pqc_mode="aes-gcm-demo",
            n_checks=effective_n,
            L=effective_L
        )

        return bundle

    @staticmethod
    def evaluate_unentangled_adversary_projection(
        expected_bit: int,
        basis: int,
        provided_syndrome: Tuple[int, int],
        p0: float = 0.02
    ) -> int:
        """
        Evaluate Bob's measurement outcome when an unentangled adversary (Eve)
        fabricates a signature bundle without access to Alice's entangled Bell state.
        """
        prob_0 = 0.50
        prob_1 = 0.50
        return int(np.random.choice([0, 1], p=[prob_0, prob_1]))

    def verify(
        self,
        bundle: SignatureBundle,
        verifier_id: str = "bob",
        delta: Optional[float] = None,
        p0: Optional[float] = None,
        override_syndromes: Optional[List[List[int]]] = None,
        mode: str = "analytic",
        min_required_n: int = MIN_SECURE_N,
        threshold_mode: str = "hoeffding"
    ) -> VerifyResult:
        """
        Verify a ShorlyNot-QDS-T1 signature bundle.
        Bob checks if the provided syndromes allow him to recover
        the original message bits via Pauli corrections.

        Security Hardening:
        - Rejects security parameter downgrade attacks (n_checks < MIN_SECURE_N).
        - Validates submitted basis and syndrome array lengths against claimed n_checks.
        """
        t_start = time.perf_counter()

        noise_floor = p0 if p0 is not None else self.p0
        reject_budget = delta if delta is not None else self.default_delta
        
        # -------------------------------------------------------------
        # Security Parameter Integrity & Downgrade Prevention
        # -------------------------------------------------------------
        if bundle.n_checks < min_required_n:
            t_end = time.perf_counter()
            # Standard reference tau for rejected parameter tampering
            tau_ref = noise_floor + np.sqrt(np.log(1.0 / reject_budget) / (2.0 * min_required_n))
            return VerifyResult(
                candidate_accepted=False,
                mismatch_rate=1.0,
                mismatches=bundle.n_checks,
                n_checks=bundle.n_checks,
                tau=round(float(tau_ref), 4),
                p0=noise_floor,
                delta=reject_budget,
                profile=bundle.profile,
                backend=bundle.backend.value,
                verification_time_ms=round((t_end - t_start) * 1000, 3)
            )

        if len(bundle.bases) < bundle.n_checks or len(bundle.correction_bits) < bundle.n_checks:
            t_end = time.perf_counter()
            tau_ref = noise_floor + np.sqrt(np.log(1.0 / reject_budget) / (2.0 * bundle.n_checks))
            return VerifyResult(
                candidate_accepted=False,
                mismatch_rate=1.0,
                mismatches=bundle.n_checks,
                n_checks=bundle.n_checks,
                tau=round(float(tau_ref), 4),
                p0=noise_floor,
                delta=reject_budget,
                profile=bundle.profile,
                backend=bundle.backend.value,
                verification_time_ms=round((t_end - t_start) * 1000, 3)
            )

        n = bundle.n_checks

        # 1. Derive expected payload bits
        expected_bits = PauliEncoding.derive_payload_bits(bundle.payload_hash, length=bundle.L)[:n]
        bases = bundle.bases[:n]
        provided_syndromes = override_syndromes if override_syndromes is not None else bundle.correction_bits[:n]

        # 2. Retrieve actual physical Bell measurement outcomes from Bob-side session store
        # With real hardware, Bob's Bell-half is the ground truth; the store simulates Bob's side.
        session = GLOBAL_ENTANGLEMENT_STORE.get_session(bundle.nonce)
        alice_measurements = None
        if session and session.key_id == bundle.key_id and session.payload_hash == bundle.payload_hash:
            alice_measurements = session.alice_bell_measurements

        engine = QiskitAerEngine(p0=noise_floor)
        mismatches = 0

        for i in range(n):
            b_exp = expected_bits[i]
            beta = bases[i]
            prov_syn: Tuple[int, int] = (
                (int(provided_syndromes[i][0]), int(provided_syndromes[i][1]))
                if i < len(provided_syndromes) and len(provided_syndromes[i]) >= 2
                else (0, 0)
            )

            if alice_measurements and i < len(alice_measurements):
                true_syn: Tuple[int, int] = (
                    (int(alice_measurements[i][0]), int(alice_measurements[i][1]))
                    if len(alice_measurements[i]) >= 2
                    else (0, 0)
                )
                if mode == "circuit":
                    # Full hardware-in-the-loop Aer circuit execution
                    measured_bit = engine.run_circuit_verification(
                        bit=b_exp,
                        basis=beta,
                        provided_syndrome=prov_syn
                    )
                else:
                    # Analytical Born-rule statevector verification (exact, O(n) complexity)
                    measured_bit = engine.simulate_bob_verification(
                        bit=b_exp,
                        basis=beta,
                        true_syndrome=true_syn,
                        provided_syndrome=prov_syn,
                        inject_noise=True
                    )
            else:
                # Unentangled adversary case: Bob measures maximally mixed subsystem rho_B = 1/2 * I
                measured_bit = self.evaluate_unentangled_adversary_projection(
                    expected_bit=b_exp,
                    basis=beta,
                    provided_syndrome=prov_syn,
                    p0=noise_floor
                )

            if measured_bit != b_exp:
                mismatches += 1

        mismatch_rate = float(mismatches) / float(n) if n > 0 else 1.0

        # Hoeffding threshold: tau = p0 + sqrt(ln(1/delta) / (2n))
        if threshold_mode == "exact":
            from shorlynot_skeleton.detect.tau import TauCalculator
            tau = TauCalculator.calculate_tau_exact(p0=noise_floor, delta=reject_budget, n=n)
        else:
            tau = noise_floor + np.sqrt(np.log(1.0 / reject_budget) / (2.0 * n))
        candidate_accepted = bool(mismatch_rate <= tau)
        t_end = time.perf_counter()

        return VerifyResult(
            candidate_accepted=candidate_accepted,
            mismatch_rate=round(mismatch_rate, 4),
            mismatches=mismatches,
            n_checks=n,
            tau=round(float(tau), 4),
            p0=noise_floor,
            delta=reject_budget,
            profile=bundle.profile,
            backend=bundle.backend.value,
            verification_time_ms=round((t_end - t_start) * 1000, 3)
        )
