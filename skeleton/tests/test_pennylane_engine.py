"""
Unit and Parity Tests for PennyLane Quantum Engine.
SIH 2026 PS 26141.
"""

import pytest

from shorlynot_skeleton.engines.pennylane_engine import PennyLaneEngine
from shorlynot_skeleton.engines.qiskit_aer import QiskitAerEngine

pennylane = pytest.importorskip("pennylane")


class TestPennyLaneEngine:

    def test_pennylane_z_basis_bit0(self):
        engine = PennyLaneEngine(p0=0.0)
        res = engine.run_teleportation_circuit(bit=0, basis=0, shots=1)
        assert res["bob_bit"] == 0
        assert res["m1"] in [0, 1]
        assert res["m2"] in [0, 1]

    def test_pennylane_z_basis_bit1(self):
        engine = PennyLaneEngine(p0=0.0)
        res = engine.run_teleportation_circuit(bit=1, basis=0, shots=1)
        assert res["bob_bit"] == 1

    def test_pennylane_x_basis_bit0(self):
        engine = PennyLaneEngine(p0=0.0)
        res = engine.run_teleportation_circuit(bit=0, basis=1, shots=1)
        assert res["bob_bit"] == 0

    def test_pennylane_x_basis_bit1(self):
        engine = PennyLaneEngine(p0=0.0)
        res = engine.run_teleportation_circuit(bit=1, basis=1, shots=1)
        assert res["bob_bit"] == 1

    def test_cross_engine_parity_with_qiskit_aer(self):
        """Verify both Qiskit Aer and PennyLane produce identical physical teleportation results."""
        qiskit_eng = QiskitAerEngine(p0=0.0)
        pl_eng = PennyLaneEngine(p0=0.0)

        for bit in [0, 1]:
            for basis in [0, 1]:
                q_res = qiskit_eng.run_teleportation_circuit(bit, basis, shots=1)
                p_res = pl_eng.run_teleportation_circuit(bit, basis, shots=1)
                assert q_res["bob_bit"] == bit, f"Qiskit Aer failed for bit={bit}, basis={basis}"
                assert p_res["bob_bit"] == bit, f"PennyLane failed for bit={bit}, basis={basis}"
