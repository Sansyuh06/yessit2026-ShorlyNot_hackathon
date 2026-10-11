"""
ShorlyNot E2E Fit Test -- Step 4 Verification.
SIH 2026 PS 26141.

This script runs the EXACT fit test the user specified:
1. Alice transfers Rs 5,000 to Bob -> works
2. Trigger forgery attack -> caught, stage escalates
3. Attacker's source is BLOCKED; Alice (the named victim) is NOT locked out
4. Replay attack -> caught
5. Reset and re-verify honest transfer works again

Run: python -m pytest tests/test_e2e_fit.py -v
"""

import pytest
import uuid
from shorlynot_skeleton.models import (
    TransactionPayload,
    TransferPipelineRequest,
    TauPreset,
    ThreatLabel,
    StageS,
)
from shorlynot_skeleton.pipeline import QuantumTransferPipeline


class TestE2EFitTest:
    """Full vertical-slice fit test: sign -> attack -> catch -> lock."""

    @pytest.fixture(autouse=True)
    def setup_pipeline(self):
        """Fresh pipeline for each test."""
        self.pipeline = QuantumTransferPipeline()

    def _make_transfer_request(
        self,
        from_user: str = "alice",
        to_user: str = "bob",
        amount: float = 5000.0,
        attack: str = None,
        source_id: str = None,
    ) -> TransferPipelineRequest:
        tx = TransactionPayload(
            from_user=from_user,
            to_user=to_user,
            amount=amount,
            currency="INR",
            tx_id=f"tx-{uuid.uuid4().hex[:12]}",
        )
        return TransferPipelineRequest(
            transaction=tx,
            signer_key_id=f"{from_user}-key-1",
            verifier_id=to_user,
            tau_preset=TauPreset.NORMAL,
            simulate_attack=attack,
            source_id=source_id,
        )

    # -- Fit Test Scenario ------------------------------------------------

    def test_fit_test_alice_honest_transfer_succeeds(self):
        """Step 1: Alice transfers Rs 5,000 to Bob -- quantum-signed, accepted."""
        req = self._make_transfer_request(amount=5000.0)
        result = self.pipeline.execute_transfer(req)

        assert result.success is True, f"Honest transfer should succeed: {result.message}"
        assert result.threat_classification.label == ThreatLabel.OK
        assert result.verify_result.candidate_accepted is True
        assert result.verify_result.mismatch_rate <= result.verify_result.tau
        assert result.stage_s == StageS.S0
        print(f"  [OK] Honest transfer: p_hat={result.verify_result.mismatch_rate:.4f} <= tau={result.verify_result.tau:.4f}")

    def test_fit_test_forgery_caught_and_stage_escalates(self):
        """Step 2: Forgery attack -> detected, stage escalates to S2+."""
        req = self._make_transfer_request(amount=9999.0, attack="forgery")
        result = self.pipeline.execute_transfer(req)

        assert result.success is False, "Forged transfer must be rejected"
        assert result.threat_classification.label == ThreatLabel.FORGERY
        assert result.verify_result.mismatch_rate > result.verify_result.tau
        assert result.stage_s.value >= StageS.S2.value
        print(f"  [FORGERY] Caught: p_hat={result.verify_result.mismatch_rate:.4f} > tau={result.verify_result.tau:.4f} -> Stage S{result.stage_s.value}")

    def test_fit_test_bank_blocks_attacker_not_victim(self):
        """Step 3: After forgery, the ATTACKER's source is blocked and the named victim is not."""
        atk_req = self._make_transfer_request(attack="forgery", source_id="203.0.113.9")
        atk_result = self.pipeline.execute_transfer(atk_req)
        assert atk_result.success is False
        assert atk_result.stage_s.value >= StageS.S2.value

        # Alice (named in the forged bundle) keeps working from her own origin
        victim_req = self._make_transfer_request(amount=1000.0, source_id="198.51.100.7")
        assert self.pipeline.execute_transfer(victim_req).success is True

        # Anything from the attacker's source is refused, even with a valid-looking request
        attacker_req = self._make_transfer_request(amount=1000.0, source_id="203.0.113.9")
        blocked = self.pipeline.execute_transfer(attacker_req)
        assert blocked.success is False
        assert blocked.status_code in (403, 423), f"Expected 403/423, got {blocked.status_code}"
        print(f"  [BLOCKED] Bank refused attacker source: {blocked.message}")

    def test_fit_test_replay_detected(self):
        """Step 4: Replay attack -> nonce duplicate detected."""
        req = self._make_transfer_request(attack="replay")
        result = self.pipeline.execute_transfer(req)

        assert result.success is False
        assert result.threat_classification.label == ThreatLabel.REPLAY
        print(f"  [REPLAY] Caught: {result.threat_classification.reason}")

    def test_fit_test_impersonation_detected(self):
        """Bonus: Impersonation attack -> identity mismatch detected."""
        req = self._make_transfer_request(attack="impersonation")
        result = self.pipeline.execute_transfer(req)

        assert result.success is False
        assert result.threat_classification.label == ThreatLabel.IMPERSONATION
        print(f"  [IMPERSONATION] Caught: {result.threat_classification.reason}")

    def test_fit_test_full_scenario_end_to_end(self):
        """
        Complete E2E scenario (the exact fit test):
        1. Honest transfer -> works
        2. Forgery -> caught
        3. Bank blocks next transfer
        4. Reset -> works again
        """
        # 1. Honest transfer
        req1 = self._make_transfer_request(amount=5000.0)
        r1 = self.pipeline.execute_transfer(req1)
        assert r1.success is True
        print(f"  [1] Honest: p_hat={r1.verify_result.mismatch_rate:.4f} <= tau={r1.verify_result.tau:.4f} OK")

        # 2. Forgery attack
        req2 = self._make_transfer_request(amount=9999.0, attack="forgery", source_id="203.0.113.9")
        r2 = self.pipeline.execute_transfer(req2)
        assert r2.success is False
        assert r2.threat_classification.label == ThreatLabel.FORGERY
        print(f"  [2] Forgery: p_hat={r2.verify_result.mismatch_rate:.4f} > tau={r2.verify_result.tau:.4f} CAUGHT")

        # 3. Attacker's source blocked
        req3 = self._make_transfer_request(amount=1000.0, source_id="203.0.113.9")
        r3 = self.pipeline.execute_transfer(req3)
        assert r3.success is False
        print(f"  [3] Blocked: {r3.message}")

        # 4. Reset stages and verify the previously blocked source works again
        self.pipeline.stage_machine.reset()
        self.pipeline.classifier.clear_replay_cache()

        req4 = self._make_transfer_request(amount=2000.0, source_id="203.0.113.9")
        r4 = self.pipeline.execute_transfer(req4)
        assert r4.success is True
        print(f"  [4] After reset: p_hat={r4.verify_result.mismatch_rate:.4f} <= tau={r4.verify_result.tau:.4f} OK")

        print("\n  === FULL FIT TEST PASSED -- All 4 steps verified ===")
