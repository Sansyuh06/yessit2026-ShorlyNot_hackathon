"""
Security Stage State Machine for ShorlyNot.
S-Stages (Signature threat driving bank lock) & Q-Stages (QKD link QBER).
Normative specification from PRD §4.4 and §8.4.
Includes progressive escalation (repeated forgeries escalate S2 -> S3 -> S4).
"""

import collections
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, List, Optional

from shorlynot_skeleton.models import (
    StageS,
    StageQ,
    ThreatLabel,
    StageEvent,
    StageState,
    TauPreset,
    QuantumBackend
)
from shorlynot_skeleton.detect.tau import TauCalculator
from shorlynot_skeleton.audit.chain import HashChainedLog


class StageStateMachine:
    """
    Manages security stage escalation and event logging for SOC and Bank enforcement.
    Features progressive escalation: repeated attacks elevate severity all the way to S4 lockdown.
    """

    def __init__(
        self,
        event_history_limit: int = 200,
        decay_seconds: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
        audit_path: Optional[str] = None,
    ) -> None:
        # Trust decay: with no new threat for `decay_seconds`, the stage steps down one level
        # (S4 -> S3 -> ... -> S0) and quarantines expire when the stage drops below S2.
        # 0 disables decay (manual reset only).
        self.decay_seconds: float = (
            decay_seconds if decay_seconds is not None
            else float(os.environ.get("SHORLYNOT_DECAY_SECONDS", "300"))
        )
        self._clock = clock
        self._last_threat_at: float = clock()
        # Tamper-evident audit trail of every stage event (hash chain; see audit/chain.py).
        self.audit = HashChainedLog(audit_path or os.environ.get("SHORLYNOT_AUDIT_LOG") or None)
        self._stage_s: StageS = StageS.S0
        self.stage_q: StageQ = StageQ.Q0
        self.last_threat: ThreatLabel = ThreatLabel.OK
        self.last_mismatch: float = 0.0
        self.preset: TauPreset = TauPreset.NORMAL
        self.backend: QuantumBackend = QuantumBackend.SIM
        self.event_limit = event_history_limit
        self.events: collections.deque = collections.deque(maxlen=event_history_limit)
        self.consecutive_threats: int = 0
        self.quarantined_accounts: set = set()   # cryptographically attributed accounts
        self.quarantined_sources: set = set()    # network/session origins (unauthenticated attackers)
        self.lock_scope: str = "none"
        self._attributed_streak: int = 0

    @property
    def stage_s(self) -> StageS:
        self._apply_decay()
        return self._stage_s

    @stage_s.setter
    def stage_s(self, value: StageS) -> None:
        self._stage_s = value

    def _record(self, event: StageEvent) -> None:
        self.events.appendleft(event)
        self.audit.append(event.model_dump(mode="json"))

    def _apply_decay(self) -> None:
        if self.decay_seconds <= 0 or self._stage_s == StageS.S0:
            return
        now = self._clock()
        while self._stage_s.value > 0 and now - self._last_threat_at >= self.decay_seconds:
            self._last_threat_at += self.decay_seconds
            self._stage_s = StageS(self._stage_s.value - 1)
            if self._stage_s.value < 2:
                self.quarantined_accounts.clear()
                self.quarantined_sources.clear()
                self.lock_scope = "none"
                self._attributed_streak = 0
                self.consecutive_threats = 0
            elif self.lock_scope == "global":
                self.lock_scope = "account"
            self._record(StageEvent(
                id=str(uuid.uuid4())[:8],
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="TRUST_DECAY",
                threat_label=ThreatLabel.OK,
                stage_s=self._stage_s,
                stage_q=self.stage_q,
                mismatch_rate=0.0,
                tau=TauCalculator.get_preset_tau(self.preset),
                actor="system",
                details=f"No new threats for {self.decay_seconds:.0f}s: stage decayed to S{self._stage_s.value}."
            ))

    def get_state(self) -> StageState:
        self._apply_decay()
        tau = TauCalculator.get_preset_tau(self.preset)
        p0 = 0.02
        n = 64
        delta = float(TauCalculator.PRESETS[self.preset]["delta"])
        transfers_allowed = (self.stage_s.value < StageS.S2.value)
        bank_locked = (self.stage_s.value >= StageS.S4.value)

        return StageState(
            stage_s=self.stage_s,
            stage_q=self.stage_q,
            last_threat=self.last_threat,
            last_mismatch=self.last_mismatch,
            tau=round(tau, 4),
            p0=p0,
            n=n,
            delta=delta,
            preset=self.preset,
            backend=self.backend,
            active_transfers_allowed=transfers_allowed,
            bank_locked=bank_locked,
            lock_scope=self.lock_scope,
            quarantined_accounts=sorted(list(self.quarantined_accounts)),
            quarantined_sources=sorted(list(self.quarantined_sources)),
            events_count=len(self.events)
        )

    def is_actor_blocked(self, actor: str, source_id: Optional[str] = None) -> bool:
        """
        Scope-aware enforcement gate (read by the pipeline and the bank).

        - Below S2: nobody is blocked.
        - lock_scope == "account": only attributed accounts and quarantined sources are blocked
          (other users keep transacting, and an unauthenticated claim of someone's name
          can never lock that person out).
        - lock_scope == "global" (or any unknown scope at S2+): everyone is blocked
          (conservative default).
        """
        if self.stage_s.value < StageS.S2.value:
            return False
        if self.lock_scope == "account":
            return actor in self.quarantined_accounts or (
                source_id is not None and source_id in self.quarantined_sources)
        return True

    def calculate_q_stage(self, qber: float) -> StageQ:
        """
        Map QBER percentage to Q stage according to Shor-Preskill literature bounds:
        Q0: < 5%
        Q1: 5% - 8%
        Q2: 8% - 11%
        Q3: 11% - 20%
        Q4: >= 20%
        """
        if qber < 0.05:
            return StageQ.Q0
        elif qber < 0.08:
            return StageQ.Q1
        elif qber < 0.11:
            return StageQ.Q2
        elif qber < 0.20:
            return StageQ.Q3
        else:
            return StageQ.Q4

    def update_qber(self, qber: float) -> None:
        self.stage_q = self.calculate_q_stage(qber)

    def process_threat_verdict(
        self,
        label: ThreatLabel,
        mismatch_rate: float,
        tau: float,
        tx_id: Optional[str] = None,
        actor: Optional[str] = None,
        details: str = "",
        attributed_actor: Optional[str] = None,
        source_id: Optional[str] = None,
        link_evidence: bool = False,
    ) -> StageS:
        """
        Escalate the S-stage for a threat verdict, and decide WHO gets blocked.

        The stage is the alert level and follows severity as before (FORGERY/IMPERSONATION -> S2,
        REPLAY/UNAUTH -> S3, CHANNEL/PARAM_TAMPER -> S4). What changed is whom the response touches:

        - `actor` is the identity the request CLAIMED. It is logged but never punished: anyone can
          type a victim's name, so punishing it turns the defence into a lock-out weapon.
        - `attributed_actor` is an account proven by cryptographic evidence (an ML-DSA signature that
          verifies under that account's registered key). Only this is quarantined as an account.
        - `source_id` is the network/session origin. Unauthenticated attackers are quarantined by source.
        - Global lock scope and S4 require either `link_evidence` (measured QBER on the physical link,
          which the sender cannot forge) or a streak of attributed violations. Unauthenticated
          events are capped at S3 with account scope, so no one can lock the whole bank by
          submitting bad bundles.
        """
        self._apply_decay()
        self.last_threat = label
        self.last_mismatch = mismatch_rate

        new_stage = self._stage_s

        if label == ThreatLabel.OK:
            self.consecutive_threats = 0
            self._attributed_streak = 0
            if self._stage_s == StageS.S1:
                new_stage = StageS.S0
                self.lock_scope = "none"
        else:
            self.consecutive_threats += 1
            self._last_threat_at = self._clock()
            if attributed_actor:
                self.quarantined_accounts.add(attributed_actor)
                self._attributed_streak += 1
            if source_id:
                self.quarantined_sources.add(source_id)

            # Global scope needs evidence the attacker cannot manufacture.
            can_go_global = bool(link_evidence) or self._attributed_streak >= 3

            if label in (ThreatLabel.CHANNEL, ThreatLabel.PARAM_TAMPER):
                if link_evidence:
                    new_stage = StageS.S4
                    self.lock_scope = "global"
                else:
                    new_stage = max(self._stage_s, StageS.S3, key=lambda x: x.value)
                    if self.lock_scope != "global":
                        self.lock_scope = "account"
            elif label in (ThreatLabel.REPLAY, ThreatLabel.UNAUTH_VERIFY):
                if self._stage_s.value < StageS.S3.value:
                    new_stage = StageS.S3
                if self.lock_scope != "global":
                    self.lock_scope = "account"
                if can_go_global and self.consecutive_threats >= 2:
                    new_stage = StageS.S4
                    self.lock_scope = "global"
            elif label in (ThreatLabel.FORGERY, ThreatLabel.IMPERSONATION):
                if self._stage_s.value < StageS.S2.value:
                    new_stage = StageS.S2
                elif self._stage_s == StageS.S2:
                    new_stage = StageS.S3
                if self.lock_scope != "global":
                    self.lock_scope = "account"
                if can_go_global and (self._stage_s.value >= StageS.S3.value or self.consecutive_threats >= 3):
                    new_stage = StageS.S4
                    self.lock_scope = "global"

        self._stage_s = new_stage

        who = attributed_actor or (f"source:{source_id}" if source_id else "unattributed")
        event = StageEvent(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="SIGNATURE_VERIFICATION" if label == ThreatLabel.OK else "SECURITY_ALERT",
            threat_label=label,
            stage_s=self._stage_s,
            stage_q=self.stage_q,
            mismatch_rate=mismatch_rate,
            tau=tau,
            tx_id=tx_id,
            actor=who,
            details=details or f"Verdict: {label.value} (Mismatch: {mismatch_rate:.4f} vs Tau: {tau:.4f})"
        )
        if actor and actor != attributed_actor:
            event.details = f"[claimed identity: {actor}] " + event.details
        self._record(event)

        return self._stage_s

    def reset(self) -> None:
        """Reset stages to normal operational baseline."""
        self._stage_s = StageS.S0
        self.stage_q = StageQ.Q0
        self.last_threat = ThreatLabel.OK
        self.last_mismatch = 0.0
        self.consecutive_threats = 0
        self._attributed_streak = 0
        self.quarantined_accounts.clear()
        self.quarantined_sources.clear()
        self.lock_scope = "none"
        self._last_threat_at = self._clock()

        self._record(StageEvent(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="ADMIN_RESET",
            threat_label=ThreatLabel.OK,
            stage_s=StageS.S0,
            stage_q=StageQ.Q0,
            mismatch_rate=0.0,
            tau=TauCalculator.get_preset_tau(self.preset),
            actor="ops",
            details="Security stages reset to normal baseline (S0, Q0) by administrator."
        ))

    def get_events(self, limit: int = 50) -> List[StageEvent]:
        return list(self.events)[:limit]
