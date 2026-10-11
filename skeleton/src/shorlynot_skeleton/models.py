"""
Data models and schemas for the ShorlyNot Quantum Security Framework.
SIH 2026 PS 26141 — Quantum-Inspired Cyber Threat Detection for Digital Signature Security
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ThreatLabel(str, Enum):
    UNAUTH_VERIFY = "UNAUTH_VERIFY"
    IMPERSONATION = "IMPERSONATION"
    REPLAY = "REPLAY"
    CHANNEL = "CHANNEL"
    PARAM_TAMPER = "PARAM_TAMPER"
    FORGERY = "FORGERY"
    OK = "OK"


class StageS(int, Enum):
    S0 = 0  # Normal / All services operational
    S1 = 1  # Soft anomaly / Warn
    S2 = 2  # Threat detected (FORGERY / IMPERSONATION) -> Block new transfers
    S3 = 3  # Pattern attack (REPLAY / UNAUTH) -> Read-only history, session reset
    S4 = 4  # Critical / Channel storm -> Full bank lock


class StageQ(int, Enum):
    Q0 = 0  # QBER < 5% (Healthy)
    Q1 = 1  # 5% <= QBER < 8% (Watch)
    Q2 = 2  # 8% <= QBER < 11% (Elevated)
    Q3 = 3  # 11% <= QBER < 20% (Compromised link)
    Q4 = 4  # QBER >= 20% (Eve interception)


class TauPreset(str, Enum):
    STRICT = "strict"      # delta = 0.001
    NORMAL = "normal"      # delta = 0.01
    LENIENT = "lenient"    # delta = 0.05


class QuantumBackend(str, Enum):
    SIM = "sim"
    IBM = "ibm"


class QuantumEngine(str, Enum):
    QISKIT = "qiskit"
    PENNYLANE = "pennylane"


class SignatureBundle(BaseModel):
    """
    ShorlyNot-QDS-T1 Signature Bundle.
    Normative schema from PRD Part C1 / Section 4.5.
    """
    payload_hash: str = Field(..., description="Hex SHA-256 hash of canonical payload")
    key_id: str = Field(..., description="Signer key identifier (e.g. alice-key-1)")
    nonce: str = Field(..., description="UUID4 random nonce for replay prevention")
    profile: str = Field(default="T1", description="Named protocol profile: T1")
    bases: List[int] = Field(..., description="Basis selection per bit: 0 for Z, 1 for X")
    correction_bits: List[List[int]] = Field(..., description="Pauli syndromes (m1, m2) per check position")
    measurement_transcript: Dict[str, Any] = Field(default_factory=dict, description="Bell measurement telemetry")
    protected_corrections: Optional[str] = Field(default=None, description="Base64 AES-256-GCM / ML-KEM wrapped corrections")
    backend: QuantumBackend = Field(default=QuantumBackend.SIM, description="Backend used (sim|ibm)")
    engine: QuantumEngine = Field(default=QuantumEngine.QISKIT, description="Quantum engine (qiskit)")
    pqc_mode: str = Field(default="aes-gcm-demo", description="PQC wrapper mode")
    identity_sig: Optional[str] = Field(default=None, description="Hex ML-DSA-44 signature over the bundle header, verified against the registered public key")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO-8601 timestamp")
    n_checks: int = Field(default=64, description="Number of check positions verified")
    L: int = Field(default=128, description="Total signature block length")


class VerifyResult(BaseModel):
    """
    Result of ShorlyNot-QDS-T1 verification.
    """
    candidate_accepted: bool = Field(..., description="Whether p_hat <= tau and quantum checks pass")
    mismatch_rate: float = Field(..., description="Empirical mismatch rate p_hat = mismatches / n")
    mismatches: int = Field(..., description="Count of mismatch bits")
    n_checks: int = Field(..., description="Total check positions")
    tau: float = Field(..., description="Hoeffding statistical threshold tau")
    p0: float = Field(default=0.02, description="Honest noise floor")
    delta: float = Field(default=0.01, description="False-reject budget delta")
    profile: str = Field(default="T1")
    backend: str = Field(default="sim")
    verification_time_ms: float = Field(default=0.0, description="Verification latency in ms")


class ThreatClassification(BaseModel):
    """
    Q-STDF Threat Classification verdict.
    """
    label: ThreatLabel = Field(..., description="Classified threat label")
    passed: bool = Field(..., description="True if OK, False if threat detected")
    reason: str = Field(..., description="Human-readable rationale")
    mismatch_rate: float = Field(..., description="Mismatch rate p_hat")
    tau: float = Field(..., description="Applied Hoeffding threshold")
    p0: float = Field(default=0.02)
    n: int = Field(default=64)
    delta: float = Field(default=0.01)
    stage_s_recommendation: StageS = Field(default=StageS.S0)
    details: Dict[str, Any] = Field(default_factory=dict)


class TransactionPayload(BaseModel):
    """
    Financial transaction payload for bank transfers.
    Normative schema from PRD §4.6.
    """
    from_user: str = Field(..., min_length=1, description="Sender username")
    to_user: str = Field(..., min_length=1, description="Recipient username")
    amount: float = Field(..., gt=0, description="Transfer amount in currency units")
    currency: str = "INR"
    tx_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("amount")
    @classmethod
    def _validate_amount_finite_positive(cls, v: float) -> float:
        if not math.isfinite(v) or v <= 0:
            raise ValueError("Amount must be a finite positive number")
        return v

    def canonical_json(self) -> str:
        """Deterministically format JSON with sorted keys and no extra whitespace."""
        return json.dumps(self.model_dump(), sort_keys=True, separators=(',', ':'))


class TransferPipelineRequest(BaseModel):
    """
    Request to execute end-to-end quantum transfer pipeline.
    """
    transaction: TransactionPayload
    signer_key_id: str
    verifier_id: str = "bob"
    tau_preset: TauPreset = TauPreset.NORMAL
    backend: QuantumBackend = QuantumBackend.SIM
    simulate_attack: Optional[str] = None  # None | forgery | impersonation | replay | unauth_verify | channel
    source_id: Optional[str] = None  # network/session origin of the request (IP, device); used for attribution


class PipelineResult(BaseModel):
    """
    Full output of the quantum transfer pipeline.
    """
    success: bool
    status_code: int
    message: str
    tx_id: str
    payload_hash: str
    qkd_session_id: str
    qber: float
    stage_q: StageQ
    signature_bundle: Optional[SignatureBundle] = None
    verify_result: Optional[VerifyResult] = None
    threat_classification: ThreatClassification
    stage_s: StageS
    bank_lock_status: str
    total_time_ms: float


class StageEvent(BaseModel):
    """
    Recorded security stage event for SOC feed.
    """
    id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str
    threat_label: ThreatLabel
    stage_s: StageS
    stage_q: StageQ
    mismatch_rate: float
    tau: float
    tx_id: Optional[str] = None
    actor: Optional[str] = None
    details: str = ""


class StageState(BaseModel):
    """
    Current global security stages and active parameters.
    """
    stage_s: StageS = StageS.S0
    stage_q: StageQ = StageQ.Q0
    last_threat: ThreatLabel = ThreatLabel.OK
    last_mismatch: float = 0.0
    tau: float = 0.210
    p0: float = 0.02
    n: int = 64
    delta: float = 0.01
    preset: TauPreset = TauPreset.NORMAL
    backend: QuantumBackend = QuantumBackend.SIM
    active_transfers_allowed: bool = True
    bank_locked: bool = False
    lock_scope: str = "none"  # none | account | global
    quarantined_accounts: List[str] = Field(default_factory=list)
    quarantined_sources: List[str] = Field(default_factory=list)
    events_count: int = 0


class MetricSummary(BaseModel):
    """
    Performance and security metrics summary for SOC and analysis.
    """
    protocol: str = "ShorlyNot-QDS-T1"
    backend: str = "sim"
    total_signatures: int = 0
    total_verifications: int = 0
    threats_detected: int = 0
    honest_accept_rate: float = 0.0
    random_forgery_accept_rate: float = 0.0
    theoretical_p_forge: float = 0.0
    avg_sign_time_ms: float = 0.0
    avg_verify_time_ms: float = 0.0
    tau_normal: float = 0.210
    tau_strict: float = 0.252
    tau_lenient: float = 0.173
    p0: float = 0.02
    n: int = 64
    delta: float = 0.01
