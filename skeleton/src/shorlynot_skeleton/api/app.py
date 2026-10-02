"""
FastAPI Microservice for ShorlyNot Quantum Security Skeleton.
SIH 2026 PS 26141 — REST API (:8000).
Normative specification from PRD §7 and Part C4.
"""

import collections
import hmac
import os
import uuid
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Query, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from shorlynot_skeleton import __version__, __protocol__
from shorlynot_skeleton.models import (
    SignatureBundle,
    TransactionPayload,
    TransferPipelineRequest,
    PipelineResult,
    StageState,
    StageEvent,
    MetricSummary,
    QuantumBackend,
    TauPreset,
    ThreatLabel
)
from shorlynot_skeleton.pipeline import QuantumTransferPipeline
from shorlynot_skeleton.backends.sim import SimBackend, IBMBackend
from shorlynot_skeleton.detect.tau import TauCalculator
from shorlynot_skeleton.qds.sessions import GLOBAL_ENTANGLEMENT_STORE
from shorlynot_skeleton.qkd.key_registry import GLOBAL_KEY_REGISTRY

API_SECRET_KEY = os.environ.get("SHORLYNOT_API_KEY", "shorlynot-service-secret-key-2026")
ADMIN_SECRET_KEY = os.environ.get("SHORLYNOT_ADMIN_KEY", "shorlynot-admin-secret-key-2026")


def verify_api_auth(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None)
) -> str:
    """Verifies service-to-service communication credentials."""
    token = x_api_key
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required: Missing X-API-Key or Bearer token header."
        )
    if not (hmac.compare_digest(token.encode("utf-8"), API_SECRET_KEY.encode("utf-8")) or
            hmac.compare_digest(token.encode("utf-8"), ADMIN_SECRET_KEY.encode("utf-8"))):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Invalid API service credentials."
        )
    return token


def verify_admin_auth(
    token: str = Depends(verify_api_auth),
    x_api_role: Optional[str] = Header(None, alias="X-API-Role")
) -> bool:
    """Verifies administrative or SOC credentials for sensitive endpoints."""
    is_admin = (
        hmac.compare_digest(token.encode("utf-8"), ADMIN_SECRET_KEY.encode("utf-8")) or
        (x_api_role in ("admin", "soc") and hmac.compare_digest(token.encode("utf-8"), API_SECRET_KEY.encode("utf-8")))
    )
    if not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Administrative or SOC privileges required."
        )
    return True


app = FastAPI(
    title="ShorlyNot Quantum Security Framework API",
    version=__version__,
    description="Teleportation-Based Quantum Digital Signatures (ShorlyNot-QDS-T1) and Non-ML Threat Detection (Q-STDF)"
)

ALLOWED_ORIGINS = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:8081",
    "http://127.0.0.1:8081",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8001",
    "http://127.0.0.1:8001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global pipeline instance (single shared brain)
pipeline = QuantumTransferPipeline()
sim_backend = SimBackend()
ibm_backend = IBMBackend()

# Live metrics telemetry storage
_METRICS_TELEMETRY: Dict[str, Any] = {
    "sign_times_ms": collections.deque(maxlen=500),
    "verify_times_ms": collections.deque(maxlen=500),
    "honest_accepted": 0,
    "honest_total": 0,
    "forgery_accepted": 0,
    "forgery_total": 0,
}


class SignRequest(BaseModel):
    payload_hash: str = Field(..., description="Hex SHA-256 hash of canonical message")
    key_id: str = Field(..., description="Signer key ID (e.g. alice-key-1)")
    n_checks: int = Field(default=64, description="Check positions count")
    L: int = Field(default=128, description="Signature block length")
    backend: QuantumBackend = Field(default=QuantumBackend.SIM)


class VerifyRequest(BaseModel):
    bundle: SignatureBundle
    verifier_id: str = "bob"
    claimed_signer: Optional[str] = None
    tau_preset: TauPreset = TauPreset.NORMAL
    update_stages: bool = Field(default=True, description="Whether verification verdict updates global security stage state machine")


class AttackTriggerRequest(BaseModel):
    attack_type: str = Field(..., description="forgery | impersonation | replay | unauth_verify | channel")
    target_user: str = "alice"
    amount: float = 1000.0


@app.get("/v1/status")
def get_status() -> Dict[str, Any]:
    """Get skeleton framework status, active backends, quantum parameters, and honesty metadata."""
    backend_status = ibm_backend.get_status() if ibm_backend.is_available() else sim_backend.get_status()
    stage_state = pipeline.stage_machine.get_state()
    return {
        "product": "ShorlyNot Skeleton Framework",
        "version": __version__,
        "protocol": __protocol__,
        "architecture": {
            "sign_engine": "Real Qiskit Aer 3-qubit teleportation circuits on AerSimulator",
            "verify_engine": "Statevector syndrome projection & depolarizing noise model",
            "threat_detection": "Q-STDF (Hoeffding Statistical Bounds - No ML)",
            "qkd_support": "BB84 protocol simulation (statistical QBER measurement)",
            "pqc_support": "AES-256-GCM authenticated encryption (ML-KEM reference interface)",
            "ibm_backend": "Sim-first MVP fallback / IBM Quantum probe"
        },
        "backend": backend_status,
        "current_stages": {
            "stage_s": stage_state.stage_s.value,
            "stage_q": stage_state.stage_q.value,
            "bank_lock_status": "locked" if stage_state.bank_locked else ("suspended" if not stage_state.active_transfers_allowed else "operational")
        },
        "active_parameters": {
            "p0": stage_state.p0,
            "n": stage_state.n,
            "delta": stage_state.delta,
            "tau": stage_state.tau,
            "preset": stage_state.preset.value
        }
    }


@app.post("/v1/qkd/session", dependencies=[Depends(verify_api_auth)])
def create_qkd_session() -> Dict[str, Any]:
    """Negotiate a BB84 QKD session key and measure channel QBER."""
    res = pipeline.qkd.negotiate_session()
    pipeline.stage_machine.update_qber(res.qber)
    return {
        "session_id": res.session_id,
        "qber": res.qber,
        "sifted_bits_count": res.sifted_bits_count,
        "channel_status": res.channel_status,
        "stage_q": pipeline.stage_machine.stage_q.value
    }


@app.post("/v1/sign", response_model=SignatureBundle, dependencies=[Depends(verify_api_auth)])
def sign_payload(req: SignRequest) -> SignatureBundle:
    """Generate a ShorlyNot-QDS-T1 signature bundle using real Qiskit Aer teleportation circuits."""
    if req.n_checks < 16 or req.n_checks > 512 or req.L > 1024:
        raise HTTPException(status_code=400, detail="Parameters out of allowable bounds (16 <= n_checks <= 512, L <= 1024).")
    key_record = GLOBAL_KEY_REGISTRY.get_key(req.key_id)
    if not key_record or key_record.status != "active":
        raise HTTPException(status_code=403, detail=f"Key '{req.key_id}' is not registered or active in quantum key registry.")

    bundle = pipeline.qds.sign(
        payload_hash=req.payload_hash,
        key_id=req.key_id,
        n_checks=req.n_checks,
        L=req.L,
        backend=req.backend
    )
    if "sign_latency_ms" in bundle.measurement_transcript:
        _METRICS_TELEMETRY["sign_times_ms"].append(bundle.measurement_transcript["sign_latency_ms"])
    return bundle


@app.post("/v1/verify", dependencies=[Depends(verify_api_auth)])
def verify_signature(req: VerifyRequest) -> Dict[str, Any]:
    """
    Verify a ShorlyNot-QDS-T1 signature bundle.
    Evaluates projective verification and runs Q-STDF deterministic classification.
    """
    delta = TauCalculator.PRESETS[req.tau_preset]["delta"]
    v_res = pipeline.qds.verify(
        bundle=req.bundle,
        verifier_id=req.verifier_id,
        delta=delta
    )
    _METRICS_TELEMETRY["verify_times_ms"].append(v_res.verification_time_ms)

    # Classify threat
    classification = pipeline.classifier.classify(
        bundle=req.bundle,
        verify_result=v_res,
        claimed_signer=req.claimed_signer,
        verifier_id=req.verifier_id
    )

    # Update stages if requested
    stage_s = pipeline.stage_machine.stage_s
    if req.update_stages:
        stage_s = pipeline.stage_machine.process_threat_verdict(
            label=classification.label,
            mismatch_rate=v_res.mismatch_rate,
            tau=v_res.tau,
            actor=req.claimed_signer or "external_client",
            details=f"Direct /v1/verify submission: {classification.reason}"
        )

    return {
        "verify_result": v_res.model_dump(),
        "threat_classification": classification.model_dump(),
        "stage_s": stage_s.value,
        "candidate_accepted": v_res.candidate_accepted and classification.passed
    }


@app.post("/v1/pipeline/transfer", response_model=PipelineResult, dependencies=[Depends(verify_api_auth)])
def execute_transfer_pipeline(req: TransferPipelineRequest) -> PipelineResult:
    """Execute end-to-end quantum transfer pipeline."""
    result = pipeline.execute_transfer(req)
    if result.signature_bundle and "sign_latency_ms" in result.signature_bundle.measurement_transcript:
        _METRICS_TELEMETRY["sign_times_ms"].append(result.signature_bundle.measurement_transcript["sign_latency_ms"])
    if result.verify_result:
        _METRICS_TELEMETRY["verify_times_ms"].append(result.verify_result.verification_time_ms)
    if req.simulate_attack == "forgery":
        _METRICS_TELEMETRY["forgery_total"] += 1
        if result.success:
            _METRICS_TELEMETRY["forgery_accepted"] += 1
    elif req.simulate_attack is None:
        _METRICS_TELEMETRY["honest_total"] += 1
        if result.success:
            _METRICS_TELEMETRY["honest_accepted"] += 1
    return result


@app.post("/v1/attacks/{attack_type}", response_model=PipelineResult, dependencies=[Depends(verify_admin_auth)])
def trigger_attack(attack_type: str, req: Optional[AttackTriggerRequest] = None) -> PipelineResult:
    """Trigger specific attack vector directly on the transfer pipeline."""
    user = req.target_user if req else "alice"
    amt = req.amount if req else 1000.0

    tx = TransactionPayload(
        from_user=user,
        to_user="bob",
        amount=amt,
        currency="INR",
        tx_id=f"atk-{attack_type}-{uuid.uuid4().hex[:8]}"
    )
    pipe_req = TransferPipelineRequest(
        transaction=tx,
        signer_key_id="alice-key-1",
        verifier_id="bob",
        tau_preset=TauPreset.NORMAL,
        simulate_attack=attack_type
    )
    return execute_transfer_pipeline(pipe_req)


@app.get("/v1/stages", response_model=StageState)
def get_stages() -> StageState:
    """Get current security stage state."""
    return pipeline.stage_machine.get_state()


@app.get("/v1/stages/events", response_model=List[StageEvent])
def get_stage_events(limit: int = Query(default=50, ge=1, le=200)) -> List[StageEvent]:
    """Get recent stage transition and threat events for SOC console."""
    return pipeline.stage_machine.get_events(limit=limit)


@app.post("/v1/stages/reset", dependencies=[Depends(verify_admin_auth)])
def reset_stages() -> Dict[str, Any]:
    """Reset security stages to normal baseline (S0, Q0)."""
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()
    GLOBAL_ENTANGLEMENT_STORE.clear()
    return {
        "status": "success",
        "message": "Security stages reset to normal operational baseline (S0, Q0). Replay cache purged.",
        "current_stages": pipeline.stage_machine.get_state().model_dump()
    }


@app.get("/v1/metrics", response_model=MetricSummary)
def get_metrics() -> MetricSummary:
    """Get performance and security metric summary computed from real recorded runs."""
    p_forge = TauCalculator.calculate_theoretical_p_forge(tau=0.2097, n=64)
    sign_times = list(_METRICS_TELEMETRY["sign_times_ms"])
    verify_times = list(_METRICS_TELEMETRY["verify_times_ms"])
    avg_sign = round(float(sum(sign_times) / len(sign_times)), 3) if sign_times else 0.0
    avg_verify = round(float(sum(verify_times) / len(verify_times)), 3) if verify_times else 0.0
    honest_total = _METRICS_TELEMETRY["honest_total"]
    honest_rate = round(float(_METRICS_TELEMETRY["honest_accepted"] / honest_total), 4) if honest_total > 0 else 1.0
    forgery_total = _METRICS_TELEMETRY["forgery_total"]
    forgery_rate = round(float(_METRICS_TELEMETRY["forgery_accepted"] / forgery_total), 4) if forgery_total > 0 else 0.0

    return MetricSummary(
        protocol=__protocol__,
        backend="sim",
        total_signatures=len(sign_times),
        total_verifications=len(verify_times),
        threats_detected=sum(1 for e in pipeline.stage_machine.events if e.threat_label != ThreatLabel.OK),
        honest_accept_rate=honest_rate,
        random_forgery_accept_rate=forgery_rate,
        theoretical_p_forge=p_forge,
        avg_sign_time_ms=avg_sign,
        avg_verify_time_ms=avg_verify,
        tau_normal=0.2097,
        tau_strict=0.2523,
        tau_lenient=0.1730,
        p0=0.02,
        n=64,
        delta=0.01
    )


class KeyGenerateRequest(BaseModel):
    user_id: str = Field(..., description="Identity to provision keys for")
    role: str = Field(default="customer", description="Role: customer | attacker | soc")
    custom_key_id: Optional[str] = Field(default=None)


class KeyRegisterRequest(BaseModel):
    user_id: str
    key_id: str
    qkd_session_id: str
    key_fingerprint: str
    role: str = "customer"


@app.post("/v1/keys/generate", dependencies=[Depends(verify_admin_auth)])
def generate_key_pair(req: KeyGenerateRequest) -> Dict[str, Any]:
    """
    Execute simulated QKD ceremony (BB84) to provision a new quantum-bound key pair for a user.
    """
    record = GLOBAL_KEY_REGISTRY.provision_key_pair(
        user_id=req.user_id,
        role=req.role,
        custom_key_id=req.custom_key_id
    )
    pipeline.classifier.register_key(req.user_id, record.key_id)
    return {
        "status": "success",
        "message": f"Quantum key '{record.key_id}' successfully provisioned via BB84 for '{req.user_id}'.",
        "key_record": record.model_dump()
    }


@app.get("/v1/keys/list")
def list_keys() -> List[Dict[str, Any]]:
    """List all active registered quantum keys in the registry."""
    return [k.model_dump() for k in GLOBAL_KEY_REGISTRY.list_keys()]


@app.post("/v1/admin/reseed", dependencies=[Depends(verify_admin_auth)])
def admin_reseed() -> Dict[str, Any]:
    """Reseed demo state, stages, and replay cache."""
    pipeline.stage_machine.reset()
    pipeline.classifier.clear_replay_cache()
    GLOBAL_ENTANGLEMENT_STORE.clear()
    _METRICS_TELEMETRY["sign_times_ms"].clear()
    _METRICS_TELEMETRY["verify_times_ms"].clear()
    _METRICS_TELEMETRY["honest_accepted"] = 0
    _METRICS_TELEMETRY["honest_total"] = 0
    _METRICS_TELEMETRY["forgery_accepted"] = 0
    _METRICS_TELEMETRY["forgery_total"] = 0
    return {
        "status": "success",
        "message": "Demo state successfully reseeded."
    }
