"""
Skeleton Framework Client for Bank Application.
Communicates via HTTP to the Skeleton API (:8000) or uses the shared API singleton.
Hard rule from PRD: Bank never reimplements QDS/QKD/PQC/detect logic.
Eliminates dual-brain desync by binding to the single source of truth.
"""

import os
import uuid
import httpx
from typing import Dict, Any, Optional, List
from shorlynot_skeleton.models import (
    TransferPipelineRequest,
    PipelineResult,
    StageState,
    StageEvent,
    MetricSummary,
    TransactionPayload,
    TauPreset
)


class SkeletonServiceClient:
    """
    Client connecting Bank to the ShorlyNot Skeleton service.
    Guarantees consistent state across Bank UI, SOC Dashboard, and Skeleton Engine.
    """

    def __init__(self, base_url: Optional[str] = None) -> None:
        # Default to environment variable or standard port 8000
        self.base_url = base_url or os.environ.get("SHORLYNOT_API_URL", "http://127.0.0.1:8000")
        self.require_api = os.environ.get("SHORLYNOT_REQUIRE_API", "0").lower() in ("1", "true", "yes")
        self.api_key = os.environ.get("SHORLYNOT_API_KEY", "shorlynot-service-secret-key-2026")
        self._shared_singleton = None
        self._client: Optional[httpx.Client] = None
        self._api_online: Optional[bool] = None

    @property
    def http_client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=5.0,
                headers={"X-API-Key": self.api_key, "X-API-Role": "soc"},
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
            )
        return self._client

    @property
    def shared_pipeline(self):
        """Lazy-import the API singleton if running in unified in-process mode."""
        if self.require_api:
            raise RuntimeError(
                f"SHORLYNOT_REQUIRE_API=1 is active, but Skeleton API at {self.base_url} is unreachable. "
                f"Dual-process mode prohibits silent in-process fallback to prevent state desynchronization."
            )
        if self._shared_singleton is None:
            from shorlynot_skeleton.api.app import pipeline
            self._shared_singleton = pipeline
        return self._shared_singleton

    def _is_api_available(self) -> bool:
        if not self.require_api and os.environ.get("PYTEST_CURRENT_TEST"):
            return False
        try:
            with httpx.Client(base_url=self.base_url, timeout=0.2) as probe_client:
                resp = probe_client.get("/v1/status")
                return resp.status_code == 200
        except Exception:
            return False

    def execute_transfer(self, req: TransferPipelineRequest) -> PipelineResult:
        if self.require_api or self._is_api_available():
            try:
                resp = self.http_client.post("/v1/pipeline/transfer", json=req.model_dump(), timeout=10.0)
                if resp.status_code in (200, 403, 423):
                    return PipelineResult(**resp.json())
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if self.require_api:
                    raise RuntimeError(
                        f"Skeleton API at {self.base_url} is unreachable ({type(e).__name__}). "
                        f"SHORLYNOT_REQUIRE_API=1 prevents fallback to ensure centralized stage enforcement."
                    ) from e
            except Exception as e:
                raise RuntimeError(f"Skeleton API communication error: {e}") from e

        # Fallback ONLY to the shared API singleton (single shared process in tests/monolith)
        return self.shared_pipeline.execute_transfer(req)

    def get_stages(self) -> StageState:
        if self.require_api or self._is_api_available():
            try:
                resp = self.http_client.get("/v1/stages", timeout=5.0)
                if resp.status_code == 200:
                    return StageState(**resp.json())
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if self.require_api:
                    raise RuntimeError(
                        f"Skeleton API at {self.base_url} is unreachable ({type(e).__name__}). "
                        f"SHORLYNOT_REQUIRE_API=1 is active."
                    ) from e
            except Exception as e:
                raise RuntimeError(f"Skeleton API communication error: {e}") from e

        return self.shared_pipeline.stage_machine.get_state()

    def get_events(self, limit: int = 50) -> List[StageEvent]:
        if self.require_api or self._is_api_available():
            try:
                resp = self.http_client.get(f"/v1/stages/events?limit={limit}", timeout=5.0)
                if resp.status_code == 200:
                    return [StageEvent(**e) for e in resp.json()]
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if self.require_api:
                    raise RuntimeError(
                        f"Skeleton API at {self.base_url} is unreachable ({type(e).__name__}). "
                        f"SHORLYNOT_REQUIRE_API=1 is active."
                    ) from e
            except Exception as e:
                raise RuntimeError(f"Skeleton API communication error: {e}") from e

        return self.shared_pipeline.stage_machine.get_events(limit=limit)

    def trigger_attack(self, attack_type: str, user: str = "alice", amount: float = 1000.0) -> PipelineResult:
        if self.require_api or self._is_api_available():
            try:
                resp = self.http_client.post(
                    f"/v1/attacks/{attack_type}",
                    json={"attack_type": attack_type, "target_user": user, "amount": amount},
                    timeout=10.0
                )
                if resp.status_code in (200, 403, 423):
                    return PipelineResult(**resp.json())
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if self.require_api:
                    raise RuntimeError(
                        f"Skeleton API at {self.base_url} is unreachable ({type(e).__name__}). "
                        f"SHORLYNOT_REQUIRE_API=1 is active."
                    ) from e
            except Exception as e:
                raise RuntimeError(f"Skeleton API communication error: {e}") from e

        tx = TransactionPayload(
            from_user=user,
            to_user="bob",
            amount=amount,
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
        return self.shared_pipeline.execute_transfer(pipe_req)

    def reset_stages(self) -> Dict[str, Any]:
        if self.require_api or self._is_api_available():
            try:
                resp = self.http_client.post("/v1/stages/reset", timeout=5.0)
                if resp.status_code == 200:
                    return resp.json()
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if self.require_api:
                    raise RuntimeError(
                        f"Skeleton API at {self.base_url} is unreachable ({type(e).__name__}). "
                        f"SHORLYNOT_REQUIRE_API=1 is active."
                    ) from e
            except Exception as e:
                raise RuntimeError(f"Skeleton API communication error: {e}") from e

        self.shared_pipeline.stage_machine.reset()
        self.shared_pipeline.classifier.clear_replay_cache()
        return {"status": "success", "message": "Stages reset on shared pipeline singleton."}

    def get_metrics(self) -> MetricSummary:
        if self.require_api or self._is_api_available():
            try:
                resp = self.http_client.get("/v1/metrics", timeout=5.0)
                if resp.status_code == 200:
                    return MetricSummary(**resp.json())
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                if self.require_api:
                    raise RuntimeError(
                        f"Skeleton API at {self.base_url} is unreachable ({type(e).__name__}). "
                        f"SHORLYNOT_REQUIRE_API=1 is active."
                    ) from e
            except Exception as e:
                raise RuntimeError(f"Skeleton API communication error: {e}") from e

        from shorlynot_skeleton.detect.tau import TauCalculator
        return MetricSummary(
            protocol="ShorlyNot-QDS-T1",
            backend="sim",
            theoretical_p_forge=TauCalculator.calculate_theoretical_p_forge(0.2097, 64),
            tau_normal=0.2097,
            tau_strict=0.2523,
            tau_lenient=0.1730
        )
