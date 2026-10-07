"""
Unit and integration tests for ShorlyNot Router Guard and KMS integration.
"""

from fastapi.testclient import TestClient
from bank.app.main import app
from bank.app.services.router_client import RouterGuardClient, HARDWARE_KMS_DEFAULT_URL

client = TestClient(app)


def test_router_client_defaults_to_hardware_kms():
    rg = RouterGuardClient()
    assert rg.hardware_kms_url == HARDWARE_KMS_DEFAULT_URL
    assert rg.hardware_info["kms_hardware_url"] == "http://192.168.1.2:8000"
    assert rg.hardware_info["router_ip"] == "192.168.1.1"
    assert rg.hardware_info["relay_port"] == 8765
    assert "192.168.1.2:8000" in rg.hardware_info["guard_daemon"]


def test_router_status_endpoint_returns_hardware_telemetry():
    resp = client.get("/api/router/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "qber" in data
    assert "key_rate" in data
    assert "hardware" in data
    assert data["hardware"]["device"] == "TP-Link Archer C6 v3.20"
    assert data["hardware_kms_url"] == "http://192.168.1.2:8000"
    assert "chain router_guard_forward" in data["nftables_output"]


def test_router_set_state_and_qber():
    # Set to RED
    resp = client.post("/api/router/set_state?state=RED", headers={"Authorization": "Bearer ops-secret-key-2026"})
    assert resp.status_code == 200
    status_data = client.get("/api/router/status").json()
    assert status_data["status"] == "RED"
    assert "drop" in status_data["last_rule"]

    # Set to GREEN
    resp = client.post("/api/router/set_state?state=GREEN", headers={"Authorization": "Bearer ops-secret-key-2026"})
    assert resp.status_code == 200
    status_data = client.get("/api/router/status").json()
    assert status_data["status"] == "GREEN"
    assert "accept" in status_data["last_rule"]


def test_transfer_blocked_when_router_is_red():
    # Login as alice
    login_resp = client.post("/login", data={"username": "alice", "password": "alice123"}, follow_redirects=False)
    assert login_resp.status_code == 303

    # Set router to RED
    client.post("/api/router/set_state?state=RED", headers={"Authorization": "Bearer ops-secret-key-2026"})

    # Attempt transfer
    transfer_resp = client.post("/transfer", data={"to_user": "bob", "amount": 100.0})
    assert transfer_resp.status_code == 200
    assert "Physical Quantum Channel Severed" in transfer_resp.text
    assert "Archer C6" in transfer_resp.text
    assert "Relay Port 8765" in transfer_resp.text

    # Restore to GREEN
    client.post("/api/router/set_state?state=GREEN", headers={"Authorization": "Bearer ops-secret-key-2026"})


def test_router_client_health_check_and_poll_counter():
    rg = RouterGuardClient(max_retries=1)
    # Initial state should show 0 polls
    assert rg._cached_status["polls"] == 0

    # Poll status triggers poll increment
    status = rg.get_status()
    assert status["polls"] >= 1
    assert "dropped_packets" in status

    # When connected and GREEN -> healthy
    rg._cached_status["connected"] = True
    rg._cached_status["status"] = "GREEN"
    assert rg.is_healthy() is True

    # When status escalates to RED -> not healthy
    rg._cached_status["status"] = "RED"
    assert rg.is_healthy() is False


def test_router_client_custom_retry_configuration():
    # Verify retry count clamping and endpoint uniqueness
    rg = RouterGuardClient(kms_url="http://192.168.1.50:9000", max_retries=3)
    assert rg.max_retries == 3
    endpoints = rg._get_candidate_endpoints()
    assert "http://192.168.1.50:9000" in endpoints
    # Ensure no duplicates in candidates
    assert len(endpoints) == len(set(endpoints))

