# DELIVERY_TABLE.md — SIH 2026 PS 26141 Compliance Matrix

| Problem Statement 26141 Requirement | Architectural Component | Source Code Path | Verified Pytest Test Name |
|---|---|---|---|
| **Teleportation-Based QDS Protocol** | ShorlyNot-QDS-T1 Sign & Verify | [`qds/protocol.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/qds/protocol.py) | `test_honest_qds_sign_and_verify_accept` |
| **Bell Entanglement Distribution ($|\Phi^+\rangle$)** | 3-Qubit Teleportation Engine | [`engines/qiskit_aer.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/engines/qiskit_aer.py) | `test_bell_measurement_from_real_circuit` |
| **Pauli Eigenstate Encoding ($Z, X$)** | BB84/Pauli State Preparation | [`qds/encoding.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/qds/encoding.py) | `test_pauli_encoding_eigenstates` |
| **Pauli Unitary Corrections ($I, X, Z, XZ$)** | Syndrome Matrix Transformations | [`qds/pauli.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/qds/pauli.py) | `test_pauli_corrections_lookup` |
| **Non-ML Statistical Thresholds ($\tau$)** | Hoeffding Bound Engine | [`detect/tau.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/detect/tau.py) | `test_hoeffding_tau_formula` |
| **Strict Zero-ML Architecture Rule** | Non-ML Static Assertion | [`detect/classifier.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/detect/classifier.py) | `test_no_ml_libraries_in_detect_module` |
| **Threat Vector 1: Signature Forgery** | Forgery Attack Simulator | [`attacks/forgery.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/attacks/forgery.py) | `test_forgery_attack_vector` |
| **Threat Vector 2: Impersonation Attack** | Identity Binding Check | [`attacks/impersonation.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/attacks/impersonation.py) | `test_impersonation_attack_vector` |
| **Threat Vector 3: Replay Attack** | Nonce Cache & Verification | [`attacks/replay.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/attacks/replay.py) | `test_replay_attack_vector` |
| **Threat Vector 4: Unauthorized Verification** | Entitlement Authorization | [`attacks/unauth_verify.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/attacks/unauth_verify.py) | `test_unauth_verify_attack_vector` |
| **Threat Vector 5: Channel Manipulation** | PQC Tampering Simulator | [`attacks/channel.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/attacks/channel.py) | `test_channel_attack_vector` |
| **Threat Vector 6: Parameter Downgrade** | Security Parameter Floor | [`attacks/param_tamper.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/attacks/param_tamper.py) | `test_parameter_tampering_downgrade_attack_vector` |
| **Dynamic Security Stages ($S_0 \to S_4$)** | Stage State Machine | [`stages/state_machine.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/stages/state_machine.py) | `test_stage_state_machine_transitions` |
| **QKD Link Support Layer & QBER ($Q_0 \to Q_4$)** | BB84 Protocol Simulator | [`qkd/bb84.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/qkd/bb84.py) | `test_q_stage_qber_bands` |
| **Dual Engine Parity (PennyLane + Qiskit)** | Cross-Framework Testing | [`engines/pennylane_engine.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/engines/pennylane_engine.py) | `test_cross_engine_parity_with_qiskit_aer` |
| **Statistical Tamper-Evidence $P_{\text{forge}}$ Analysis** | Monte Carlo Benchmarks | [`analysis/benchmark.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/analysis/benchmark.py) | `test_hoeffding_tau_formula` |
| **Embeddable Framework / Microservice** | Skeleton REST API (:8000) | [`api/app.py`](file:///d:/fyeshi/project/quantum/iptable/skeleton/src/shorlynot_skeleton/api/app.py) | `test_fit_test_alice_honest_transfer_succeeds` |
| **Operational Proof: Mock Bank App** | FastAPI Web Application (:8080) | [`bank/app/main.py`](file:///d:/fyeshi/project/quantum/iptable/bank/app/main.py) | `test_bank_login_and_home_access` |
| **App-Level Lockdown (No iptables/root)** | Stage Policy Enforcement | [`bank/app/main.py`](file:///d:/fyeshi/project/quantum/iptable/bank/app/main.py) | `test_bank_transfers_blocked_when_attack_escalates_stage` |
| **Real-Time Dark SOC Threat Console** | Live Telemetry & Feed (`/soc`) | [`bank/app/templates/soc.html`](file:///d:/fyeshi/project/quantum/iptable/bank/app/templates/soc.html) | `test_soc_reset_restores_operations` |
| **Authenticated SOC Control Plane** | Role-Based Access Guard | [`bank/app/main.py`](file:///d:/fyeshi/project/quantum/iptable/bank/app/main.py) | `test_soc_unauthenticated_write_rejected` |
| **North Star Fit Test (< 2 Minutes)** | E2E Integration Scenario | [`tests/test_e2e_fit.py`](file:///d:/fyeshi/project/quantum/iptable/tests/test_e2e_fit.py) | `test_fit_test_full_scenario_end_to_end` |
| **OpenWrt Hardware Router Guard** | TP-Link Archer C6 fw4 Daemon | [`ShorlyNot-Router-Firmware/`](file:///d:/fyeshi/project/quantum/iptable/ShorlyNot-Router-Firmware/) | `test_transfer_blocked_when_router_is_red` |
| **Router Guard KMS Client & Retries** | Resilient Telemetry Bridge | [`bank/app/services/router_client.py`](file:///d:/fyeshi/project/quantum/iptable/bank/app/services/router_client.py) | `test_router_client_custom_retry_configuration` |

