# ShorlyNot

ShorlyNot is a quantum digital signature (QDS) simulation and statistical threat detection framework. It simulates teleportation-assisted quantum digital signatures (ShorlyNot-QDS-T1) using Qiskit Aer, evaluates syndrome consistency against recorded entanglement ground truth, and uses non-ML statistical bounds (Q-STDF) to flag signature tampering in real time.

When verification error rates exceed statistical noise thresholds, the system triggers security stage transitions ($S_0 \to S_4$) that enforce application-level transfer lockouts on an integrated mock banking application.

## Overview

The repository consists of two primary components:

- **`skeleton/`**: The core cryptographic engine and microservice (FastAPI on `:8000`). Handles Pauli eigenstate encoding, Bell-state teleportation circuit simulation, analytical and statevector verification, and Hoeffding-bound anomaly classification.
- **`bank/`**: A mock banking web portal and security operations console (Flask on `:8080`). Demonstrates how real-time QDS verification failures halt financial transfers and quarantine compromised accounts at the application layer.

## How It Works

### 1. ShorlyNot-QDS-T1 Protocol
- **Sign Path**: The sender (Alice) encodes message bits into Pauli eigenstates ($Z$ and $X$ bases) and performs Bell-state measurements across message qubits and shared EPR pairs ($|\Phi^+\rangle$). Classical measurement outcomes $(m_1, m_2)$ form the signature syndrome. Circuits are simulated locally using Qiskit Aer (with PennyLane and optional IBM Quantum hardware support).
- **Verify Path**: The verifier (Bob) validates received syndromes against his recorded half of the entangled state. Bob computes the projective measurement mismatch rate $\hat{p}$ across check positions. For sub-millisecond verification throughput, this evaluation uses exact Born-rule projection against local statevector expectations, with an optional full Aer circuit simulation mode.

### 2. Threat Detection (Q-STDF)
Instead of opaque machine learning models that can be misled or suffer from training distribution drift, threat detection relies strictly on Hoeffding statistical bounds:

$$\tau = p_0 + \sqrt{\frac{\ln(1/\delta)}{2n}}$$

Where:
- $p_0$ is the known physical/channel noise floor (default 0.02).
- $n$ is the number of transmitted signature bits (e.g., 64).
- $\delta$ is the false reject probability budget (e.g., 0.01 for standard, 0.001 for strict).
- $\tau$ is the resulting acceptance threshold.

An honest signature produces an observed mismatch rate $\hat{p} \approx p_0 < \tau$. An attacker guessing states or tampering with the channel causes projective measurement collapse, driving $\hat{p} \to 0.50$, which reliably exceeds $\tau$ and triggers detection without attacker cooperation or injected flags.

### 3. Identity, PQC and Response Policy
- **Identity**: every bundle header carries an ML-DSA-44 (FIPS 204) signature checked against the registered key. Impersonators are caught and attributed from the signature alone.
- **Key wrap**: syndromes are protected with AES-256-GCM under HKDF(BB84 key, ML-KEM-768 secret).
- **Response**: only proven accounts and attacker sources are quarantined. A forged bundle that names Alice cannot lock Alice out. Stages decay over time, and every event goes into a tamper-evident hash chain.
- **Attack-strength analysis**: see [ROC_ANALYSIS.md](docs/ROC_ANALYSIS.md) and [CLAIMS_VS_EVIDENCE.md](docs/CLAIMS_VS_EVIDENCE.md).

### 4. Stage Escalation & App-Level Bank Lock
When suspicious activity or threshold violations occur, the system steps through security stages:
- **S0 (Normal)**: All operations permitted.
- **S1 (Suspicious)**: Warnings logged, heightened telemetry.
- **S2 (Quarantine / Suspended)**: Transfers from the attributed account or attacker source are rejected.
- **S3 (High Threat)**: Elevated alert level. Scope stays per account or source unless link evidence exists.
- **S4 (Lockdown)**: Full application-level gateway freeze. Requires measured link evidence (QBER) or a streak of attributed violations.

All enforcement occurs at the application gateway (within the bank ledger and API client), without requiring privileged OS-level firewall or network modifications.

## Project Layout

```
.
├── skeleton/            # Core QDS engine, Q-STDF detection, and FastAPI service
│   ├── src/shorlynot_skeleton/
│   │   ├── qds/         # Protocol logic, Pauli encoding, Bell teleportation, sessions
│   │   ├── detect/      # Hoeffding threshold calculations and decision ladder
│   │   ├── stages/      # Stage state machine (S0-S4, Q0-Q4)
│   │   ├── qkd/         # BB84 session key distribution simulation
│   │   ├── pqc/         # Encapsulation and authenticated encryption
│   │   ├── attacks/     # Executable threat vectors (forgery, replay, etc.)
│   │   ├── engines/     # Qiskit Aer and PennyLane execution engines
│   │   └── api/         # FastAPI REST application
│   └── tests/           # Unit and integration test suite
├── bank/                # Mock banking application & SOC console
│   ├── app/             # Web routes, auth, ledger, and skeleton client
│   ├── static/          # Frontend styling and SOC telemetry scripts
│   └── tests/           # Bank integration tests
├── scripts/             # Demonstration launchers, scoreboard, smoke tests
└── docs/                # Mathematical specs, benchmarks, and architecture details
```

## Quick Start

### Prerequisites
- Python 3.11+
- Virtual environment recommended

### Installation

```bash
pip install -r requirements.txt
pip install -e ./skeleton
pip install -r bank/requirements.txt
```

### Running the Demo

Start both the skeleton API and the mock bank with a single script:

**Windows**:
```cmd
.\scripts\run_demo.bat
```

**Linux / macOS**:
```bash
chmod +x ./scripts/run_demo.sh
./scripts/run_demo.sh
```

Alternatively, run each service manually in separate terminals:

```bash
# Terminal 1: Skeleton Framework API (:8000)
uvicorn shorlynot_skeleton.api.app:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Mock Bank Application (:8080)
python -m bank.app.main
```

### Accessing the Applications
- **Bank Customer Portal**: [http://127.0.0.1:8080](http://127.0.0.1:8080)  
  Log in as `alice` / `alice123` to test honest transfers.
- **Security Operations Console (SOC)**: [http://127.0.0.1:8080/soc](http://127.0.0.1:8080/soc)  
  Monitor real-time mismatch rates, stage transitions, and trigger simulated attack vectors.
- **Skeleton API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Verification and Metrics

Run the automated scoreboard to evaluate detection rates and theoretical forgery bounds across bit lengths ($n \in \{32, 64, 128\}$):

```bash
python scripts/scoreboard.py
python scripts/roc_benchmark.py   # attack-strength ROC analysis and plots
python scripts/demo_attacks.py    # 8-step attack and defence walkthrough
```

Run test suite:

```bash
pytest -v
```

## Documentation

- [System Architecture](docs/ARCHITECTURE.md): Data flow diagrams and component interaction.
- [Mathematical Model](docs/MODEL.md): Derivations of Bell states, Pauli corrections, and Hoeffding bounds.
- [Security Analysis](docs/SECURITY_ANALYSIS.md): Threat models, attack vectors, and bound tightness.
- [Benchmarks](docs/BENCHMARKS.md): Empirical latency and false reject rate curves.
- [Deployment Guide](docs/DEPLOY.md): Configuration flags, multi-node deployment, and demo walkthrough.
- [Known Limitations](docs/KNOWN_LIMITATIONS.md): Implementation boundaries and hardware trade-offs.
- [Attack-Strength ROC Analysis](docs/ROC_ANALYSIS.md): Detector behaviour against partially informed attackers, Hoeffding vs exact threshold.
- [Claims vs Evidence](docs/CLAIMS_VS_EVIDENCE.md): What each claim rests on, and what it does not show.
