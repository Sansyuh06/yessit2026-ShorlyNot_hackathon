# ARCHITECTURE.md — ShorlyNot System Architecture

```mermaid
flowchart TD
    subgraph ClientLayer["1. Client Layer"]
        Customer["Customer Bank UI (:8080)"]
        SOC["Dark SOC Monitoring (:8080/soc)"]
        Attacker["Interactive Attack Suite"]
    end

    subgraph BankApp["2. Bank Application (:8080)"]
        Auth["Session Auth & Role Enforcement"]
        Ledger["Double-Entry Account Ledger"]
        Enforce["App-Level Security Lock (S0-S4)"]
        BankClient["Skeleton API Client"]
    end

    subgraph SkeletonFramework["3. ShorlyNot Skeleton Framework (:8000)"]
        Pipeline["Atomic Pipeline Orchestrator"]
        
        subgraph QDS["QDS-T1 Engine"]
            PauliEncoding["Pauli Eigenstate Encoder (Z, X)"]
            BellPrep["Bell Pair Generator (|Φ+>)"]
            BellMeas["Bell-State Measurement (m1, m2)"]
            PauliCorrect["Pauli Corrector (I, X, Z, XZ)"]
            ProjectiveVerify["Projective Verify (Z-basis)"]
        end
        
        subgraph QSTDF["Q-STDF Threat Engine (No ML)"]
            TauMath["Hoeffding Threshold (τ)"]
            Ladder["6-Step Deterministic Decision Ladder"]
            Stages["S0-S4 / Q0-Q4 Stage Manager"]
        end

        subgraph SupportLayers["Support Layers"]
            QKD["BB84 Session & QBER Monitor"]
            PQC["AES-256-GCM / ML-KEM Wrap"]
        end

        subgraph Backends["Quantum Execution Backends"]
            SimAer["Qiskit Aer Simulator (Depolarizing Noise)"]
            IBMRuntime["IBM Quantum Runtime Adapter"]
        end
    end

    Customer -->|Submit Transfer| Auth
    Auth --> Enforce
    Enforce -->|Allowed| BankClient
    BankClient -->|POST /v1/pipeline/transfer| Pipeline
    
    Pipeline --> QKD
    Pipeline --> QDS
    Pipeline --> PQC
    Pipeline --> QSTDF
    
    QDS --> SimAer
    QDS -.-> IBMRuntime
    
    QSTDF -->|Return Classification & S/Q Stages| Pipeline
    Pipeline -->|Signature & Verdict| BankClient
    BankClient -->|Commit or Reject| Ledger
    
    SOC -->|Poll Events, Stages, Metrics| BankClient
    Attacker -->|Simulate Threat| Pipeline
```

## Security Pipeline Flow
1. **User Action**: Alice requests ₹1000 transfer to Bob.
2. **Canonical Commitment**: Bank serializes transaction JSON canonically and derives SHA-256 payload commitment.
3. **QKD Session**: Generates session key material and measures channel QBER ($Q_0 - Q_4$).
4. **QDS-T1 Sign**: Encodes $L=128$ bits as Pauli eigenstates $\{|0\rangle, |1\rangle, |+\rangle, |-\rangle\}$, applies Bell measurements with shared $|\Phi^+\rangle$ pairs, outputs $(m_1, m_2)$ syndromes.
5. **PQC Wrapping**: Encapsulates classical correction syndromes using AES-256-GCM under a hybrid BB84 + ML-KEM-768 key, with ML-DSA-44 identity signatures.
6. **QDS-T1 Verify**: Verifier decrypts syndromes, applies Pauli corrections $\{I, X, Z, XZ\}$, projects onto measurement bases, calculates $\hat{p} = \text{mismatches}/n$.
7. **Q-STDF Classification**: Evaluates Hoeffding bound $\tau$ and protocol bindings (order: `UNAUTH_VERIFY` $\to$ `IMPERSONATION` $\to$ `REPLAY` $\to$ `CHANNEL` $\to$ `FORGERY` $\to$ `OK`).
8. **App Lockdown**: Escalates stage ($S_0 - S_4$). If $S \ge 2$, new transfers are immediately blocked at the application level.
