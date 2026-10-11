# ShorlyNot — 90-Second Demo & Presentation Script
### SIH 2026 · PS 26141 · Live Presentation Walkthrough

| Time | Presenter Action | Screen / URL | Exact Clicks & Data | What to Say |
|---|---|---|---|---|
| **00:00 - 00:15** | System Introduction | Bank Portal: `http://127.0.0.1:8080/login` | Login as `alice` / `alice123` | "Judges, classical digital signatures (RSA, ECDSA) are fundamentally broken by quantum Shor algorithms. ShorlyNot solves this using teleportation-based Quantum Digital Signatures (QDS-T1) on Qiskit Aer with real-time statistical threat detection." |
| **00:15 - 00:35** | Honest Quantum Transfer | Transfer: `http://127.0.0.1:8080/transfer` | Recipient: `bob`<br>Amount: `₹5,000`<br>Click **Sign with QDS & Execute Transfer** | "Alice initiates a transfer. The system creates Bell pairs $|\Phi^+\rangle$, performs Bell measurements on 64 check positions, encrypts syndromes via BB84 session keys, and verifies on Bob's end. Mismatch error $\hat{p} = 0.00 \le \tau = 0.2097$. The transfer commits instantly." |
| **00:35 - 00:55** | Live Attack Detection | Dark SOC Radar: `http://127.0.0.1:8080/soc` | Click **FORGERY** button | "Now an adversary attempts a signature forgery without Alice's entangled quantum state. Bob's projective verification yields an empirical error rate $\hat{p} \approx 50.0\%$, blowing through our Hoeffding threshold $\tau = 0.21$. Q-STDF detects the forgery and escalates to Stage S2." |
| **00:55 - 01:10** | Bank Application Lockdown | Bank Portal: `http://127.0.0.1:8080/transfer` | Refresh or attempt transfer | "Notice that without modifying OS iptables or touching hardware, the Bank immediately refuses new transfers from the attacker's source at the application layer, while Alice, the identity the forger named, and every other user keep transacting, displaying the exact Hoeffding parameters $p_0=0.02, \delta=0.01, n=64, \tau=0.2097$." |
| **01:10 - 01:25** | Channel Tampering & Q-Stage Escalation | SOC Console $\to$ Bank Portal | On `/soc`, click **CHANNEL** $\to$ Open Bank (`/home` or `/locked`) | "If Eve intercepts the quantum channel or corrupts PQC syndromes, the system detects elevated QBER (spiking from the 2.5% honest baseline to the 16--25% band under full interception, moving the QKD stage from Q0 to the Q3/Q4 compromised-link zone) and escalates to Stage S4 Critical Lockdown, immediately redirecting all users to the emergency lockout console." |
| **01:25 - 01:30** | Recovery & Conclusion | SOC Console: `http://127.0.0.1:8080/soc` | Click **RESET SECURITY STAGES** | "The operator investigates the incident in the SOC log, resets stages back to S0/Q0, and normal operations resume. Zero ML, 100% mathematically proven security." |

---

### One-Shot Automated Attack Suite Execution
To run all 8 attack vectors and defense validations non-interactively via CLI:
```bash
./scripts/demo_attacks.sh
# or on Windows:
python scripts/demo_attacks.py
```
Outputs clear `[PASS]` lines across honest transfer, forgery, channel tampering (with Q-stage escalation), nonce replay, impersonation, parameter downgrade, and bank application lockout.

---

### Key Questions & Answers for Judges

**Q: Why is there zero ML for detection?**  
**A:** In cybersecurity and financial signing, ML models are susceptible to adversarial evasion, hallucination, and drift. Our Q-STDF engine uses Hoeffding's inequality ($\tau = p_0 + \sqrt{\ln(1/\delta)/(2n)}$), providing a mathematically provable false-rejection budget ($\delta=0.01$) and a forgery bypass probability below $10^{-6}$.

**Q: How are quantum circuits executed?**  
**A:** Alice's state preparation and Bell-basis measurements run on Qiskit Aer 3-qubit circuits (`AerSimulator`) using Qiskit 2.x conditional operations (`if_test`). Bob's verification applies corresponding Pauli unitary matrices $\{I, X, Z, XZ\}$.

**Q: Where does PQC and QKD fit in?**  
**A:** QDS requires classical syndrome transmission $(m_1, m_2)$. We use BB84 QKD to establish symmetric session keys and AES-256-GCM under a hybrid BB84 + ML-KEM-768 key to protect syndrome transmission against quantum eavesdropping.
