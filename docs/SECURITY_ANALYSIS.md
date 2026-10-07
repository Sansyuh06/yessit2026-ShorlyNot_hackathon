# SECURITY_ANALYSIS.md — ShorlyNot-QDS-T1 & Q-STDF Security Model

**SIH 2026 · Problem Statement 26141**  
**Document Classification**: Mathematical Assumptions, Threat Models & Honesty Framing  
**Protocol Profile**: ShorlyNot-QDS-T1  

---

## 1. System Model & Assumptions

ShorlyNot-QDS-T1 is an application-level quantum digital signature framework designed for financial transaction integrity in a post-RSA/ECC environment. The security proofs and operational guarantees are founded on the following explicit assumptions:

1. **Two-Party Model (Alice Signer, Bob Verifier)**:
   - Alice and Bob share entangled Bell pairs $|\Phi^+\rangle_{AB} = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$.
   - Alice performs Bell-state projective measurements on $(q_A, \text{epr}_A)$, yielding syndrome $(m_1, m_2) \in \{00, 01, 10, 11\}$.
   - Bob applies Pauli unitary corrections $U(m_1, m_2) \in \{I, X, Z, XZ\}$ to recover Alice's prepared Pauli eigenstate $|psi(b, \beta)\rangle$.
2. **Channel Noise Assumption ($p_0$)**:
   - Honest depolarizing channel noise and simulator gate infidelity are bounded by a known noise floor $p_0$ (default: $p_0 = 0.02$, or 2.0%).
3. **Classical Authenticated Binding**:
   - Signature bundles contain cryptographic hashes of canonical JSON transaction payloads, unique UUID nonces, and signer `key_id` bindings established during registration.
4. **App-Level Enforcement (No OS Privileges Required)**:
   - Security policy enforcement (Stages $S_0 \to S_4$) acts at the application boundary (bank ledger refusing transfers, revoking sessions, or locking accounts), without invoking unsafe OS-level `iptables` or kernel hooks.

---

## 2. Derivation & Meaning of the Hoeffding Threshold $\tau$

Under the honest transmission model, each check position exhibits an independent bit mismatch with probability $\le p_0$. For a sample of $n$ check positions, let $X = \sum_{i=1}^n X_i$ denote the total number of observed mismatches, and $\hat{p} = X/n$ denote the empirical mismatch rate.

By Hoeffding's Inequality, for any $\epsilon > 0$:
$$\Pr(\hat{p} - p_0 \ge \epsilon) \le \exp\left(-2n\epsilon^2\right)$$

To ensure that an honest signature is falsely rejected with probability at most $\delta$ (the false-reject budget):
$$\exp\left(-2n\epsilon^2\right) = \delta \implies \epsilon = \sqrt{\frac{\ln(1/\delta)}{2n}}$$

Therefore, the decision threshold $\tau$ is defined as:
$$\tau = p_0 + \sqrt{\frac{\ln(1/\delta)}{2n}}$$

### Threshold Calibration Table ($p_0 = 0.02, n = 64$):
| Preset | False-Reject Budget ($\delta$) | $\epsilon$ | Threshold ($\tau$) | Operational Posture |
|---|---|---|---|---|
| **Strict** | $0.001$ ($0.1\%$) | $0.2323$ | **$0.2523$** | High assurance, zero tolerance for channel disturbance |
| **Normal** | $0.010$ ($1.0\%$) | $0.1897$ | **$0.2097$** | Default financial transaction baseline |
| **Lenient**| $0.050$ ($5.0\%$) | $0.1530$ | **$0.1730$** | High-noise quantum repeater environments |

Any candidate signature with $\hat{p} > \tau$ is classified as a potential **FORGERY** or severe channel perturbation.

---

## 3. Statistical Tamper-Evidence & Forgery Detection Bound ($P_{\text{forge}}$)

When an adversary (Eve) attempts to fabricate a signature bundle without access to Alice's entangled qubit:
1. Bob's subsystem state is the maximally mixed density matrix $\rho_B = \text{Tr}_A(|\Phi^+\rangle\langle\Phi^+|) = \frac{1}{2}I$.
2. For any guessed syndrome $(m_1, m_2)$ and arbitrary unitary $U$, measuring $\rho_B$ in basis $\beta \in \{Z, X\}$ yields independent random outcomes in the idealized projective model:
   $$\Pr(b' = b) = 0.50, \quad \Pr(b' \ne b) = 0.50$$
3. For $n$ independent check positions, the number of mismatches follows the binomial distribution $\text{Binomial}(n, 0.50)$.
4. The candidate signature is accepted if and only if the total mismatches $X \le \lfloor \tau n \rfloor$.

Thus, the theoretical forgery acceptance probability under independent unentangled guessing is bounded by:
$$P_{\text{forge}}(n, \tau) = \sum_{k=0}^{\lfloor \tau \cdot n \rfloor} \binom{n}{k} \left(\frac{1}{2}\right)^n$$

### Scaling vs. Qubit Number ($p_0 = 0.02, \delta = 0.01$):
- For $n = 32, \tau \approx 0.288 \implies P_{\text{forge}} \approx 1.00 \times 10^{-2}$ (1.003% acceptance probability)
- For $n = 64, \tau \approx 0.210 \implies P_{\text{forge}} \approx 9.40 \times 10^{-7}$
- For $n = 128, \tau \approx 0.154 \implies P_{\text{forge}} < 10^{-15}$

---

## 4. Explicit Non-Claims & Symmetric Tamper-Evidence Framing (Scientific Honesty)

To maintain scientific integrity for SIH 2026 evaluation:
- **Symmetric Tamper-Evidence Framing**: As acknowledged in Whitepaper §5.1, the teleportation profile implemented in this software framework provides symmetric tamper-evident authentication across sender and verifier rather than a standalone non-repudiation signature against an untrusted verifier. Forgery bounds reflect statistical projection limits against independent unentangled guessing under the stated model, not physical information-theoretic guarantees from laboratory hardware.
- **No Physical Photon Hardware Claim**: ShorlyNot is a software and quantum simulator framework (Qiskit Aer / PennyLane); we do not claim to have deployed physical laser/fiber hardware.
- **No Novel Quantum Physics Claim**: Teleportation and Bell-basis measurements are established principles (Bennett et al. 1993, Gottesman-Chuang 2001). Our novelty is **Q-STDF**: the non-ML statistical threat detection ladder, multi-stage application state machine, and atomic banking workflow integration.
- **No Machine Learning Claim**: Detection relies strictly on Hoeffding statistical bounds and rule ladders; no neural networks or black-box classifiers are used for threat decisions.
- **Application & Perimeter Enforcement Separation**: Core bank lockdown is enforced at the application layer ($S_0 \to S_4$), while the companion OpenWrt router firmware guards physical relay forwarding via netfilter/nftables rules.

---

## 5. Known Limitations & Architectural Scope

1. **Two-Party MVP (Alice Signer, Bob Verifier)**:
   - Designed for point-to-point payment authorization. Multi-receiver transferable non-repudiation (requiring arbitrated Trent or optical multiports) is formally reserved for future profile T2-AQS.
2. **Global Gateway Threat Escalation**:
   - The Stage State Machine ($S_0 \to S_4$) acts as a central financial gateway firewall. When high-severity attacks occur (e.g. channel compromise or repeated forgery), the system escalates the global operational posture to protect customer balances.
3. **Strict Verifier-Owned Security Parameters**:
   - The verifier enforces a strict security floor $\text{MIN\_SECURE\_N} = 32$. Any attempt by an adversary to submit downgraded check lengths ($n_{\text{checks}} < 32$) is immediately intercepted and rejected as a parameter tampering attack.
4. **Demonstration Authentication & Session Scope**:
   - Mock bank accounts use pre-seeded test credentials in RAM to allow repeatable demo execution, while all verified transaction logs are persisted to SQLite. Production deployments would swap this for OAuth2 / HSM-backed authentication.
