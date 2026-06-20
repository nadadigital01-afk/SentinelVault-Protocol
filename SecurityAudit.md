# Security Audit Report — YieldVault Reentrancy Finding

> **EDUCATIONAL ONLY — DO NOT USE VULNERABLE CODE ON LIVE NETWORKS**

| Item | Details |
| :--- | :--- |
| **Target** | `YieldVault.sol` |
| **Remediated Version** | `YieldVaultSecure.sol` |
| **Audit Type** | Manual review + static analysis, educational reference |
| **Methodology** | Manual control-flow tracing, Slither, Foundry differential testing |

---

## 1. Executive Summary
YieldVault is a share-based yield vault. The withdrawal function contains a reentrancy vulnerability that follows the same root-cause pattern as the 2016 DAO exploit. This is rated **Critical (CVSS 9.8)** as it allows an attacker to drain the vault's assets. A fully remediated version is provided in `YieldVaultSecure.sol`.

## 2. Vulnerability Summary Table

| ID | Title | Severity | CVSS | Location |
| :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | Reentrancy in `withdraw()` | **Critical** | 9.8 | `Vault.sol:withdraw()` |
| **INFO-01** | Misleading `previewWithdraw` context | Low | 3.1 | `Vault.sol:previewWithdraw()` |

## 3. Forensic Breakdown — VULN-01
### Root Cause
The contract performs an external call (`safeTransfer`) to a potentially malicious address **before** updating the internal accounting state (`shares` and `totalAssets`). 

### Attack Trace
1. Attacker calls `withdraw()` for their full balance.
2. Vault calls `safeTransfer` to pay the attacker.
3. Attacker's malicious contract triggers a callback (e.g., `tokensReceived`) that calls `withdraw()` again.
4. Because the first call hasn't updated the state yet, the vault "thinks" the attacker still has their full balance and pays out again.
5. Recursion drains the vault.

## 4. Remediation Plan
`YieldVaultSecure.sol` implements three stacked mitigations:
1. **Checks-Effects-Interactions (Primary):** All state mutations are finalized before any external call.
2. **ReentrancyGuard (Defense in Depth):** Added `nonReentrant` to all sensitive functions.
3. **Pull-Payment Pattern:** Fees are no longer pushed synchronously; they are claimed via a separate `claimFees()` function, reducing the attack surface.

## 5. Security Best Practices Checklist
- [x] State-mutating functions follow Checks-Effects-Interactions.
- [x] Sensitive functions are wrapped in `nonReentrant`.
- [x] Pull-payment used for external third-party transfers.
- [x] Slither and Foundry tests integrated for CI/CD.
- [x] Independent third-party audit required before mainnet launch.

---
*Disclaimer: This audit package is for educational purposes. Never deploy vulnerable code to production networks.*
