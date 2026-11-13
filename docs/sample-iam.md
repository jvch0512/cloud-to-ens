# Cloud to ENS and NIS2 findings

Account: examples/credential-report.csv (aws)

## Summary

| Severity | Findings |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 1 |

## Findings

| Severity | Resource | Finding | ENS measure | NIS2 | Remediation |
|---|---|---|---|---|---|
| Critical | root | Root account has no MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Enable hardware MFA on the root account, remove root access keys and stop using it day to day. |
| High | bob | Console user without MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Enforce MFA through policy or federate sign-in with your identity provider. |
| High | old-contractor | Console user without MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Enforce MFA through policy or federate sign-in with your identity provider. |
| Medium | bob | Access key is 437 days old | op.acc.4, op.exp.11 | Art. 21(2)(i) access control and asset management | Rotate keys at most every 90 days, or replace long-lived keys with roles. |
| Low | old-contractor | Console user unused for 201 days | op.acc.4 | Art. 21(2)(i) access control and asset management | Disable or remove accounts that are no longer needed. |

## Findings by ENS measure

| ENS measure | Findings |
|---|---|
| op.acc.5 | 3 |
| op.acc.6 | 3 |
| op.acc.4 | 2 |
| op.exp.11 | 1 |

Indicative mapping to ENS (Royal Decree 311/2022, Annex II) and NIS2 Art. 21(2). Confirm measure applicability for your system category and level against the official text. This tool reads a configuration snapshot only; it does not call any cloud API.
