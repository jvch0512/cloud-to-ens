# Cloud to ENS and NIS2 findings

Account: 123456789012 (prod) (aws)

## Summary

| Severity | Findings |
|---|---|
| Critical | 5 |
| High | 4 |
| Medium | 8 |
| Low | 7 |

## Findings

| Severity | Resource | Finding | ENS measure | NIS2 | Remediation |
|---|---|---|---|---|---|
| Critical | orders-db | Database is publicly accessible | mp.com.1, op.acc.4 | Art. 21(2)(i) access control and asset management | Move it to a private subnet and disable public access. |
| Critical | sg-bastion (22) | Administrative port 22 open to the internet | mp.com.1, op.acc.8 | Art. 21(2)(i) access control and asset management | Remove the rule; use a bastion, a VPN or a session manager with MFA. |
| Critical | sg-legacy (all) | Rule allows all ports from the internet | mp.com.1, mp.com.4 | Art. 21(2)(a) risk analysis and security policies | Replace with the minimum required ports and restrict the source. |
| Critical | root | Root account has no MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Enable hardware MFA on the root account, remove root access keys and stop using it day to day. |
| Critical | public-assets | Storage is publicly accessible | mp.com.1, op.acc.4, op.nub.1 | Art. 21(2)(i) access control and asset management | Turn on block-public-access, review bucket policies and ACLs, and serve public content through a CDN with origin access control. |
| High | orders-db | Database is not encrypted at rest | mp.info.3 | Art. 21(2)(h) cryptography and encryption | Create an encrypted copy from a snapshot and switch over; encryption cannot be added in place on most services. |
| High | sg-db (5432) | Database port 5432 open to the internet | mp.com.1, mp.com.4 | Art. 21(2)(a) risk analysis and security policies | Restrict the source to application subnets or private endpoints. |
| High | bob | Console user without MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Enforce MFA through policy or federate sign-in with your identity provider. |
| High | old-contractor | Console user without MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Enforce MFA through policy or federate sign-in with your identity provider. |
| Medium | audit trail | Audit trail does not cover all regions | op.exp.8 | Art. 21(2)(b) incident handling | Make the trail multi-region so activity in unused regions is also logged. |
| Medium | orders-db | Backup retention is 1 day(s) | mp.info.9, op.cont.2 | Art. 21(2)(c) business continuity and backup | Keep at least 7 days, longer per your continuity plan, and test restores. |
| Medium | network flow logs | Network flow logs are off | op.exp.8, mp.com.4 | Art. 21(2)(b) incident handling | Enable flow logs on VPCs and send them to central storage. |
| Medium | bob | Access key is 410 days old | op.acc.4, op.exp.11 | Art. 21(2)(i) access control and asset management | Rotate keys at most every 90 days, or replace long-lived keys with roles. |
| Medium | ci-deploy | Access key is 220 days old | op.acc.4, op.exp.11 | Art. 21(2)(i) access control and asset management | Rotate keys at most every 90 days, or replace long-lived keys with roles. |
| Medium | password policy | Minimum password length is 8 | op.acc.6 | Art. 21(2)(i) access control and asset management | Require at least 12 characters, or move to passwordless or federated sign-in. |
| Medium | us-east-1: customer-exports | Resources in us-east-1, outside the EEA | op.nub.1, op.ext.1 | Art. 21(2)(d) supply chain security | Confirm the data location is allowed for the information category and has a valid transfer basis; prefer EEA regions for public-sector data. |
| Medium | customer-exports | Storage is not encrypted at rest | mp.info.3, mp.si.2 | Art. 21(2)(h) cryptography and encryption | Enable default encryption, preferably with a customer-managed key. |
| Low | audit trail | Log file integrity validation is off | op.exp.10 | Art. 21(2)(b) incident handling | Enable integrity validation so tampering can be detected. |
| Low | audit trail | Log retention is 90 days | op.exp.10 | Art. 21(2)(b) incident handling | Align retention with your policy and legal obligations; one year is a common baseline. |
| Low | orders-db | No multi-AZ or replica | op.cont.2 | Art. 21(2)(c) business continuity and backup | Enable multi-AZ for services with availability requirements. |
| Low | kms-data | Key rotation is off | op.exp.11 | Art. 21(2)(h) cryptography and encryption | Enable automatic rotation for customer-managed keys. |
| Low | public-assets | Access logging is off | op.exp.8 | Art. 21(2)(b) incident handling | Send access logs to a separate, protected log bucket. |
| Low | public-assets | Versioning is off | mp.info.9 | Art. 21(2)(c) business continuity and backup | Enable versioning and object lock where records must be preserved. |
| Low | old-contractor | Console user unused for 200 days | op.acc.4 | Art. 21(2)(i) access control and asset management | Disable or remove accounts that are no longer needed. |

## Findings by ENS measure

| ENS measure | Findings |
|---|---|
| mp.com.1 | 5 |
| op.acc.4 | 5 |
| op.acc.6 | 4 |
| mp.com.4 | 3 |
| op.acc.5 | 3 |
| op.exp.11 | 3 |
| op.exp.8 | 3 |
| mp.info.3 | 2 |
| mp.info.9 | 2 |
| op.cont.2 | 2 |
| op.exp.10 | 2 |
| op.nub.1 | 2 |
| mp.si.2 | 1 |
| op.acc.8 | 1 |
| op.ext.1 | 1 |

Indicative mapping to ENS (Royal Decree 311/2022, Annex II) and NIS2 Art. 21(2). Confirm measure applicability for your system category and level against the official text. This tool reads a configuration snapshot only; it does not call any cloud API.
