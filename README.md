# cloud-to-ens

Turn an exported cloud configuration into findings mapped to the Spanish ENS (Esquema Nacional de Seguridad, Royal Decree 311/2022) and to NIS2 Art. 21(2), with remediation in English or Spanish. Zero runtime dependencies. CLI and browser tool. It reads files only: no cloud API is called and no credentials are needed.

Live demo: https://jvch0512.github.io/cloud-to-ens/ (runs in the tab, nothing is uploaded)

## Why

Spanish public-sector suppliers and NIS2 entities have to show that their cloud setup meets ENS measures. The evidence usually lives in console screens. cloud-to-ens takes a neutral snapshot, or the AWS IAM credential report you can export in one command, and produces a prioritised list that an auditor and an engineer can both read.

## Quick start

```bash
npm install
npm test
node dist/src/cli.js check examples/snapshot.json                 # English
node dist/src/cli.js check examples/snapshot.json --lang es       # Español
node dist/src/cli.js iam-report examples/credential-report.csv    # AWS credential report
node dist/src/cli.js check snapshot.json --fail-on high           # CI gate, exit 1
npm start                                                         # UI on http://127.0.0.1:8787
```

Get the AWS credential report with `aws iam generate-credential-report` then `aws iam get-credential-report --query Content --output text | base64 -d > report.csv`.

## Snapshot format

A small provider-neutral JSON: `storage`, `network` (security group rules), `databases`, `identity` (root MFA, users, password policy), `logging` (audit trail, flow logs), `keys`. See `examples/snapshot.json`. Every field is optional, missing sections are skipped.

## Checks

Public storage and databases, unencrypted storage and databases, administrative and database ports open to the internet, any-any rules, root and user MFA, old access keys, stale users, weak password length, missing or incomplete audit logging, short log retention, missing flow logs, key rotation, short backup retention, no multi-AZ, resources outside the EEA. Each finding carries ENS measure ids (for example op.acc.6, op.exp.8, mp.info.3, mp.com.1, op.nub.1), the NIS2 Art. 21(2) letter, and a remediation in both languages.

## Limits

The mapping is indicative. ENS applicability depends on the category and level of your system, and measure ids and titles should be confirmed against Annex II of the official text. Thresholds (90 days, 12 characters, 365 days, 7 days) are common baselines, adjust them to your policy. The tool does not prove compliance, it finds configuration gaps.

## License

MIT
