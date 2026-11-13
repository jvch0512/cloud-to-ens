node dist/src/cli.js check examples/snapshot.json > /tmp/a.md; diff /tmp/a.md docs/sample-report.md
node dist/src/cli.js check examples/snapshot.json --lang es > /tmp/b.md; diff /tmp/b.md docs/sample-report.es.md
node dist/src/cli.js iam-report examples/credential-report.csv --today 2026-11-13 > /tmp/c.md; diff /tmp/c.md docs/sample-iam.md
test "$(node dist/src/cli.js check examples/snapshot.json --fail-on critical >/dev/null; echo $?)" = "1"
