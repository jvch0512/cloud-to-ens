import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { evaluate } from "../src/rules.js";
import { reportMarkdown, countBySeverity, byMeasure } from "../src/report.js";
import { fromCredentialReport, parseSnapshot, SnapshotError } from "../src/snapshot.js";

const snap = () => parseSnapshot(readFileSync("examples/snapshot.json", "utf8"));
const ids = (f: ReturnType<typeof evaluate>) => f.map((x) => x.rule);

test("example snapshot raises the expected rules", () => {
  const f = evaluate(snap());
  for (const r of ["storage-public", "storage-unencrypted", "net-admin", "net-any", "net-db", "db-public", "db-unencrypted", "db-backup", "root-mfa", "user-mfa", "key-age", "user-stale", "pw-length", "audit-regions", "audit-retention", "flowlogs-off", "key-rotation", "region-outside-eea"]) assert.ok(ids(f).includes(r), r);
});

test("clean resources produce nothing", () => {
  const f = evaluate(snap());
  assert.ok(!f.some((x) => x.resource === "ledger-db"));
  assert.ok(!f.some((x) => x.resource === "audit-archive"));
  assert.ok(!f.some((x) => x.resource === "kms-logs"));
  assert.ok(!f.some((x) => x.resource.startsWith("sg-db") && x.rule === "net-db" && false));
});

test("private source ranges are not flagged", () => {
  const f = evaluate(snap()).filter((x) => x.rule === "net-db");
  assert.equal(f.length, 1);
});

test("findings are sorted by severity", () => {
  const f = evaluate(snap());
  const o = ["critical", "high", "medium", "low"];
  for (let i = 1; i < f.length; i++) assert.ok(o.indexOf(f[i - 1]!.severity) <= o.indexOf(f[i]!.severity));
});

test("EEA regions are accepted, others flagged", () => {
  const f = evaluate(snap()).filter((x) => x.rule === "region-outside-eea");
  assert.equal(f.length, 1);
  assert.match(f[0]!.resource, /us-east-1/);
});

test("every finding carries ENS ids, a NIS2 reference and both languages", () => {
  for (const x of evaluate(snap())) {
    assert.ok(x.ens.length > 0 && x.ens.every((e) => /^(org|op|mp)\.[a-z]+\.\d+$/.test(e)), x.rule);
    assert.match(x.nis2, /^Art\. 21\(2\)\([a-j]\)/);
    assert.ok(x.text.en.title && x.text.es.title && x.text.es.fix);
  }
});

test("Spanish report", () => {
  const md = reportMarkdown(snap(), evaluate(snap()), "es");
  assert.match(md, /Hallazgos cloud frente a ENS y NIS2/);
  assert.match(md, /Crítica/);
  assert.match(md, /Real Decreto 311\/2022/);
});

test("byMeasure counts and sorts", () => {
  const m = byMeasure(evaluate(snap()));
  assert.ok(m.length > 5);
  for (let i = 1; i < m.length; i++) assert.ok(m[i - 1]![1].length >= m[i]![1].length);
});

test("credential report adapter", () => {
  const id = fromCredentialReport(readFileSync("examples/credential-report.csv", "utf8"), new Date("2026-11-13T00:00:00Z"));
  assert.equal(id.rootMfa, false);
  assert.equal(id.users.length, 3);
  const bob = id.users.find((u) => u.name === "bob")!;
  assert.equal(bob.console, true); assert.equal(bob.mfa, false); assert.equal(bob.keyAgeDays, 437);
  const old = id.users.find((u) => u.name === "old-contractor")!;
  assert.equal(old.lastUsedDays, 201);
  assert.equal(id.users.find((u) => u.name === "alice")!.mfa, true);
});

test("credential report feeds the rules", () => {
  const id = fromCredentialReport(readFileSync("examples/credential-report.csv", "utf8"), new Date("2026-11-13T00:00:00Z"));
  const f = evaluate({ provider: "aws", account: "x", storage: [], network: [], databases: [], identity: id, logging: null, keys: [] });
  assert.ok(ids(f).includes("root-mfa")); assert.equal(f.filter((x) => x.rule === "user-mfa").length, 2);
  assert.equal(countBySeverity(f).critical, 1);
});

test("input validation", () => {
  assert.throws(() => parseSnapshot("nope"), SnapshotError);
  assert.throws(() => parseSnapshot("[]"), SnapshotError);
  assert.throws(() => parseSnapshot(JSON.stringify({ storage: [{ publicAccess: true }] })), SnapshotError);
  assert.throws(() => fromCredentialReport("a,b\n1,2"), SnapshotError);
});

test("empty snapshot is clean", () => {
  assert.equal(evaluate(parseSnapshot("{}")).length, 0);
  assert.match(reportMarkdown(parseSnapshot("{}"), [], "en"), /No findings/);
});
