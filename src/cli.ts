#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { evaluate, Lang, Severity } from "./rules.js";
import { reportMarkdown, countBySeverity } from "./report.js";
import { fromCredentialReport, parseSnapshot, SnapshotError, Snapshot } from "./snapshot.js";

const USAGE = `cloud-to-ens

  cloud-to-ens check <snapshot.json> [--lang en|es] [--json] [--fail-on critical|high|medium|low]
  cloud-to-ens iam-report <credential-report.csv> [--lang en|es] [--today YYYY-MM-DD] [--fail-on ...]

Reads exported configuration only; no cloud API is called.
Exit codes: 0 ok, 1 findings at or above --fail-on, 2 bad input.`;

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

function opt(a: string[], n: string): string | undefined { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; }

function main(argv: string[]): number {
  const [cmd, file] = argv;
  if ((cmd !== "check" && cmd !== "iam-report") || !file) { console.error(USAGE); return 2; }
  const lang = (opt(argv, "--lang") ?? "en") as Lang;
  if (lang !== "en" && lang !== "es") { console.error("--lang must be en or es"); return 2; }
  const failOn = opt(argv, "--fail-on") as Severity | undefined;
  if (failOn && !ORDER.includes(failOn)) { console.error(`--fail-on must be one of ${ORDER.join(", ")}`); return 2; }
  const today = opt(argv, "--today");
  if (today && !/^\d{4}-\d{2}-\d{2}$/.test(today)) { console.error("--today must be YYYY-MM-DD"); return 2; }
  try {
    const text = readFileSync(file, "utf8");
    const snap: Snapshot = cmd === "check" ? parseSnapshot(text) : { provider: "aws", account: file, storage: [], network: [], databases: [], identity: fromCredentialReport(text, today ? new Date(`${today}T00:00:00Z`) : new Date()), logging: null, keys: [] };
    const f = evaluate(snap);
    process.stdout.write(argv.includes("--json") ? JSON.stringify(f, null, 2) + "\n" : reportMarkdown(snap, f, lang));
    const c = countBySeverity(f);
    return failOn && ORDER.slice(0, ORDER.indexOf(failOn) + 1).some((s) => c[s] > 0) ? 1 : 0;
  } catch (e) {
    if (e instanceof SnapshotError || (e as NodeJS.ErrnoException).code === "ENOENT") { console.error(`error: ${(e as Error).message}`); return 2; }
    throw e;
  }
}

process.exitCode = main(process.argv.slice(2));
