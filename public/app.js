import { evaluate } from "/lib/rules.js";
import { byMeasure, countBySeverity, reportMarkdown } from "/lib/report.js";
import { fromCredentialReport, parseSnapshot } from "/lib/snapshot.js";

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function table(headers, rows, classes = []) {
  const t = document.createElement("table");
  const h = document.createElement("tr");
  headers.forEach((x) => h.append(el("th", x)));
  t.append(h);
  rows.forEach((r) => { const tr = document.createElement("tr"); r.forEach((c, i) => tr.append(el("td", String(c), classes[i] ? classes[i](c) : undefined))); t.append(tr); });
  return t;
}
function cards(items) {
  const box = el("div", undefined, "cards");
  for (const [label, value, cls] of items) { const c = el("div", undefined, `card ${cls ?? ""}`); c.append(el("b", String(value)), el("span", label)); box.append(c); }
  return box;
}
function panel(title, ...kids) { const p = el("div", undefined, "panel"); p.append(el("h2", title), ...kids); return p; }
function copyButton(getMd) {
  const b = el("button", "Copy markdown");
  b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(getMd()); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy markdown"; }, 1500); } catch { /* clipboard blocked */ } });
  return b;
}
function downloadButton(getMd, name) {
  const b = el("button", "Download .md");
  b.type = "button";
  b.addEventListener("click", () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([getMd()], { type: "text/markdown" })); a.download = name; a.click(); URL.revokeObjectURL(a.href); });
  return b;
}
async function sample(name) { return (await fetch(`/examples/${name}`)).text(); }
function showError(box, e) { box.replaceChildren(el("p", String(e.message ?? e), "err")); }
function setupTabs() {
  document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll(".tab").forEach((s) => { s.hidden = s.id !== `p-${b.dataset.tab}`; });
  }));
}
const cls = (map) => (v) => map[v] ?? "";


function load(t) {
  if (t.trimStart().startsWith("{")) return parseSnapshot(t);
  return { provider: "aws", account: "IAM credential report", storage: [], network: [], databases: [], identity: fromCredentialReport(t), logging: null, keys: [] };
}

function run() {
  const out = $("out");
  out.replaceChildren();
  const t = $("input").value.trim();
  if (!t) return;
  try {
    const lang = $("lang").value;
    const snap = load(t);
    const f = evaluate(snap);
    const c = countBySeverity(f);
    const md = reportMarkdown(snap, f, lang);
    out.append(cards([["Critical", c.critical, c.critical ? "bad" : "ok"], ["High", c.high, c.high ? "bad" : "ok"], ["Medium", c.medium, c.medium ? "warn" : "ok"], ["Low", c.low]]));
    out.append(panel("Findings", f.length ? table(["Severity", "Resource", "Finding", "ENS", "NIS2", "Remediation"], f.map((x) => [x.severity, x.resource, x.text[lang].title, x.ens.join(", "), x.nis2, x.text[lang].fix]), [cls({ critical: "s-high", high: "s-high", medium: "s-medium", low: "s-low" })]) : el("p", "No findings.")));
    if (f.length) out.append(panel("By ENS measure", table(["Measure", "Findings"], byMeasure(f).map(([m, xs]) => [m, xs.length]))));
    const row = el("div", undefined, "row");
    row.append(copyButton(() => md), downloadButton(() => md, "cloud-to-ens.md"));
    out.append(row);
  } catch (e) { showError(out, e); }
}

for (const b of document.querySelectorAll("[data-sample]")) b.addEventListener("click", async () => { $("input").value = await sample(b.dataset.sample); run(); });
$("input").addEventListener("input", run);
$("lang").addEventListener("change", run);
