import { Finding, Lang, Severity } from "./rules.js";
import { Snapshot } from "./snapshot.js";

const T = {
  en: { title: "Cloud to ENS and NIS2 findings", finding: "Finding", account: "Account", sum: "Summary", sev: "Severity", n: "Findings", measure: "ENS measure", res: "Resource", fix: "Remediation", nis: "NIS2", by: "Findings by ENS measure", none: "No findings.", note: "Indicative mapping to ENS (Royal Decree 311/2022, Annex II) and NIS2 Art. 21(2). Confirm measure applicability for your system category and level against the official text. This tool reads a configuration snapshot only; it does not call any cloud API." },
  es: { title: "Hallazgos cloud frente a ENS y NIS2", finding: "Hallazgo", account: "Cuenta", sum: "Resumen", sev: "Severidad", n: "Hallazgos", measure: "Medida ENS", res: "Recurso", fix: "Remediación", nis: "NIS2", by: "Hallazgos por medida ENS", none: "Sin hallazgos.", note: "Correspondencia orientativa con el ENS (Real Decreto 311/2022, Anexo II) y NIS2 art. 21.2. Confirme la aplicabilidad de cada medida según la categoría y el nivel de su sistema en el texto oficial. La herramienta lee solo una instantánea de configuración; no llama a ninguna API cloud." },
};
const SEV: Record<Lang, Record<Severity, string>> = { en: { critical: "Critical", high: "High", medium: "Medium", low: "Low" }, es: { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja" } };

export function countBySeverity(f: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const x of f) c[x.severity]++;
  return c;
}

export function byMeasure(f: Finding[]): [string, Finding[]][] {
  const m = new Map<string, Finding[]>();
  for (const x of f) for (const e of x.ens) m.set(e, [...(m.get(e) ?? []), x]);
  return [...m.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
}

export function reportMarkdown(s: Snapshot, f: Finding[], lang: Lang = "en"): string {
  const t = T[lang];
  const c = countBySeverity(f);
  const L: string[] = [`# ${t.title}`, "", `${t.account}: ${s.account} (${s.provider})`, "", `## ${t.sum}`, "", `| ${t.sev} | ${t.n} |`, "|---|---|"];
  for (const k of ["critical", "high", "medium", "low"] as Severity[]) L.push(`| ${SEV[lang][k]} | ${c[k]} |`);
  if (!f.length) L.push("", t.none);
  else {
    L.push("", `## ${t.n}`, "", `| ${t.sev} | ${t.res} | ${t.finding} | ${t.measure} | ${t.nis} | ${t.fix} |`, "|---|---|---|---|---|---|");
    for (const x of f) L.push(`| ${SEV[lang][x.severity]} | ${x.resource} | ${x.text[lang].title} | ${x.ens.join(", ")} | ${x.nis2} | ${x.text[lang].fix} |`);
    L.push("", `## ${t.by}`, "", `| ${t.measure} | ${t.n} |`, "|---|---|");
    for (const [m, xs] of byMeasure(f)) L.push(`| ${m} | ${xs.length} |`);
  }
  L.push("", t.note);
  return L.join("\n") + "\n";
}
