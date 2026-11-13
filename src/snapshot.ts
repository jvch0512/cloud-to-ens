export class SnapshotError extends Error {}

export interface Storage { name: string; region?: string; publicAccess: boolean; encrypted: boolean; versioning: boolean; accessLogging: boolean }
export interface Rule { port: string; protocol?: string; source: string }
export interface NetGroup { name: string; region?: string; rules: Rule[] }
export interface Database { name: string; region?: string; publiclyAccessible: boolean; encrypted: boolean; backupRetentionDays: number; multiAz: boolean }
export interface User { name: string; console: boolean; mfa: boolean; keyAgeDays: number | null; lastUsedDays: number | null }
export interface Identity { rootMfa: boolean | null; users: User[]; passwordMinLength: number | null }
export interface Logging { auditTrail: boolean; allRegions: boolean; retentionDays: number | null; logValidation: boolean; flowLogs: boolean }
export interface Key { name: string; rotation: boolean }
export interface Snapshot {
  provider: string; account: string;
  storage: Storage[]; network: NetGroup[]; databases: Database[];
  identity: Identity | null; logging: Logging | null; keys: Key[];
}

const o = (v: unknown, w: string): Record<string, unknown> => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new SnapshotError(`${w} must be an object`);
  return v as Record<string, unknown>;
};
const arr = (v: unknown, w: string): unknown[] => {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new SnapshotError(`${w} must be an array`);
  return v;
};
const s = (v: unknown, w: string): string => { if (typeof v !== "string" || !v) throw new SnapshotError(`${w} must be a non-empty string`); return v; };
const b = (v: unknown, d = false): boolean => (typeof v === "boolean" ? v : d);
const n = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const rg = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

export function parseSnapshot(text: string): Snapshot {
  let j: unknown;
  try { j = JSON.parse(text); } catch { throw new SnapshotError("snapshot is not valid JSON"); }
  const r = o(j, "snapshot");
  const id = r["identity"] === undefined ? null : o(r["identity"], "identity");
  const lg = r["logging"] === undefined ? null : o(r["logging"], "logging");
  const snap: Snapshot = {
    provider: typeof r["provider"] === "string" ? r["provider"] : "generic",
    account: typeof r["account"] === "string" ? r["account"] : "(unnamed)",
    storage: arr(r["storage"], "storage").map((x, i) => { const q = o(x, `storage[${i}]`); return { name: s(q["name"], `storage[${i}].name`), region: rg(q["region"]), publicAccess: b(q["publicAccess"]), encrypted: b(q["encrypted"]), versioning: b(q["versioning"]), accessLogging: b(q["accessLogging"]) }; }),
    network: arr(r["network"], "network").map((x, i) => { const q = o(x, `network[${i}]`); return { name: s(q["name"], `network[${i}].name`), region: rg(q["region"]), rules: arr(q["rules"], `network[${i}].rules`).map((y, k) => { const z = o(y, `network[${i}].rules[${k}]`); return { port: String(z["port"] ?? "all"), protocol: rg(z["protocol"]), source: s(z["source"], `network[${i}].rules[${k}].source`) }; }) }; }),
    databases: arr(r["databases"], "databases").map((x, i) => { const q = o(x, `databases[${i}]`); return { name: s(q["name"], `databases[${i}].name`), region: rg(q["region"]), publiclyAccessible: b(q["publiclyAccessible"]), encrypted: b(q["encrypted"]), backupRetentionDays: n(q["backupRetentionDays"]) ?? 0, multiAz: b(q["multiAz"]) }; }),
    identity: id && { rootMfa: typeof id["rootMfa"] === "boolean" ? id["rootMfa"] : null, passwordMinLength: n(id["passwordMinLength"]), users: arr(id["users"], "identity.users").map((x, i) => { const q = o(x, `identity.users[${i}]`); return { name: s(q["name"], `identity.users[${i}].name`), console: b(q["console"]), mfa: b(q["mfa"]), keyAgeDays: n(q["keyAgeDays"]), lastUsedDays: n(q["lastUsedDays"]) }; }) },
    logging: lg && { auditTrail: b(lg["auditTrail"]), allRegions: b(lg["allRegions"]), retentionDays: n(lg["retentionDays"]), logValidation: b(lg["logValidation"]), flowLogs: b(lg["flowLogs"]) },
    keys: arr(r["keys"], "keys").map((x, i) => { const q = o(x, `keys[${i}]`); return { name: s(q["name"], `keys[${i}].name`), rotation: b(q["rotation"]) }; }),
  };
  return snap;
}

function csvRows(text: string): string[][] {
  const rows: string[][] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const cells: string[] = [];
    let cur = "", q = false;
    for (const ch of line) {
      if (ch === '"') q = !q;
      else if (ch === "," && !q) { cells.push(cur); cur = ""; } else cur += ch;
    }
    cells.push(cur);
    rows.push(cells);
  }
  return rows;
}

/** Converts an AWS IAM credential report (CSV) into the identity part of a snapshot. */
export function fromCredentialReport(text: string, now: Date = new Date()): Identity {
  const rows = csvRows(text);
  const head = rows[0];
  if (!head || !head.includes("user") || !head.includes("mfa_active")) throw new SnapshotError("not an IAM credential report (expected columns user and mfa_active)");
  const idx = (c: string) => head.indexOf(c);
  const days = (v: string | undefined): number | null => {
    if (!v || v === "N/A" || v === "no_information" || v === "not_supported") return null;
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : Math.max(0, Math.floor((now.getTime() - t) / 86400000));
  };
  const id: Identity = { rootMfa: null, users: [], passwordMinLength: null };
  for (const r of rows.slice(1)) {
    const name = r[idx("user")] ?? "";
    const mfa = r[idx("mfa_active")] === "true";
    if (name === "<root_account>") { id.rootMfa = mfa; continue; }
    const k1 = r[idx("access_key_1_active")] === "true" ? days(r[idx("access_key_1_last_rotated")]) : null;
    const k2 = r[idx("access_key_2_active")] === "true" ? days(r[idx("access_key_2_last_rotated")]) : null;
    const ages = [k1, k2].filter((x): x is number => x !== null);
    const used = [days(r[idx("password_last_used")]), days(r[idx("access_key_1_last_used_date")]), days(r[idx("access_key_2_last_used_date")])].filter((x): x is number => x !== null);
    id.users.push({ name, console: r[idx("password_enabled")] === "true", mfa, keyAgeDays: ages.length ? Math.max(...ages) : null, lastUsedDays: used.length ? Math.min(...used) : null });
  }
  return id;
}
