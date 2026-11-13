import { Snapshot } from "./snapshot.js";

export type Lang = "en" | "es";
export type Severity = "critical" | "high" | "medium" | "low";
export interface Finding { rule: string; severity: Severity; resource: string; ens: string[]; nis2: string; text: Record<Lang, { title: string; fix: string }> }

const EEA = new Set(["eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2", "westeurope", "northeurope", "francecentral", "germanywestcentral", "swedencentral", "spaincentral", "italynorth", "polandcentral", "norwayeast", "europe-west1", "europe-west3", "europe-west4", "europe-west8", "europe-west9", "europe-southwest1", "europe-north1"]);
const ADMIN_PORTS = new Set(["22", "23", "3389", "5985", "5986"]);
const DB_PORTS = new Set(["1433", "1521", "3306", "5432", "6379", "9200", "11211", "27017"]);
const OPEN = (src: string) => src === "0.0.0.0/0" || src === "::/0";

export const NIS2 = {
  risk: "Art. 21(2)(a) risk analysis and security policies",
  incident: "Art. 21(2)(b) incident handling",
  continuity: "Art. 21(2)(c) business continuity and backup",
  supply: "Art. 21(2)(d) supply chain security",
  acquisition: "Art. 21(2)(e) security in acquisition, development and maintenance",
  effectiveness: "Art. 21(2)(f) assessing the effectiveness of measures",
  crypto: "Art. 21(2)(h) cryptography and encryption",
  access: "Art. 21(2)(i) access control and asset management",
  mfa: "Art. 21(2)(j) multi-factor authentication",
} as const;

export function evaluate(s: Snapshot): Finding[] {
  const out: Finding[] = [];
  const add = (rule: string, severity: Severity, resource: string, ens: string[], nis2: string, en: [string, string], es: [string, string]) =>
    out.push({ rule, severity, resource, ens, nis2, text: { en: { title: en[0], fix: en[1] }, es: { title: es[0], fix: es[1] } } });

  for (const b of s.storage) {
    if (b.publicAccess) add("storage-public", "critical", b.name, ["mp.com.1", "op.acc.4", "op.nub.1"], NIS2.access, ["Storage is publicly accessible", "Turn on block-public-access, review bucket policies and ACLs, and serve public content through a CDN with origin access control."], ["El almacenamiento es de acceso público", "Active el bloqueo de acceso público, revise políticas y ACL y sirva el contenido público a través de una CDN con control de acceso al origen."]);
    if (!b.encrypted) add("storage-unencrypted", "medium", b.name, ["mp.info.3", "mp.si.2"], NIS2.crypto, ["Storage is not encrypted at rest", "Enable default encryption, preferably with a customer-managed key."], ["El almacenamiento no está cifrado en reposo", "Active el cifrado por defecto, preferiblemente con clave gestionada por el cliente."]);
    if (!b.versioning) add("storage-versioning", "low", b.name, ["mp.info.9"], NIS2.continuity, ["Versioning is off", "Enable versioning and object lock where records must be preserved."], ["El versionado está desactivado", "Active el versionado y el bloqueo de objetos cuando deban conservarse registros."]);
    if (!b.accessLogging) add("storage-logging", "low", b.name, ["op.exp.8"], NIS2.incident, ["Access logging is off", "Send access logs to a separate, protected log bucket."], ["El registro de accesos está desactivado", "Envíe los registros de acceso a un almacén de logs separado y protegido."]);
  }
  for (const g of s.network) for (const r of g.rules) {
    if (!OPEN(r.source)) continue;
    const port = r.port.toLowerCase();
    if (port === "all" || port === "-1" || port === "0-65535") add("net-any", "critical", `${g.name} (${r.port})`, ["mp.com.1", "mp.com.4"], NIS2.risk, ["Rule allows all ports from the internet", "Replace with the minimum required ports and restrict the source."], ["La regla permite todos los puertos desde internet", "Sustitúyala por los puertos mínimos necesarios y restrinja el origen."]);
    else if (ADMIN_PORTS.has(port)) add("net-admin", "critical", `${g.name} (${r.port})`, ["mp.com.1", "op.acc.8"], NIS2.access, [`Administrative port ${r.port} open to the internet`, "Remove the rule; use a bastion, a VPN or a session manager with MFA."], [`Puerto de administración ${r.port} abierto a internet`, "Elimine la regla; use un bastión, una VPN o un gestor de sesiones con MFA."]);
    else if (DB_PORTS.has(port)) add("net-db", "high", `${g.name} (${r.port})`, ["mp.com.1", "mp.com.4"], NIS2.risk, [`Database port ${r.port} open to the internet`, "Restrict the source to application subnets or private endpoints."], [`Puerto de base de datos ${r.port} abierto a internet`, "Restrinja el origen a las subredes de aplicación o a endpoints privados."]);
  }
  for (const d of s.databases) {
    if (d.publiclyAccessible) add("db-public", "critical", d.name, ["mp.com.1", "op.acc.4"], NIS2.access, ["Database is publicly accessible", "Move it to a private subnet and disable public access."], ["La base de datos es accesible públicamente", "Muévala a una subred privada y desactive el acceso público."]);
    if (!d.encrypted) add("db-unencrypted", "high", d.name, ["mp.info.3"], NIS2.crypto, ["Database is not encrypted at rest", "Create an encrypted copy from a snapshot and switch over; encryption cannot be added in place on most services."], ["La base de datos no está cifrada en reposo", "Cree una copia cifrada desde un snapshot y migre; en la mayoría de servicios no se puede cifrar in situ."]);
    if (d.backupRetentionDays < 7) add("db-backup", "medium", d.name, ["mp.info.9", "op.cont.2"], NIS2.continuity, [`Backup retention is ${d.backupRetentionDays} day(s)`, "Keep at least 7 days, longer per your continuity plan, and test restores."], [`La retención de copias es de ${d.backupRetentionDays} día(s)`, "Mantenga al menos 7 días, más según su plan de continuidad, y pruebe las restauraciones."]);
    if (!d.multiAz) add("db-multiaz", "low", d.name, ["op.cont.2"], NIS2.continuity, ["No multi-AZ or replica", "Enable multi-AZ for services with availability requirements."], ["Sin multi-AZ ni réplica", "Active multi-AZ en servicios con requisitos de disponibilidad."]);
  }
  const id = s.identity;
  if (id) {
    if (id.rootMfa === false) add("root-mfa", "critical", "root", ["op.acc.6", "op.acc.5"], NIS2.mfa, ["Root account has no MFA", "Enable hardware MFA on the root account, remove root access keys and stop using it day to day."], ["La cuenta raíz no tiene MFA", "Active MFA con llave hardware en la cuenta raíz, elimine sus claves y no la use a diario."]);
    for (const u of id.users) {
      if (u.console && !u.mfa) add("user-mfa", "high", u.name, ["op.acc.6", "op.acc.5"], NIS2.mfa, ["Console user without MFA", "Enforce MFA through policy or federate sign-in with your identity provider."], ["Usuario de consola sin MFA", "Imponga MFA mediante política o federe el acceso con su proveedor de identidad."]);
      if (u.keyAgeDays !== null && u.keyAgeDays > 90) add("key-age", "medium", u.name, ["op.acc.4", "op.exp.11"], NIS2.access, [`Access key is ${u.keyAgeDays} days old`, "Rotate keys at most every 90 days, or replace long-lived keys with roles."], [`La clave de acceso tiene ${u.keyAgeDays} días`, "Rote las claves como máximo cada 90 días o sustitúyalas por roles."]);
      if (u.console && u.lastUsedDays !== null && u.lastUsedDays > 90) add("user-stale", "low", u.name, ["op.acc.4"], NIS2.access, [`Console user unused for ${u.lastUsedDays} days`, "Disable or remove accounts that are no longer needed."], [`Usuario de consola sin uso desde hace ${u.lastUsedDays} días`, "Desactive o elimine las cuentas que ya no sean necesarias."]);
    }
    if (id.passwordMinLength !== null && id.passwordMinLength < 12) add("pw-length", "medium", "password policy", ["op.acc.6"], NIS2.access, [`Minimum password length is ${id.passwordMinLength}`, "Require at least 12 characters, or move to passwordless or federated sign-in."], [`La longitud mínima de contraseña es ${id.passwordMinLength}`, "Exija al menos 12 caracteres o migre a acceso federado o sin contraseña."]);
  }
  const lg = s.logging;
  if (lg) {
    if (!lg.auditTrail) add("audit-off", "high", "audit trail", ["op.exp.8", "op.exp.10"], NIS2.incident, ["No audit trail of control-plane activity", "Enable an organisation-wide trail to a protected, separate account."], ["Sin registro de auditoría de la actividad del plano de control", "Active un trail a nivel de organización hacia una cuenta separada y protegida."]);
    else {
      if (!lg.allRegions) add("audit-regions", "medium", "audit trail", ["op.exp.8"], NIS2.incident, ["Audit trail does not cover all regions", "Make the trail multi-region so activity in unused regions is also logged."], ["El registro de auditoría no cubre todas las regiones", "Haga el trail multirregión para registrar también la actividad en regiones no usadas."]);
      if (lg.retentionDays !== null && lg.retentionDays < 365) add("audit-retention", "low", "audit trail", ["op.exp.10"], NIS2.incident, [`Log retention is ${lg.retentionDays} days`, "Align retention with your policy and legal obligations; one year is a common baseline."], [`La retención de logs es de ${lg.retentionDays} días`, "Alinee la retención con su política y obligaciones legales; un año es una base habitual."]);
      if (!lg.logValidation) add("audit-integrity", "low", "audit trail", ["op.exp.10"], NIS2.incident, ["Log file integrity validation is off", "Enable integrity validation so tampering can be detected."], ["La validación de integridad de logs está desactivada", "Active la validación de integridad para detectar manipulaciones."]);
    }
    if (!lg.flowLogs) add("flowlogs-off", "medium", "network flow logs", ["op.exp.8", "mp.com.4"], NIS2.incident, ["Network flow logs are off", "Enable flow logs on VPCs and send them to central storage."], ["Los flow logs de red están desactivados", "Active los flow logs en las VPC y envíelos a un almacén central."]);
  }
  for (const k of s.keys) if (!k.rotation) add("key-rotation", "low", k.name, ["op.exp.11"], NIS2.crypto, ["Key rotation is off", "Enable automatic rotation for customer-managed keys."], ["La rotación de claves está desactivada", "Active la rotación automática en las claves gestionadas por el cliente."]);

  const regions = new Map<string, string[]>();
  for (const x of [...s.storage, ...s.network, ...s.databases]) if (x.region && !EEA.has(x.region)) regions.set(x.region, [...(regions.get(x.region) ?? []), x.name]);
  for (const [r, names] of regions) add("region-outside-eea", "medium", `${r}: ${names.slice(0, 3).join(", ")}${names.length > 3 ? "…" : ""}`, ["op.nub.1", "op.ext.1"], NIS2.supply, [`Resources in ${r}, outside the EEA`, "Confirm the data location is allowed for the information category and has a valid transfer basis; prefer EEA regions for public-sector data."], [`Recursos en ${r}, fuera del EEE`, "Confirme que la ubicación de los datos es admisible para la categoría de información y tiene base de transferencia válida; prefiera regiones del EEE para datos del sector público."]);

  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity] || a.rule.localeCompare(b.rule) || a.resource.localeCompare(b.resource));
}
