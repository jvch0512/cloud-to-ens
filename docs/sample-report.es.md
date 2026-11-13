# Hallazgos cloud frente a ENS y NIS2

Cuenta: 123456789012 (prod) (aws)

## Resumen

| Severidad | Hallazgos |
|---|---|
| Crítica | 5 |
| Alta | 4 |
| Media | 8 |
| Baja | 7 |

## Hallazgos

| Severidad | Recurso | Hallazgo | Medida ENS | NIS2 | Remediación |
|---|---|---|---|---|---|
| Crítica | orders-db | La base de datos es accesible públicamente | mp.com.1, op.acc.4 | Art. 21(2)(i) access control and asset management | Muévala a una subred privada y desactive el acceso público. |
| Crítica | sg-bastion (22) | Puerto de administración 22 abierto a internet | mp.com.1, op.acc.8 | Art. 21(2)(i) access control and asset management | Elimine la regla; use un bastión, una VPN o un gestor de sesiones con MFA. |
| Crítica | sg-legacy (all) | La regla permite todos los puertos desde internet | mp.com.1, mp.com.4 | Art. 21(2)(a) risk analysis and security policies | Sustitúyala por los puertos mínimos necesarios y restrinja el origen. |
| Crítica | root | La cuenta raíz no tiene MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Active MFA con llave hardware en la cuenta raíz, elimine sus claves y no la use a diario. |
| Crítica | public-assets | El almacenamiento es de acceso público | mp.com.1, op.acc.4, op.nub.1 | Art. 21(2)(i) access control and asset management | Active el bloqueo de acceso público, revise políticas y ACL y sirva el contenido público a través de una CDN con control de acceso al origen. |
| Alta | orders-db | La base de datos no está cifrada en reposo | mp.info.3 | Art. 21(2)(h) cryptography and encryption | Cree una copia cifrada desde un snapshot y migre; en la mayoría de servicios no se puede cifrar in situ. |
| Alta | sg-db (5432) | Puerto de base de datos 5432 abierto a internet | mp.com.1, mp.com.4 | Art. 21(2)(a) risk analysis and security policies | Restrinja el origen a las subredes de aplicación o a endpoints privados. |
| Alta | bob | Usuario de consola sin MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Imponga MFA mediante política o federe el acceso con su proveedor de identidad. |
| Alta | old-contractor | Usuario de consola sin MFA | op.acc.6, op.acc.5 | Art. 21(2)(j) multi-factor authentication | Imponga MFA mediante política o federe el acceso con su proveedor de identidad. |
| Media | audit trail | El registro de auditoría no cubre todas las regiones | op.exp.8 | Art. 21(2)(b) incident handling | Haga el trail multirregión para registrar también la actividad en regiones no usadas. |
| Media | orders-db | La retención de copias es de 1 día(s) | mp.info.9, op.cont.2 | Art. 21(2)(c) business continuity and backup | Mantenga al menos 7 días, más según su plan de continuidad, y pruebe las restauraciones. |
| Media | network flow logs | Los flow logs de red están desactivados | op.exp.8, mp.com.4 | Art. 21(2)(b) incident handling | Active los flow logs en las VPC y envíelos a un almacén central. |
| Media | bob | La clave de acceso tiene 410 días | op.acc.4, op.exp.11 | Art. 21(2)(i) access control and asset management | Rote las claves como máximo cada 90 días o sustitúyalas por roles. |
| Media | ci-deploy | La clave de acceso tiene 220 días | op.acc.4, op.exp.11 | Art. 21(2)(i) access control and asset management | Rote las claves como máximo cada 90 días o sustitúyalas por roles. |
| Media | password policy | La longitud mínima de contraseña es 8 | op.acc.6 | Art. 21(2)(i) access control and asset management | Exija al menos 12 caracteres o migre a acceso federado o sin contraseña. |
| Media | us-east-1: customer-exports | Recursos en us-east-1, fuera del EEE | op.nub.1, op.ext.1 | Art. 21(2)(d) supply chain security | Confirme que la ubicación de los datos es admisible para la categoría de información y tiene base de transferencia válida; prefiera regiones del EEE para datos del sector público. |
| Media | customer-exports | El almacenamiento no está cifrado en reposo | mp.info.3, mp.si.2 | Art. 21(2)(h) cryptography and encryption | Active el cifrado por defecto, preferiblemente con clave gestionada por el cliente. |
| Baja | audit trail | La validación de integridad de logs está desactivada | op.exp.10 | Art. 21(2)(b) incident handling | Active la validación de integridad para detectar manipulaciones. |
| Baja | audit trail | La retención de logs es de 90 días | op.exp.10 | Art. 21(2)(b) incident handling | Alinee la retención con su política y obligaciones legales; un año es una base habitual. |
| Baja | orders-db | Sin multi-AZ ni réplica | op.cont.2 | Art. 21(2)(c) business continuity and backup | Active multi-AZ en servicios con requisitos de disponibilidad. |
| Baja | kms-data | La rotación de claves está desactivada | op.exp.11 | Art. 21(2)(h) cryptography and encryption | Active la rotación automática en las claves gestionadas por el cliente. |
| Baja | public-assets | El registro de accesos está desactivado | op.exp.8 | Art. 21(2)(b) incident handling | Envíe los registros de acceso a un almacén de logs separado y protegido. |
| Baja | public-assets | El versionado está desactivado | mp.info.9 | Art. 21(2)(c) business continuity and backup | Active el versionado y el bloqueo de objetos cuando deban conservarse registros. |
| Baja | old-contractor | Usuario de consola sin uso desde hace 200 días | op.acc.4 | Art. 21(2)(i) access control and asset management | Desactive o elimine las cuentas que ya no sean necesarias. |

## Hallazgos por medida ENS

| Medida ENS | Hallazgos |
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

Correspondencia orientativa con el ENS (Real Decreto 311/2022, Anexo II) y NIS2 art. 21.2. Confirme la aplicabilidad de cada medida según la categoría y el nivel de su sistema en el texto oficial. La herramienta lee solo una instantánea de configuración; no llama a ninguna API cloud.
