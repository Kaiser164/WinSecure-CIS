# CIS Hardening Automation — Windows 10 Level 1

> Automatización de endurecimiento de seguridad basada en el benchmark **CIS Microsoft Windows 10 Stand-alone v2.0 (Level 1)**.  
> Evalúa, aplica y verifica 55 controles de seguridad con generación de informes HTML, CSV y JSON.

---

## Tabla de contenidos

- [Descripción](#descripción)
- [Requisitos](#requisitos)
- [Instalación rápida](#instalación-rápida)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Modos de ejecución](#modos-de-ejecución)
- [Controles CIS cubiertos](#controles-cis-cubiertos)
- [Backup y restauración](#backup-y-restauración)
- [Informes generados](#informes-generados)
- [Referencia de comandos](#referencia-de-comandos)
- [Solución de problemas](#solución-de-problemas)
- [Notas técnicas](#notas-técnicas)

---

## Descripción

**CIS Hardening Automation** es un conjunto de scripts PowerShell que implementa el ciclo completo de endurecimiento CIS sobre Windows 10 Pro/Enterprise standalone (sin Active Directory):

```
PRETEST  →  BACKUP  →  HARDENING  →  POSTEST  →  INFORME
  54%    →   snap   →   aplica    →    100%    →   HTML+CSV+JSON
```

El proyecto evalúa **55 controles** distribuidos en 6 categorías, crea un backup completo antes de aplicar cambios, y genera una comparativa detallada del estado inicial vs. final del sistema.

> **English summary:** PowerShell automation for CIS Windows 10 Level 1 hardening. Evaluates 55 controls, creates a system backup, applies security policies, and generates HTML/CSV/JSON reports showing compliance improvement.

---

## Requisitos

| Requisito | Mínimo |
|---|---|
| Sistema operativo | Windows 10 Pro / Enterprise (Build 19041+) |
| PowerShell | 5.1 o superior |
| Permisos | Administrador local |
| Espacio en disco | ~50 MB (backups incluidos) |
| Active Directory | No requerido — diseñado para equipos standalone |

---

## Instalación rápida

### Opción A — Primer uso (recomendado)

```powershell
# 1. Descargar o clonar el repositorio en cualquier carpeta
# 2. Abrir PowerShell como Administrador
# 3. Navegar a la raíz del proyecto
cd "C:\ruta\donde\descargaste\HARDENING"

# 4. Ejecutar el script de configuración inicial
.\setup.ps1
```

`setup.ps1` hace todo lo necesario: desbloquea los scripts, repara encoding, verifica requisitos y crea las carpetas de trabajo.

### Opción B — Manual

```powershell
# Desbloquear scripts descargados de internet
Get-ChildItem -Recurse -Filter "*.ps1" | Unblock-File

# Verificar política de ejecución
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Ejecutar
.\01-Main.ps1 -Mode Full
```

> **Nota:** El proyecto detecta su propia ubicación automáticamente. No hay rutas hardcodeadas — funciona desde cualquier carpeta en cualquier equipo.

---

## Estructura del proyecto

```
HARDENING\
│
├── 00-Config.ps1              ← Configuración central (rutas, controles CIS)
├── 01-Main.ps1                ← Orquestador principal
├── setup.ps1                  ← Configuración inicial (primer uso)
├── fix-encoding.ps1           ← Repara encoding UTF-8 de todos los scripts .ps1
├── Setup-LimitedUser.ps1      ← Crear usuario limitado para pruebas
├── .gitattributes             ← Configuración de encoding para Git
│
├── Apply\                     ← Scripts de aplicación de hardening
│   ├── Set-AccountPolicies.ps1
│   ├── Set-AdminTemplates.ps1
│   ├── Set-AuditPolicy.ps1
│   ├── Set-Firewall.ps1
│   ├── Set-SecurityOptions.ps1
│   └── Set-UserRights.ps1
│
├── Pretest\                   ← Scripts de evaluación CIS
│   ├── Test-AccountPolicies.ps1
│   ├── Test-AdminTemplates.ps1
│   ├── Test-AuditPolicy.ps1
│   ├── Test-Firewall.ps1
│   ├── Test-SecurityOptions.ps1
│   └── Test-UserRights.ps1
│
├── Utils\                     ← Utilidades compartidas
│   ├── Write-Log.ps1
│   ├── Backup-Config.ps1
│   ├── Compare-Results.ps1
│   └── Export-Report.ps1
│
├── Data\                      ← Generado automáticamente
│   └── cis-controls.json
│
├── Logs\                      ← Generado automáticamente
│   └── CIS-Hardening.log
│
├── Reports\                   ← Generado automáticamente
│   ├── hardening-report.html
│   ├── hardening-report.csv
│   ├── hardening-report.json
│   ├── pretest.json
│   └── postest.json
│
└── Backups\                   ← Generado automáticamente
    └── backup-YYYYMMDD-HHmmss\
        ├── security-policy.inf
        ├── registry-*.reg
        ├── firewall-rules.wfw
        └── hash-manifest.json
```

---

## Modos de ejecución

### Flujo completo (recomendado)

```powershell
.\01-Main.ps1 -Mode Full
```

Ejecuta las 5 fases: pretest → backup → hardening → postest → informe.

### Solo evaluación (sin cambios)

```powershell
.\01-Main.ps1 -Mode PretestOnly
```

Ideal para auditar el estado actual sin modificar nada.

### Simular hardening

```powershell
.\01-Main.ps1 -Mode Full -WhatIf
```

Muestra qué cambios se aplicarían sin ejecutar ninguno.

### Solo una categoría

```powershell
.\01-Main.ps1 -Mode Full -Category Firewall
.\01-Main.ps1 -Mode Full -Category AuditPolicy
.\01-Main.ps1 -Mode Full -Category AccountPolicies -SecurityLevel Maximum
```

### Niveles de seguridad disponibles

| Nivel | Descripción |
|---|---|
| `CIS-Minimum` | Valores mínimos exigidos por la norma |
| `Secure` | Balance seguridad / usabilidad *(por defecto)* |
| `Maximum` | Máxima restricción (puede afectar usabilidad) |

### Solo aplicar hardening (requiere pretest previo)

```powershell
.\01-Main.ps1 -Mode ApplyOnly
```

Aplica el hardening sin ejecutar el pretest. Útil cuando ya tienes una evaluación inicial y solo quieres aplicar los cambios.

### Re-evaluar tras reinicio

```powershell
.\01-Main.ps1 -Mode PostestOnly
```

---

## Controles CIS cubiertos

**55 controles** del benchmark CIS Microsoft Windows 10 Stand-alone v2.0 Level 1:

| Categoría | Controles | IDs |
|---|---|---|
| Account Policies | 10 | 1.1.1 – 1.1.7, 1.2.1, 1.2.2, 1.2.4 |
| Firewall | 4 | 9.2.1, 9.2.2, 9.3.1, 9.3.2 |
| Security Options | 8 | 2.3.1.1 – 2.3.1.3, 2.3.7.2, 2.3.7.4, 2.3.10.12, 2.3.17.1, 2.3.17.6 |
| Administrative Templates | 10 | 18.4.1, 18.4.2, 18.10.8.3, 18.10.43.10.2–5, 18.10.59.3, 18.10.66.2, 18.10.93.2.1 |
| User Rights Assignment | 13 | 2.2.1, 2.2.2, 2.2.4 – 2.2.8, 2.2.11, 2.2.15, 2.2.16, 2.2.19, 2.2.23, 2.2.24 |
| Advanced Audit Policy | 10 | 17.1.1, 17.2.2, 17.2.3, 17.3.2, 17.5.1, 17.5.4, 17.5.5, 17.6.2, 17.7.1, 17.9.5 |

> **Nota:** El perfil Domain del Firewall (9.1.x) está excluido intencionalmente — el proyecto está diseñado para equipos standalone sin Active Directory.

---

## Backup y restauración

### Crear backup manualmente

```powershell
.\Utils\Backup-Config.ps1
```

### Restaurar con limpieza profunda (recomendado)

```powershell
# Ver backups disponibles
Get-ChildItem ".\Backups\"

# Restaurar
.\Utils\Backup-Config.ps1 -Restore -BackupPath ".\Backups\backup-20260531-204519" -DeepClean
```

`-DeepClean` ejecuta primero un reset completo (auditpol, secedit, registro, firewall) y luego aplica el backup encima, garantizando que no queden rastros del hardening.

### Solo limpiar (sin backup)

```powershell
.\Utils\Backup-Config.ps1 -ResetOnly
```

Útil cuando no tienes backup disponible o quieres devolver el sistema a defaults de Windows.

---

## Informes generados

Cada ejecución genera hasta 3 formatos en `Reports\`:

| Archivo | Formato | Uso |
|---|---|---|
| `hardening-report.html` | HTML | Visualización en navegador, presentación |
| `hardening-report.csv` | CSV | Excel, análisis de datos |
| `hardening-report.json` | JSON | Integración con SIEM, herramientas externas |
| `pretest.json` | JSON | Estado inicial del sistema |
| `postest.json` | JSON | Estado final tras el hardening |

El informe HTML incluye tarjetas de resumen, porcentajes de cumplimiento inicial y final, mejora total, y tabla detallada por control con estado pretest/postest.

---

## Referencia de comandos

### Get-Help completo

```powershell
# Orquestador principal
Get-Help .\01-Main.ps1 -Full
Get-Help .\01-Main.ps1 -Examples

# Scripts de aplicación (Apply\)
Get-Help .\Apply\Set-AccountPolicies.ps1 -Full
Get-Help .\Apply\Set-AuditPolicy.ps1 -Examples
Get-Help .\Apply\Set-Firewall.ps1 -Full
Get-Help .\Apply\Set-SecurityOptions.ps1 -Full
Get-Help .\Apply\Set-AdminTemplates.ps1 -Full
Get-Help .\Apply\Set-UserRights.ps1 -Full

# Scripts de evaluación (Pretest\)
Get-Help .\Pretest\Test-AccountPolicies.ps1 -Detailed
Get-Help .\Pretest\Test-AuditPolicy.ps1 -Detailed
Get-Help .\Pretest\Test-Firewall.ps1 -Detailed
Get-Help .\Pretest\Test-SecurityOptions.ps1 -Detailed
Get-Help .\Pretest\Test-AdminTemplates.ps1 -Detailed
Get-Help .\Pretest\Test-UserRights.ps1 -Detailed

# Utilidades (Utils\)
Get-Help .\Utils\Backup-Config.ps1 -Full
Get-Help .\Utils\Backup-Config.ps1 -Examples
Get-Help .\Utils\Export-Report.ps1 -Full
Get-Help .\Utils\Compare-Results.ps1 -Full
Get-Help .\Utils\Write-Log.ps1 -Full
```

---

## Solución de problemas

### Los scripts no se ejecutan (política de ejecución)

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Caracteres corruptos en consola (Ã¡, âœ", etc.)

```powershell
.\fix-encoding.ps1
```

### No se generan reportes ni logs

Verificar que `00-Config.ps1` detecta la ruta correcta:

```powershell
. .\00-Config.ps1
Write-Host $global:ProjectRoot
Write-Host $global:ReportsPath
```

Si la ruta es incorrecta, ejecutar `setup.ps1` que recrea las carpetas automáticamente.

### El postest muestra FAIL en controles ya aplicados

Dos controles requieren los archivos corregidos de esta versión:

- **18.4.1** (SMB v1 client): usar `Pretest\Test-AdminTemplates.ps1` actualizado — el original marcaba FAIL cuando el driver no está instalado (que es el estado correcto).
- **2.3.1.2** (Guest account): usar `Pretest\Test-SecurityOptions.ps1` actualizado — el original buscaba la cuenta por nombre `"Guest"`, fallando en Windows en español donde se llama `"Invitado"`.

### Error al restaurar backup: "integridad comprometida"

```powershell
.\Utils\Backup-Config.ps1 -Restore -BackupPath ".\Backups\backup-YYYYMMDD" -DeepClean -SkipIntegrityCheck
```

### Reiniciar recomendado

Algunas políticas de cuenta y User Rights requieren reinicio para aplicarse completamente. Si el postest muestra valores incorrectos en AccountPolicies o UserRights, reiniciar y volver a correr:

```powershell
.\01-Main.ps1 -Mode PostestOnly
```

---

## Notas técnicas

### Detección dinámica de rutas

`00-Config.ps1` usa `$MyInvocation.MyCommand.Path` para detectar su propia ubicación. El proyecto funciona desde cualquier ruta sin modificar ningún archivo — se puede mover, renombrar o copiar a otra PC.

### Compatibilidad de idioma del SO

Los scripts usan SIDs en lugar de nombres de cuenta para máxima compatibilidad:

- Cuenta Guest: buscada por SID terminado en `-501` (funciona en ES, EN y otras localizaciones)
- User Rights: comparados por SID, no por nombre de grupo

### Sistema de backup (doble capa)

- **Capa 1** — `Reset-ToWindowsDefaults`: limpieza completa antes de restaurar (auditpol, secedit, registro, firewall)
- **Capa 2** — `Restore-Backup`: aplica el snapshot pre-hardening sobre el estado limpio

Este enfoque garantiza restauración completa aunque `secedit` y `reg import` sean operaciones de merge que no eliminan claves nuevas.

### Archivos de backup generados

| Archivo | Contenido |
|---|---|
| `security-policy.inf` | Políticas de cuenta y User Rights (secedit) |
| `registry-*.reg` | Claves de registro (LSA, Policies, Defender, WU) |
| `firewall-rules.wfw` | Reglas completas de Windows Firewall |
| `hash-manifest.json` | Hashes SHA-256 para verificación de integridad |

---

## Referencia rápida / Quick reference

```powershell
# Full hardening
.\01-Main.ps1 -Mode Full

# Audit only (no changes)
.\01-Main.ps1 -Mode PretestOnly

# Dry run
.\01-Main.ps1 -Mode Full -WhatIf

# Restore
.\Utils\Backup-Config.ps1 -Restore -BackupPath ".\Backups\backup-XXXXXX" -DeepClean

# First-time setup
.\setup.ps1
```

---

*Basado en CIS Microsoft Windows 10 Stand-alone Benchmark v2.0 — Level 1*  
*Compatible con CIS-CAT Lite | PowerShell 5.1 | Entorno standalone*

