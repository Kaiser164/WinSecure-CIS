# ============================================
<#
.SYNOPSIS
    Configuracion central y carga de controles CIS del proyecto de hardening.

.DESCRIPTION
    Define todas las rutas globales, colores de consola y la tabla maestra de
    controles CIS Microsoft Windows 10 Level 1 usada por el resto del proyecto.

    Este script NO se ejecuta directamente: es importado con dot-source por
    01-Main.ps1 al inicio de cada ejecucion.

    Variables globales que expone:
      $global:ProjectRoot     — Raiz del proyecto.
      $global:LogPath         — Carpeta de logs.
      $global:ReportsPath     — Carpeta de informes HTML y JSON.
      $global:BackupPath      — Carpeta de backups de configuracion.
      $global:DataPath        — Carpeta con cis-controls.json.
      $global:CISControls     — Hashtable con los 55 controles CIS agrupados
                                por categoria (AccountPolicies, Firewall, etc.).

    Funcion Load-CISControls:
      Intenta cargar los controles desde Data\cis-controls.json.
      Si el archivo no existe, lo crea con los valores por defecto definidos
      en este script (Depth 5 para serializar objetos anidados correctamente).

.NOTES
    Edita $global:ProjectRoot si cambias la ubicacion del proyecto.
    Los directorios Logs, Reports, Backups y Data se crean automaticamente
    si no existen en el momento de la ejecucion.
    Invocado por : 01-Main.ps1 mediante dot-source
#>

# Variables globales

# FIX: ProjectRoot se detecta dinámicamente desde la ubicación real
# de este archivo (00-Config.ps1), sin importar dónde esté el proyecto.
# Funciona aunque muevas la carpeta, la renombres o la copies a otra PC.
#
# $MyInvocation.MyCommand.Path  → ruta completa de este .ps1
# Split-Path -Parent            → carpeta que lo contiene = raíz del proyecto
#
# Si el script fue dot-sourced desde otro directorio (ej: 01-Main.ps1),
# $MyInvocation.MyCommand.Path apunta igualmente a 00-Config.ps1, no al llamante.
$global:ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LogPath = "$global:ProjectRoot\Logs"
$global:ReportsPath = "$global:ProjectRoot\Reports"
$global:BackupPath = "$global:ProjectRoot\Backups"
$global:DataPath = "$global:ProjectRoot\Data"

# Colores para output
$global:Colors = @{
    Info    = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error   = "Red"
    Header  = "Magenta"
}

# Archivo de configuración de controles CIS
$global:CISControlsFile = "$global:DataPath\cis-controls.json"

# ✅ CORREGIDO: Depth 5 para serialización correcta de objetos anidados
$global:CISControls = @{
    "AccountPolicies" = @(
        @{ ControlID = "1.1.1"; Name = "Enforce password history"; ExpectedValue = 24; Category = "Account Policies" }
        @{ ControlID = "1.1.2"; Name = "Maximum password age"; ExpectedValue = 365; Category = "Account Policies" }
        @{ ControlID = "1.1.3"; Name = "Minimum password age"; ExpectedValue = 1; Category = "Account Policies" }
        @{ ControlID = "1.1.4"; Name = "Minimum password length"; ExpectedValue = 14; Category = "Account Policies" }
        @{ ControlID = "1.1.5"; Name = "Password complexity enabled"; ExpectedValue = 1; Category = "Account Policies" }
        @{ ControlID = "1.1.6"; Name = "Relax min password length limits"; ExpectedValue = 1; Category = "Account Policies"; Note = "CIS v1.11+ only" }
        @{ ControlID = "1.1.7"; Name = "Store passwords reversible"; ExpectedValue = 0; Category = "Account Policies" }
        @{ ControlID = "1.2.1"; Name = "Account lockout duration"; ExpectedValue = 15; Category = "Account Policies" }
        @{ ControlID = "1.2.2"; Name = "Account lockout threshold"; ExpectedValue = 5; Category = "Account Policies" }
        @{ ControlID = "1.2.4"; Name = "Reset lockout counter after"; ExpectedValue = 15; Category = "Account Policies" }
    )
    # FIX: Domain profile (9.1.x) excluido — el proyecto esta disenado para
    # equipos standalone sin Active Directory. Test-FirewallSettings tampoco
    # evalua 9.1.x, por lo que incluirlos solo generaba controles fantasma.
    "Firewall" = @(
        @{ ControlID = "9.2.1"; Name = "Firewall - Private profile ON"; ExpectedValue = $true; Category = "Firewall" }
        @{ ControlID = "9.2.2"; Name = "Firewall - Private inbound BLOCK"; ExpectedValue = "Block"; Category = "Firewall" }
        @{ ControlID = "9.3.1"; Name = "Firewall - Public profile ON"; ExpectedValue = $true; Category = "Firewall" }
        @{ ControlID = "9.3.2"; Name = "Firewall - Public inbound BLOCK"; ExpectedValue = "Block"; Category = "Firewall" }
    )
    "SecurityOptions" = @(
        @{ ControlID = "2.3.1.1"; Name = "Block Microsoft accounts"; ExpectedValue = 3; Category = "Security Options" }
        @{ ControlID = "2.3.1.2"; Name = "Guest account disabled"; ExpectedValue = $false; Category = "Security Options" }
        @{ ControlID = "2.3.1.3"; Name = "Limit blank passwords to console"; ExpectedValue = 1; Category = "Security Options" }
        @{ ControlID = "2.3.7.2"; Name = "Don't display last signed-in"; ExpectedValue = 1; Category = "Security Options" }
        @{ ControlID = "2.3.7.4"; Name = "Machine inactivity limit"; ExpectedValue = 900; Category = "Security Options" }
        @{ ControlID = "2.3.10.12"; Name = "Sharing and security model"; ExpectedValue = 0; Category = "Security Options" }
        @{ ControlID = "2.3.17.1"; Name = "UAC for built-in admin"; ExpectedValue = 1; Category = "Security Options" }
        @{ ControlID = "2.3.17.6"; Name = "Run all admins in Admin Approval Mode"; ExpectedValue = 1; Category = "Security Options" }
    )
    "AdminTemplates" = @(
        @{ ControlID = "18.4.1"; Name = "SMB v1 client driver"; ExpectedValue = 4; Category = "Admin Templates" }
        @{ ControlID = "18.4.2"; Name = "SMB v1 server"; ExpectedValue = "Disabled"; Category = "Admin Templates" }
        @{ ControlID = "18.10.8.3"; Name = "Turn off Autoplay"; ExpectedValue = 255; Category = "Admin Templates" }
        @{ ControlID = "18.10.43.10.2"; Name = "Scan all downloaded files"; ExpectedValue = 0; Category = "Admin Templates" }
        @{ ControlID = "18.10.43.10.3"; Name = "Real-time protection"; ExpectedValue = 0; Category = "Admin Templates" }
        @{ ControlID = "18.10.43.10.4"; Name = "Behavior monitoring"; ExpectedValue = 0; Category = "Admin Templates" }
        @{ ControlID = "18.10.43.10.5"; Name = "Script scanning"; ExpectedValue = 0; Category = "Admin Templates" }
        @{ ControlID = "18.10.59.3"; Name = "Disable Cortana"; ExpectedValue = 0; Category = "Admin Templates" }
        @{ ControlID = "18.10.66.2"; Name = "Automatic updates"; ExpectedValue = 0; Category = "Admin Templates" }
        @{ ControlID = "18.10.93.2.1"; Name = "Configure Automatic Updates"; ExpectedValue = 4; Category = "Admin Templates" }
    )
    "UserRights" = @(
        @{ ControlID = "2.2.1"; Name = "Access Credential Manager"; ExpectedValue = ""; Category = "User Rights" }
        @{ ControlID = "2.2.2"; Name = "Access from network"; ExpectedValue = "S-1-5-32-544,S-1-5-32-555"; Category = "User Rights" }
        @{ ControlID = "2.2.4"; Name = "Adjust memory quotas"; ExpectedValue = "S-1-5-32-544,S-1-5-19,S-1-5-20"; Category = "User Rights" }
        @{ ControlID = "2.2.5"; Name = "Allow log on locally"; ExpectedValue = "S-1-5-32-544,S-1-5-32-545"; Category = "User Rights" }
        @{ ControlID = "2.2.6"; Name = "Allow log on through RDP"; ExpectedValue = "S-1-5-32-544,S-1-5-32-555"; Category = "User Rights" }
        @{ ControlID = "2.2.7"; Name = "Backup files"; ExpectedValue = "S-1-5-32-544"; Category = "User Rights" }
        @{ ControlID = "2.2.8"; Name = "Change system time"; ExpectedValue = "S-1-5-32-544,S-1-5-19"; Category = "User Rights" }
        @{ ControlID = "2.2.11"; Name = "Create token object"; ExpectedValue = ""; Category = "User Rights" }
        @{ ControlID = "2.2.15"; Name = "Debug programs"; ExpectedValue = "S-1-5-32-544"; Category = "User Rights" }
        @{ ControlID = "2.2.16"; Name = "Deny access from network"; ExpectedValue = "S-1-5-32-546"; Category = "User Rights" }
        @{ ControlID = "2.2.19"; Name = "Deny log on locally"; ExpectedValue = "S-1-5-32-546"; Category = "User Rights" }
        @{ ControlID = "2.2.23"; Name = "Generate security audits"; ExpectedValue = "S-1-5-19,S-1-5-20"; Category = "User Rights" }
        @{ ControlID = "2.2.24"; Name = "Impersonate a client"; ExpectedValue = "S-1-5-32-544,S-1-5-19,S-1-5-20,S-1-5-6"; Category = "User Rights" }
    )
    "AuditPolicy" = @(
        @{ ControlID = "17.1.1"; Name = "Audit Credential Validation"; ExpectedValue = "Success and Failure"; Category = "Audit Policy" }
        @{ ControlID = "17.2.2"; Name = "Audit Security Group Management"; ExpectedValue = "Success"; Category = "Audit Policy" }
        @{ ControlID = "17.2.3"; Name = "Audit User Account Management"; ExpectedValue = "Success and Failure"; Category = "Audit Policy" }
        @{ ControlID = "17.3.2"; Name = "Audit Process Creation"; ExpectedValue = "Success"; Category = "Audit Policy" }
        @{ ControlID = "17.5.1"; Name = "Audit Account Lockout"; ExpectedValue = "Failure"; Category = "Audit Policy" }
        @{ ControlID = "17.5.4"; Name = "Audit Logon"; ExpectedValue = "Success and Failure"; Category = "Audit Policy" }
        @{ ControlID = "17.5.5"; Name = "Audit Other Logon/Logoff Events"; ExpectedValue = "Success and Failure"; Category = "Audit Policy" }
        @{ ControlID = "17.6.2"; Name = "Audit File Share"; ExpectedValue = "Success and Failure"; Category = "Audit Policy" }
        @{ ControlID = "17.7.1"; Name = "Audit Audit Policy Change"; ExpectedValue = "Success"; Category = "Audit Policy" }
        @{ ControlID = "17.9.5"; Name = "Audit System Integrity"; ExpectedValue = "Success and Failure"; Category = "Audit Policy" }
    )
}

# ✅ CORREGIDO: Función Load-CISControls con retorno lógico correcto
function Load-CISControls {
    param([string]$JsonPath = $global:CISControlsFile)
    
    if (Test-Path $JsonPath) {
        try {
            # ✅ Depth 5 para leer objetos anidados correctamente
            $loadedControls = Get-Content $JsonPath -Raw | ConvertFrom-Json
            $global:CISControls = $loadedControls
            Write-Host "✅ Controles CIS cargados desde: $JsonPath" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "⚠️ Error cargando JSON, usando controles por defecto: $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    } else {
        Write-Host "ℹ️ No se encontró $JsonPath, creando archivo con controles por defecto" -ForegroundColor Gray
        try {
            # ✅ Depth 5 para serialización correcta
            $global:CISControls | ConvertTo-Json -Depth 5 | Set-Content $JsonPath -Force
            Write-Host "📄 Archivo de ejemplo creado en: $JsonPath" -ForegroundColor Green
            return $true  # ✅ El archivo se creó exitosamente
        } catch {
            Write-Host "⚠️ Error creando archivo JSON: $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    }
}

# Crear directorios necesarios
$directories = @($global:LogPath, $global:ReportsPath, $global:BackupPath, $global:DataPath)
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Cargar controles CIS
$loadResult = Load-CISControls
if (-not $loadResult) {
    Write-Host "⚠️ Usando controles CIS por defecto (sin persistencia)" -ForegroundColor Yellow
}

Write-Host "✅ Configuración cargada - Proyecto: $global:ProjectRoot" -ForegroundColor Green
Write-Host "📊 Controles CIS disponibles: $($global:CISControls.Count) categorías" -ForegroundColor Cyan

$env:HardeningProjectRoot = $global:ProjectRoot