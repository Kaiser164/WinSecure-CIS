#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aplica los derechos de usuario CIS (seccion 2.2.x) en Windows 10.

.DESCRIPTION
    Configura mediante secedit los derechos de usuario (User Rights Assignment)
    definidos en el benchmark CIS Microsoft Windows 10 Level 1, seccion 2.2:
      2.2.1  - Acceso al Administrador de credenciales: nadie.
      2.2.2  - Acceso a este equipo desde la red: solo Admins + RDP Users.
      2.2.4  - Ajustar cuotas de memoria: Admins + LOCAL SERVICE + NETWORK SERVICE.
      2.2.5  - Permitir inicio de sesion local: Admins + Users.
      2.2.6  - Permitir inicio de sesion por RDP: Admins + RDP Users.
      2.2.7  - Hacer copias de seguridad: solo Administrators.
      2.2.8  - Cambiar hora del sistema: Admins + LOCAL SERVICE.
      2.2.11 - Crear objetos de token: nadie.
      2.2.15 - Depurar programas: solo Administrators.
      2.2.16 - Denegar acceso desde red: solo Guests.
      2.2.19 - Denegar inicio de sesion local: solo Guests.
      2.2.23 - Generar auditorias de seguridad: LOCAL + NETWORK SERVICE.
      2.2.24 - Suplantar a un cliente: Admins + LOCAL + NETWORK + SERVICE.

    El proceso exporta la configuracion actual con secedit, edita el .inf
    y lo reimporta, preservando cualquier otra configuracion existente.

.PARAMETER WhatIf
    Simula la aplicacion sin modificar el sistema. Muestra que cambios se harian.

.EXAMPLE
    # Aplicar todos los User Rights Assignment
    .\Set-UserRights.ps1

.EXAMPLE
    # Simular sin cambios reales
    .\Set-UserRights.ps1 -WhatIf

.NOTES
    Controles CIS cubiertos : 2.2.1, 2.2.2, 2.2.4, 2.2.5, 2.2.6, 2.2.7,
                               2.2.8, 2.2.11, 2.2.15, 2.2.16, 2.2.19,
                               2.2.23, 2.2.24  (13 controles)
    Mecanismo              : secedit /export + edicion .inf + secedit /configure
    Para revertir          : Utils\Backup-Config.ps1 -Restore -BackupPath "..." -DeepClean
    Requiere               : Administrador, PowerShell 5.1, Windows 10
    Invocado por           : 01-Main.ps1 -> Apply\Set-UserRights.ps1
#>

# ============================================================
# IMPORTAR CONFIGURACION Y UTILIDADES
# ============================================================
. "$PSScriptRoot\..\Utils\Write-Log.ps1"

# ============================================
# Apply\Set-UserRights.ps1
# CORRECCIONES: H-05, M-01, L-02
# ============================================

function Set-UserRights {
    param([switch]$WhatIf)
    
    # FIX: inicializar en $script: para que Register-Result (funciÃ³n anidada)
    # y el cÃ³digo padre compartan la misma variable.
    $script:results = @()
    
    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  APLICANDO USER RIGHTS ASSIGNMENT" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    
    function Register-Result {
        param([string]$ControlID, [string]$Operation, [bool]$Success, [string]$Details = "")
        $script:results += [PSCustomObject]@{ ControlID=$ControlID; Operation=$Operation; Success=$Success; Timestamp=Get-Date; Details=$Details }
        Write-ApplyResult -ControlID $ControlID -Operation $Operation -Success $Success -Details $Details
    }
    
    if ($WhatIf) {
        Register-Result -ControlID "2.2.1" -Operation "Set Credential Manager access to No one" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.2" -Operation "Set network access to Admins + RDP Users" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.4" -Operation "Set memory quotas to Admins + LOCAL + NETWORK" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.5" -Operation "Set local logon to Admins + Users" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.6" -Operation "Set RDP logon to Admins + RDP Users" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.7" -Operation "Set backup privilege to Admins only" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.8" -Operation "Set time change to Admins + LOCAL SERVICE" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.11" -Operation "Set token creation to No one" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.15" -Operation "Set debug privilege to Admins only" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.16" -Operation "Set deny network to Guests" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.19" -Operation "Set deny local logon to Guests" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.23" -Operation "Set audit generation to LOCAL + NETWORK" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.2.24" -Operation "Set impersonate to Admins + LOCAL + NETWORK + SERVICE" -Success $true -Details "SIMULATED"
        return $script:results
    }
    
    Write-Host " Esta operacionn modifica la politica de seguridad local" -ForegroundColor Yellow
    
    $tempFile = "$env:TEMP\secedit-$(Get-Date -Format 'yyyyMMdd-HHmmss').cfg"
    secedit /export /cfg $tempFile 2>$null
    
    if (-not (Test-Path $tempFile)) {
        Register-Result -ControlID "GLOBAL" -Operation "Export secedit config" -Success $false -Details "No se pudo exportar"
        return $script:results
    }
    
    # FIX: usar $script:config para que Update-SeceditValue y el write final
    # operen sobre la misma variable (Update-SeceditValue escribe a $script:config).
    $script:config = Get-Content $tempFile
    
    function Update-SeceditValue {
        param([string]$Key, [string]$Value)
        $newConfig = @()
        $found = $false
        foreach ($line in $script:config) {
            if ($line -match "^$Key\s*=") { $newConfig += "$Key = $Value"; $found = $true }
            else { $newConfig += $line }
        }
        if (-not $found) { $newConfig += "$Key = $Value" }
        $script:config = $newConfig
    }
    
    Update-SeceditValue -Key "SeTrustedCredManAccessPrivilege" -Value ""
    Register-Result -ControlID "2.2.1" -Operation "Set Credential Manager access to No one" -Success $true
    
    Update-SeceditValue -Key "SeNetworkLogonRight" -Value "*S-1-5-32-544,*S-1-5-32-555"
    Register-Result -ControlID "2.2.2" -Operation "Set network access to Admins + RDP Users" -Success $true
    
    Update-SeceditValue -Key "SeIncreaseQuotaPrivilege" -Value "*S-1-5-32-544,*S-1-5-19,*S-1-5-20"
    Register-Result -ControlID "2.2.4" -Operation "Set memory quotas" -Success $true
    
    Update-SeceditValue -Key "SeInteractiveLogonRight" -Value "*S-1-5-32-544,*S-1-5-32-545"
    Register-Result -ControlID "2.2.5" -Operation "Set local logon to Admins + Users" -Success $true
    
    Update-SeceditValue -Key "SeRemoteInteractiveLogonRight" -Value "*S-1-5-32-544,*S-1-5-32-555"
    Register-Result -ControlID "2.2.6" -Operation "Set RDP logon to Admins + RDP Users" -Success $true
    
    Update-SeceditValue -Key "SeBackupPrivilege" -Value "*S-1-5-32-544"
    Register-Result -ControlID "2.2.7" -Operation "Set backup privilege to Admins only" -Success $true
    
    Update-SeceditValue -Key "SeSystemtimePrivilege" -Value "*S-1-5-32-544,*S-1-5-19"
    Register-Result -ControlID "2.2.8" -Operation "Set time change" -Success $true
    
    Update-SeceditValue -Key "SeCreateTokenPrivilege" -Value ""
    Register-Result -ControlID "2.2.11" -Operation "Set token creation to No one" -Success $true
    
    Update-SeceditValue -Key "SeDebugPrivilege" -Value "*S-1-5-32-544"
    Register-Result -ControlID "2.2.15" -Operation "Set debug privilege to Admins only" -Success $true
    
    Update-SeceditValue -Key "SeDenyNetworkLogonRight" -Value "*S-1-5-32-546"
    Register-Result -ControlID "2.2.16" -Operation "Set deny network to Guests" -Success $true
    
    Update-SeceditValue -Key "SeDenyInteractiveLogonRight" -Value "*S-1-5-32-546"
    Register-Result -ControlID "2.2.19" -Operation "Set deny local logon to Guests" -Success $true
    
    Update-SeceditValue -Key "SeAuditPrivilege" -Value "*S-1-5-19,*S-1-5-20"
    Register-Result -ControlID "2.2.23" -Operation "Set audit generation" -Success $true
    
    Update-SeceditValue -Key "SeImpersonatePrivilege" -Value "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6"
    Register-Result -ControlID "2.2.24" -Operation "Set impersonate" -Success $true
    
    $newConfigFile = "$env:TEMP\secedit-new-$([Guid]::NewGuid()).cfg"
    # FIX: escribir $script:config (con todos los cambios acumulados),
    # no la variable local $config que nunca fue actualizada.
    $script:config | Set-Content $newConfigFile
    
    try {
        secedit /configure /db C:\Windows\security\local.sdb /cfg $newConfigFile /areas USER_RIGHTS 2>&1
        Register-Result -ControlID "GLOBAL" -Operation "Apply secedit configuration" -Success $true
    } catch {
        Register-Result -ControlID "GLOBAL" -Operation "Apply secedit configuration" -Success $false -Details $_.Exception.Message
    }
    
    Remove-Item $tempFile -Force -EA 0
    Remove-Item $newConfigFile -Force -EA 0
    
    Write-Host "`n✅ User Rights Assignment aplicadas" -ForegroundColor Green
    return $script:results
}

if ($MyInvocation.InvocationName -ne '.') { Set-UserRights }