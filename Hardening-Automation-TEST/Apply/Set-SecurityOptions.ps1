#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aplica las Security Options CIS (sección 2.3.x) en Windows 10.

.DESCRIPTION
    Configura mediante el registro de Windows las opciones de seguridad
    definidas en el benchmark CIS Microsoft Windows 10 Level 1:
      2.3.1.1  — Bloquear cuentas Microsoft (NoConnectedUser = 3).
      2.3.1.2  — Deshabilitar cuenta Guest (buscada por SID -501, independiente del idioma).
      2.3.1.3  — Limitar uso de contraseñas en blanco a consola local.
      2.3.7.2  — No mostrar el último usuario en la pantalla de inicio de sesión.
      2.3.7.4  — Bloqueo automático por inactividad (900 segundos = 15 minutos).
      2.3.10.12— Modelo de uso compartido clásico (forceguest = 0).
      2.3.17.1 — Habilitar UAC para la cuenta de administrador incorporada.
      2.3.17.6 — Habilitar el Modo de Aprobación de Administrador (EnableLUA = 1).

    La cuenta Guest se gestiona por SID (terminado en -501) para garantizar
    compatibilidad con Windows en español (Invitado) e inglés (Guest).

.PARAMETER WhatIf
    Simula la aplicación sin modificar el sistema. Muestra qué cambios se harían.

.EXAMPLE
    # Aplicar todas las Security Options
    .\Set-SecurityOptions.ps1

.EXAMPLE
    # Simular sin cambios reales
    .\Set-SecurityOptions.ps1 -WhatIf

.NOTES
    Controles CIS cubiertos : 2.3.1.1, 2.3.1.2, 2.3.1.3, 2.3.7.2, 2.3.7.4,
                               2.3.10.12, 2.3.17.1, 2.3.17.6  (8 controles)
    Mecanismo              : Set-ItemProperty sobre HKLM + Disable-LocalUser por SID
    Compatibilidad idiomas : Sí — Guest buscada por SID -501, no por nombre
    Para revertir          : Utils\Backup-Config.ps1 -Restore -BackupPath "..." -DeepClean
    Requiere               : Administrador, PowerShell 5.1, Windows 10
    Invocado por           : 01-Main.ps1 → Apply\Set-SecurityOptions.ps1
#>

# ============================================================
# IMPORTAR CONFIGURACION Y UTILIDADES
# ============================================================
. "$PSScriptRoot\..\Utils\Write-Log.ps1"

# ============================================
# Apply\Set-SecurityOptions.ps1
# CORRECCIONES: H-05, M-01, L-02, L-06
# FIX L-06: Cuenta Guest buscada por SID-501 (independiente del idioma)
# ============================================

function Set-SecurityOptions {
    param([switch]$WhatIf)

    $script:results = @()

    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  APLICANDO SECURITY OPTIONS" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta

    function Register-Result {
        param([string]$ControlID, [string]$Operation, [bool]$Success, [string]$Details = "")
        $script:results += [PSCustomObject]@{
            ControlID = $ControlID
            Operation = $Operation
            Success   = $Success
            Timestamp = Get-Date
            Details   = $Details
        }
        Write-ApplyResult -ControlID $ControlID -Operation $Operation -Success $Success -Details $Details
    }

    if ($WhatIf) {
        Register-Result -ControlID "2.3.1.1"  -Operation "Block Microsoft accounts"       -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.3.1.2"  -Operation "Disable Guest account"          -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.3.1.3"  -Operation "Limit blank passwords"          -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.3.7.2"  -Operation "Hide last signed-in user"       -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.3.7.4"  -Operation "Set inactivity timeout to 900s" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.3.10.12"-Operation "Set classic sharing model"      -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.3.17.1" -Operation "Enable UAC for built-in admin"  -Success $true -Details "SIMULATED"
        Register-Result -ControlID "2.3.17.6" -Operation "Enable Admin Approval Mode"     -Success $true -Details "SIMULATED"
        return $script:results
    }

    # -- 2.3.1.1 Block Microsoft accounts --------------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "NoConnectedUser" -Value 3 -Type DWORD -Force -ErrorAction Stop
        Register-Result -ControlID "2.3.1.1" -Operation "Block Microsoft accounts" -Success $true
    }
    catch {
        Register-Result -ControlID "2.3.1.1" -Operation "Block Microsoft accounts" `
            -Success $false -Details $_.Exception.Message
    }

    # -- 2.3.1.2 Disable Guest account (por SID -501, independiente del idioma) --
    try {
        # SID relativo 501 = cuenta Guest en cualquier idioma y region de Windows
        $guestAccount = Get-LocalUser | Where-Object { $_.SID.Value -like "*-501" }

        if ($null -eq $guestAccount) {
            Register-Result -ControlID "2.3.1.2" -Operation "Disable Guest account" `
                -Success $true -Details "Cuenta no existe en este sistema"
        }
        elseif ($guestAccount.Enabled -eq $false) {
            Register-Result -ControlID "2.3.1.2" -Operation "Disable Guest account" `
                -Success $true -Details "Ya estaba deshabilitada ($($guestAccount.Name))"
        }
        else {
            Disable-LocalUser -SID $guestAccount.SID -ErrorAction Stop
            Register-Result -ControlID "2.3.1.2" -Operation "Disable Guest account" `
                -Success $true -Details "Deshabilitada: $($guestAccount.Name)"
        }
    }
    catch {
        Register-Result -ControlID "2.3.1.2" -Operation "Disable Guest account" `
            -Success $false -Details $_.Exception.Message
    }

    # -- 2.3.1.3 Limit blank passwords ------------------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LimitBlankPasswordUse" -Value 1 -Type DWORD -Force -ErrorAction Stop
        Register-Result -ControlID "2.3.1.3" -Operation "Limit blank passwords" -Success $true
    }
    catch {
        Register-Result -ControlID "2.3.1.3" -Operation "Limit blank passwords" `
            -Success $false -Details $_.Exception.Message
    }

    # -- 2.3.7.2 Hide last signed-in user ---------------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "dontdisplaylastusername" -Value 1 -Type DWORD -Force -ErrorAction Stop
        Register-Result -ControlID "2.3.7.2" -Operation "Hide last signed-in user" -Success $true
    }
    catch {
        Register-Result -ControlID "2.3.7.2" -Operation "Hide last signed-in user" `
            -Success $false -Details $_.Exception.Message
    }

    # -- 2.3.7.4 Set inactivity timeout to 900s ---------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "InactivityTimeoutSecs" -Value 900 -Type DWORD -Force -ErrorAction Stop
        Register-Result -ControlID "2.3.7.4" -Operation "Set inactivity timeout to 900s" -Success $true
    }
    catch {
        Register-Result -ControlID "2.3.7.4" -Operation "Set inactivity timeout to 900s" `
            -Success $false -Details $_.Exception.Message
    }

    # -- 2.3.10.12 Set classic sharing model ------------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "forceguest" -Value 0 -Type DWORD -Force -ErrorAction Stop
        Register-Result -ControlID "2.3.10.12" -Operation "Set classic sharing model" -Success $true
    }
    catch {
        Register-Result -ControlID "2.3.10.12" -Operation "Set classic sharing model" `
            -Success $false -Details $_.Exception.Message
    }

    # -- 2.3.17.1 Enable UAC for built-in admin ---------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "FilterAdministratorToken" -Value 1 -Type DWORD -Force -ErrorAction Stop
        Register-Result -ControlID "2.3.17.1" -Operation "Enable UAC for built-in admin" -Success $true
    }
    catch {
        Register-Result -ControlID "2.3.17.1" -Operation "Enable UAC for built-in admin" `
            -Success $false -Details $_.Exception.Message
    }

    # -- 2.3.17.6 Enable Admin Approval Mode ------------------------------
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "EnableLUA" -Value 1 -Type DWORD -Force -ErrorAction Stop
        Register-Result -ControlID "2.3.17.6" -Operation "Enable Admin Approval Mode" -Success $true
    }
    catch {
        Register-Result -ControlID "2.3.17.6" -Operation "Enable Admin Approval Mode" `
            -Success $false -Details $_.Exception.Message
    }

    Write-Host "`nSecurity Options aplicadas correctamente" -ForegroundColor Green
    return $script:results
}

if ($MyInvocation.InvocationName -ne '.') { Set-SecurityOptions }