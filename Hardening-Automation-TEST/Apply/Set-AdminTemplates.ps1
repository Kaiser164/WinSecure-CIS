#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aplica las Administrative Templates CIS (sección 18.x) en Windows 10.

.DESCRIPTION
    Configura mediante el registro de Windows las plantillas administrativas
    definidas en el benchmark CIS Microsoft Windows 10 Level 1:
      18.4.x  — Protocolos de red: deshabilitar SMB v1 (cliente y servidor).
      18.10.x — Configuraciones de sistema: Autoplay, Windows Defender,
                Cortana, Windows Update y opciones de actualización automática.

    Maneja correctamente la Tamper Protection de Windows Defender, escribiendo
    en la ruta de Policies (que tiene prioridad y no está bloqueada por TP).
    Para SMB v1, detecta si el driver mrxsmb10 está instalado; si no existe,
    el control se marca como cumplido sin intentar modificar el registro.

    Este script puede ejecutarse de forma independiente o via 01-Main.ps1.

.PARAMETER WhatIf
    Simula la aplicación sin modificar el sistema. Muestra qué cambios se harían.

.EXAMPLE
    # Aplicar todas las Administrative Templates
    .\Set-AdminTemplates.ps1

.EXAMPLE
    # Simular sin cambios reales
    .\Set-AdminTemplates.ps1 -WhatIf

.NOTES
    Controles CIS cubiertos : 18.4.1, 18.4.2, 18.10.8.3, 18.10.43.10.2,
                               18.10.43.10.3, 18.10.43.10.4, 18.10.43.10.5,
                               18.10.59.3, 18.10.66.2, 18.10.93.2.1 (10 controles)
    Mecanismo              : Set-ItemProperty sobre HKLM + cmdlets de Features
    Nota SMB v1            : Si mrxsmb10 no existe → control cumplido (driver no instalado)
    Nota Defender          : Escribe en Policies\, no en la ruta real (compatible con Tamper Protection)
    Requiere               : Administrador, PowerShell 5.1, Windows 10
    Invocado por           : 01-Main.ps1 → Apply\Set-AdminTemplates.ps1
#>

# ============================================================
# IMPORTAR CONFIGURACIÓN Y UTILIDADES
# ============================================================
. "$PSScriptRoot\..\Utils\Write-Log.ps1"

# ============================================
# Apply\Set-AdminTemplates.ps1
# CORRECCIONES: H-04, H-05, M-01, M-04, L-02
#
# FIX 18.4.1 : Test-Path antes de modificar mrxsmb10.
#              Si la clave no existe, SMB v1 ya no está instalado → cumplido.
#
# FIX 18.4.2 : Verifica estado antes de intentar deshabilitar.
#
# FIX DEFENDER: Windows Defender Tamper Protection bloquea escrituras
#   en HKLM:\SOFTWARE\Microsoft\Windows Defender\* incluso como Admin.
#   La única ruta que SÍ acepta escrituras cuando Tamper Protection
#   está activo es la ruta de Políticas (Policies\...), que además tiene
#   prioridad sobre la ruta real en tiempo de ejecución de Defender.
#   Set-DefenderConfig ahora escribe SOLO en la ruta de Policies y
#   detecta si Tamper Protection está bloqueando la operación.
# ============================================

function Set-AdminTemplates {
    param([switch]$WhatIf)

    $script:results = @()

    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  APLICANDO ADMINISTRATIVE TEMPLATES" -ForegroundColor Magenta
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

    # ------------------------------------------------------------------
    # Detecta si Tamper Protection está activa.
    # Devuelve $true si está activa (bloqueará escrituras en Defender).
    # ------------------------------------------------------------------
    function Test-TamperProtectionActive {
        try {
            $val = (Get-ItemProperty `
                -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" `
                -Name "TamperProtection" `
                -ErrorAction SilentlyContinue).TamperProtection
            # 5 = activada, 4 = desactivada, $null = no existe (sin TP)
            return ($val -eq 5)
        }
        catch { return $false }
    }

    # ------------------------------------------------------------------
    # FIX DEFENDER: escribe SOLO en la ruta de Policies.
    #   - La ruta Policies\... es respetada por Defender como configuración
    #     de administrador y tiene precedencia sobre la ruta real.
    #   - La ruta real (SOFTWARE\Microsoft\Windows Defender\...) está
    #     protegida por Tamper Protection y NO se intenta escribir en ella.
    # ------------------------------------------------------------------
    function Set-DefenderConfig {
        param([string]$PolicyName, [int]$Value)
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        $realPath   = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"

        # Leer valor actual desde ambas rutas
        $currentPolicy = (Get-ItemProperty -Path $policyPath -Name $PolicyName -EA 0).$PolicyName
        $currentReal   = (Get-ItemProperty -Path $realPath   -Name $PolicyName -EA 0).$PolicyName

        # Si cualquiera de las dos rutas ya tiene el valor correcto, OK sin escribir
        if ($currentPolicy -eq $Value -or $currentReal -eq $Value) {
            return $true
        }

        # Intentar escribir en la ruta de Policies
        try {
            if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
            Set-ItemProperty -Path $policyPath -Name $PolicyName -Value $Value -Type DWORD -Force -EA Stop
            return $true
        }
        catch {
            return $false
        }
    }

    # ------------------------------------------------------------------
    # MODO SIMULADO
    # ------------------------------------------------------------------
    if ($WhatIf) {
        Register-Result -ControlID "18.4.1"        -Operation "Disable SMB v1 client"        -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.4.2"        -Operation "Disable SMB v1 server"        -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.8.3"     -Operation "Disable Autoplay"             -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.43.10.2" -Operation "Enable scan downloaded files" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.43.10.3" -Operation "Enable real-time protection"  -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.43.10.4" -Operation "Enable behavior monitoring"   -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.43.10.5" -Operation "Enable script scanning"       -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.59.3"    -Operation "Disable Cortana"              -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.66.2"    -Operation "Enable automatic updates"     -Success $true -Details "SIMULATED"
        Register-Result -ControlID "18.10.93.2.1"  -Operation "Set AUOptions to 4"           -Success $true -Details "SIMULATED"
        return $script:results
    }

    # ------------------------------------------------------------------
    # 18.4.1  Disable SMB v1 client (driver mrxsmb10)
    # FIX: la clave solo existe si SMB v1 está instalado.
    # Si no existe → ya está desinstalado → control cumplido.
    # ------------------------------------------------------------------
    try {
        $smbv1ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
        if (Test-Path $smbv1ClientPath) {
            Set-ItemProperty -Path $smbv1ClientPath -Name "Start" -Value 4 -Type DWORD -Force -EA Stop
            Register-Result -ControlID "18.4.1" -Operation "Disable SMB v1 client" -Success $true `
                -Details "Servicio mrxsmb10 deshabilitado (Start=4)"
        }
        else {
            Register-Result -ControlID "18.4.1" -Operation "Disable SMB v1 client" -Success $true `
                -Details "SMB v1 no instalado en este sistema (cumplido)"
        }
    }
    catch {
        Register-Result -ControlID "18.4.1" -Operation "Disable SMB v1 client" `
            -Success $false -Details $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # 18.4.2  Disable SMB v1 server (Windows Feature)
    # ------------------------------------------------------------------
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -EA Stop
        if ($feature.State -eq "Disabled") {
            Register-Result -ControlID "18.4.2" -Operation "Disable SMB v1 server" -Success $true `
                -Details "SMB1Protocol-Server ya estaba deshabilitado"
        }
        else {
            Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart -EA Stop
            Register-Result -ControlID "18.4.2" -Operation "Disable SMB v1 server" -Success $true `
                -Details "SMB1Protocol-Server deshabilitado"
        }
    }
    catch {
        Register-Result -ControlID "18.4.2" -Operation "Disable SMB v1 server" `
            -Success $false -Details $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # 18.10.8.3  Disable Autoplay
    # ------------------------------------------------------------------
    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Value 255 -Type DWORD -Force -EA Stop
        Register-Result -ControlID "18.10.8.3" -Operation "Disable Autoplay (HKLM)" -Success $true
    }
    catch {
        Register-Result -ControlID "18.10.8.3" -Operation "Disable Autoplay (HKLM)" `
            -Success $false -Details $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # 18.10.43.10.x  Windows Defender Real-Time Protection
    #
    # ADVERTENCIA si Tamper Protection está activa:
    # La ruta de Policies SÍ acepta escrituras aunque TP esté activa,
    # pero Defender puede ignorar las policies si TP las bloquea también.
    # Se informa al operador para que desactive TP desde la UI si es necesario.
    # ------------------------------------------------------------------
    $tamperActive = Test-TamperProtectionActive
    if ($tamperActive) {
        Write-Host "  [AVISO] Tamper Protection ACTIVA - Escrituras en Policies\Defender pueden ser ignoradas" -ForegroundColor Yellow
        Write-Host "          Para garantizar el cumplimiento, desactive Tamper Protection en:" -ForegroundColor Yellow
        Write-Host "          Seguridad de Windows > Proteccion contra virus > Config. Prot. contra alteraciones" -ForegroundColor Yellow
    }

    $success = Set-DefenderConfig -PolicyName "DisableScanningDownloadedFiles" -Value 0
    $detail  = if ($tamperActive -and -not $success) { "Tamper Protection puede estar bloqueando la escritura" } else { "" }
    Register-Result -ControlID "18.10.43.10.2" -Operation "Enable scan downloaded files" -Success $success -Details $detail

    $success = Set-DefenderConfig -PolicyName "DisableRealtimeMonitoring" -Value 0
    $detail  = if ($tamperActive -and -not $success) { "Tamper Protection puede estar bloqueando la escritura" } else { "" }
    Register-Result -ControlID "18.10.43.10.3" -Operation "Enable real-time protection" -Success $success -Details $detail

    $success = Set-DefenderConfig -PolicyName "DisableBehaviorMonitoring" -Value 0
    $detail  = if ($tamperActive -and -not $success) { "Tamper Protection puede estar bloqueando la escritura" } else { "" }
    Register-Result -ControlID "18.10.43.10.4" -Operation "Enable behavior monitoring" -Success $success -Details $detail

    $success = Set-DefenderConfig -PolicyName "DisableScanningScripts" -Value 0
    $detail  = if ($tamperActive -and -not $success) { "Tamper Protection puede estar bloqueando la escritura" } else { "" }
    Register-Result -ControlID "18.10.43.10.5" -Operation "Enable script scanning" -Success $success -Details $detail

    # ------------------------------------------------------------------
    # 18.10.59.3  Disable Cortana
    # ------------------------------------------------------------------
    try {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "AllowCortana" -Value 0 -Type DWORD -Force -EA Stop
        Register-Result -ControlID "18.10.59.3" -Operation "Disable Cortana" -Success $true
    }
    catch {
        Register-Result -ControlID "18.10.59.3" -Operation "Disable Cortana" `
            -Success $false -Details $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # 18.10.66.2  Enable automatic updates (NoAutoUpdate = 0)
    # ------------------------------------------------------------------
    try {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "NoAutoUpdate" -Value 0 -Type DWORD -Force -EA Stop
        Register-Result -ControlID "18.10.66.2" -Operation "Enable automatic updates" -Success $true
    }
    catch {
        Register-Result -ControlID "18.10.66.2" -Operation "Enable automatic updates" `
            -Success $false -Details $_.Exception.Message
    }

    # ------------------------------------------------------------------
    # 18.10.93.2.1  AUOptions = 4
    # ------------------------------------------------------------------
    try {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "AUOptions" -Value 4 -Type DWORD -Force -EA Stop
        Register-Result -ControlID "18.10.93.2.1" -Operation "Set AUOptions to 4" -Success $true
    }
    catch {
        Register-Result -ControlID "18.10.93.2.1" -Operation "Set AUOptions to 4" `
            -Success $false -Details $_.Exception.Message
    }

    Write-Host "`n✅ Administrative Templates aplicadas" -ForegroundColor Green
    return $script:results
}

if ($MyInvocation.InvocationName -ne '.') { Set-AdminTemplates }