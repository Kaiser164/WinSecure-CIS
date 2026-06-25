# ============================================
<#
.SYNOPSIS
    Evalua las Administrative Templates CIS (seccion 18.x) en Windows 10.

.DESCRIPTION
    Lee el registro de Windows y verifica el cumplimiento de los controles
    CIS Microsoft Windows 10 Level 1, seccion 18:
      18.4.x  - SMB v1 (cliente y servidor).
      18.10.x - Autoplay, Windows Defender, Cortana, Windows Update.

    FIX 18.4.1: Si la clave mrxsmb10 no existe en el registro (driver no
    instalado), el control se marca como cumplido. CIS acepta la ausencia
    del driver como equivalente a tenerlo deshabilitado.

    Para Windows Defender verifica tanto la ruta de Policies (prioridad
    sobre Tamper Protection) como la ruta real del sistema.

.EXAMPLE
    # Ejecutar evaluacion standalone
    .\Test-AdminTemplates.ps1

.EXAMPLE
    # Ver resultados como tabla
    .\Test-AdminTemplates.ps1 | Format-Table -AutoSize

.NOTES
    Controles CIS evaluados : 18.4.1, 18.4.2, 18.10.8.3, 18.10.43.10.2,
                               18.10.43.10.3, 18.10.43.10.4, 18.10.43.10.5,
                               18.10.59.3, 18.10.66.2, 18.10.93.2.1 (10 controles)
    Fix aplicado           : 18.4.1 usa Test-Path antes de leer mrxsmb10
    Invocado por           : 01-Main.ps1 como Test-AdminTemplates
#>

# Cargar Write-Log si no esta disponible (ejecucion standalone)
if (-not (Get-Command Write-TestResult -ErrorAction SilentlyContinue)) {
    $writeLogPath = "$PSScriptRoot\..\Utils\Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
    else { Write-Warning "Write-Log.ps1 no encontrado en $writeLogPath" }
}

function Test-AdminTemplates {
    $results = @()
    
    Write-Host "=== INICIANDO TEST DE ADMINISTRATIVE TEMPLATES ===" -ForegroundColor Cyan
    
    function Get-DefenderConfig {
        param([string]$PolicyName, [int]$DefaultValue = 0)
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        $realPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        $policyValue = (Get-ItemProperty -Path $policyPath -Name $PolicyName -EA 0).$PolicyName
        $realValue = (Get-ItemProperty -Path $realPath -Name $PolicyName -EA 0).$PolicyName
        if ($realValue -ne $null) { return @{ Value = $realValue; Source = "Real" } }
        if ($policyValue -ne $null) { return @{ Value = $policyValue; Source = "Policy" } }
        return @{ Value = $DefaultValue; Source = "Default" }
    }
    
    # 18.4.1 - FIX: Si la clave mrxsmb10 no existe, SMB v1 no está instalado → cumplido
    $smbv1ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
    if (-not (Test-Path $smbv1ClientPath)) {
        $compliant    = $true
        $current      = 4
        $displayValue = "Disabled (not installed)"
    } else {
        $current = (Get-ItemProperty $smbv1ClientPath -Name "Start" -EA 0).Start
        $compliant    = ($current -eq 4)
        $displayValue = switch ($current) { 1{"Enabled"} 2{"Manual"} 3{"Auto"} 4{"Disabled"} default{"Not found"} }
    }
    Write-TestResult -ControlID "18.4.1" -ControlName "SMB v1 client driver" -Compliant $compliant -CurrentValue $displayValue -ExpectedValue "Disabled"
    $results += [PSCustomObject]@{ ControlID="18.4.1"; Name="SMB v1 client driver"; Compliant=$compliant; CurrentValue=$displayValue; ExpectedValue="Disabled"; Category="Admin Templates" }
    
    # 18.4.2
    try { $feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -EA 0; $current = $feature.State; $compliant = ($current -eq "Disabled") }
    catch { $current = "Not available"; $compliant = $true }
    Write-TestResult -ControlID "18.4.2" -ControlName "SMB v1 server" -Compliant $compliant -CurrentValue $current -ExpectedValue "Disabled"
    $results += [PSCustomObject]@{ ControlID="18.4.2"; Name="SMB v1 server"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="Disabled"; Category="Admin Templates" }
    
    # 18.10.8.3
    $hkLmValue = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -EA 0).NoDriveTypeAutoRun
    $compliant = ($hkLmValue -eq 255)
    $currentValue = if ($hkLmValue -ne $null) { $hkLmValue } else { "No configurado" }
    Write-TestResult -ControlID "18.10.8.3" -ControlName "Turn off Autoplay" -Compliant $compliant -CurrentValue $currentValue -ExpectedValue "255 (HKLM)"
    $results += [PSCustomObject]@{ ControlID="18.10.8.3"; Name="Turn off Autoplay"; Compliant=$compliant; CurrentValue=$currentValue; ExpectedValue="255"; Category="Admin Templates" }
    
    # 18.10.43.10.2
    $config = Get-DefenderConfig -PolicyName "DisableScanningDownloadedFiles"
    $compliant = ($config.Value -eq 0)
    Write-TestResult -ControlID "18.10.43.10.2" -ControlName "Scan downloaded files" -Compliant $compliant -CurrentValue $(if($config.Value -eq 0){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled" -Details "Fuente: $($config.Source)"
    $results += [PSCustomObject]@{ ControlID="18.10.43.10.2"; Name="Scan downloaded files"; Compliant=$compliant; CurrentValue=$(if($config.Value -eq 0){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Admin Templates" }
    
    # 18.10.43.10.3
    $config = Get-DefenderConfig -PolicyName "DisableRealtimeMonitoring"
    $compliant = ($config.Value -eq 0)
    Write-TestResult -ControlID "18.10.43.10.3" -ControlName "Real-time protection" -Compliant $compliant -CurrentValue $(if($config.Value -eq 0){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled"
    $results += [PSCustomObject]@{ ControlID="18.10.43.10.3"; Name="Real-time protection"; Compliant=$compliant; CurrentValue=$(if($config.Value -eq 0){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Admin Templates" }
    
    # 18.10.43.10.4
    $config = Get-DefenderConfig -PolicyName "DisableBehaviorMonitoring"
    $compliant = ($config.Value -eq 0)
    Write-TestResult -ControlID "18.10.43.10.4" -ControlName "Behavior monitoring" -Compliant $compliant -CurrentValue $(if($config.Value -eq 0){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled"
    $results += [PSCustomObject]@{ ControlID="18.10.43.10.4"; Name="Behavior monitoring"; Compliant=$compliant; CurrentValue=$(if($config.Value -eq 0){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Admin Templates" }
    
    # 18.10.43.10.5
    $config = Get-DefenderConfig -PolicyName "DisableScanningScripts"
    $compliant = ($config.Value -eq 0)
    Write-TestResult -ControlID "18.10.43.10.5" -ControlName "Script scanning" -Compliant $compliant -CurrentValue $(if($config.Value -eq 0){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled"
    $results += [PSCustomObject]@{ ControlID="18.10.43.10.5"; Name="Script scanning"; Compliant=$compliant; CurrentValue=$(if($config.Value -eq 0){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Admin Templates" }
    
    # 18.10.59.3
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -EA 0).AllowCortana
    $compliant = ($current -eq 0)
    Write-TestResult -ControlID "18.10.59.3" -ControlName "Disable Cortana" -Compliant $compliant -CurrentValue $(if($current -eq 0){"Disabled"}else{"Enabled/Not configured"}) -ExpectedValue "Disabled"
    $results += [PSCustomObject]@{ ControlID="18.10.59.3"; Name="Disable Cortana"; Compliant=$compliant; CurrentValue=$(if($current -eq 0){"Disabled"}else{"Enabled"}); ExpectedValue="Disabled"; Category="Admin Templates" }
    
    # 18.10.66.2
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -EA 0).NoAutoUpdate
    $compliant = ($current -eq 0)
    Write-TestResult -ControlID "18.10.66.2" -ControlName "Automatic updates" -Compliant $compliant -CurrentValue $(if($current -eq 0){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled"
    $results += [PSCustomObject]@{ ControlID="18.10.66.2"; Name="Automatic updates"; Compliant=$compliant; CurrentValue=$(if($current -eq 0){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Admin Templates" }
    
    # 18.10.93.2.1
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -EA 0).AUOptions
    $compliant = ($current -eq 4)
    Write-TestResult -ControlID "18.10.93.2.1" -ControlName "Configure AU" -Compliant $compliant -CurrentValue $(switch($current){2{"Notify"}3{"Download"}4{"Schedule"}default{"Not set"}}) -ExpectedValue "Auto schedule (4)"
    $results += [PSCustomObject]@{ ControlID="18.10.93.2.1"; Name="Configure AU"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="4"; Category="Admin Templates" }
    
    Write-Host "=== FIN TEST ADMINISTRATIVE TEMPLATES ===" -ForegroundColor Cyan
    return $results
}

if ($MyInvocation.InvocationName -ne '.') { Test-AdminTemplates | Format-Table -AutoSize }