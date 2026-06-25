# ============================================
<#
.SYNOPSIS
    Evalua las politicas de cuenta CIS (seccion 1.1 y 1.2) en Windows 10.

.DESCRIPTION
    Lee con secedit la configuracion real del sistema y verifica el
    cumplimiento de los controles CIS Microsoft Windows 10 Level 1:
      1.1.x - Politicas de contrasena (historial, vigencia, longitud, complejidad).
      1.2.x - Politicas de bloqueo de cuenta (duracion, umbral, ventana de reset).

    Devuelve un array de PSCustomObjects con los campos:
    ControlID, Name, Compliant, CurrentValue, ExpectedValue, Category.
    Estos objetos son consumidos por 01-Main.ps1 para calcular el porcentaje
    de cumplimiento y generar el informe HTML.

.EXAMPLE
    # Ejecutar evaluacion standalone
    .\Test-AccountPolicies.ps1

.EXAMPLE
    # Ver resultados como tabla
    .\Test-AccountPolicies.ps1 | Format-Table -AutoSize

.NOTES
    Controles CIS evaluados : 1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.1.6,
                               1.1.7, 1.2.1, 1.2.2, 1.2.4  (10 controles)
    Mecanismo              : secedit /export a .inf temporal + parsing
    Invocado por           : 01-Main.ps1 como Test-AccountPolicies
#>



# Cargar Write-Log si no esta disponible (ejecucion standalone)
if (-not (Get-Command Write-TestResult -ErrorAction SilentlyContinue)) {
    $writeLogPath = "$PSScriptRoot\..\Utils\Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
    else { Write-Warning "Write-Log.ps1 no encontrado en $writeLogPath" }
}

function Test-AccountPolicies {
    $results = @()
    
    Write-Host "=== INICIANDO TEST DE POLÍTICAS DE CUENTA ===" -ForegroundColor Cyan
    Write-Host "Nota: Leyendo configuración REAL del sistema (secedit)" -ForegroundColor Gray
    
    $tempFile = "$env:TEMP\secedit-account-$([Guid]::NewGuid()).cfg"
    secedit /export /cfg $tempFile /areas SECURITYPOLICY 2>$null
    
    if (-not (Test-Path $tempFile)) {
        Write-Host "ERROR: No se pudo exportar la configuración de seguridad" -ForegroundColor Red
        return $results
    }
    
    $secConfig = Get-Content $tempFile -Raw
    
    function Get-SeceditValue {
        param([string]$Key)
        if ($secConfig -match "(?m)^$Key\s*=\s*(-?\d+)") {
            return [int]$matches[1]
        }
        return $null
    }
    
    # 1.1.1
    $current = Get-SeceditValue "PasswordHistorySize"
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -ge 24)
    Write-TestResult -ControlID "1.1.1" -ControlName "Enforce password history" -Compliant $compliant -CurrentValue $current -ExpectedValue "≥ 24"
    $results += [PSCustomObject]@{ ControlID="1.1.1"; Name="Enforce password history"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="≥24"; Category="Account Policies" }
    
    # 1.1.2
    $current = Get-SeceditValue "MaximumPasswordAge"
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -le 365 -and $current -ne 0)
    Write-TestResult -ControlID "1.1.2" -ControlName "Maximum password age" -Compliant $compliant -CurrentValue $current -ExpectedValue "≤ 365"
    $results += [PSCustomObject]@{ ControlID="1.1.2"; Name="Maximum password age"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="≤365"; Category="Account Policies" }
    
    # 1.1.3
    $current = Get-SeceditValue "MinimumPasswordAge"
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -ge 1)
    Write-TestResult -ControlID "1.1.3" -ControlName "Minimum password age" -Compliant $compliant -CurrentValue $current -ExpectedValue "≥ 1"
    $results += [PSCustomObject]@{ ControlID="1.1.3"; Name="Minimum password age"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="≥1"; Category="Account Policies" }
    
    # 1.1.4
    $current = Get-SeceditValue "MinimumPasswordLength"
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -ge 14)
    Write-TestResult -ControlID "1.1.4" -ControlName "Minimum password length" -Compliant $compliant -CurrentValue $current -ExpectedValue "≥ 14"
    $results += [PSCustomObject]@{ ControlID="1.1.4"; Name="Minimum password length"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="≥14"; Category="Account Policies" }
    
    # 1.1.5
    $current = Get-SeceditValue "PasswordComplexity"
    if ($current -eq $null) { 
        $current = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -EA 0).PasswordComplexity
        if ($current -eq $null) { $current = 0 }
    }
    $compliant = ($current -eq 1)
    Write-TestResult -ControlID "1.1.5" -ControlName "Password complexity" -Compliant $compliant -CurrentValue $(if($current -eq 1){"Activada"}else{"Desactivada"}) -ExpectedValue "Activada"
    $results += [PSCustomObject]@{ ControlID="1.1.5"; Name="Password complexity"; Compliant=$compliant; CurrentValue=$(if($current -eq 1){"Activada"}else{"Desactivada"}); ExpectedValue="Activada"; Category="Account Policies" }
    
    # 1.1.6
    $current = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RelaxMinimumPasswordLengthLimits" -EA 0).RelaxMinimumPasswordLengthLimits
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -eq 1)
    Write-TestResult -ControlID "1.1.6" -ControlName "Relax password limits (CIS v1.11+)" -Compliant $compliant -CurrentValue $(if($current -eq 1){"Activado"}else{"Desactivado"}) -ExpectedValue "Activado"
    $results += [PSCustomObject]@{ ControlID="1.1.6"; Name="Relax password limits (CIS v1.11+)"; Compliant=$compliant; CurrentValue=$(if($current -eq 1){"Activado"}else{"Desactivado"}); ExpectedValue="Activado"; Category="Account Policies" }
    
    # 1.1.7
    $current = Get-SeceditValue "ClearTextPassword"
    if ($current -eq $null) {
        $current = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ClearTextPassword" -EA 0).ClearTextPassword
        if ($current -eq $null) { $current = 0 }
    }
    $compliant = ($current -eq 0 -or $current -eq $null)
    Write-TestResult -ControlID "1.1.7" -ControlName "Store passwords reversible" -Compliant $compliant -CurrentValue $(if($current -eq 1){"Activado"}else{"Desactivado"}) -ExpectedValue "Desactivado"
    $results += [PSCustomObject]@{ ControlID="1.1.7"; Name="Store passwords reversible"; Compliant=$compliant; CurrentValue=$(if($current -eq 1){"Activado"}else{"Desactivado"}); ExpectedValue="Desactivado"; Category="Account Policies" }
    
    # 1.2.1 (con soporte para -1)
    $current = Get-SeceditValue "LockoutDuration"
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -ge 15 -or $current -eq -1)
    $displayValue = if ($current -eq -1) { "Indefinido (-1)" } else { "$current minutos" }
    Write-TestResult -ControlID "1.2.1" -ControlName "Account lockout duration" -Compliant $compliant -CurrentValue $displayValue -ExpectedValue "≥ 15 min o indefinido"
    $results += [PSCustomObject]@{ ControlID="1.2.1"; Name="Account lockout duration"; Compliant=$compliant; CurrentValue=$(if($current -eq -1){"Indefinido"}else{$current}); ExpectedValue="≥15 o -1"; Category="Account Policies" }
    
    # 1.2.2
    $current = Get-SeceditValue "LockoutBadCount"
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -le 5 -and $current -ne 0)
    Write-TestResult -ControlID "1.2.2" -ControlName "Account lockout threshold" -Compliant $compliant -CurrentValue $current -ExpectedValue "≤ 5"
    $results += [PSCustomObject]@{ ControlID="1.2.2"; Name="Account lockout threshold"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="≤5"; Category="Account Policies" }
    
    # 1.2.4
    $current = Get-SeceditValue "ResetLockoutCount"
    if ($current -eq $null) { $current = 0 }
    $compliant = ($current -ge 15)
    Write-TestResult -ControlID "1.2.4" -ControlName "Reset lockout counter" -Compliant $compliant -CurrentValue $current -ExpectedValue "≥ 15 min"
    $results += [PSCustomObject]@{ ControlID="1.2.4"; Name="Reset lockout counter"; Compliant=$compliant; CurrentValue=$current; ExpectedValue="≥15"; Category="Account Policies" }
    
    Remove-Item $tempFile -Force -EA 0
    
    Write-Host "=== FIN TEST POLÍTICAS DE CUENTA ===" -ForegroundColor Cyan
    return $results
}

if ($MyInvocation.InvocationName -ne '.') { Test-AccountPolicies | Format-Table -AutoSize }




















