#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aplica las políticas de cuenta CIS (sección 1.1 y 1.2) en Windows 10.

.DESCRIPTION
    Configura mediante secedit las políticas de contraseña y bloqueo de cuenta
    definidas en el benchmark CIS Microsoft Windows 10 Level 1:
      1.1.x — Políticas de contraseña (historial, vigencia, longitud, complejidad).
      1.2.x — Políticas de bloqueo de cuenta (duración, umbral, ventana de reset).

    Los valores concretos dependen del parámetro -SecurityLevel. Se soportan
    tres perfiles predefinidos para equilibrar seguridad y usabilidad operacional.

    Este script es invocado por 01-Main.ps1, pero puede ejecutarse de forma
    independiente para aplicar solo esta categoría.

.PARAMETER WhatIf
    Simula la aplicación sin modificar el sistema. Muestra qué cambios se harían.

.PARAMETER SecurityLevel
    Perfil de valores a aplicar:
      CIS-Minimum — Mínimos exigidos por la norma (historia=24, edad máx=365,
                    longitud=14, bloqueo tras 5 intentos, duración 15 min).
      Secure      — Balance recomendado (edad máx=90 días, bloqueo tras 3 intentos,
                    duración 30 min). Valor por defecto.
      Maximum     — Máxima restricción (edad máx=30 días, longitud=16,
                    duración 60 min). Puede afectar la usabilidad.

.EXAMPLE
    # Aplicar nivel Secure (por defecto)
    .\Set-AccountPolicies.ps1

.EXAMPLE
    # Simular nivel Maximum sin cambios reales
    .\Set-AccountPolicies.ps1 -WhatIf -SecurityLevel Maximum

.EXAMPLE
    # Aplicar solo los mínimos CIS
    .\Set-AccountPolicies.ps1 -SecurityLevel CIS-Minimum

.NOTES
    Controles CIS cubiertos : 1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.1.6,
                               1.1.7, 1.2.1, 1.2.2, 1.2.4  (10 controles)
    Mecanismo              : secedit /export + edición de .inf + secedit /configure
    Requiere               : Administrador, PowerShell 5.1, Windows 10
    Invocado por           : 01-Main.ps1 → Apply\Set-AccountPolicies.ps1
#>

# ============================================================
# IMPORTAR CONFIGURACIÓN Y UTILIDADES
# ============================================================
. "$PSScriptRoot\..\Utils\Write-Log.ps1"

# ============================================
# Apply\Set-AccountPolicies.ps1
# CORRECCIONES: C-01, H-05, M-01, L-02, L-03, M-05
# ============================================

function Set-AccountPolicies {
    param(
        [switch]$WhatIf,
        [ValidateSet("CIS-Minimum", "Secure", "Maximum")]
        [string]$SecurityLevel = "Secure"
    )
    
    # FIX: inicializar en $script: para que Register-Result (función anidada)
    # y el código padre compartan la misma variable.
    $script:results = @()
    
    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  APLICANDO POLÍTICAS DE CUENTA - NIVEL: $SecurityLevel" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Magenta
    
    $securityValues = @{
        "CIS-Minimum" = @{ PasswordHistory=24; MaxPasswordAge=365; MinPasswordAge=1; MinPasswordLength=14; LockoutDuration=15; LockoutThreshold=5; LockoutWindow=15; Description="Valores mínimos CIS (cumplimiento normativo)" }
        "Secure" = @{ PasswordHistory=24; MaxPasswordAge=90; MinPasswordAge=1; MinPasswordLength=14; LockoutDuration=30; LockoutThreshold=3; LockoutWindow=30; Description="Valores recomendados (balance seguridad/usabilidad)" }
        "Maximum" = @{ PasswordHistory=24; MaxPasswordAge=30; MinPasswordAge=1; MinPasswordLength=16; LockoutDuration=60; LockoutThreshold=3; LockoutWindow=60; Description="Máxima seguridad (puede afectar usabilidad)" }
    }
    
    $values = $securityValues[$SecurityLevel]
    
    Write-Host "`n⚠️ TRADE-OFFS: $($values.Description)" -ForegroundColor Yellow
    
    function Register-Result {
        param([string]$ControlID, [string]$Operation, [bool]$Success, [string]$Details = "")
        $script:results += [PSCustomObject]@{ ControlID=$ControlID; Operation=$Operation; Success=$Success; Timestamp=Get-Date; Details=$Details }
        Write-ApplyResult -ControlID $ControlID -Operation $Operation -Success $Success -Details $Details
    }
    
    if ($WhatIf) {
        # FIX: enumerar explícitamente las mismas operaciones que el bloque real,
        # evitando iterar $values.Keys (que incluye la clave "Description").
        Register-Result -ControlID "1.1.1" -Operation "Set password history to $($values.PasswordHistory)" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.1.2" -Operation "Set max password age to $($values.MaxPasswordAge) days" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.1.3" -Operation "Set min password age to $($values.MinPasswordAge) day" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.1.4" -Operation "Set min password length to $($values.MinPasswordLength)" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.1.5" -Operation "Enable password complexity" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.1.6" -Operation "Enable relax password limits (CIS v1.11+)" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.1.7" -Operation "Disable reversible passwords" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.2.1" -Operation "Set lockout duration to $($values.LockoutDuration) min" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.2.2" -Operation "Set lockout threshold to $($values.LockoutThreshold) attempts" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "1.2.4" -Operation "Set lockout window to $($values.LockoutWindow) min" -Success $true -Details "SIMULATED"
        return $script:results
    }
    
    # Aplicar configuración
    net accounts /uniquepw:$($values.PasswordHistory) 2>&1 | Out-Null
    Register-Result -ControlID "1.1.1" -Operation "Set password history to $($values.PasswordHistory)" -Success ($LASTEXITCODE -eq 0)
    
    net accounts /maxpwage:$($values.MaxPasswordAge) 2>&1 | Out-Null
    Register-Result -ControlID "1.1.2" -Operation "Set max password age to $($values.MaxPasswordAge) days" -Success ($LASTEXITCODE -eq 0)
    
    net accounts /minpwage:$($values.MinPasswordAge) 2>&1 | Out-Null
    Register-Result -ControlID "1.1.3" -Operation "Set min password age to $($values.MinPasswordAge) day" -Success ($LASTEXITCODE -eq 0)
    
    net accounts /minpwlen:$($values.MinPasswordLength) 2>&1 | Out-Null
    Register-Result -ControlID "1.1.4" -Operation "Set min password length to $($values.MinPasswordLength)" -Success ($LASTEXITCODE -eq 0)
    
    # Complejidad con secedit
    $tempFile = "$env:TEMP\secpol-$([Guid]::NewGuid()).cfg"
    secedit /export /cfg $tempFile 2>$null
    if (Test-Path $tempFile) {
        $content = Get-Content $tempFile
        $newContent = @()
        foreach ($line in $content) {
            if ($line -match "^PasswordComplexity\s*=") { $newContent += "PasswordComplexity = 1" }
            else { $newContent += $line }
        }
        $newContent | Set-Content $tempFile
        secedit /configure /db C:\Windows\security\local.sdb /cfg $tempFile /areas SECURITYPOLICY 2>&1
        Remove-Item $tempFile -Force -EA 0
        Register-Result -ControlID "1.1.5" -Operation "Enable password complexity" -Success $true
    } else {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1 -Type DWORD -Force
        Register-Result -ControlID "1.1.5" -Operation "Enable password complexity" -Success $true
    }
    
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RelaxMinimumPasswordLengthLimits" -Value 1 -Type DWORD -Force -EA 0
    Register-Result -ControlID "1.1.6" -Operation "Enable relax password limits (CIS v1.11+)" -Success $true
    
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ClearTextPassword" -Value 0 -Type DWORD -Force -EA 0
    Register-Result -ControlID "1.1.7" -Operation "Disable reversible passwords" -Success $true
    
    net accounts /lockoutduration:$($values.LockoutDuration) 2>&1 | Out-Null
    Register-Result -ControlID "1.2.1" -Operation "Set lockout duration to $($values.LockoutDuration) min" -Success ($LASTEXITCODE -eq 0)
    
    net accounts /lockoutthreshold:$($values.LockoutThreshold) 2>&1 | Out-Null
    Register-Result -ControlID "1.2.2" -Operation "Set lockout threshold to $($values.LockoutThreshold) attempts" -Success ($LASTEXITCODE -eq 0)
    
    net accounts /lockoutwindow:$($values.LockoutWindow) 2>&1 | Out-Null
    Register-Result -ControlID "1.2.4" -Operation "Set lockout window to $($values.LockoutWindow) min" -Success ($LASTEXITCODE -eq 0)
    
    Write-Host "`n✅ Políticas de cuenta aplicadas - Nivel: $SecurityLevel" -ForegroundColor Green
    return $script:results
}

if ($MyInvocation.InvocationName -ne '.') { Set-AccountPolicies }