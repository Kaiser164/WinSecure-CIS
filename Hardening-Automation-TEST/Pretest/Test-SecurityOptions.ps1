# ============================================
<#
.SYNOPSIS
    Evalua las Security Options CIS (seccion 2.3.x) en Windows 10.

.DESCRIPTION
    Lee el registro de Windows y verifica el cumplimiento de los controles
    CIS Microsoft Windows 10 Level 1, seccion 2.3:
      2.3.1.1  - Bloqueo de cuentas Microsoft.
      2.3.1.2  - Cuenta Guest deshabilitada (buscada por SID -501).
      2.3.1.3  - Contrasenas en blanco solo en consola local.
      2.3.7.2  - No mostrar el ultimo usuario en la pantalla de inicio.
      2.3.7.4  - Bloqueo por inactividad (maximo 900 segundos).
      2.3.10.12- Modelo de uso compartido clasico.
      2.3.17.1 - UAC para la cuenta de administrador incorporada.
      2.3.17.6 - Modo de Aprobacion de Administrador (EnableLUA).

    FIX 2.3.1.2: La cuenta Guest se busca por SID terminado en -501
    (RID estandar en todo Windows) en lugar del nombre "Guest", garantizando
    compatibilidad con Windows en espanol (Invitado) y otros idiomas.

.EXAMPLE
    # Ejecutar evaluacion standalone
    .\Test-SecurityOptions.ps1

.EXAMPLE
    # Ver resultados como tabla
    .\Test-SecurityOptions.ps1 | Format-Table -AutoSize

.NOTES
    Controles CIS evaluados : 2.3.1.1, 2.3.1.2, 2.3.1.3, 2.3.7.2, 2.3.7.4,
                               2.3.10.12, 2.3.17.1, 2.3.17.6  (8 controles)
    Fix aplicado           : 2.3.1.2 usa SID -501 en lugar de nombre "Guest"
    Compatibilidad idiomas : Si - funciona en ES, EN y otras localizaciones
    Invocado por           : 01-Main.ps1 como Test-SecurityOptions
#>

# Cargar Write-Log si no esta disponible (ejecucion standalone)
if (-not (Get-Command Write-TestResult -ErrorAction SilentlyContinue)) {
    $writeLogPath = "$PSScriptRoot\..\Utils\Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
    else { Write-Warning "Write-Log.ps1 no encontrado en $writeLogPath" }
}

function Test-SecurityOptions {
    $results = @()
    
    Write-Host "=== INICIANDO TEST DE SECURITY OPTIONS ===" -ForegroundColor Cyan
    
    # 2.3.1.1
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -EA 0).NoConnectedUser
    $compliant = ($current -eq 3)
    Write-TestResult -ControlID "2.3.1.1" -ControlName "Block Microsoft accounts" -Compliant $compliant -CurrentValue $(if($current -eq 3){"Blocked"}else{"Not blocked"}) -ExpectedValue "Blocked"
    $results += [PSCustomObject]@{ ControlID="2.3.1.1"; Name="Block Microsoft accounts"; Compliant=$compliant; CurrentValue=$(if($current -eq 3){"Blocked"}else{"Not blocked"}); ExpectedValue="Blocked"; Category="Security Options" }
    
    # 2.3.1.2 - FIX: Buscar por SID -501 en lugar de nombre (compatible con todos los idiomas)
    try {
        $guestAccount = Get-LocalUser -EA 0 | Where-Object { $_.SID.Value -match "-501$" }
        $current = if ($guestAccount) { $guestAccount.Enabled } else { $false }
    } catch { $current = $false }
    $compliant = ($current -eq $false)
    Write-TestResult -ControlID "2.3.1.2" -ControlName "Guest account disabled" -Compliant $compliant -CurrentValue $(if($current -eq $false){"Disabled"}else{"Enabled"}) -ExpectedValue "Disabled"
    $results += [PSCustomObject]@{ ControlID="2.3.1.2"; Name="Guest account disabled"; Compliant=$compliant; CurrentValue=$(if($current -eq $false){"Disabled"}else{"Enabled"}); ExpectedValue="Disabled"; Category="Security Options" }
    
    # 2.3.1.3
    $current = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -EA 0).LimitBlankPasswordUse
    $compliant = ($current -eq 1)
    Write-TestResult -ControlID "2.3.1.3" -ControlName "Limit blank passwords" -Compliant $compliant -CurrentValue $(if($current -eq 1){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled"
    $results += [PSCustomObject]@{ ControlID="2.3.1.3"; Name="Limit blank passwords"; Compliant=$compliant; CurrentValue=$(if($current -eq 1){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Security Options" }
    
    # 2.3.7.2
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -EA 0).dontdisplaylastusername
    $compliant = ($current -eq 1)
    Write-TestResult -ControlID "2.3.7.2" -ControlName "Don't display last user" -Compliant $compliant -CurrentValue $(if($current -eq 1){"Hidden"}else{"Displayed"}) -ExpectedValue "Hidden"
    $results += [PSCustomObject]@{ ControlID="2.3.7.2"; Name="Don't display last user"; Compliant=$compliant; CurrentValue=$(if($current -eq 1){"Hidden"}else{"Displayed"}); ExpectedValue="Hidden"; Category="Security Options" }
    
    # 2.3.7.4
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -EA 0).InactivityTimeoutSecs
    $compliant = ($current -le 900 -and $current -gt 0)
    Write-TestResult -ControlID "2.3.7.4" -ControlName "Inactivity limit" -Compliant $compliant -CurrentValue "$($current) seg" -ExpectedValue "≤ 900 seg"
    $results += [PSCustomObject]@{ ControlID="2.3.7.4"; Name="Inactivity limit"; Compliant=$compliant; CurrentValue="$($current) seg"; ExpectedValue="≤900"; Category="Security Options" }
    
    # 2.3.10.12
    $current = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "forceguest" -EA 0).forceguest
    $compliant = ($current -eq 0)
    Write-TestResult -ControlID "2.3.10.12" -ControlName "Sharing model" -Compliant $compliant -CurrentValue $(if($current -eq 0){"Classic"}else{"Guest only"}) -ExpectedValue "Classic"
    $results += [PSCustomObject]@{ ControlID="2.3.10.12"; Name="Sharing model"; Compliant=$compliant; CurrentValue=$(if($current -eq 0){"Classic"}else{"Guest only"}); ExpectedValue="Classic"; Category="Security Options" }
    
    # 2.3.17.1
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -EA 0).FilterAdministratorToken
    $compliant = ($current -eq 1)
    Write-TestResult -ControlID "2.3.17.1" -ControlName "UAC for built-in admin" -Compliant $compliant -CurrentValue $(if($current -eq 1){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled"
    $results += [PSCustomObject]@{ ControlID="2.3.17.1"; Name="UAC for built-in admin"; Compliant=$compliant; CurrentValue=$(if($current -eq 1){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Security Options" }
    
    # 2.3.17.6
    $current = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -EA 0).EnableLUA
    $compliant = ($current -eq 1)
    Write-TestResult -ControlID "2.3.17.6" -ControlName "Admin Approval Mode" -Compliant $compliant -CurrentValue $(if($current -eq 1){"Enabled"}else{"Disabled"}) -ExpectedValue "Enabled"
    $results += [PSCustomObject]@{ ControlID="2.3.17.6"; Name="Admin Approval Mode"; Compliant=$compliant; CurrentValue=$(if($current -eq 1){"Enabled"}else{"Disabled"}); ExpectedValue="Enabled"; Category="Security Options" }
    
    Write-Host "=== FIN TEST SECURITY OPTIONS ===" -ForegroundColor Cyan
    return $results
}

if ($MyInvocation.InvocationName -ne '.') { Test-SecurityOptions | Format-Table -AutoSize }