# ============================================
<#
.SYNOPSIS
    Evalua los derechos de usuario CIS (seccion 2.2.x) en Windows 10.

.DESCRIPTION
    Lee con secedit la configuracion real del sistema y verifica el
    cumplimiento de los controles CIS Microsoft Windows 10 Level 1,
    seccion 2.2 (User Rights Assignment):
      2.2.1  - Acceso al Administrador de credenciales: nadie.
      2.2.2  - Acceso desde la red: solo Admins + RDP Users.
      2.2.4  - Ajustar cuotas de memoria.
      2.2.5  - Inicio de sesion local: Admins + Users.
      2.2.6  - Inicio de sesion por RDP: Admins + RDP Users.
      2.2.7  - Copias de seguridad: solo Administrators.
      2.2.8  - Cambio de hora del sistema.
      2.2.11 - Creacion de objetos de token: nadie.
      2.2.15 - Depuracion de programas: solo Administrators.
      2.2.16 - Denegar acceso desde red: solo Guests.
      2.2.19 - Denegar inicio de sesion local: solo Guests.
      2.2.23 - Generar auditorias de seguridad.
      2.2.24 - Suplantacion de cliente.

    La comparacion de SIDs es flexible: acepta variaciones de orden
    y grupos extra que Windows agrega por defecto (SERVICE, etc.).

.EXAMPLE
    # Ejecutar evaluacion standalone
    .\Test-UserRights.ps1

.EXAMPLE
    # Ver resultados como tabla
    .\Test-UserRights.ps1 | Format-Table -AutoSize

.NOTES
    Controles CIS evaluados : 2.2.1, 2.2.2, 2.2.4, 2.2.5, 2.2.6, 2.2.7,
                               2.2.8, 2.2.11, 2.2.15, 2.2.16, 2.2.19,
                               2.2.23, 2.2.24  (13 controles)
    Mecanismo              : secedit /export a .inf temporal + parsing de SIDs
    Invocado por           : 01-Main.ps1 como Test-UserRights
#>



# Cargar Write-Log si no esta disponible (ejecucion standalone)
if (-not (Get-Command Write-TestResult -ErrorAction SilentlyContinue)) {
    $writeLogPath = "$PSScriptRoot\..\Utils\Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
    else { Write-Warning "Write-Log.ps1 no encontrado en $writeLogPath" }
}

function Test-UserRights {
    $results = @()
    
    Write-Host "=== INICIANDO TEST DE USER RIGHTS ASSIGNMENT ===" -ForegroundColor Cyan
    Write-Host "Nota: Leyendo configuraciÃ³n REAL del sistema (secedit)" -ForegroundColor Gray
    
    $sidToName = @{
        "S-1-5-32-544" = "Administrators"
        "S-1-5-32-545" = "Users"
        "S-1-5-32-546" = "Guests"
        "S-1-5-32-555" = "Remote Desktop Users"
        "S-1-5-19"     = "LOCAL SERVICE"
        "S-1-5-20"     = "NETWORK SERVICE"
        "S-1-5-6"      = "SERVICE"
    }
    
    function Convert-SidsToNames {
        param([string]$SidString)
        if ([string]::IsNullOrWhiteSpace($SidString)) { return "No one" }
        $result = @()
        $sids = $SidString -split ','
        foreach ($sid in $sids) {
            $sid = $sid.Trim().TrimStart('*')
            if ($sidToName.ContainsKey($sid)) { $result += $sidToName[$sid] }
            else { $result += $sid }
        }
        return ($result -join ', ')
    }
    
    function Test-ExclusiveGroupMembership {
        param([string]$CurrentValue, [array]$ExpectedSids)
        if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
            return @{ Compliant = $false; Reason = "No hay grupos asignados" }
        }
        $currentSids = $CurrentValue -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }
        $expectedSet = $ExpectedSids | ForEach-Object { $_.TrimStart('*') }
        $allPresent = $true
        foreach ($expected in $expectedSet) {
            if ($currentSids -notcontains $expected) { $allPresent = $false; break }
        }
        $extraSids = $currentSids | Where-Object { $expectedSet -notcontains $_ }
        $compliant = $allPresent -and ($extraSids.Count -eq 0)
        $reason = if (-not $allPresent) { "Faltan grupos" } elseif ($extraSids.Count -gt 0) { "Grupos extra: $($extraSids -join ', ')" } else { "OK" }
        return @{ Compliant = $compliant; Reason = $reason }
    }
    
    $tempFile = "$env:TEMP\secedit-userrights-$([Guid]::NewGuid()).cfg"
    secedit /export /cfg $tempFile 2>$null
    
    if (-not (Test-Path $tempFile)) {
        Write-Host "ERROR: No se pudo exportar la configuraciÃ³n" -ForegroundColor Red
        return $results
    }
    
    $secConfig = Get-Content $tempFile -Raw
    
    function Get-SeceditValue {
        param([string]$Key)
        if ($secConfig -match "$Key = (.+?)(?:\r?\n|$)") { return $matches[1].Trim() }
        return $null
    }
    
    # 2.2.2
    $current = Get-SeceditValue "SeNetworkLogonRight"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544", "S-1-5-32-555")
    Write-TestResult -ControlID "2.2.2" -ControlName "Access from network" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Administrators, RDP Users" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.2"; Name="Access from network"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators,RDP Users"; Category="User Rights" }
    
    # 2.2.4
    $current = Get-SeceditValue "SeIncreaseQuotaPrivilege"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544", "S-1-5-19", "S-1-5-20")
    Write-TestResult -ControlID "2.2.4" -ControlName "Adjust memory quotas" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Admins, LOCAL, NETWORK" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.4"; Name="Adjust memory quotas"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators,LOCAL SERVICE,NETWORK SERVICE"; Category="User Rights" }
    
    # 2.2.5
    $current = Get-SeceditValue "SeInteractiveLogonRight"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544", "S-1-5-32-545")
    Write-TestResult -ControlID "2.2.5" -ControlName "Allow log on locally" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Administrators, Users" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.5"; Name="Allow log on locally"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators,Users"; Category="User Rights" }
    
    # 2.2.6
    $current = Get-SeceditValue "SeRemoteInteractiveLogonRight"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544", "S-1-5-32-555")
    Write-TestResult -ControlID "2.2.6" -ControlName "Allow log on through RDP" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Administrators, RDP Users" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.6"; Name="Allow log on through RDP"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators,RDP Users"; Category="User Rights" }
    
    # 2.2.7
    $current = Get-SeceditValue "SeBackupPrivilege"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544")
    Write-TestResult -ControlID "2.2.7" -ControlName "Backup files" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Administrators" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.7"; Name="Backup files"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators"; Category="User Rights" }
    
    # 2.2.8
    $current = Get-SeceditValue "SeSystemtimePrivilege"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544", "S-1-5-19")
    Write-TestResult -ControlID "2.2.8" -ControlName "Change system time" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Administrators, LOCAL SERVICE" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.8"; Name="Change system time"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators,LOCAL SERVICE"; Category="User Rights" }
    
    # 2.2.11
    $current = Get-SeceditValue "SeCreateTokenPrivilege"
    $compliant = ([string]::IsNullOrWhiteSpace($current))
    Write-TestResult -ControlID "2.2.11" -ControlName "Create token object" -Compliant $compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "No one"
    $results += [PSCustomObject]@{ ControlID="2.2.11"; Name="Create token object"; Compliant=$compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="No one"; Category="User Rights" }
    
    # 2.2.15
    $current = Get-SeceditValue "SeDebugPrivilege"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544")
    Write-TestResult -ControlID "2.2.15" -ControlName "Debug programs" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Administrators" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.15"; Name="Debug programs"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators"; Category="User Rights" }
    
    # Funcion auxiliar para 2.2.16 y 2.2.19:
    # CIS exige que Guests (S-1-5-32-546) este INCLUIDO en la lista.
    # Windows agrega automaticamente SIDs de usuarios locales no privilegiados
    # al reimportar la politica via secedit cuando existen esas cuentas.
    # La verificacion es INCLUSIVA: Guests debe estar, SIDs adicionales son aceptables.
    function Test-IncludesGuests {
        param([string]$CurrentValue)
        if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
            return @{ Compliant = $false; Reason = "Guests no esta asignado" }
        }
        $currentSids = $CurrentValue -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }
        $hasGuests = $currentSids -contains "S-1-5-32-546"
        if ($hasGuests) {
            $extras = $currentSids | Where-Object { $_ -ne "S-1-5-32-546" }
            $extraDesc = if ($extras.Count -gt 0) {
                $names = $extras | ForEach-Object {
                    try {
                        $sid = New-Object System.Security.Principal.SecurityIdentifier($_)
                        $sid.Translate([System.Security.Principal.NTAccount]).Value
                    } catch { $_ }
                }
                " (incluye ademas: $($names -join ', '))"
            } else { "" }
            return @{ Compliant = $true; Reason = "OK -- Guests presente$extraDesc" }
        }
        return @{ Compliant = $false; Reason = "Guests (S-1-5-32-546) no esta en la lista" }
    }

    # 2.2.16
    $current = Get-SeceditValue "SeDenyNetworkLogonRight"
    $validation = Test-IncludesGuests -CurrentValue $current
    Write-TestResult -ControlID "2.2.16" -ControlName "Deny access from network" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "Guests (y opcionalmente cuentas locales adicionales)" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.16"; Name="Deny access from network"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Guests"; Category="User Rights" }

    # 2.2.19
    $current = Get-SeceditValue "SeDenyInteractiveLogonRight"
    $validation = Test-IncludesGuests -CurrentValue $current
    Write-TestResult -ControlID "2.2.19" -ControlName "Deny log on locally" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "Guests (y opcionalmente cuentas locales adicionales)" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.19"; Name="Deny log on locally"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Guests"; Category="User Rights" }
    
    # 2.2.23
    $current = Get-SeceditValue "SeAuditPrivilege"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-19", "S-1-5-20")
    Write-TestResult -ControlID "2.2.23" -ControlName "Generate security audits" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO LOCAL, NETWORK SERVICE" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.23"; Name="Generate security audits"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="LOCAL SERVICE,NETWORK SERVICE"; Category="User Rights" }
    
    # 2.2.24
    $current = Get-SeceditValue "SeImpersonatePrivilege"
    $validation = Test-ExclusiveGroupMembership -CurrentValue $current -ExpectedSids @("S-1-5-32-544", "S-1-5-19", "S-1-5-20", "S-1-5-6")
    Write-TestResult -ControlID "2.2.24" -ControlName "Impersonate a client" -Compliant $validation.Compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "SOLO Admins, LOCAL, NETWORK, SERVICE" -Details $validation.Reason
    $results += [PSCustomObject]@{ ControlID="2.2.24"; Name="Impersonate a client"; Compliant=$validation.Compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE"; Category="User Rights" }
    
    # 2.2.1
    $current = Get-SeceditValue "SeTrustedCredManAccessPrivilege"
    $compliant = ([string]::IsNullOrWhiteSpace($current))
    Write-TestResult -ControlID "2.2.1" -ControlName "Access Credential Manager" -Compliant $compliant -CurrentValue (Convert-SidsToNames $current) -ExpectedValue "No one"
    $results += [PSCustomObject]@{ ControlID="2.2.1"; Name="Access Credential Manager"; Compliant=$compliant; CurrentValue=(Convert-SidsToNames $current); ExpectedValue="No one"; Category="User Rights" }
    
    Remove-Item $tempFile -Force -EA 0
    Write-Host "=== FIN TEST USER RIGHTS ASSIGNMENT ===" -ForegroundColor Cyan
    
    return $results
}

if ($MyInvocation.InvocationName -ne '.') { Test-UserRights | Format-Table -AutoSize }
