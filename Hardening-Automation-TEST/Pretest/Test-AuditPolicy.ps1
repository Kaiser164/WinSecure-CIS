# ============================================
<#
.SYNOPSIS
    Evalua las Advanced Audit Policies CIS (seccion 17.x) en Windows 10.

.DESCRIPTION
    Lee con auditpol /get /subcategory:{GUID} /r el estado real de cada
    subcategoria de auditoria avanzada y verifica el cumplimiento de los
    controles CIS Microsoft Windows 10 Level 1, seccion 17.

    FIX (idioma + parsing): se usa el modificador /r (reporte CSV) junto
    con el GUID de cada subcategoria. Esto evita dos problemas a la vez:
      1. auditpol /get /subcategory:"<nombre>" puede devolver el error
         0x00000057 ("The parameter is incorrect") cuando el nombre no
         coincide exactamente con el de auditpol (p.ej. agregar "Audit "
         al inicio, como muestra Group Policy Editor). Usar el GUID evita
         ese problema por completo, sin importar el idioma del sistema.
      2. La salida normal (sin /r) usa columnas posicionales y nombres de
         categoria en el idioma del sistema operativo, lo cual rompe el
         parsing en cualquier Windows que no este en espanol. La salida
         /r (CSV) usa encabezados de columna FIJOS en ingles
         (Inclusion Setting, Exclusion Setting, etc.) sin importar el
         idioma del SO, y el valor ya viene como cadena estandar:
         "Success and Failure", "Success", "Failure" o "No Auditing".

    Usa los mismos 10 GUIDs que Apply\Set-AuditPolicy.ps1, garantizando
    que Test y Set evaluan/aplican exactamente la misma subcategoria.

.EXAMPLE
    # Ejecutar evaluacion standalone
    .\Test-AuditPolicy.ps1

.EXAMPLE
    # Ver resultados como tabla
    .\Test-AuditPolicy.ps1 | Format-Table -AutoSize

.NOTES
    Controles CIS evaluados : 17.1.1, 17.2.2, 17.2.3, 17.3.2, 17.5.1,
                               17.5.4, 17.5.5, 17.6.2, 17.7.1, 17.9.5 (10 controles)
    Mecanismo               : auditpol /get /subcategory:{GUID} /r (CSV)
    Compatibilidad idiomas  : Si - GUID + columnas /r fijas en ingles
    Invocado por            : 01-Main.ps1 como Test-AuditPolicy
#>

# Cargar Write-Log si no esta disponible (ejecucion standalone)
# Reutiliza Write-TestResult de Utils\Write-Log.ps1 igual que el resto
# de los modulos Test-*.ps1, en lugar de redefinirla localmente.
if (-not (Get-Command Write-TestResult -ErrorAction SilentlyContinue)) {
    $writeLogPath = "$PSScriptRoot\..\Utils\Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
    else { Write-Warning "Write-Log.ps1 no encontrado en $writeLogPath" }
}

function Test-AuditPolicy {
    $results = @()

    Write-Host "=== INICIANDO TEST DE ADVANCED AUDIT POLICY ===" -ForegroundColor Cyan

    # GUIDs de subcategorias Advanced Audit Policy (mismos que Set-AuditPolicy.ps1)
    $auditGUIDs = @{
        "Credential Validation"     = "{0cce923f-69ae-11d9-bed3-505054503030}"
        "Security Group Management" = "{0cce9237-69ae-11d9-bed3-505054503030}"
        "User Account Management"   = "{0cce9235-69ae-11d9-bed3-505054503030}"
        "Process Creation"          = "{0cce922b-69ae-11d9-bed3-505054503030}"
        "Account Lockout"           = "{0cce9217-69ae-11d9-bed3-505054503030}"
        "Logon"                     = "{0cce9215-69ae-11d9-bed3-505054503030}"
        "Other Logon/Logoff Events" = "{0cce921c-69ae-11d9-bed3-505054503030}"
        "File Share"                = "{0cce9224-69ae-11d9-bed3-505054503030}"
        "Audit Policy Change"       = "{0cce922f-69ae-11d9-bed3-505054503030}"
        "System Integrity"          = "{0cce9212-69ae-11d9-bed3-505054503030}"
    }

    # ------------------------------------------------------------------
    # Lee el estado real de una subcategoria via GUID + /r (CSV).
    # /r fuerza encabezados de columna en ingles sin importar el idioma
    # del sistema operativo: Machine Name, Policy Target, Subcategory,
    # Subcategory GUID, Inclusion Setting, Exclusion Setting.
    # ------------------------------------------------------------------
    function Get-AuditStatusByGUID {
        param([string]$Guid)

        try {
            $csv = auditpol /get /subcategory:$Guid /r 2>$null | ConvertFrom-Csv
        }
        catch {
            return "No Auditing"
        }

        if (-not $csv -or -not $csv[0].'Inclusion Setting') {
            return "No Auditing"
        }

        # Valores posibles ya estandarizados por auditpol /r:
        # "Success and Failure", "Success", "Failure", "No Auditing"
        return $csv[0].'Inclusion Setting'
    }

    $controls = @(
        @{ Key="Credential Validation";     ID="17.1.1"; Name="Audit Credential Validation";     Exp="Success and Failure"; Logic="both" }
        @{ Key="Security Group Management"; ID="17.2.2"; Name="Audit Security Group Management"; Exp="Success";             Logic="success_or_both" }
        @{ Key="User Account Management";   ID="17.2.3"; Name="Audit User Account Management";   Exp="Success and Failure"; Logic="both" }
        @{ Key="Process Creation";          ID="17.3.2"; Name="Audit Process Creation";           Exp="Success";             Logic="success_or_both" }
        @{ Key="Account Lockout";           ID="17.5.1"; Name="Audit Account Lockout";            Exp="Failure";             Logic="failure_or_both" }
        @{ Key="Logon";                     ID="17.5.4"; Name="Audit Logon";                      Exp="Success and Failure"; Logic="both" }
        @{ Key="Other Logon/Logoff Events"; ID="17.5.5"; Name="Audit Other Logon/Logoff";         Exp="Success and Failure"; Logic="both" }
        @{ Key="File Share";                ID="17.6.2"; Name="Audit File Share";                 Exp="Success and Failure"; Logic="both" }
        @{ Key="Audit Policy Change";       ID="17.7.1"; Name="Audit Audit Policy Change";        Exp="Success";             Logic="success_or_both" }
        @{ Key="System Integrity";          ID="17.9.5"; Name="Audit System Integrity";           Exp="Success and Failure"; Logic="both" }
    )

    foreach ($ctrl in $controls) {
        $guid = $auditGUIDs[$ctrl.Key]
        if (-not $guid) {
            Write-Host "  [AVISO] GUID no encontrado para: $($ctrl.Key)" -ForegroundColor Yellow
            continue
        }

        $current = Get-AuditStatusByGUID -Guid $guid

        $compliant = switch ($ctrl.Logic) {
            "both"            { $current -eq "Success and Failure" }
            "success_or_both" { $current -eq "Success" -or $current -eq "Success and Failure" }
            "failure_or_both" { $current -eq "Failure" -or $current -eq "Success and Failure" }
            default           { $current -eq $ctrl.Exp }
        }

        Write-TestResult -ControlID $ctrl.ID -ControlName $ctrl.Name `
            -Compliant $compliant -CurrentValue $current -ExpectedValue $ctrl.Exp

        $results += [PSCustomObject]@{
            ControlID     = $ctrl.ID
            Name          = $ctrl.Name
            Compliant     = $compliant
            CurrentValue  = $current
            ExpectedValue = $ctrl.Exp
            Category      = "Audit Policy"
        }
    }

    Write-Host "=== FIN TEST ADVANCED AUDIT POLICY ===" -ForegroundColor Cyan
    return $results
}

if ($MyInvocation.InvocationName -ne '.') { Test-AuditPolicy | Format-Table -AutoSize }
