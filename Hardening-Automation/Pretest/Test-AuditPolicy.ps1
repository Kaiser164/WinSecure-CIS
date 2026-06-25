# ============================================
# Pretest\Test-AuditPolicy.ps1
# FIX: nombres con tildes exactos del output de auditpol en Windows espanol
# ============================================

# Funcion auxiliar para mostrar resultados
function Write-TestResult {
    param(
        [string]$ControlID,
        [string]$ControlName,
        [bool]$Compliant,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$Details = ""
    )
    
    $icon = if ($Compliant) { "✅" } else { "❌" }
    $color = if ($Compliant) { "Green" } else { "Red" }
    $status = if ($Compliant) { "CUMPLE" } else { "NO CUMPLE" }
    
    if ($Details) {
        Write-Host "  $icon [$ControlID] $ControlName : $status (Actual: $CurrentValue | Esperado: $ExpectedValue) - $Details" -ForegroundColor $color
    } else {
        Write-Host "  $icon [$ControlID] $ControlName : $status (Actual: $CurrentValue | Esperado: $ExpectedValue)" -ForegroundColor $color
    }
}

function Test-AuditPolicy {
    $results = @()

    Write-Host "=== INICIANDO TEST DE ADVANCED AUDIT POLICY ===" -ForegroundColor Cyan

    # auditpol /get /subcategory: falla en Windows espanol (0x00000057)
    # Se usa /category:* y se parsea buscando los nombres exactos con tildes
    $auditOutput = auditpol /get /category:* 2>$null

    function Get-AuditStatusFromOutput {
        param([string[]]$Output, [string]$SpanishName)
        foreach ($line in $Output) {
            $trimmed = $line.Trim()
            if ($trimmed -like "$SpanishName*") {
                if     ($trimmed -match "Aciertos y errores") { return "Success and Failure" }
                elseif ($trimmed -match "Sin auditor")        { return "No Auditing"         }
                elseif ($trimmed -match "Aciertos")           { return "Success"             }
                elseif ($trimmed -match "Errores")            { return "Failure"             }
                else { return ($trimmed -replace [regex]::Escape($SpanishName), "").Trim() }
            }
        }
        return "No Auditing"
    }

    $controls = @(
        @{ ES="Validación de credenciales"; ID="17.1.1"; Name="Audit Credential Validation"; Exp="Success and Failure"; Logic="both" }
        @{ ES="Administración de grupos de seguridad"; ID="17.2.2"; Name="Audit Security Group Management"; Exp="Success"; Logic="success_or_both" }
        @{ ES="Administración de cuentas de usuario"; ID="17.2.3"; Name="Audit User Account Management"; Exp="Success and Failure"; Logic="both" }
        @{ ES="Creación del proceso"; ID="17.3.2"; Name="Audit Process Creation"; Exp="Success"; Logic="success_or_both" }
        @{ ES="Bloqueo de cuenta"; ID="17.5.1"; Name="Audit Account Lockout"; Exp="Failure"; Logic="failure_or_both" }
        @{ ES="Inicio de sesión"; ID="17.5.4"; Name="Audit Logon"; Exp="Success and Failure"; Logic="both" }
        @{ ES="Otros eventos de inicio y cierre de sesión"; ID="17.5.5"; Name="Audit Other Logon/Logoff"; Exp="Success and Failure"; Logic="both" }
        @{ ES="Recurso compartido de archivos"; ID="17.6.2"; Name="Audit File Share"; Exp="Success and Failure"; Logic="both" }
        @{ ES="Cambio en la directiva de auditoría"; ID="17.7.1"; Name="Audit Audit Policy Change"; Exp="Success"; Logic="success_or_both" }
        @{ ES="Integridad del sistema"; ID="17.9.5"; Name="Audit System Integrity"; Exp="Success and Failure"; Logic="both" }
    )

    foreach ($ctrl in $controls) {
        $current = Get-AuditStatusFromOutput -Output $auditOutput -SpanishName $ctrl.ES

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