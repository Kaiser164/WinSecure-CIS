#Requires -RunAsAdministrator

# ============================================================
# IMPORTAR CONFIGURACION Y UTILIDADES
# ============================================================
. "$PSScriptRoot\..\Utils\Write-Log.ps1"

# ============================================
# Apply\Set-AuditPolicy.ps1
# CORRECCIONES: H-04, M-01, L-02, L-07
# FIX L-07: Subcategorias auditpol por GUID (independiente del idioma)
# ============================================

# Funcion auxiliar para mostrar resultados
function Write-ApplyResult {
    param(
        [string]$ControlID,
        [string]$Operation,
        [bool]$Success,
        [string]$Details = ""
    )
    
    $icon = if ($Success) { "✅" } else { "❌" }
    $color = if ($Success) { "Green" } else { "Red" }
    $status = if ($Success) { "OK" } else { "FAIL" }
    
    if ($Details) {
        Write-Host "  $icon [$ControlID] $Operation : $status - $Details" -ForegroundColor $color
    } else {
        Write-Host "  $icon [$ControlID] $Operation : $status" -ForegroundColor $color
    }
    
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "$Operation : $status" -Level $(if ($Success) { "INFO" } else { "ERROR" })
    }
}

function Set-AuditPolicy {
    param([switch]$WhatIf)

    $script:results = @()

    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  APLICANDO ADVANCED AUDIT POLICY" -ForegroundColor Magenta
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

    $auditpolPath = Get-Command auditpol.exe -ErrorAction SilentlyContinue
    if (-not $auditpolPath) {
        Register-Result -ControlID "GLOBAL" -Operation "Verify auditpol availability" `
            -Success $false -Details "auditpol.exe no encontrado"
        return $script:results
    }

    # GUIDs de subcategorias Advanced Audit Policy
    $auditGUIDs = @{
        "Credential Validation"       = "{0cce923f-69ae-11d9-bed3-505054503030}"
        "Security Group Management"   = "{0cce9237-69ae-11d9-bed3-505054503030}"
        "User Account Management"     = "{0cce9235-69ae-11d9-bed3-505054503030}"
        "Process Creation"            = "{0cce922b-69ae-11d9-bed3-505054503030}"
        "Account Lockout"             = "{0cce9217-69ae-11d9-bed3-505054503030}"
        "Logon"                       = "{0cce9215-69ae-11d9-bed3-505054503030}"
        "Other Logon/Logoff Events"   = "{0cce921c-69ae-11d9-bed3-505054503030}"
        "File Share"                  = "{0cce9224-69ae-11d9-bed3-505054503030}"
        "Audit Policy Change"         = "{0cce922f-69ae-11d9-bed3-505054503030}"
        "System Integrity"            = "{0cce9212-69ae-11d9-bed3-505054503030}"
    }

    function Set-AuditSubcategory {
        param([string]$SubcategoryName, [bool]$EnableSuccess, [bool]$EnableFailure)

        $guid = $auditGUIDs[$SubcategoryName]
        if (-not $guid) {
            return $false
        }

        $arguments = @(
            "/set",
            "/subcategory:$guid",
            $(if ($EnableSuccess) { "/success:enable" } else { "/success:disable" }),
            $(if ($EnableFailure) { "/failure:enable" } else { "/failure:disable" })
        )

        try {
            $process = Start-Process -FilePath "auditpol.exe" `
                -ArgumentList $arguments -NoNewWindow -Wait -PassThru
            return ($process.ExitCode -eq 0)
        }
        catch {
            return $false
        }
    }

    if ($WhatIf) {
        Register-Result -ControlID "17.1.1" -Operation "Set Credential Validation to S+F"      -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.2.2" -Operation "Set Security Group Management to S"    -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.2.3" -Operation "Set User Account Management to S+F"    -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.3.2" -Operation "Set Process Creation to S"             -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.5.1" -Operation "Set Account Lockout to F"              -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.5.4" -Operation "Set Logon to S+F"                      -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.5.5" -Operation "Set Other Logon/Logoff to S+F"         -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.6.2" -Operation "Set File Share to S+F"                 -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.7.1" -Operation "Set Audit Policy Change to S"          -Success $true -Details "SIMULATED"
        Register-Result -ControlID "17.9.5" -Operation "Set System Integrity to S+F"           -Success $true -Details "SIMULATED"
        return $script:results
    }

    # Aplicar configuraciones
    $ok = Set-AuditSubcategory -SubcategoryName "Credential Validation" -EnableSuccess $true -EnableFailure $true
    Register-Result -ControlID "17.1.1" -Operation "Set Credential Validation" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "Security Group Management" -EnableSuccess $true -EnableFailure $false
    Register-Result -ControlID "17.2.2" -Operation "Set Security Group Management" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "User Account Management" -EnableSuccess $true -EnableFailure $true
    Register-Result -ControlID "17.2.3" -Operation "Set User Account Management" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "Process Creation" -EnableSuccess $true -EnableFailure $false
    Register-Result -ControlID "17.3.2" -Operation "Set Process Creation" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "Account Lockout" -EnableSuccess $false -EnableFailure $true
    Register-Result -ControlID "17.5.1" -Operation "Set Account Lockout" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "Logon" -EnableSuccess $true -EnableFailure $true
    Register-Result -ControlID "17.5.4" -Operation "Set Logon" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "Other Logon/Logoff Events" -EnableSuccess $true -EnableFailure $true
    Register-Result -ControlID "17.5.5" -Operation "Set Other Logon/Logoff" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "File Share" -EnableSuccess $true -EnableFailure $true
    Register-Result -ControlID "17.6.2" -Operation "Set File Share" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "Audit Policy Change" -EnableSuccess $true -EnableFailure $false
    Register-Result -ControlID "17.7.1" -Operation "Set Audit Policy Change" -Success $ok

    $ok = Set-AuditSubcategory -SubcategoryName "System Integrity" -EnableSuccess $true -EnableFailure $true
    Register-Result -ControlID "17.9.5" -Operation "Set System Integrity" -Success $ok

    Write-Host "`n✅ Advanced Audit Policy aplicadas correctamente" -ForegroundColor Green
    return $script:results
}

if ($MyInvocation.InvocationName -ne '.') { Set-AuditPolicy }