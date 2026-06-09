#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Compara los resultados de pretest y postest CIS y genera la comparativa de mejora.

.DESCRIPTION
    Recibe los resultados de evaluacion inicial (pretest) y final (postest) del
    workflow de hardening y produce un objeto estructurado con la comparativa:
      - Porcentaje de cumplimiento inicial y final.
      - Mejora absoluta (puntos porcentuales).
      - Conteo de controles mejorados y regresionados.
      - Array DetailedComparison con el estado por-control (ControlID, Name,
        Category, InitialStatus, FinalStatus, Improved, Regressed, valores).

    Usa ArrayList en lugar de += para evitar O(nÂ²) en arrays de PowerShell,
    e indexa los controles del postest por ControlID para busqueda O(1).
    Incluye null guards tanto en los parametros como en el loop interno
    para manejar objetos extra que PS 5.1 puede emitir involuntariamente.

    El objeto resultado es consumido por Export-HardeningReport para generar
    el informe HTML y por 01-Main.ps1 para el resumen ejecutivo en consola.

.PARAMETER Pretest
    Hashtable o PSObject con los resultados del pretest, agrupados por categoria
    (AccountPolicies, Firewall, SecurityOptions, AdminTemplates, UserRights, AuditPolicy).
    Es el campo .Results devuelto por Invoke-EvaluationPhase en 01-Main.ps1.

.PARAMETER Postest
    Igual que -Pretest pero con los resultados de la evaluacion post-hardening.

.EXAMPLE
    # Uso tipico desde 01-Main.ps1
    $comparison = Compare-CISResults -Pretest $pretestData.Results -Postest $postestData.Results
    $comparison.InitialPercentage   # ej: 54.55
    $comparison.FinalPercentage     # ej: 96.36
    $comparison.Improvement         # ej: 41.82

.EXAMPLE
    # Inspeccionar controles que mejoraron
    $comparison.DetailedComparison | Where-Object { $_.Improved } | Format-Table

.NOTES
    Funcion exportada  : Compare-CISResults
    Retorna            : Hashtable con TotalControls, InitialCompliant, InitialPercentage,
                         FinalCompliant, FinalPercentage, Improvement, ImprovedCount,
                         RegressedCount, DetailedComparison, Timestamp
    Optimizaciones     : ArrayList (O(n) vs O(nÂ²)), indice por ControlID (O(1)), @() guard
    Invocado por       : 01-Main.ps1 Fase 5 â†’ Export-HardeningReport
#>

# ============================================================
# IMPORTAR CONFIGURACION Y UTILIDADES
# ============================================================
# Guard de carga â€” evita ruta rota cuando este script es dot-sourced
# desde un llamante (ej: 01-Main.ps1) donde $PSScriptRoot apunta al
# directorio del llamante, no al de este script.
# Si Write-Log ya esta cargado (por el llamante), se omite.
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    $writeLogPath = Join-Path $PSScriptRoot "Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
}

# ============================================
# Utils\Compare-Results.ps1 - Comparador de resultados
# CORRECCIONES: C-04, M-03, A1-A9
# A1: BOM eliminado
# A2: #Requires agregado
# A3: Entry point agregado
# A4: CmdletBinding agregado
# A5: Parametros tipados y validados
# A6: ArrayList reemplaza += en bucles (O(n) vs O(n2))
# A7: @() fuerza array antes de .Count en Where-Object
# A8: Unicode eliminado de Write-Log
# A9: Null guard en $Pretest y $Postest
# ============================================

function Compare-CISResults {
    [CmdletBinding()]
    param(
        # A5: parametros tipados â€” PSObject acepta hashtable o custom object
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [object]$Pretest,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [object]$Postest
    )

    Write-Log "Generando comparativa de resultados..." -Level "INFO"

    # A9: Null guard explicito con mensaje claro
    if ($null -eq $Pretest) {
        Write-Log "Compare-CISResults: Pretest es null" -Level "ERROR"
        return $null
    }
    if ($null -eq $Postest) {
        Write-Log "Compare-CISResults: Postest es null" -Level "ERROR"
        return $null
    }

    # A6: ArrayList para O(n) en lugar de array += que es O(n2)
    function Get-AllControls {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [AllowNull()]
            [object]$Results
        )

        if ($null -eq $Results) { return @() }

        $list = [System.Collections.ArrayList]::new()
        $keys = @('AccountPolicies','Firewall','SecurityOptions',
                  'AdminTemplates','UserRights','AuditPolicy')
        foreach ($key in $keys) {
            if ($Results.$key) {
                foreach ($item in $Results.$key) {
                    [void]$list.Add($item)
                }
            }
        }
        return $list.ToArray()
    }

    $pretestControls = Get-AllControls -Results $Pretest
    $postestControls = Get-AllControls -Results $Postest

    # Indice por ControlID para busqueda O(1)
    $postestDict = @{}
    foreach ($control in $postestControls) {
        if ($control.ControlID) {
            $postestDict[$control.ControlID] = $control
        }
    }

    # A6: ArrayList para construir comparacion sin O(n2)
    $comparisonList = [System.Collections.ArrayList]::new()

    foreach ($pretestControl in $pretestControls) {
        # FIX: saltar objetos sin ControlID â€” pueden llegar desde JSON
        # deserializado o como objetos extra del pipeline de PS 5.1
        if ([string]::IsNullOrWhiteSpace($pretestControl.ControlID)) { continue }

        $postestControl = $postestDict[$pretestControl.ControlID]

        if ($null -eq $postestControl) {
            [void]$comparisonList.Add([PSCustomObject]@{
                ControlID     = $pretestControl.ControlID
                Name          = $pretestControl.Name
                Category      = $pretestControl.Category
                InitialStatus = if ($pretestControl.Compliant) { "Cumple" } else { "No cumple" }
                FinalStatus   = "No evaluado"
                Improved      = $false
                Regressed     = $false
                InitialValue  = $pretestControl.CurrentValue
                FinalValue    = "N/A"
                ExpectedValue = $pretestControl.ExpectedValue
            })
            continue
        }

        [void]$comparisonList.Add([PSCustomObject]@{
            ControlID     = $pretestControl.ControlID
            Name          = $pretestControl.Name
            Category      = $pretestControl.Category
            InitialStatus = if ($pretestControl.Compliant)  { "Cumple" } else { "No cumple" }
            FinalStatus   = if ($postestControl.Compliant)  { "Cumple" } else { "No cumple" }
            Improved      = ($pretestControl.Compliant -eq $false -and $postestControl.Compliant -eq $true)
            Regressed     = ($pretestControl.Compliant -eq $true  -and $postestControl.Compliant -eq $false)
            InitialValue  = $pretestControl.CurrentValue
            FinalValue    = $postestControl.CurrentValue
            ExpectedValue = $pretestControl.ExpectedValue
        })
    }

    # Convertir a array fijo para las consultas siguientes
    $comparison = $comparisonList.ToArray()

    # A7: @() fuerza array â€” Where-Object con 1 resultado devuelve
    # un objeto suelto en PS 5.1, no un array, y .Count seria 0
    $initialCompliant = @($comparison | Where-Object { $_.InitialStatus -eq "Cumple" }).Count
    $finalCompliant   = @($comparison | Where-Object { $_.FinalStatus   -eq "Cumple" }).Count
    $total            = $comparison.Count

    $safeTotal = if ($total -gt 0) { $total } else { 1 }

    $improvement = [math]::Round((($finalCompliant - $initialCompliant) / $safeTotal) * 100, 2)

    $result = @{
        Timestamp          = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalControls      = $total
        InitialCompliant   = $initialCompliant
        InitialPercentage  = [math]::Round(($initialCompliant / $safeTotal) * 100, 2)
        FinalCompliant     = $finalCompliant
        FinalPercentage    = [math]::Round(($finalCompliant   / $safeTotal) * 100, 2)
        Improvement        = $improvement
        ImprovedCount      = @($comparison | Where-Object { $_.Improved  -eq $true }).Count
        RegressedCount     = @($comparison | Where-Object { $_.Regressed -eq $true }).Count
        DetailedComparison = $comparison
    }

    # A8: sin Unicode en Write-Log
    $sign = if ($improvement -ge 0) { "+" } else { "" }
    Write-Log "Comparativa: $($result.InitialPercentage)% -> $($result.FinalPercentage)% ($sign$improvement%)" -Level "SUCCESS"
    return $result
}

# A3: Entry point â€” permite dot-source sin efecto y ejecucion directa
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "" 
    Write-Host "  Compare-Results.ps1 â€” Modulo de utilidades CIS Hardening" -ForegroundColor Cyan
    Write-Host "  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€" -ForegroundColor DarkGray
    Write-Host "  No ejecutar directamente. Importar con dot-source:" -ForegroundColor Gray
    Write-Host "    . .\Utils\Compare-Results.ps1" -ForegroundColor White
    Write-Host "" 
    Write-Host "  Uso tipico (desde 01-Main.ps1):" -ForegroundColor Gray
    Write-Host "    Compare-CISResults -Pretest <results> -Postest <results>" -ForegroundColor White
    Write-Host "" 
    Write-Host "  Get-Help:" -ForegroundColor Gray
    Write-Host "    Get-Help .\Utils\Compare-Results.ps1 -Full" -ForegroundColor White
    Write-Host ""
}