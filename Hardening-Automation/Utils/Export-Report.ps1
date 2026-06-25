#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Genera el informe HTML de hardening CIS con resumen ejecutivo y tabla de controles.

.DESCRIPTION
    Toma el objeto de comparativa producido por Compare-CISResults y genera un
    archivo HTML completo con:
      - Encabezado con degradado y fecha/hora de generacion.
      - Tarjetas de resumen: total controles, cumplimiento inicial/final, mejora.
      - Tabla detallada por control: ID, nombre, categoria, estado pretest/postest,
        icono de mejora/regresion/neutral, y valores inicial -> final.
      - Colores semanticos: verde (cumple), rojo (falla), gris (no evaluado).

    Usa StringBuilder en lugar de += en el bucle de filas para rendimiento O(n).
    Aplica escape HTML a los valores de los controles para evitar inyeccion.
    Abre el informe automaticamente en el navegador por defecto al terminar
    (desactivable con -NoOpen para uso en automatizacion o servidores sin GUI).

.PARAMETER Comparison
    Objeto devuelto por Compare-CISResults. Debe contener:
    TotalControls, InitialPercentage, FinalPercentage, Improvement,
    Timestamp y DetailedComparison (array de controles comparados).

.PARAMETER OutputPath
    Ruta completa del archivo HTML a generar.
    Por defecto: $global:ReportsPath\hardening-report.html

.PARAMETER NoOpen
    Si se especifica, no abre el archivo en el navegador al terminar.
    Util en ejecuciones automatizadas o en servidores sin interfaz grafica.

.EXAMPLE
    # Uso tipico desde 01-Main.ps1
    Export-HardeningReport -Comparison $comparison

.EXAMPLE
    # Generar en ruta personalizada sin abrir el navegador
    Export-HardeningReport -Comparison $comparison `
        -OutputPath "C:\Auditorias\reporte-junio.html" -NoOpen

.EXAMPLE
    # Generar y capturar la ruta del archivo creado
    $rutaInforme = Export-HardeningReport -Comparison $comparison -NoOpen
    Write-Host "Informe guardado en: $rutaInforme"

.NOTES
    Funcion exportada  : Export-HardeningReport
    Retorna            : Ruta del archivo HTML generado (string)
    Optimizaciones     : StringBuilder (O(n) vs O(n2)), escape HTML sin System.Web
    Colores HTML       : Verde #4CAF50, Rojo #f44336, Gris #9E9E9E (no evaluado)
    Compatibilidad     : PowerShell 5.1 y 7+, sin dependencias externas
    Invocado por       : 01-Main.ps1 Fase 5
#>

# ============================================================
# IMPORTAR CONFIGURACION Y UTILIDADES
# ============================================================
# Guard de carga - evita ruta rota cuando este script es dot-sourced
# desde un llamante (ej: 01-Main.ps1) donde $PSScriptRoot apunta al
# directorio del llamante, no al de este script.
# Si Write-Log ya esta cargado (por el llamante), se omite.
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    $writeLogPath = Join-Path $PSScriptRoot "Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
}

# ============================================
# Utils\Export-Report.ps1 - Generador de informe HTML
# CORRECCIONES: C-04, M-03, B1-B10
# B1: BOM eliminado
# B2: #Requires agregado
# B3: Entry point agregado
# B4: Null guard en $Comparison y DetailedComparison
# B5: StringBuilder reemplaza += en bucle (O(n) vs O(n2))
# B6: Signo de Improvement calculado dinamicamente
# B7: Tercer color para FinalStatus "No evaluado"
# B8: Unicode eliminado de Write-Log
# B9: CmdletBinding agregado
# B10: Set-Content con -Force
# ============================================

if (-not $global:ReportsPath) {
    $global:ReportsPath = Join-Path $PSScriptRoot "..\Reports"
}

function Export-HardeningReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [object]$Comparison,

        [string]$OutputPath = (Join-Path $global:ReportsPath "hardening-report.html"),

        [switch]$NoOpen,

        # Generar tambien CSV y JSON al mismo tiempo que el HTML
        [switch]$AlsoCSV,
        [switch]$AlsoJSON
    )

    # B4: Null guard - verificar que Comparison tiene los campos esperados
    if ($null -eq $Comparison) {
        Write-Log "Export-HardeningReport: Comparison es null" -Level "ERROR"
        return $null
    }
    if ($null -eq $Comparison.DetailedComparison) {
        Write-Log "Export-HardeningReport: Comparison.DetailedComparison es null" -Level "ERROR"
        return $null
    }

    Write-Log "Generando informe HTML..." -Level "INFO"

    # Crear directorio de salida si no existe
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    # Escape HTML - sin System.Web, compatible PS 5.1 y PS 7
    function ConvertTo-HtmlSafe {
        param([string]$Text)
        if ($null -eq $Text) { return "" }
        $Text -replace '&', '&amp;' `
              -replace '<', '&lt;'  `
              -replace '>', '&gt;'  `
              -replace '"', '&quot;'
    }

    # B5: StringBuilder para O(n) - += sobre string en bucle es O(n2)
    $rowsSB = [System.Text.StringBuilder]::new()

    foreach ($control in $Comparison.DetailedComparison) {

        $improvedIcon = if ($control.Improved)      { "&#x2705;" }      # check
                        elseif ($control.Regressed) { "&#x26A0;&#xFE0F;" } # warn
                        else                        { "&#x2796;" }      # neutral

        # B7: Tercer color para "No evaluado" - gris en lugar de rojo
        $initialColor = if ($control.InitialStatus -eq 'Cumple') { '#4CAF50' } else { '#f44336' }
        $finalColor   = switch ($control.FinalStatus) {
            'Cumple'       { '#4CAF50' }
            'No evaluado'  { '#9E9E9E' }   # gris - no es fallo, es dato ausente
            default        { '#f44336' }
        }

        $safeInitial = ConvertTo-HtmlSafe $control.InitialValue
        $safeFinal   = ConvertTo-HtmlSafe $control.FinalValue

        [void]$rowsSB.Append("
        <tr>
            <td><code>$($control.ControlID)</code></td>
            <td>$($control.Name)</td>
            <td>$($control.Category)</td>
            <td style='color:$initialColor'>$($control.InitialStatus)</td>
            <td style='color:$finalColor'>$($control.FinalStatus)</td>
            <td style='text-align:center'>$improvedIcon</td>
            <td><small>$safeInitial -> $safeFinal</small></td>
        </tr>")
    }

    $rowsHtml = $rowsSB.ToString()

    # B6: Signo de Improvement dinamico - evita mostrar "+-5%" en regresion
    $improvVal  = $Comparison.Improvement
    $improvSign = if ($improvVal -ge 0) { "+" } else { "" }
    $improvHtml = "$improvSign$improvVal%"

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe de Hardening CIS - Windows 10</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f0f2f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 20px; }
        .summary-card { background: white; padding: 15px; border-radius: 10px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .summary-card .value { font-size: 2em; font-weight: bold; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #667eea; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f5f5f5; }
        .footer { background: #333; color: white; padding: 15px; text-align: center; font-size: 0.8em; border-radius: 0 0 10px 10px; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔒 Informe de Hardening CIS Benchmark</h1>
        <p>Windows 10 Level 1 | $($Comparison.Timestamp)</p>
    </div>
    <div class="summary">
        <div class="summary-card">
            <div class="label">Controles</div>
            <div class="value">$($Comparison.TotalControls)</div>
        </div>
        <div class="summary-card">
            <div class="label">Cumplimiento Inicial</div>
            <div class="value" style="color:#f44336">$($Comparison.InitialPercentage)%</div>
        </div>
        <div class="summary-card">
            <div class="label">Cumplimiento Final</div>
            <div class="value" style="color:#4CAF50">$($Comparison.FinalPercentage)%</div>
        </div>
        <div class="summary-card">
            <div class="label">Mejora</div>
            <div class="value" style="color:$(if ($improvVal -ge 0) {'#4CAF50'} else {'#f44336'})">$improvHtml</div>
        </div>
    </div>
    <div style="padding:20px; overflow-x:auto;">
        <h2>📋 Detalle de Controles</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th><th>Control</th><th>Categoria</th>
                    <th>Pretest</th><th>Postest</th><th>Mejora</th><th>Valor</th>
                </tr>
            </thead>
            <tbody>$rowsHtml</tbody>
        </table>
    </div>
    <div class="footer"><p>Generado por CIS Hardening Automation Tool</p></div>
</div>
</body>
</html>
"@

    # B10: -Force garantiza escritura aunque el archivo exista y este bloqueado
    Set-Content -Path $OutputPath -Value $html -Encoding UTF8 -Force
    # B8: sin Unicode en Write-Log
    Write-Log "Informe HTML generado: $OutputPath" -Level "SUCCESS"
    Write-Host "  [OK] Informe generado: $OutputPath" -ForegroundColor Green

    if (-not $NoOpen) {
        Start-Process $OutputPath
    }

    # Exportar formatos adicionales si se solicitan
    if ($AlsoCSV)  { Export-HardeningCSV  -Comparison $Comparison }
    if ($AlsoJSON) { Export-HardeningJSON -Comparison $Comparison }

    return $OutputPath
}

# ── Export-HardeningJSON ──────────────────────────────────────────────
# Guarda el objeto de comparacion completo en JSON estructurado.
# Util para integracion con herramientas externas, SIEM o bases de datos.
function Export-HardeningJSON {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNull()][object]$Comparison,
        [string]$OutputPath = (Join-Path $global:ReportsPath "hardening-report.json")
    )
    if ($null -eq $Comparison) {
        Write-Log "Export-HardeningJSON: Comparison es null" -Level "ERROR"
        return $null
    }
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
    try {
        $Comparison | ConvertTo-Json -Depth 5 | Set-Content $OutputPath -Encoding UTF8 -Force
        Write-Log "Informe JSON generado: $OutputPath" -Level "SUCCESS"
        Write-Host "  [OK] JSON: $OutputPath" -ForegroundColor Green
        return $OutputPath
    }
    catch {
        Write-Log "Error generando JSON: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# ── Export-HardeningCSV ───────────────────────────────────────────────
# Exporta el detalle de controles en CSV compatible con Excel.
function Export-HardeningCSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateNotNull()][object]$Comparison,
        [string]$OutputPath = (Join-Path $global:ReportsPath "hardening-report.csv")
    )
    if ($null -eq $Comparison -or $null -eq $Comparison.DetailedComparison) {
        Write-Log "Export-HardeningCSV: Comparison o DetailedComparison es null" -Level "ERROR"
        return $null
    }
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
    try {
        $Comparison.DetailedComparison |
            Select-Object ControlID, Name, Category,
                          InitialStatus, FinalStatus,
                          Improved, Regressed,
                          InitialValue, FinalValue, ExpectedValue |
            Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Log "Informe CSV generado: $OutputPath" -Level "SUCCESS"
        Write-Host "  [OK] CSV: $OutputPath" -ForegroundColor Green
        return $OutputPath
    }
    catch {
        Write-Log "Error generando CSV: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# B3: Entry point informativo - este script es un modulo de utilidades
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ""
    Write-Host "  Export-Report.ps1 - Modulo de utilidades CIS Hardening" -ForegroundColor Cyan
    Write-Host "  ------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  No ejecutar directamente. Importar con dot-source:" -ForegroundColor Gray
    Write-Host "    . .\Utils\Export-Report.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "  Uso tipico (desde 01-Main.ps1):" -ForegroundColor Gray
    Write-Host "    Export-HardeningReport -Comparison <objeto> [-OutputPath <ruta>] [-NoOpen]" -ForegroundColor White
    Write-Host ""
    Write-Host "  Get-Help:" -ForegroundColor Gray
    Write-Host "    Get-Help .\Utils\Export-Report.ps1 -Full" -ForegroundColor White
    Write-Host ""
}