#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Orquestador principal del proyecto CIS Hardening Automation para Windows 10 Level 1.

.DESCRIPTION
    Ejecuta el flujo completo de endurecimiento CIS sobre Windows 10 Pro/Enterprise:
      Fase 1 — PRETEST  : Evalúa el estado de cumplimiento inicial (55 controles).
      Fase 2 — BACKUP   : Exporta secedit, registro y firewall antes de aplicar cambios.
      Fase 3 — HARDENING: Aplica las políticas CIS seleccionadas.
      Fase 4 — POSTEST  : Re-evalúa el cumplimiento tras el hardening.
      Fase 5 — INFORME  : Genera comparativa HTML y resumen ejecutivo en consola.

    El script requiere PowerShell 5.1+ y debe ejecutarse como Administrador.
    Usa 00-Config.ps1 para rutas globales y los módulos de Apply\ y Pretest\.

.PARAMETER Mode
    Controla qué fases se ejecutan:
      Full        — Todas las fases (por defecto).
      PretestOnly — Solo Fase 1 (evaluación inicial, sin cambios).
      ApplyOnly   — Solo Fases 2-3 (backup + hardening, sin tests).
      PostestOnly — Solo Fase 4 (requiere pretest.json previo).

.PARAMETER Category
    Limita el hardening a una categoría CIS específica. Por defecto: All.
    Valores: All | AccountPolicies | Firewall | SecurityOptions |
             AdminTemplates | UserRights | AuditPolicy

.PARAMETER SecurityLevel
    Nivel de rigor en AccountPolicies:
      CIS-Minimum — Valores mínimos de cumplimiento normativo.
      Secure      — Balance seguridad / usabilidad (por defecto).
      Maximum     — Máxima seguridad (puede afectar la usabilidad).

.PARAMETER WhatIf
    Simula todas las operaciones sin aplicar cambios reales al sistema.

.PARAMETER SkipBackup
    Omite la Fase 2 (backup). Útil en entornos de laboratorio o re-ejecuciones.

.PARAMETER AutoRollback
    Si alguna categoría falla durante el hardening, restaura el backup automáticamente.

.EXAMPLE
    # Flujo completo con configuración por defecto
    .\01-Main.ps1 -Mode Full

.EXAMPLE
    # Solo evaluar sin tocar nada (pretest de auditoría)
    .\01-Main.ps1 -Mode PretestOnly

.EXAMPLE
    # Simular el hardening completo (modo prueba, sin cambios reales)
    .\01-Main.ps1 -Mode Full -WhatIf

.EXAMPLE
    # Endurecer solo el firewall al nivel máximo
    .\01-Main.ps1 -Mode Full -Category Firewall -SecurityLevel Maximum

.EXAMPLE
    # Aplicar hardening con rollback automático si algo falla
    .\01-Main.ps1 -Mode Full -AutoRollback

.EXAMPLE
    # Re-evaluar tras un reinicio sin repetir el hardening
    .\01-Main.ps1 -Mode PostestOnly

.NOTES
    Autor      : CIS Hardening Automation Project
    Versión    : 1.1
    Requisitos : Windows 10 Build 19045+, PowerShell 5.1, Administrador
    Referencia : CIS Microsoft Windows 10 Enterprise Benchmark v2.0 (Level 1)

    ESTRUCTURA DE CARPETAS ESPERADA:
      <raíz>\
        00-Config.ps1
        01-Main.ps1
        Apply\       → Set-AccountPolicies.ps1, Set-Firewall.ps1, ...
        Pretest\     → Test-AccountPolicies.ps1, Test-Firewall.ps1, ...
        Utils\       → Write-Log.ps1, Backup-Config.ps1, ...
        Reports\     → hardening-report.html, pretest.json, postest.json
        Backups\     → backup-YYYYMMDD-HHmmss\
        Logs\        → hardening.log
#>

param(
    [ValidateSet("Full", "PretestOnly", "ApplyOnly", "PostestOnly")]
    [string]$Mode = "Full",

    [switch]$WhatIf,

    [switch]$SkipBackup,

    [switch]$AutoRollback,

    [ValidateSet("All", "AccountPolicies", "Firewall", "SecurityOptions", "AdminTemplates", "UserRights", "AuditPolicy")]
    [string]$Category = "All",

    [ValidateSet("CIS-Minimum", "Secure", "Maximum")]
    [string]$SecurityLevel = "Secure"
)

# ============================================================
# VARIABLES GLOBALES
# ============================================================
$global:ReportsPath = "$PSScriptRoot\Reports"
$global:BackupPath  = "$PSScriptRoot\Backups"    # fallback; 00-Config.ps1 puede sobreescribirlo

$global:Colors = @{
    Header  = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error   = "Red"
    Info    = "White"
}

# Crear directorio Reports si no existe
if (-not (Test-Path $global:ReportsPath)) {
    New-Item -ItemType Directory -Path $global:ReportsPath -Force | Out-Null
}

# ============================================================
# CARGAR CONFIGURACION (00-Config.ps1)
# ============================================================
if (Test-Path "$PSScriptRoot\00-Config.ps1") {
    . "$PSScriptRoot\00-Config.ps1"
}

# ============================================================
# IMPORTAR UTILIDADES
# FIX PS 5.1: dot-source sin param() de nivel script para evitar
# que PS 5.1 intente enlazar $PSBoundParameters del scope llamante.
# ============================================================
$utilsPaths = @(
    "$PSScriptRoot\Utils\Write-Log.ps1",
    "$PSScriptRoot\Utils\Backup-Config.ps1",
    "$PSScriptRoot\Utils\Compare-Results.ps1",
    "$PSScriptRoot\Utils\Export-Report.ps1"
)
foreach ($path in $utilsPaths) {
    if (Test-Path $path) {
        . $path
    } else {
        Write-Host "  [AVISO] No se encontro: $path" -ForegroundColor DarkYellow
    }
}

# ============================================================
# IMPORTAR MODULOS DE PRETEST / POSTEST
# ============================================================
$testModulePaths = @(
    "$PSScriptRoot\Pretest\Test-AccountPolicies.ps1",
    "$PSScriptRoot\Pretest\Test-Firewall.ps1",
    "$PSScriptRoot\Pretest\Test-SecurityOptions.ps1",
    "$PSScriptRoot\Pretest\Test-AdminTemplates.ps1",
    "$PSScriptRoot\Pretest\Test-UserRights.ps1",
    "$PSScriptRoot\Pretest\Test-AuditPolicy.ps1"
)
foreach ($path in $testModulePaths) {
    if (Test-Path $path) {
        . $path
    } else {
        Write-Host "  [AVISO] Modulo de test no encontrado: $path" -ForegroundColor DarkYellow
    }
}

# ============================================================
# IMPORTAR MODULOS DE APLICACION (Apply)
# ============================================================
$applyModulePaths = @(
    "$PSScriptRoot\Apply\Set-AccountPolicies.ps1",
    "$PSScriptRoot\Apply\Set-Firewall.ps1",
    "$PSScriptRoot\Apply\Set-SecurityOptions.ps1",
    "$PSScriptRoot\Apply\Set-AdminTemplates.ps1",
    "$PSScriptRoot\Apply\Set-UserRights.ps1",
    "$PSScriptRoot\Apply\Set-AuditPolicy.ps1"
)
foreach ($path in $applyModulePaths) {
    if (Test-Path $path) {
        . $path
    } else {
        Write-Host "  [AVISO] Modulo de apply no encontrado: $path" -ForegroundColor DarkYellow
    }
}

# ============================================================
# DICCIONARIOS DE FUNCIONES
# Se definen DESPUES de los dot-source para que las funciones
# ya existan en el scope cuando se construyen los scriptblocks.
# ============================================================
$testFunctions = @{
    AccountPolicies = { Test-AccountPolicies  }
    Firewall        = { Test-FirewallSettings }
    SecurityOptions = { Test-SecurityOptions  }
    AdminTemplates  = { Test-AdminTemplates   }
    UserRights      = { Test-UserRights       }
    AuditPolicy     = { Test-AuditPolicy      }
}

$applyFunctions = @{
    AccountPolicies = { Set-AccountPolicies -WhatIf:$WhatIf -SecurityLevel $SecurityLevel }
    Firewall        = { Set-FirewallSettings -WhatIf:$WhatIf }
    SecurityOptions = { Set-SecurityOptions  -WhatIf:$WhatIf }
    AdminTemplates  = { Set-AdminTemplates   -WhatIf:$WhatIf }
    UserRights      = { Set-UserRights       -WhatIf:$WhatIf }
    AuditPolicy     = { Set-AuditPolicy      -WhatIf:$WhatIf }
}

# ============================================================
# FUNCION: Write-Section
# ============================================================
function Write-Section {
    param([string]$Title)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title"  -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

# ============================================================
# FUNCION: Test-WindowsVersion
# ============================================================
function Test-WindowsVersion {
    param(
        [int]$RequiredBuild      = 19045,
        [string]$RequiredEdition = "Professional"
    )

    Write-Host "`nVerificando version de Windows..." -ForegroundColor Cyan

    $os          = Get-CimInstance -ClassName Win32_OperatingSystem
    $version     = $os.Version
    $build       = [System.Environment]::OSVersion.Version.Build
    $edition     = (Get-ItemProperty `
                        -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
                        -Name "EditionID" `
                        -ErrorAction SilentlyContinue).EditionID
    $productName = $os.Caption

    Write-Host "  Sistema : $productName"             -ForegroundColor Gray
    Write-Host "  Version : $version (Build: $build)" -ForegroundColor Gray
    Write-Host "  Edicion : $edition"                 -ForegroundColor Gray

    $issues   = @()
    $warnings = @()

    if ($version -notlike "10.*") {
        $issues += "Este script esta disenado para Windows 10. Detectado: $version"
    }
    if ($build -lt $RequiredBuild) {
        $warnings += "Build $build es anterior a la recomendada ($RequiredBuild)."
    }
    if ($edition -ne $RequiredEdition -and $edition -ne "Enterprise") {
        $warnings += "Edicion $edition detectada. Probado en Windows 10 Pro/Enterprise."
    }
    if ([Environment]::Is64BitOperatingSystem) {
        Write-Host "  Arquitectura: 64 bits OK" -ForegroundColor Green
    } else {
        $warnings += "Arquitectura 32 bits detectada."
    }

    if ($issues.Count -gt 0) {
        Write-Host "`nERRORES CRITICOS:" -ForegroundColor Red
        foreach ($issue in $issues) { Write-Host "  * $issue" -ForegroundColor Red }
        return $false
    }

    if ($warnings.Count -gt 0) {
        Write-Host "`nADVERTENCIAS:" -ForegroundColor Yellow
        foreach ($w in $warnings) { Write-Host "  * $w" -ForegroundColor Yellow }

        $continuar = Read-Host "`nDesea continuar de todas formas? (S/N)"
        if ($continuar -ne "S" -and $continuar -ne "s") {
            Write-Host "Ejecucion cancelada" -ForegroundColor Red
            return $false
        }
    }

    Write-Host "`nSistema operativo compatible" -ForegroundColor Green
    return $true
}

# ============================================================
# FUNCION INTERNA: Invoke-Pretest / Invoke-Postest
# Centraliza la logica de evaluacion para no repetir codigo.
# ============================================================
function Invoke-EvaluationPhase {
    param(
        [string]$PhaseName,           # "PRETEST" o "POSTEST"
        [string[]]$Categories,
        [hashtable]$Functions         # $testFunctions
    )

    $results = @{}

    foreach ($cat in $Categories) {

        # Verificar que la funcion existe antes de llamarla
        if (-not $Functions.ContainsKey($cat)) {
            Write-Host "  [AVISO] No hay funcion de test para: $cat" -ForegroundColor DarkYellow
            continue
        }

        $funcName = switch ($cat) {
            "AccountPolicies" { "Test-AccountPolicies"  }
            "Firewall"        { "Test-FirewallSettings" }
            "SecurityOptions" { "Test-SecurityOptions"  }
            "AdminTemplates"  { "Test-AdminTemplates"   }
            "UserRights"      { "Test-UserRights"       }
            "AuditPolicy"     { "Test-AuditPolicy"      }
        }

        if (-not (Get-Command $funcName -ErrorAction SilentlyContinue)) {
            Write-Host "  [AVISO] Funcion no disponible: $funcName (script no cargado?)" -ForegroundColor Yellow
            $results[$cat] = @()
            continue
        }

        Write-Host "  Evaluando: $cat" -ForegroundColor Gray
        try {
            $results[$cat] = & $Functions[$cat]
        }
        catch {
            Write-Host "  [ERROR] Fallo al evaluar $cat : $($_.Exception.Message)" -ForegroundColor Red
            $results[$cat] = @()
        }
    }

    # Calcular porcentaje de cumplimiento
    # FIX: filtrar solo objetos que sean controles validos (tienen ControlID y Compliant)
    # En PS 5.1, & {scriptblock} captura TODO el pipeline del scriptblock,
    # incluyendo objetos extra emitidos involuntariamente por los Test-*.
    # Sin este filtro, esos objetos inflan el total sin ser controles reales.
    $allControls = @()
    foreach ($cat in $results.Keys) {
        foreach ($item in @($results[$cat])) {
            if ($null -ne $item -and
                $item.PSObject.Properties.Name -contains "Compliant" -and
                $item.PSObject.Properties.Name -contains "ControlID") {
                $allControls += $item
            }
        }
    }

    $compliant  = @($allControls | Where-Object { $_.Compliant -eq $true }).Count
    $total      = $allControls.Count
    $percentage = if ($total -gt 0) { [math]::Round(($compliant / $total) * 100, 2) } else { 0 }

    Write-Host "CUMPLIMIENTO $PhaseName : $compliant / $total ($percentage%)" -ForegroundColor Cyan

    return @{
        Results    = $results
        Compliant  = $compliant
        Total      = $total
        Percentage = $percentage
    }
}

# ============================================================
# FUNCION PRINCIPAL: Start-HardeningWorkflow
# ============================================================
function Start-HardeningWorkflow {
    param(
        [string]$Mode,
        [switch]$WhatIf,
        [switch]$SkipBackup,
        [switch]$AutoRollback,
        [string]$Category,
        [string]$SecurityLevel
    )

    Write-Section "CIS HARDENING AUTOMATION - Windows 10 Level 1"
    Write-Host "Modo: $Mode | Categoria: $Category | WhatIf: $WhatIf | SecurityLevel: $SecurityLevel" `
        -ForegroundColor Gray

    # Categorias a procesar
    $categoriesToProcess = if ($Category -eq "All") {
        @("AccountPolicies","Firewall","SecurityOptions","AdminTemplates","UserRights","AuditPolicy")
    } else {
        @($Category)
    }

    $pretestData     = $null
    $postestData     = $null
    $backupInfo      = $null
    $pretestJsonPath = "$global:ReportsPath\pretest.json"

    # ======================================================
    # FASE 1: PRETEST
    # ======================================================
    if ($Mode -in @("Full", "PretestOnly")) {
        Write-Section "FASE 1: PRETEST - Evaluacion inicial"

        $pretestData = Invoke-EvaluationPhase `
            -PhaseName  "PRETEST" `
            -Categories $categoriesToProcess `
            -Functions  $testFunctions

        # Guardar resultados en JSON para uso posterior en PostestOnly
        try {
            $pretestData.Results | ConvertTo-Json -Depth 5 |
                Set-Content $pretestJsonPath -Encoding UTF8
            Write-Host "Resultados pretest guardados en: $pretestJsonPath" -ForegroundColor Green
        }
        catch {
            Write-Host "  [WARN] No se pudo guardar pretest.json : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # ======================================================
    # FASE 2: BACKUP
    # ======================================================
    if (($Mode -eq "Full" -or $Mode -eq "ApplyOnly") -and -not $SkipBackup -and -not $WhatIf) {
        Write-Section "FASE 2: BACKUP DE CONFIGURACION"

        if (Get-Command Backup-Configuration -ErrorAction SilentlyContinue) {
            try {
                $backupInfo = Backup-Configuration
                if ($backupInfo.Success) {
                    Write-Host "  Backup completado en: $($backupInfo.Path)" -ForegroundColor Green
                } else {
                    Write-Host "  [WARN] Backup completado con errores" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  [ERROR] Fallo el backup: $($_.Exception.Message)" -ForegroundColor Red
                $backupInfo = $null
            }
        } else {
            Write-Host "  [AVISO] Funcion Backup-Configuration no disponible" -ForegroundColor DarkYellow
        }
    }

    # ======================================================
    # FASE 3: APLICACION DE HARDENING
    # ======================================================
    $applyFailed      = $false
    $failedOperations = @()
    $applyResults     = @{}

    if ($Mode -in @("Full", "ApplyOnly")) {
        Write-Section "FASE 3: APLICACION DE HARDENING"

        if ($WhatIf) {
            Write-Host "  MODO SIMULACION - No se aplicaran cambios reales" -ForegroundColor Yellow
        }

        foreach ($cat in $categoriesToProcess) {

            if (-not $applyFunctions.ContainsKey($cat)) {
                Write-Host "  [AVISO] Sin funcion de apply para: $cat" -ForegroundColor DarkYellow
                continue
            }

            Write-Host "  Aplicando categoria: $cat" -ForegroundColor Gray
            try {
                $result            = & $applyFunctions[$cat]
                $applyResults[$cat] = $result

                if ($result -is [array] -and $result.Count -gt 0) {
                    $failures = $result | Where-Object { $_.Success -eq $false }
                    if ($failures -and $failures.Count -gt 0) {
                        $applyFailed        = $true
                        $failedOperations  += $failures
                        Write-Host "  Fallos en $cat : $($failures.Count) operaciones" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                $applyFailed        = $true
                $failedOperations  += [PSCustomObject]@{
                    Category = $cat
                    Error    = $_.Exception.Message
                    Success  = $false
                }
                Write-Host "  Excepcion en $cat : $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # Rollback automatico si hubo fallos
        if ($applyFailed -and $AutoRollback -and $backupInfo -and -not $WhatIf) {
            Write-Section "DETECTADOS FALLOS - INICIANDO ROLLBACK"
            Write-Host "  Iniciando restauracion automatica..." -ForegroundColor Yellow

            if (Get-Command Restore-Backup -ErrorAction SilentlyContinue) {
                try {
                    $restoreSuccess = Restore-Backup -RestorePath $backupInfo.Path -WhatIf:$false
                    if ($restoreSuccess) {
                        Write-Host "  Rollback completado" -ForegroundColor Green
                    } else {
                        Write-Host "  CRITICO: Fallo el rollback automatico" -ForegroundColor Red
                    }
                }
                catch {
                    Write-Host "  CRITICO: Excepcion en rollback: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "  [ERROR] Funcion Restore-Backup no disponible" -ForegroundColor Red
            }
        }

        if (-not $WhatIf -and -not $applyFailed) {
            Write-Host "  Hardening aplicado exitosamente" -ForegroundColor Green
            Write-Host "  SE RECOMIENDA REINICIAR EL SISTEMA"  -ForegroundColor Yellow
        }
    }

    # ======================================================
    # FASE 4: POSTEST
    # ======================================================
    if ($Mode -in @("Full", "PostestOnly")) {

        # En PostestOnly cargar pretest desde JSON
        if ($Mode -eq "PostestOnly") {
            if (-not (Test-Path $pretestJsonPath)) {
                Write-Host "No se puede ejecutar PostestOnly sin un pretest previo." -ForegroundColor Red
                Write-Host "  Ejecute primero: .\01-Main.ps1 -Mode PretestOnly"      -ForegroundColor Yellow
                return
            }
            try {
                $rawJson     = Get-Content $pretestJsonPath -Raw
                $pretestData = @{ Results = ($rawJson | ConvertFrom-Json) }
                Write-Host "  Pretest cargado desde archivo" -ForegroundColor Green
            }
            catch {
                Write-Host "  Archivo pretest.json corrupto o invalido" -ForegroundColor Red
                return
            }
        }

        Write-Section "FASE 4: POSTEST - Evaluacion final"

        $postestData = Invoke-EvaluationPhase `
            -PhaseName  "POSTEST" `
            -Categories $categoriesToProcess `
            -Functions  $testFunctions

        try {
            $postestData.Results | ConvertTo-Json -Depth 5 |
                Set-Content "$global:ReportsPath\postest.json" -Encoding UTF8
            Write-Host "  Resultados postest guardados" -ForegroundColor Green
        }
        catch {
            Write-Host "  [WARN] No se pudo guardar postest.json : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # ======================================================
    # FASE 5: INFORME FINAL (solo en Full)
    # ======================================================
    if ($Mode -eq "Full") {
        Write-Section "FASE 5: GENERANDO INFORME FINAL"

        $comparison = $null

        if (Get-Command Compare-CISResults -ErrorAction SilentlyContinue) {
            try {
                $comparison = Compare-CISResults `
                    -Pretest $pretestData.Results `
                    -Postest $postestData.Results
            }
            catch {
                Write-Host "  [WARN] Error en Compare-CISResults: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        if (Get-Command Export-HardeningReport -ErrorAction SilentlyContinue) {
            try {
                Export-HardeningReport `
                    -Comparison $comparison `
                    -OutputPath "$global:ReportsPath\hardening-report.html" `
                    -AlsoCSV `
                    -AlsoJSON
            }
            catch {
                Write-Host "  [WARN] Error en Export-HardeningReport: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        # Valores para el resumen (usa datos directos si Compare-CISResults no esta disponible)
        $ini = if ($comparison)   { $comparison.InitialPercentage } `
               elseif ($pretestData) { $pretestData.Percentage } else { 0 }
        $fin = if ($comparison)   { $comparison.FinalPercentage   } `
               elseif ($postestData) { $postestData.Percentage } else { 0 }
        $mej = if ($comparison)   { $comparison.Improvement       } `
               else { [math]::Max(0, $fin - $ini) }

        # ── Barra de progreso visual ────────────────────────────
        function Show-Bar {
            param([int]$Percentage, [string]$Color)
            $barLength = 30
            $filled    = [math]::Round($barLength * $Percentage / 100)
            $filled    = [math]::Max(0, [math]::Min($barLength, $filled))
            $bar       = ("#" * $filled) + ("-" * ($barLength - $filled))
            Write-Host "  [$bar]" -ForegroundColor $Color -NoNewline
            Write-Host " $($Percentage)%" -ForegroundColor White
        }

        Write-Section "RESUMEN EJECUTIVO"
        $lineWidth = 44
        $border    = "+" + ("-" * $lineWidth) + "+"
        Write-Host "  $border"  -ForegroundColor Cyan
        Write-Host ("  | " + "RESULTADOS DEL HARDENING CIS W10 L1".PadRight($lineWidth - 2) + " |") -ForegroundColor Cyan
        Write-Host "  $border"  -ForegroundColor Cyan
        Write-Host "  Inicial : " -ForegroundColor Yellow -NoNewline ; Show-Bar -Percentage $ini -Color "Yellow"
        Write-Host "  Final   : " -ForegroundColor Green  -NoNewline ; Show-Bar -Percentage $fin -Color "Green"
        Write-Host "  Mejora  : " -ForegroundColor Cyan   -NoNewline ; Show-Bar -Percentage $mej -Color "Cyan"
        Write-Host "  $border"  -ForegroundColor Cyan
    }

    Write-Host "`nWORKFLOW COMPLETADO" -ForegroundColor Green

}  # --- fin de Start-HardeningWorkflow

# ============================================================
# VERIFICACION DE PERMISOS (ya cubierta por #Requires arriba,
# pero se mantiene para mensaje explicativo claro)
# ============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal]`
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

if (-not $isAdmin) {
    Write-Host "Este script requiere permisos de Administrador." -ForegroundColor Red
    Write-Host "Ejecute PowerShell como Administrador y vuelva a intentar." -ForegroundColor Yellow
    exit 1
}

# ============================================================
# VERIFICACION DE VERSION DE WINDOWS
# ============================================================
if (-not (Test-WindowsVersion)) {
    Write-Host "Version de Windows no compatible. Ejecucion abortada." -ForegroundColor Red
    exit 1
}

# ============================================================
# PUNTO DE ENTRADA — lanzar workflow principal
# ============================================================
Start-HardeningWorkflow `
    -Mode          $Mode `
    -WhatIf:       $WhatIf `
    -SkipBackup:   $SkipBackup `
    -AutoRollback: $AutoRollback `
    -Category      $Category `
    -SecurityLevel $SecurityLevel