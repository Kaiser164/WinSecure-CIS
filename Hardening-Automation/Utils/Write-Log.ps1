<#
.SYNOPSIS
    Funciones de logging y escritura de resultados para el proyecto CIS Hardening.

.DESCRIPTION
    Provee cuatro funciones de utilidad usadas por todos los modulos del proyecto:

    Write-Log
      Escribe una entrada con timestamp y nivel en el archivo CIS-Hardening.log
      y opcionalmente en consola con color segun nivel (INFO/SUCCESS/WARNING/ERROR).
      Crea el directorio de logs automaticamente si no existe.
      Usa try/catch para detectar fallos reales de escritura sin ocultarlos.

    Write-OutputWithLog
      Escribe un mensaje en consola y en el log simultaneamente.
      Util para mensajes de progreso que tambien deben quedar registrados.

    Write-TestResult
      Formato estandar para resultados de evaluacion CIS:
        "  ControlID : Nombre = Valor (esperado: X) -> OK/FAIL"
      Verde si cumple, amarillo si falla. Llama a Write-Log internamente.

    Write-ApplyResult
      Formato estandar para resultados de aplicacion de hardening:
        "  ControlID : Operacion -> OK/FAIL (detalles)"
      Verde si exitoso, rojo si fallo. Llama a Write-Log internamente.

    Este script NO se ejecuta directamente. Es importado con dot-source
    por todos los modulos Apply\ y Pretest\, y por los Utils que lo necesiten.

.PARAMETER Message
    (Write-Log) Texto del mensaje a registrar.

.PARAMETER Level
    (Write-Log) Nivel de severidad: INFO | SUCCESS | WARNING | ERROR.
    Controla el color de consola y la etiqueta en el archivo de log.

.PARAMETER LogFile
    (Write-Log) Ruta del archivo de log. Por defecto: $global:LogPath\CIS-Hardening.log.

.PARAMETER NoConsole
    (Write-Log) Si se especifica, escribe solo en el archivo sin mostrar en pantalla.

.EXAMPLE
    # Uso tipico desde cualquier modulo del proyecto
    Write-Log "Iniciando evaluacion" -Level "INFO"
    Write-Log "Control aplicado correctamente" -Level "SUCCESS"
    Write-Log "Valor fuera de rango" -Level "WARNING"
    Write-Log "Error critico" -Level "ERROR"

.EXAMPLE
    # Escribir resultado de test (usado por todos los Test-*.ps1)
    Write-TestResult -ControlID "1.1.4" -ControlName "Min password length" `
        -Compliant $true -CurrentValue "14" -ExpectedValue "14"

.EXAMPLE
    # Escribir resultado de apply (usado por todos los Set-*.ps1)
    Write-ApplyResult -ControlID "1.1.4" -Operation "Set min password length to 14" `
        -Success $true

.NOTES
    Funciones exportadas : Write-Log, Write-OutputWithLog,
                           Write-TestResult, Write-ApplyResult
    Archivo de log       : $global:LogPath\CIS-Hardening.log
    Fallback LogPath     : Si 00-Config.ps1 no fue cargado, usa PSScriptRoot\..\Logs
    Invocado por         : Todos los modulos Apply\, Pretest\ y Utils\
#>

# ============================================
# Utils\Write-Log.ps1 - Funciones de logging
# CORRECCIONES: C-04, H-01, M-03, L-02
# FIX: fallback LogPath, dir-guard, try/catch en Add-Content
# ============================================

# FIX-1: Fallback para $global:LogPath
# Si 00-Config.ps1 no fue cargado antes, el módulo no se rompe.
# $script: lo mantiene aislado a este archivo al ser dot-sourced.
if (-not $global:LogPath) {
    $global:LogPath = Join-Path $PSScriptRoot "..\Logs"
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO",

        [Parameter(Mandatory=$false)]
        [string]$LogFile = (Join-Path $global:LogPath "CIS-Hardening.log"),

        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry  = "$timestamp [$Level] $Message"

    # FIX-2: Crear directorio si no existe antes de escribir
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # FIX-3: try/catch en lugar de SilentlyContinue
    # SilentlyContinue ocultaba fallos reales de escritura en logs de auditoría.
    try {
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Host "WARN: No se pudo escribir en log '$LogFile': $_" -ForegroundColor DarkYellow
    }

    if (-not $NoConsole) {
        $color = switch ($Level) {
            "INFO"    { "Cyan"   }
            "SUCCESS" { "Green"  }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red"    }
            default   { "White"  }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Write-OutputWithLog {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White",
        [string]$LogLevel = "INFO"
    )

    Write-Host $Message -ForegroundColor $ForegroundColor
    Write-Log -Message $Message -Level $LogLevel -NoConsole
}

function Write-TestResult {
    param(
        [string]$ControlID,
        [string]$ControlName,
        [bool]$Compliant,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$Details = ""
    )

    $status  = if ($Compliant) { "✅ OK" } else { "❌ FAIL" }
    $color   = if ($Compliant) { "Green" } else { "Yellow" }

    $message = "  $ControlID : $ControlName = $CurrentValue (esperado: $ExpectedValue) -> $status"
    if ($Details) { $message += " | $Details" }

    Write-Host $message -ForegroundColor $color
    Write-Log -Message "$ControlID : $ControlName -> $status" -Level $(if($Compliant){"SUCCESS"}else{"WARNING"}) -NoConsole
}

function Write-ApplyResult {
    param(
        [string]$ControlID,
        [string]$Operation,
        [bool]$Success,
        [string]$Details = ""
    )

    $status  = if ($Success) { "✅ OK" } else { "❌ FAIL" }
    $color   = if ($Success) { "Green" } else { "Red"   }

    $message = "  $ControlID : $Operation -> $status"
    if ($Details) { $message += " ($Details)" }

    Write-Host $message -ForegroundColor $color
    Write-Log -Message "$ControlID : $Operation -> $status" -Level $(if($Success){"SUCCESS"}else{"ERROR"}) -NoConsole
}