#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configuracion inicial del proyecto CIS Hardening Automation.

.DESCRIPTION
    Ejecutar como primer paso despues de descargar o descomprimir el proyecto.
    Automatiza todo lo necesario para poder usar el hardening inmediatamente.

    Orden de ejecucion:
      [1] Verificar PowerShell 5.1+ y Windows 10
      [2] Verificar integridad del proyecto (scripts raiz y carpetas requeridas)
      [3] Desbloquear todos los scripts .ps1 (Unblock-File)
      [4] Reparar codificacion de caracteres (fix-encoding.ps1)
      [5] Verificar politica de ejecucion (scope LocalMachine)
      [6] Crear carpetas de trabajo (Logs, Reports, Backups, Data)
      [7] Verificar carga de 00-Config.ps1 y cis-controls.json
      [8] Resumen con proximos pasos

.PARAMETER SkipEncoding
    Omite el paso de reparacion de encoding.
    Usar si fix-encoding.ps1 no esta disponible o ya se ejecuto antes.

.PARAMETER SkipPolicy
    Omite la verificacion y cambio de ExecutionPolicy.
    Usar en entornos donde la politica ya esta configurada correctamente.

.EXAMPLE
    # Primer uso — configuracion completa
    .\setup.ps1

.EXAMPLE
    # Omitir reparacion de encoding (ya ejecutada)
    .\setup.ps1 -SkipEncoding

.EXAMPLE
    # Omitir cambio de politica (ya configurada por GPO)
    .\setup.ps1 -SkipPolicy

.NOTES
    Requiere       : Administrador, PowerShell 5.1+, Windows 10
    Ruta           : Detectada automaticamente — funciona desde cualquier carpeta
    Log de setup   : Logs\setup.log (creado aunque Logs\ no exista aun)
    Scripts raiz   : 01-Main.ps1, 00-Config.ps1, fix-encoding.ps1,
                     Setup-LimitedUser.ps1
    Carpetas req.  : Apply\, Pretest\, Utils\
    Carpetas auto  : Logs\, Reports\, Backups\, Data\
#>

param(
    [switch]$SkipEncoding,
    [switch]$SkipPolicy
)

# ============================================================
# INICIALIZACION — ruta dinamica, sin hardcoding
# ============================================================
$proyectoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$setupLog     = Join-Path $proyectoRoot "setup.log"
$erroresCrit  = 0
$advertencias = 0

function Write-Setup {
    param(
        [string]$Msg,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    $ts   = Get-Date -Format "HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    Write-Host $Msg -ForegroundColor $Color
    try { Add-Content -Path $setupLog -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

# Header
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  CIS HARDENING AUTOMATION — Configuracion inicial"          -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Ruta    : $proyectoRoot" -ForegroundColor Gray
Write-Host "  Log     : $setupLog"     -ForegroundColor Gray
Write-Host "  Fecha   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

Add-Content -Path $setupLog -Value "========== SETUP INICIADO $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==========" -Encoding UTF8 -ErrorAction SilentlyContinue

# ============================================================
# [1] REQUISITOS DEL SISTEMA
# ============================================================
Write-Host "[1/7] Verificando requisitos del sistema..." -ForegroundColor Yellow

$psVersion = $PSVersionTable.PSVersion.Major
if ($psVersion -ge 5) {
    Write-Setup "  OK  PowerShell $psVersion detectado" "SUCCESS" "Green"
} else {
    Write-Setup "  FAIL Se requiere PowerShell 5.1 o superior (actual: $psVersion)" "ERROR" "Red"
    exit 1
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osBuild = $os.BuildNumber
    if ($os.Caption -like "*Windows 10*") {
        Write-Setup "  OK  $($os.Caption) (Build $osBuild)" "SUCCESS" "Green"
        if ([int]$osBuild -lt 19041) {
            Write-Setup "  WARN Build $osBuild anterior al minimo recomendado (19041)" "WARNING" "Yellow"
            $advertencias++
        }
    } else {
        Write-Setup "  WARN Sistema no soportado oficialmente: $($os.Caption)" "WARNING" "Yellow"
        $advertencias++
    }
} catch {
    Write-Setup "  WARN No se pudo verificar version del SO: $($_.Exception.Message)" "WARNING" "Yellow"
    $advertencias++
}

# ============================================================
# [2] INTEGRIDAD DEL PROYECTO
# Scripts raiz obligatorios + carpetas requeridas
# Verificado ANTES de hacer cualquier cambio —
# evita crear carpetas en un proyecto incompleto
# ============================================================
Write-Host ""
Write-Host "[2/7] Verificando integridad del proyecto..." -ForegroundColor Yellow

# Scripts raiz obligatorios
$scriptsObligatorios = @("01-Main.ps1", "00-Config.ps1")
foreach ($script in $scriptsObligatorios) {
    $scriptPath = Join-Path $proyectoRoot $script
    if (Test-Path $scriptPath) {
        Write-Setup "  OK  $script encontrado" "SUCCESS" "Green"
    } else {
        Write-Setup "  FAIL $script no encontrado — proyecto incompleto" "ERROR" "Red"
        $erroresCrit++
    }
}

# Scripts raiz opcionales (presencia informativa)
$scriptsOpcionales = @("fix-encoding.ps1", "Setup-LimitedUser.ps1")
foreach ($script in $scriptsOpcionales) {
    $scriptPath = Join-Path $proyectoRoot $script
    if (Test-Path $scriptPath) {
        Write-Setup "  OK  $script encontrado" "SUCCESS" "Green"
    } else {
        Write-Setup "  INFO $script no encontrado (opcional)" "INFO" "Gray"
    }
}

# Carpetas requeridas con conteo de scripts
$carpetasRequeridas = @("Apply", "Pretest", "Utils")
foreach ($folder in $carpetasRequeridas) {
    $folderPath = Join-Path $proyectoRoot $folder
    if (Test-Path $folderPath) {
        $count = (Get-ChildItem $folderPath -Filter "*.ps1" -EA SilentlyContinue).Count
        Write-Setup "  OK  $folder\ ($count scripts)" "SUCCESS" "Green"
        if ($count -eq 0) {
            Write-Setup "  WARN $folder\ existe pero no tiene scripts .ps1" "WARNING" "Yellow"
            $advertencias++
        }
    } else {
        Write-Setup "  FAIL Carpeta requerida faltante: $folder\" "ERROR" "Red"
        $erroresCrit++
    }
}

if ($erroresCrit -gt 0) {
    Write-Host ""
    Write-Host "  FAIL $erroresCrit error(es) critico(s). Descarga el proyecto completo." -ForegroundColor Red
    Write-Setup "Setup abortado — $erroresCrit errores criticos" "ERROR" "Red"
    exit 1
}

# ============================================================
# [3] DESBLOQUEAR SCRIPTS
# ============================================================
Write-Host ""
Write-Host "[3/7] Desbloqueando scripts..." -ForegroundColor Yellow

$scripts = Get-ChildItem -Path $proyectoRoot -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue
if ($scripts.Count -gt 0) {
    try {
        $scripts | Unblock-File -ErrorAction Stop
        Write-Setup "  OK  $($scripts.Count) script(s) desbloqueados" "SUCCESS" "Green"
    } catch {
        Write-Setup "  WARN No se pudieron desbloquear algunos scripts: $($_.Exception.Message)" "WARNING" "Yellow"
        $advertencias++
    }
} else {
    Write-Setup "  WARN No se encontraron scripts .ps1" "WARNING" "Yellow"
    $advertencias++
}

# ============================================================
# [4] REPARAR ENCODING
# ============================================================
Write-Host ""
Write-Host "[4/7] Reparando codificacion de caracteres..." -ForegroundColor Yellow

if ($SkipEncoding) {
    Write-Setup "  INFO Omitido (-SkipEncoding)" "INFO" "Gray"
} else {
    $fixPath = Join-Path $proyectoRoot "fix-encoding.ps1"
    if (Test-Path $fixPath) {
        try {
            $fixOutput = & $fixPath -Force 2>&1
            $fixOutput | ForEach-Object { Add-Content -Path $setupLog -Value "[fix-encoding] $_" -Encoding UTF8 -ErrorAction SilentlyContinue }
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                Write-Setup "  WARN fix-encoding termino con errores (codigo $LASTEXITCODE) — revisa $setupLog" "WARNING" "Yellow"
                $advertencias++
            } else {
                Write-Setup "  OK  Encoding reparado" "SUCCESS" "Green"
            }
        } catch {
            Write-Setup "  WARN fix-encoding.ps1 fallo: $($_.Exception.Message)" "WARNING" "Yellow"
            Write-Setup "       Los scripts pueden tener caracteres corruptos" "WARNING" "Yellow"
            $advertencias++
        }
    } else {
        Write-Setup "  INFO fix-encoding.ps1 no encontrado — omitiendo" "INFO" "Gray"
    }
}

# ============================================================
# [5] POLITICA DE EJECUCION
# Se verifica en LocalMachine (global) no en CurrentUser del admin
# ============================================================
Write-Host ""
Write-Host "[5/7] Verificando politica de ejecucion..." -ForegroundColor Yellow

if ($SkipPolicy) {
    Write-Setup "  INFO Omitido (-SkipPolicy)" "INFO" "Gray"
} else {
    $polMachine = Get-ExecutionPolicy -Scope LocalMachine -EA SilentlyContinue
    $polUser    = Get-ExecutionPolicy -Scope CurrentUser  -EA SilentlyContinue
    $polEfect   = Get-ExecutionPolicy
    Write-Setup "  INFO LocalMachine : $polMachine" "INFO" "Gray"
    Write-Setup "  INFO CurrentUser  : $polUser"    "INFO" "Gray"
    Write-Setup "  INFO Efectiva     : $polEfect"   "INFO" "Gray"

    if ($polEfect -eq "Restricted") {
        Write-Setup "  WARN Politica Restricted — los scripts no podran ejecutarse" "WARNING" "Yellow"
        $confirm = Read-Host "  Cambiar LocalMachine a RemoteSigned? (S/N)"
        if ($confirm -in 'S','s') {
            try {
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -EA Stop
                Write-Setup "  OK  LocalMachine cambiado a RemoteSigned" "SUCCESS" "Green"
            } catch {
                Write-Setup "  FAIL No se pudo cambiar la politica: $($_.Exception.Message)" "ERROR" "Red"
                $advertencias++
            }
        } else {
            Write-Setup "  WARN Politica no cambiada. Los scripts pueden no ejecutarse." "WARNING" "Yellow"
            $advertencias++
        }
    } else {
        Write-Setup "  OK  Politica efectiva: $polEfect" "SUCCESS" "Green"
    }
}

# ============================================================
# [6] CREAR CARPETAS DE TRABAJO
# Se ejecuta DESPUES de verificar integridad del proyecto
# ============================================================
Write-Host ""
Write-Host "[6/7] Creando carpetas de trabajo..." -ForegroundColor Yellow

$carpetasTrabajo = @("Logs", "Reports", "Backups", "Data")
foreach ($dir in $carpetasTrabajo) {
    $dirPath = Join-Path $proyectoRoot $dir
    if (-not (Test-Path $dirPath)) {
        try {
            New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
            Write-Setup "  OK  Creada: $dir\" "SUCCESS" "Green"
        } catch {
            Write-Setup "  FAIL No se pudo crear $dir\: $($_.Exception.Message)" "ERROR" "Red"
            $advertencias++
        }
    } else {
        Write-Setup "  INFO Ya existe: $dir\" "INFO" "Gray"
    }
}

# ============================================================
# [7] VERIFICAR 00-Config.ps1 Y cis-controls.json
# Cargar config y confirmar que los controles CIS se generan
# ============================================================
Write-Host ""
Write-Host "[7/7] Verificando configuracion y controles CIS..." -ForegroundColor Yellow

$configPath = Join-Path $proyectoRoot "00-Config.ps1"
if (Test-Path $configPath) {
    try {
        . $configPath -ErrorAction Stop
        if ($global:ProjectRoot) {
            Write-Setup "  OK  00-Config.ps1 cargado — ProjectRoot: $global:ProjectRoot" "SUCCESS" "Green"
        }
        if ($global:CISControls -and $global:CISControls.Count -gt 0) {
            Write-Setup "  OK  $($global:CISControls.Count) categorias CIS cargadas" "SUCCESS" "Green"
        } else {
            Write-Setup "  WARN CISControls vacio tras cargar 00-Config.ps1" "WARNING" "Yellow"
            $advertencias++
        }
        $jsonPath = Join-Path $proyectoRoot "Data\cis-controls.json"
        if (Test-Path $jsonPath) {
            Write-Setup "  OK  cis-controls.json existe" "SUCCESS" "Green"
        } else {
            Write-Setup "  INFO cis-controls.json se creara en la primera ejecucion de 01-Main.ps1" "INFO" "Gray"
        }
    } catch {
        Write-Setup "  WARN No se pudo cargar 00-Config.ps1: $($_.Exception.Message)" "WARNING" "Yellow"
        $advertencias++
    }
}

# ============================================================
# RESUMEN FINAL
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($erroresCrit -eq 0 -and $advertencias -eq 0) {
    Write-Host "  CONFIGURACION COMPLETADA SIN ERRORES" -ForegroundColor Green
} elseif ($erroresCrit -eq 0) {
    Write-Host "  CONFIGURACION COMPLETADA CON $advertencias ADVERTENCIA(S)" -ForegroundColor Yellow
} else {
    Write-Host "  CONFIGURACION FALLIDA — $erroresCrit ERROR(ES) CRITICO(S)" -ForegroundColor Red
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Proximos pasos:" -ForegroundColor White
Write-Host ""
Write-Host "    .\01-Main.ps1 -Mode PretestOnly   # Auditar sin cambios"    -ForegroundColor Cyan
Write-Host "    .\01-Main.ps1 -Mode Full -WhatIf  # Simular hardening"      -ForegroundColor Cyan
Write-Host "    .\01-Main.ps1 -Mode Full           # Flujo completo"         -ForegroundColor Cyan
Write-Host ""
Write-Host "  Scripts adicionales disponibles:" -ForegroundColor White
Write-Host ""

$setupLimitedPath = Join-Path $proyectoRoot "Setup-LimitedUser.ps1"
if (Test-Path $setupLimitedPath) {
    Write-Host "    .\Setup-LimitedUser.ps1            # Crear usuario limitado para pruebas" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  Log de esta sesion: $setupLog" -ForegroundColor Gray
Write-Host ""

Write-Setup "Setup finalizado — errores: $erroresCrit, advertencias: $advertencias" $(if($erroresCrit -gt 0){"ERROR"}elseif($advertencias -gt 0){"WARNING"}else{"SUCCESS"}) "Gray"
