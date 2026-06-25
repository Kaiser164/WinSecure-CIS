#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Repara automaticamente la codificacion de todos los scripts .ps1 del proyecto.

.DESCRIPTION
    Convierte archivos corruptos a UTF-8 con BOM y restaura caracteres especiales
    danados durante la descarga o transferencia.

    CORRECCIONES APLICADAS (auditoria):
      - FIX-C1: Se excluye a si mismo y a setup.ps1 del procesamiento.
      - FIX-C2: Agrega #Requires -RunAsAdministrator.
      - FIX-A1: Tabla de reemplazos ordenada: especificos ANTES que genericos.
      - FIX-A2: Get-Content con -Encoding Byte para leer el archivo sin interpretacion.
      - FIX-A3: Usa [string]::Contains() en lugar de -match para evitar colisiones regex.
      - FIX-M1: Crea backup .bak antes de sobreescribir cada archivo.
      - FIX-B1: Eliminada entrada 'Axc3xa1' (estaba marcada como inactiva).
                'Ã' eliminado del mapeo final — era demasiado agresivo (prefijo
                de todas las vocales con tilde). Secuencias no reconocidas se
                dejan intactas para revision manual en lugar de destruirse.

.EXAMPLE
    .\fix-encoding.ps1

.EXAMPLE
    .\fix-encoding.ps1 -Force

.NOTES
    Compatible con PowerShell 5.1 y 7+
    Requiere permisos de administrador (escribe archivos protegidos del proyecto)
#>

param([switch]$Force)

$proyectoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$thisScript   = $MyInvocation.MyCommand.Path

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Reparando codificacion del proyecto"   -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Ruta: $proyectoRoot" -ForegroundColor Gray
Write-Host ""

# FIX-A1: Tabla ordenada de especifico a generico.
# Las entradas mas largas deben reemplazarse ANTES que las mas cortas
# para evitar que "A" consuma el inicio de "Axba1" antes de procesarlo.
# Usamos un array ordenado de pares, no un hashtable (que no garantiza orden).
$reemplazos = [ordered]@{
    # Secuencias multibyte especificas (deben ir PRIMERO)
    'Axe2x80x94' = '--'  # em dash corrupto
    # Vocales con tilde (secuencias 2-byte UTF-8 leidas como Latin-1)
    'Axc3xa9' = 'e'
    'Axc3xad' = 'i'
    'Axc3xb3' = 'o'
    'Axc3xba' = 'u'
    'Axc3xb1' = 'n'   # n~
    'Axc3x91' = 'N'   # N~
    'Axc3xbc' = 'u'   # u con dieresis
    'Axc3x93' = 'O'
    'Axc3x89' = 'E'
    # Representaciones mojibake tipicas (Latin-1 sobre UTF-8)
    'Ã¡' = 'á'
    'Ã©' = 'é'
    'Ã­' = 'í'
    'Ã³' = 'ó'
    'Ãº' = 'ú'
    'Ã±' = 'ñ'
    'Ã''' = 'Ñ'
    'Ã¼' = 'ü'
    'Ã"' = 'Ó'
    'Ã‰' = 'É'
    'Â¿' = '¿'
    'Â¡' = '¡'
    'â€"' = '-'
    'Â©' = '(c)'
    # FIX-A1: 'Â' va AL FINAL — es prefijo de las anteriores.
    # 'Ã' se omite intencionalmente: es prefijo de todas las vocales con tilde.
    # Si llega aqui significa que habia una secuencia no reconocida — se deja
    # intacta para que sea visible en revision manual en lugar de destruirla.
    'Â' = ''
}

# FIX-C1: Excluir este script y setup.ps1 del procesamiento.
# Procesar fix-encoding.ps1 sobre si mismo puede corromperse si sus
# propios mensajes de consola contienen caracteres que estan en la tabla.
$scriptsExcluidos = @(
    $thisScript
    (Join-Path $proyectoRoot "setup.ps1")
)

$archivos = Get-ChildItem -Path $proyectoRoot -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue |
            Where-Object { $scriptsExcluidos -notcontains $_.FullName }

if ($archivos.Count -eq 0) {
    Write-Host "  No se encontraron archivos .ps1 para procesar." -ForegroundColor Yellow
    exit 0
}

Write-Host "  $($archivos.Count) archivo(s) a procesar (fix-encoding.ps1 y setup.ps1 excluidos)" -ForegroundColor Yellow
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "Proceder con la reparacion? (S/N)"
    if ($confirm -ne 'S' -and $confirm -ne 's') {
        Write-Host "Operacion cancelada." -ForegroundColor Red
        exit 0
    }
}

$archivosReparados = 0
$archivosNormales  = 0
$archivosError     = 0

foreach ($archivo in $archivos) {
    Write-Host "  Procesando: $($archivo.Name)" -ForegroundColor Gray

    # FIX-A2: Leer como texto con encoding explicito.
    # En PS 5.1, -Encoding Default usa la codepage del sistema (ANSI/CP1252).
    # Para detectar mojibake UTF-8-sobre-Latin1, leemos con UTF8 para ver
    # exactamente como llegaron los bytes al disco.
    try {
        $contenido = [System.IO.File]::ReadAllText($archivo.FullName, [System.Text.Encoding]::UTF8)
    }
    catch {
        Write-Host "    WARN No se pudo leer: $($_.Exception.Message)" -ForegroundColor Yellow
        $archivosError++
        continue
    }

    $modificado = $false

    # FIX-A3: [string]::Contains en lugar de -match.
    # -match interpreta el patron como regex: caracteres como â€" contienen
    # bytes que pueden ser meta-caracteres de regex y dar falsos positivos.
    foreach ($corrupto in $reemplazos.Keys) {
        if ($contenido.Contains($corrupto)) {
            $contenido = $contenido.Replace($corrupto, $reemplazos[$corrupto])
            $modificado = $true
        }
    }

    # FIX-M1: Crear backup .bak antes de sobreescribir.
    # Si el proceso se interrumpe, el original queda recuperable.
    if ($modificado) {
        $backupPath = $archivo.FullName + ".bak"
        try {
            Copy-Item -Path $archivo.FullName -Destination $backupPath -Force -ErrorAction Stop
        }
        catch {
            Write-Host "    WARN No se pudo crear backup, omitiendo: $($_.Exception.Message)" -ForegroundColor Yellow
            $archivosError++
            continue
        }
    }

    # Escribir siempre con UTF-8 + BOM (requerido por PS 5.1)
    try {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($archivo.FullName, $contenido, $utf8Bom)

        if ($modificado) {
            Write-Host "    OK Reparado: $($archivo.Name)" -ForegroundColor Green
            $archivosReparados++
        } else {
            Write-Host "    OK Normalizado (sin cambios de contenido): $($archivo.Name)" -ForegroundColor Gray
            $archivosNormales++
        }
    }
    catch {
        Write-Host "    FAIL No se pudo escribir: $($_.Exception.Message)" -ForegroundColor Red
        $archivosError++
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  REPARACION COMPLETADA"                 -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Reparados   : $archivosReparados archivo(s)" -ForegroundColor Green
Write-Host "  Normalizados: $archivosNormales archivo(s)"  -ForegroundColor Gray
Write-Host "  Errores     : $archivosError archivo(s)"     -ForegroundColor $(if ($archivosError -gt 0) { 'Red' } else { 'Gray' })
Write-Host "  Total       : $($archivos.Count) archivo(s)" -ForegroundColor Yellow
if ($archivosReparados -gt 0) {
    Write-Host ""
    Write-Host "  Backups .bak creados junto a cada archivo reparado." -ForegroundColor Gray
    Write-Host "  Puedes eliminarlos con: Get-ChildItem -Recurse -Filter *.bak | Remove-Item" -ForegroundColor Gray
}
Write-Host "========================================" -ForegroundColor Cyan

exit $(if ($archivosError -gt 0) { 1 } else { 0 })
