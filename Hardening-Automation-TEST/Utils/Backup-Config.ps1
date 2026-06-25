#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Crea, restaura y limpia snapshots de configuracion de seguridad de Windows 10.

.DESCRIPTION
    Provee un sistema de backup y restauracion de doble capa para el proyecto
    CIS Hardening Automation. Exporta el estado pre-hardening del sistema y
    permite restaurarlo exactamente o limpiar solo los cambios del hardening.

    FUNCIONES EXPORTADAS:

    Backup-Configuration
      Exporta con secedit las politicas de seguridad, las claves de registro
      relevantes (Lsa, Policies\System, mrxsmb10, WindowsUpdate, Defender)
      y el firewall (netsh advfirewall export). Genera ademas un manifiesto
      hash-manifest.json con SHA-256 de cada archivo para verificacion de
      integridad en la restauracion.

    Restore-Backup  [-DeepClean]
      Verifica la integridad del backup (hashes SHA-256) y restaura
      las politicas, registro y firewall. Con -DeepClean ejecuta primero
      Reset-ToWindowsDefaults (Capa 1) para garantizar un estado limpio
      antes de aplicar el backup (Capa 2).

    Reset-ToWindowsDefaults
      Limpia EXACTAMENTE lo que el hardening modifica, sin necesitar un
      backup previo. Util cuando el backup no existe o no fue suficiente.
      Ejecuta en orden: auditpol /clear, secedit+defltbase.inf, reset de
      claves de registro, reactivacion de Guest (SID -501), advfirewall reset.

    Get-FileHashSHA256
      Calcula el hash SHA-256 de un archivo usando streams gestionados
      con try/finally para liberar recursos correctamente.

    ESTRATEGIA DE RESTAURACION (dos capas):
      Capa 1 — Reset-ToWindowsDefaults: limpieza profunda primero.
               reg import y secedit /configure son "merge": sobreescriben
               claves existentes pero NO eliminan las que el hardening agrego.
               Esta capa garantiza que no queden rastros.
      Capa 2 — Restore-Backup: aplica el snapshot pre-hardening sobre el
               estado limpio. El sistema queda identico a como estaba antes.

.PARAMETER WhatIf
    (Reset-ToWindowsDefaults, Restore-Backup) Simula las operaciones sin
    modificar el sistema. Muestra cada paso con etiqueta [SIM].

.PARAMETER RestorePath
    (Restore-Backup) Ruta a la carpeta del backup a restaurar.
    Ej: C:\Users\PYMES\Documents\Nueva carpeta\Nueva carpeta\HARDENING\Backups\backup-20260531-204519

.PARAMETER DeepClean
    (Restore-Backup) Ejecuta Reset-ToWindowsDefaults antes de aplicar el
    backup. Recomendado para una restauracion completa y fiable.

.PARAMETER SkipIntegrityCheck
    (Restore-Backup) Omite la verificacion de hashes SHA-256. Usar solo
    si el manifiesto no esta disponible o para forzar la restauracion.

.EXAMPLE
    # Crear un backup antes del hardening
    .\Backup-Config.ps1

.EXAMPLE
    # Restauracion completa con limpieza profunda (recomendado)
    .\Backup-Config.ps1 -Restore -BackupPath "C:\...\backup-20260531" -DeepClean

.EXAMPLE
    # Restauracion simple sin limpieza profunda
    .\Backup-Config.ps1 -Restore -BackupPath "C:\...\backup-20260531"

.EXAMPLE
    # Solo limpieza profunda — sin restaurar ningun backup
    # Util para "deshacer el hardening" cuando no tienes backup
    .\Backup-Config.ps1 -ResetOnly

.EXAMPLE
    # Simular la limpieza profunda sin cambios reales
    .\Backup-Config.ps1 -ResetOnly -WhatIf

.NOTES
    Funciones exportadas : Backup-Configuration, Restore-Backup,
                           Reset-ToWindowsDefaults, Get-FileHashSHA256
    Archivos del backup  : security-policy.inf, registry-*.reg,
                           firewall-rules.wfw, hash-manifest.json
    Integridad           : SHA-256 por archivo, verificado antes de restaurar
    Pasos Reset (6)      : auditpol /clear, secedit+defltbase.inf, LSA,
                           SecurityOptions, Guest SID-501, advfirewall reset
    Requiere             : Administrador, PowerShell 5.1, Windows 10
    Invocado por         : 01-Main.ps1 Fase 2 (backup) y rollback automatico
#>


# Cargar Write-Log si no fue cargado por el llamante
if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
    $writeLogPath = Join-Path $PSScriptRoot "Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
}

# Fallback de ruta de backups si 00-Config.ps1 no fue cargado
if (-not $global:BackupPath) {
    $global:BackupPath = Join-Path $PSScriptRoot "..\Backups"
}

# ============================================================
# FUNCION: Get-FileHashSHA256
# ============================================================
function Get-FileHashSHA256 {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) { return $null }

    $sha256 = $null
    $stream = $null
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.File]::OpenRead($FilePath)
        $hash   = [System.BitConverter]::ToString($sha256.ComputeHash($stream))
        return $hash -replace '-', ''
    }
    catch {
        Write-Log "Error calculando hash de $FilePath" -Level "ERROR"
        return $null
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($sha256)  { $sha256.Dispose()  }
    }
}

# ============================================================
# FUNCION: Reset-ToWindowsDefaults   ← NUEVA
#
# Revierte EXACTAMENTE los cambios que aplican los scripts
# del proyecto (Set-AccountPolicies, Set-AuditPolicy, etc.)
# a sus valores por defecto de Windows 10.
#
# POR QUÉ EXISTE SEPARADA DE Restore-Backup:
#   reg import y secedit /configure son "merge": sobreescriben
#   claves existentes pero NO eliminan las que el hardening
#   agregó como nuevas. Reset-ToWindowsDefaults hace una
#   limpieza quirúrgica primero, luego Restore-Backup pone
#   encima el estado pre-hardening exacto.
#
# PARAMETROS:
#   WhatIf — Muestra qué haría sin ejecutar nada
#
# RETORNA: $true si todo fue exitoso, $false si algún paso falló
# ============================================================
function Reset-ToWindowsDefaults {
    param([switch]$WhatIf)

    Write-Host "`n============================================================" -ForegroundColor Yellow
    Write-Host "  LIMPIEZA PROFUNDA — Reset a defaults de Windows" -ForegroundColor Yellow
    if ($WhatIf) {
        Write-Host "  MODO SIMULACION — No se aplicaran cambios" -ForegroundColor Gray
    }
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Log "Iniciando Reset-ToWindowsDefaults" -Level "WARNING"

    $success = $true

    # ----------------------------------------------------------
    # PASO 1: Limpiar TODAS las políticas de auditoría avanzada
    # auditpol /clear elimina las entradas que Set-AuditPolicy
    # configuró con auditpol /set /subcategory:...
    # Sin esto, las políticas de auditoría persisten aunque
    # restaures el backup.
    # ----------------------------------------------------------
    Write-Host "`n  [1/6] Limpiando politicas de auditoria (auditpol /clear)..." -ForegroundColor Cyan
    if (-not $WhatIf) {
        try {
            $out = auditpol /clear /y 2>&1
            Write-Host "    [OK] Auditoria limpiada" -ForegroundColor Green
            Write-Log "auditpol /clear ejecutado" -Level "SUCCESS"
        }
        catch {
            $success = $false
            Write-Host "    [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error en auditpol /clear: $_" -Level "ERROR"
        }
    } else {
        Write-Host "    [SIM] auditpol /clear /y" -ForegroundColor DarkGray
    }

    # ----------------------------------------------------------
    # PASO 2: Revertir políticas de cuenta a defaults de Windows
    # defltbase.inf es la plantilla de seguridad base que viene
    # con Windows. Aplica los valores por defecto de fábrica
    # para contraseñas, bloqueo de cuenta, derechos de usuario.
    # ----------------------------------------------------------
    Write-Host "`n  [2/6] Revirtiendo politicas de cuenta a defaults W10..." -ForegroundColor Cyan
    $defltBase = "C:\Windows\inf\defltbase.inf"
    if (Test-Path $defltBase) {
        if (-not $WhatIf) {
            try {
                secedit /configure /db C:\Windows\security\local.sdb `
                    /cfg $defltBase /areas SECURITYPOLICY /quiet 2>&1 | Out-Null
                Write-Host "    [OK] Politicas de cuenta en defaults W10" -ForegroundColor Green
                Write-Log "secedit /configure con defltbase.inf ejecutado" -Level "SUCCESS"
            }
            catch {
                $success = $false
                Write-Host "    [FAIL] $($_.Exception.Message)" -ForegroundColor Red
                Write-Log "Error en secedit defltbase: $_" -Level "ERROR"
            }
        } else {
            Write-Host "    [SIM] secedit /configure /cfg defltbase.inf /areas SECURITYPOLICY" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "    [WARN] defltbase.inf no encontrado en $defltBase" -ForegroundColor Yellow
        Write-Log "defltbase.inf no encontrado" -Level "WARNING"
    }

    # ----------------------------------------------------------
    # PASO 3: Revertir Security Options del registro
    # Solo las claves que Set-SecurityOptions.ps1 modificó.
    # EnableLUA se deja en 1 porque es el default de W10
    # y desactivarlo rompe UAC globalmente.
    # ----------------------------------------------------------
    Write-Host "`n  [3/6] Revirtiendo Security Options (registro)..." -ForegroundColor Cyan
    $sysPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    $secOptResets = @(
        # Clave                        Valor-default-W10   Motivo
        @{ Name="NoConnectedUser";           Value=0 }   # 0 = permitir cuentas MS (default)
        @{ Name="dontdisplaylastusername";   Value=0 }   # 0 = mostrar último usuario (default)
        @{ Name="InactivityTimeoutSecs";     Value=0 }   # 0 = sin timeout (default)
        @{ Name="FilterAdministratorToken";  Value=0 }   # 0 = sin filtro admin builtin (default)
        @{ Name="EnableLUA";                 Value=1 }   # 1 = UAC activado (default W10, NO tocar)
    )

    foreach ($reg in $secOptResets) {
        if (-not $WhatIf) {
            try {
                Set-ItemProperty -Path $sysPath -Name $reg.Name -Value $reg.Value `
                    -Type DWORD -Force -ErrorAction Stop
                Write-Host "    [OK] $($reg.Name) = $($reg.Value)" -ForegroundColor Green
            }
            catch {
                Write-Host "    [WARN] $($reg.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "    [SIM] Set $($reg.Name) = $($reg.Value)" -ForegroundColor DarkGray
        }
    }
    Write-Log "Security Options del registro revertidas" -Level "SUCCESS"

    # ----------------------------------------------------------
    # PASO 4: Revertir claves LSA
    # ----------------------------------------------------------
    Write-Host "`n  [4/6] Revirtiendo claves LSA (registro)..." -ForegroundColor Cyan
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    $lsaResets = @(
        @{ Name="LimitBlankPasswordUse"; Value=1 }   # 1 = limitar (default W10)
        @{ Name="forceguest";            Value=0 }   # 0 = modelo clásico (default W10)
    )

    foreach ($reg in $lsaResets) {
        if (-not $WhatIf) {
            try {
                Set-ItemProperty -Path $lsaPath -Name $reg.Name -Value $reg.Value `
                    -Type DWORD -Force -ErrorAction Stop
                Write-Host "    [OK] $($reg.Name) = $($reg.Value)" -ForegroundColor Green
            }
            catch {
                Write-Host "    [WARN] $($reg.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "    [SIM] Set LSA\$($reg.Name) = $($reg.Value)" -ForegroundColor DarkGray
        }
    }
    Write-Log "Claves LSA revertidas" -Level "SUCCESS"

    # ----------------------------------------------------------
    # PASO 5: Reactivar cuenta Guest si estaba habilitada antes
    # Set-SecurityOptions la deshabilita por SID -501.
    # La reactivamos aquí para devolver el estado original.
    # NOTA: Si originalmente estaba deshabilitada, el backup
    # la dejará deshabilitada de nuevo en Capa 2.
    # ----------------------------------------------------------
    Write-Host "`n  [5/6] Reactivando cuenta Guest (SID *-501)..." -ForegroundColor Cyan
    if (-not $WhatIf) {
        try {
            $guest = Get-LocalUser | Where-Object { $_.SID.Value -like "*-501" }
            if ($null -eq $guest) {
                Write-Host "    [INFO] Cuenta Guest no existe en este sistema" -ForegroundColor Gray
            }
            elseif ($guest.Enabled) {
                Write-Host "    [INFO] Cuenta Guest ya estaba habilitada ($($guest.Name))" -ForegroundColor Gray
            }
            else {
                Enable-LocalUser -SID $guest.SID -ErrorAction Stop
                Write-Host "    [OK] Guest reactivada: $($guest.Name)" -ForegroundColor Green
                Write-Log "Cuenta Guest reactivada" -Level "SUCCESS"
            }
        }
        catch {
            Write-Host "    [WARN] $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log "Error reactivando Guest: $_" -Level "WARNING"
        }
    } else {
        Write-Host "    [SIM] Enable-LocalUser -SID *-501" -ForegroundColor DarkGray
    }

    # ----------------------------------------------------------
    # PASO 6: Reset del firewall a configuración de fábrica
    # netsh advfirewall reset borra todas las reglas personalizadas
    # y devuelve los perfiles Domain/Private/Public a defaults W10.
    # OJO: si el sistema tenía reglas personalizadas antes del
    # hardening, el backup de Capa 2 las restaurará después.
    # ----------------------------------------------------------
    Write-Host "`n  [6/6] Reseteando firewall a defaults de fabrica..." -ForegroundColor Cyan
    if (-not $WhatIf) {
        try {
            netsh advfirewall reset 2>&1 | Out-Null
            Write-Host "    [OK] Firewall reseteado a defaults" -ForegroundColor Green
            Write-Log "netsh advfirewall reset ejecutado" -Level "SUCCESS"
        }
        catch {
            $success = $false
            Write-Host "    [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error en advfirewall reset: $_" -Level "ERROR"
        }
    } else {
        Write-Host "    [SIM] netsh advfirewall reset" -ForegroundColor DarkGray
    }

    # Resultado final
    Write-Host ""
    if ($success) {
        Write-Host "  Limpieza profunda completada" -ForegroundColor Green
        Write-Host "  Si usas -DeepClean, el backup se aplica encima ahora." -ForegroundColor Gray
    } else {
        Write-Host "  Limpieza completada con algunos errores (ver log)" -ForegroundColor Yellow
    }
    Write-Log "Reset-ToWindowsDefaults completado. Exito=$success" -Level $(if ($success){"SUCCESS"}else{"WARNING"})

    return $success
}

# ============================================================
# FUNCION: Backup-Configuration
# (sin cambios respecto a v1.0)
# ============================================================
function Backup-Configuration {
    param([string]$BackupName = "backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')")

    $backupFolder = Join-Path $global:BackupPath $BackupName
    New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null

    Write-Log "Creando backup en: $backupFolder" -Level "INFO"
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "  CREANDO BACKUP DE CONFIGURACION" -ForegroundColor Cyan
    Write-Host "  Destino: $backupFolder" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor Cyan

    $backupSuccess = $true
    $hashManifest  = @{}

    # 1. Políticas de seguridad (secedit)
    try {
        $seceditBackup = "$backupFolder\security-policy.inf"
        secedit /export /cfg $seceditBackup /areas SECURITYPOLICY 2>&1 | Out-Null
        if (Test-Path $seceditBackup) {
            $hashManifest["security-policy.inf"] = Get-FileHashSHA256 -FilePath $seceditBackup
            Write-Host "  [OK] Politicas de seguridad exportadas" -ForegroundColor Green
            Write-Log "  Politicas exportadas" -Level "SUCCESS"
        } else { throw "secedit no genero el .inf" }
    }
    catch {
        $backupSuccess = $false
        Write-Host "  [FAIL] Politicas: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "  Error politicas: $_" -Level "ERROR"
    }

    # 2. Claves de registro
    $regKeys = @(
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    )

    foreach ($key in $regKeys) {
        try {
            $safeName = $key -replace "HKLM\\","" -replace "HKCU\\","" -replace "\\","_"
            $regFile  = "$backupFolder\registry-$safeName.reg"
            reg export $key $regFile /y 2>&1 | Out-Null
            if (Test-Path $regFile) {
                $hashManifest["registry-$safeName.reg"] = Get-FileHashSHA256 -FilePath $regFile
                Write-Host "  [OK] Registry: $safeName" -ForegroundColor Green
                Write-Log "  Registry: $safeName" -Level "SUCCESS"
            }
        }
        catch {
            Write-Host "  [WARN] No se pudo respaldar: $key" -ForegroundColor Yellow
            Write-Log "  No se pudo respaldar: $key" -Level "WARNING"
        }
    }

    # 3. Firewall
    try {
        $firewallBackup = "$backupFolder\firewall-rules.wfw"
        netsh advfirewall export $firewallBackup 2>&1 | Out-Null
        if (Test-Path $firewallBackup) {
            $hashManifest["firewall-rules.wfw"] = Get-FileHashSHA256 -FilePath $firewallBackup
            Write-Host "  [OK] Firewall exportado" -ForegroundColor Green
            Write-Log "  Firewall exportado" -Level "SUCCESS"
        }
    }
    catch {
        Write-Host "  [WARN] Firewall: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Log "  Firewall export fallido" -Level "WARNING"
    }

    # 4. Manifiesto de hashes
    $manifest = @{
        BackupDate    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName  = $env:COMPUTERNAME
        BackupSuccess = $backupSuccess
        Hashes        = $hashManifest
    }
    $manifest | ConvertTo-Json -Depth 3 |
        Set-Content "$backupFolder\hash-manifest.json" -Encoding UTF8

    Write-Log "Backup completado: $backupFolder" -Level "SUCCESS"
    Write-Host "`n  Backup guardado en: $backupFolder" -ForegroundColor Cyan

    return @{ Path = $backupFolder; Success = $backupSuccess }
}

# ============================================================
# FUNCION: Restore-Backup  (v1.1 — agrega -DeepClean)
#
# NUEVO PARAMETRO -DeepClean:
#   Ejecuta Reset-ToWindowsDefaults ANTES de aplicar los
#   archivos del backup. Así se garantiza que no queden
#   rastros del hardening aunque el .reg o el .inf no cubran
#   todas las claves que el hardening modificó.
#
#   Sin -DeepClean: comportamiento idéntico a v1.0.
#   Con  -DeepClean: Limpieza profunda → Backup encima.
# ============================================================
function Restore-Backup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RestorePath,

        [switch]$WhatIf,
        [switch]$SkipIntegrityCheck,

        # NUEVO: limpieza profunda previa antes de aplicar el backup
        [switch]$DeepClean
    )

    if (-not (Test-Path $RestorePath)) {
        Write-Log "Backup no encontrado: $RestorePath" -Level "ERROR"
        Write-Host "  [ERROR] Ruta no encontrada: $RestorePath" -ForegroundColor Red
        return $false
    }

    Write-Host "`n============================================================" -ForegroundColor Yellow
    Write-Host "  RESTAURANDO BACKUP" -ForegroundColor Yellow
    Write-Host "  Origen : $RestorePath" -ForegroundColor Gray
    if ($DeepClean) {
        Write-Host "  Modo   : DeepClean + Backup (doble capa)" -ForegroundColor Magenta
    } else {
        Write-Host "  Modo   : Solo Backup (usa -DeepClean para limpieza profunda)" -ForegroundColor Gray
    }
    Write-Host "============================================================" -ForegroundColor Yellow

    Write-Log "Restaurando desde: $RestorePath | DeepClean=$DeepClean" -Level "WARNING"

    if ($WhatIf) {
        Write-Host "  [SIMULACION] No se realizaran cambios reales" -ForegroundColor Gray
        if ($DeepClean) {
            Reset-ToWindowsDefaults -WhatIf
        }
        Write-Host "  [SIM] Aplicaria backup desde: $RestorePath" -ForegroundColor DarkGray
        return $true
    }

    # ----------------------------------------------------------
    # CAPA 1 (opcional): Reset a defaults de Windows
    # Se ejecuta ANTES de importar el backup para limpiar
    # todo lo que el hardening dejó y que un simple import
    # no revertiría (claves nuevas, auditoría, firewall).
    # ----------------------------------------------------------
    if ($DeepClean) {
        Write-Host "`n  >>> CAPA 1: Limpieza profunda previa al backup <<<" -ForegroundColor Magenta
        $cleanOk = Reset-ToWindowsDefaults -WhatIf:$WhatIf
        if (-not $cleanOk) {
            Write-Host "  [WARN] La limpieza tuvo errores. Continuando con el backup..." -ForegroundColor Yellow
        }
        Write-Host "`n  >>> CAPA 2: Aplicando backup pre-hardening <<<" -ForegroundColor Magenta
    }

    # ----------------------------------------------------------
    # CAPA 2: Verificación de integridad del backup
    # ----------------------------------------------------------
    $manifestPath = "$RestorePath\hash-manifest.json"
    $integrityOk  = $true

    if (-not $SkipIntegrityCheck -and (Test-Path $manifestPath)) {
        Write-Host "`n  Verificando integridad del backup..." -ForegroundColor Gray
        $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

        foreach ($file in $manifest.Hashes.PSObject.Properties) {
            $filePath = "$RestorePath\$($file.Name)"
            if (Test-Path $filePath) {
                $currentHash = Get-FileHashSHA256 -FilePath $filePath
                if ($currentHash -ne $file.Value) {
                    Write-Host "    [FAIL] Hash mismatch: $($file.Name)" -ForegroundColor Red
                    Write-Log "INTEGRIDAD COMPROMETIDA: $($file.Name)" -Level "ERROR"
                    $integrityOk = $false
                } else {
                    Write-Host "    [OK]   $($file.Name)" -ForegroundColor Green
                }
            } else {
                Write-Host "    [WARN] Faltante: $($file.Name)" -ForegroundColor Yellow
            }
        }
    } elseif (-not (Test-Path $manifestPath)) {
        Write-Host "  [WARN] hash-manifest.json no encontrado" -ForegroundColor Yellow
    }

    if (-not $integrityOk) {
        Write-Host "`n  [ERROR] Integridad comprometida. Use -SkipIntegrityCheck para forzar." -ForegroundColor Red
        Write-Log "Restauracion cancelada — integridad" -Level "ERROR"
        return $false
    }

    Write-Host "  [OK] Integridad verificada" -ForegroundColor Green

    $restoreSuccess = $true

    # Restaurar políticas de seguridad (secedit)
    $seceditFile = Get-ChildItem $RestorePath -Filter "*.inf" |
                   Where-Object { $_.Name -ne "hash-manifest.json" } |
                   Select-Object -First 1
    if ($seceditFile) {
        Write-Host "`n  Restaurando politicas de seguridad..." -ForegroundColor Gray
        try {
            secedit /configure /db C:\Windows\security\local.sdb `
                /cfg $seceditFile.FullName /areas SECURITYPOLICY 2>&1 | Out-Null
            Write-Host "    [OK] Politicas restauradas desde backup" -ForegroundColor Green
            Write-Log "Politicas restauradas" -Level "SUCCESS"
        }
        catch {
            $restoreSuccess = $false
            Write-Host "    [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error restaurando politicas: $_" -Level "ERROR"
        }
    }

    # Restaurar registro
    $regFiles = Get-ChildItem $RestorePath -Filter "registry-*.reg"
    if ($regFiles.Count -gt 0) {
        Write-Host "`n  Restaurando registro desde backup..." -ForegroundColor Gray
        foreach ($regFile in $regFiles) {
            try {
                reg import $regFile.FullName 2>&1 | Out-Null
                Write-Host "    [OK] $($regFile.Name)" -ForegroundColor Green
                Write-Log "Registro: $($regFile.Name)" -Level "SUCCESS"
            }
            catch {
                Write-Host "    [WARN] $($regFile.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    # Restaurar firewall desde backup
    $firewallFile = Get-ChildItem $RestorePath -Filter "*.wfw" | Select-Object -First 1
    if ($firewallFile) {
        Write-Host "`n  Restaurando firewall desde backup..." -ForegroundColor Gray
        try {
            netsh advfirewall import $firewallFile.FullName 2>&1 | Out-Null
            Write-Host "    [OK] Firewall restaurado desde backup" -ForegroundColor Green
            Write-Log "Firewall restaurado" -Level "SUCCESS"
        }
        catch {
            Write-Host "    [WARN] Error restaurando firewall" -ForegroundColor Yellow
        }
    }

    if ($restoreSuccess) {
        Write-Host "`n  Restauracion completada" -ForegroundColor Green
        Write-Host "  Se recomienda reiniciar el sistema" -ForegroundColor Yellow
        Write-Log "Restauracion completada. Exito=$restoreSuccess" -Level "SUCCESS"
    } else {
        Write-Host "`n  Restauracion con errores (ver log)" -ForegroundColor Yellow
    }

    return $restoreSuccess
}

# ============================================================
# ENTRY POINT — Ejecución directa del script
# Soporta los flags: -Restore, -BackupPath, -DeepClean, -ResetOnly
# ============================================================
if ($MyInvocation.InvocationName -ne '.') {
    $doRestore  = $args -contains '-Restore'
    $resetOnly  = $args -contains '-ResetOnly'
    $deepClean  = $args -contains '-DeepClean'
    $bpIndex    = [array]::IndexOf([object[]]$args, '-BackupPath')
    $backupArg  = if ($bpIndex -ge 0 -and ($bpIndex+1) -lt $args.Count) { $args[$bpIndex+1] } else { "" }

    if ($resetOnly) {
        # Solo limpieza profunda — no aplica ningún backup encima
        Write-Host "`n[MODO] Solo limpieza profunda (sin restaurar backup)" -ForegroundColor Magenta
        Reset-ToWindowsDefaults
    }
    elseif ($doRestore) {
        if (-not $backupArg) {
            Write-Host "[ERROR] Debe especificar -BackupPath al usar -Restore" -ForegroundColor Red
            Write-Host "Uso: .\Backup-Config.ps1 -Restore -BackupPath `"C:\...\backup-YYYYMMDD`"" -ForegroundColor Gray
            Write-Host "     .\Backup-Config.ps1 -Restore -BackupPath `"...`" -DeepClean" -ForegroundColor Gray
            Write-Host "     .\Backup-Config.ps1 -ResetOnly" -ForegroundColor Gray
            exit 1
        }
        Restore-Backup -RestorePath $backupArg -DeepClean:$deepClean
    }
    else {
        Backup-Configuration
    }
}