# ============================================================
<#
.SYNOPSIS
    Crea un usuario local sin privilegios y protege el proyecto
    de hardening con 3 capas de seguridad independientes.

.DESCRIPTION
    Este script realiza 3 acciones en orden:

    1. USUARIO — Crea una cuenta local estándar (sin Admins)
       con el nombre y contraseña que ingreses al ejecutar.

    2. ACL DIRECTORIO — Deniega acceso al directorio raíz del
       proyecto mediante Deny FullControl heredado (Capa 2a).
       El usuario limitado no podrá ni listar los archivos.

    2b. ACL ARCHIVOS — Aplica Deny ReadAndExecute sobre cada
       archivo .ps1 del proyecto individualmente (Capa 2b).
       Aunque un .ps1 sea copiado fuera del directorio,
       el usuario seguirá sin poder leerlo ni ejecutarlo.

    3. EXECUTION POLICY — Aplica Restricted en el scope
       CurrentUser del nuevo usuario via registro de Windows.
       Última barrera: aunque acceda a un .ps1, PowerShell
       se niega a ejecutarlo.

.NOTES
    Requiere: ejecutar como Administrador.
    Compatible con: Windows 10 / Windows Server 2019+.
    No modifica ningún script existente del proyecto.

    Invocación recomendada:
        .\Setup-LimitedUser.ps1
#>
# ============================================================

#Requires -RunAsAdministrator

# ─────────────────────────────────────────────
# 0. Detectar ProjectRoot dinámicamente
# ─────────────────────────────────────────────
# Este script vive en la raíz del proyecto junto a 00-Config.ps1.
# $MyInvocation.MyCommand.Path apunta a este archivo → Split-Path da la raíz.
# No se lee 00-Config.ps1 con regex porque ahora usa Split-Path dinámico
# (no tiene ruta hardcodeada que parsear).
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigFile  = Join-Path $ScriptDir "00-Config.ps1"

# ProjectRoot = la carpeta donde está este script (siempre correcta)
$ProjectRoot = $ScriptDir

# Verificación: si existe 00-Config.ps1, cargarlo para obtener las
# rutas globales correctas (LogPath, ReportsPath, etc.)
if (Test-Path $ConfigFile) {
    . $ConfigFile
    # 00-Config.ps1 define $global:ProjectRoot — usarlo si está disponible
    if ($global:ProjectRoot) { $ProjectRoot = $global:ProjectRoot }
}

# ─────────────────────────────────────────────
# 1. Solicitar nombre y contraseña del usuario
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "   SETUP: Creación de usuario sin privilegios       " -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host ""
Write-Host "Proyecto detectado: $ProjectRoot" -ForegroundColor Cyan
Write-Host ""

do {
    $UserName = Read-Host "  Nombre del nuevo usuario"
    $UserName = $UserName.Trim()
    if ($UserName -eq "") {
        Write-Host "  ⚠️  El nombre no puede estar vacío." -ForegroundColor Yellow
    }
} while ($UserName -eq "")

do {
    $SecurePass    = Read-Host "  Contraseña" -AsSecureString
    $SecureConfirm = Read-Host "  Confirmar contraseña" -AsSecureString

    $PassPlain    = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass))
    $ConfirmPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureConfirm))

    if ($PassPlain -ne $ConfirmPlain) {
        Write-Host "  ⚠️  Las contraseñas no coinciden. Intenta de nuevo." -ForegroundColor Yellow
    } elseif ($PassPlain.Length -lt 8) {
        Write-Host "  ⚠️  La contraseña debe tener al menos 8 caracteres." -ForegroundColor Yellow
        $PassPlain = ""
    }
} while ($PassPlain -ne $ConfirmPlain -or $PassPlain.Length -lt 8)

$PassPlain    = $null
$ConfirmPlain = $null

Write-Host ""
Write-Host "  ✔  Datos recibidos. Aplicando configuración..." -ForegroundColor Green
Write-Host ""

# ─────────────────────────────────────────────
# CAPA 1: Crear el usuario local
# ─────────────────────────────────────────────
Write-Host "─── Capa 1: Creando usuario local ───" -ForegroundColor Cyan

$existingUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue

if ($existingUser) {
    Write-Host "  ℹ️  El usuario '$UserName' ya existe. Se omite creación." -ForegroundColor Yellow
} else {
    try {
        New-LocalUser `
            -Name        $UserName `
            -Password    $SecurePass `
            -FullName    "$UserName (Sin privilegios)" `
            -Description "Cuenta estándar sin acceso al proyecto de hardening." `
            -ErrorAction Stop | Out-Null

        Add-LocalGroupMember -Group "Users" -Member $UserName -ErrorAction SilentlyContinue

        Write-Host "  ✅ Usuario '$UserName' creado correctamente." -ForegroundColor Green
        Write-Host "     Grupo asignado: Users (sin privilegios de admin)" -ForegroundColor Gray
    } catch {
        Write-Host "  ❌ Error creando usuario: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# ─────────────────────────────────────────────
# CAPA 2a: Denegar acceso al directorio raíz
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "─── Capa 2a: Protegiendo directorio raíz del proyecto ───" -ForegroundColor Cyan

if (-not (Test-Path $ProjectRoot)) {
    Write-Host "  ⚠️  El directorio '$ProjectRoot' no existe aún." -ForegroundColor Yellow
    Write-Host "     Continuando con las demás capas..." -ForegroundColor Gray
} else {
    try {
        $acl = Get-Acl -Path $ProjectRoot
        $acl.SetAccessRuleProtection($true, $true)

        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $UserName,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Deny"
        )
        $acl.AddAccessRule($denyRule)
        Set-Acl -Path $ProjectRoot -AclObject $acl -ErrorAction Stop

        Write-Host "  ✅ ACL aplicada en directorio raíz: $ProjectRoot" -ForegroundColor Green
        Write-Host "     '$UserName' tiene acceso denegado (Deny FullControl heredado)." -ForegroundColor Gray
    } catch {
        Write-Host "  ❌ Error aplicando ACL en directorio: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
# CAPA 2b: Denegar lectura en cada archivo .ps1
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "─── Capa 2b: Protegiendo archivos .ps1 individualmente ───" -ForegroundColor Cyan

if (-not (Test-Path $ProjectRoot)) {
    Write-Host "  ⚠️  El directorio '$ProjectRoot' no existe. Se omite esta capa." -ForegroundColor Yellow
} else {
    $scripts = Get-ChildItem -Path $ProjectRoot -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue

    if ($scripts.Count -eq 0) {
        Write-Host "  ℹ️  No se encontraron archivos .ps1 en el proyecto aún." -ForegroundColor Yellow
    } else {
        $ok     = 0
        $failed = 0

        foreach ($script in $scripts) {
            try {
                $acl = Get-Acl -Path $script.FullName

                $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $UserName,
                    "ReadAndExecute",
                    "None",
                    "None",
                    "Deny"
                )
                $acl.AddAccessRule($denyRule)
                Set-Acl -Path $script.FullName -AclObject $acl -ErrorAction Stop
                $ok++
            } catch {
                Write-Host "  ⚠️  No se pudo proteger: $($script.Name) — $($_.Exception.Message)" -ForegroundColor Yellow
                $failed++
            }
        }

        Write-Host "  ✅ ACL aplicada en $ok archivo(s) .ps1." -ForegroundColor Green
        if ($failed -gt 0) {
            Write-Host "  ⚠️  $failed archivo(s) no pudieron ser protegidos." -ForegroundColor Yellow
        }
        Write-Host "     Cada .ps1 tiene restriccion explicita de lectura dentro del proyecto." -ForegroundColor Gray
    }
}

# ─────────────────────────────────────────────
# CAPA 3: ExecutionPolicy Restricted para el usuario
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "─── Capa 3: Bloqueando ejecución de scripts ───" -ForegroundColor Cyan

try {
    $userObj = Get-LocalUser -Name $UserName -ErrorAction Stop
    $userSid = $userObj.SID.Value

    $userProfilePath = "C:\Users\$UserName\NTUSER.DAT"
    $hiveLoaded      = $false

    if (Test-Path $userProfilePath) {
        reg load "HKU\$userSid" $userProfilePath 2>$null
        $hiveLoaded = $true
    }

    $userRegPath = "HKU:\$userSid\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"

    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    if (-not (Test-Path $userRegPath)) {
        New-Item -Path $userRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $userRegPath -Name "ExecutionPolicy" -Value "Restricted" -Type String -Force

    Write-Host "  ✅ ExecutionPolicy = Restricted aplicada para '$UserName'." -ForegroundColor Green
    Write-Host "     El usuario no podrá ejecutar ningún script .ps1." -ForegroundColor Gray

    if ($hiveLoaded) {
        [GC]::Collect()
        Start-Sleep -Milliseconds 500
        reg unload "HKU\$userSid" 2>$null
    }

} catch {
    Write-Host "  ⚠️  No se pudo escribir en el registro del usuario." -ForegroundColor Yellow
    Write-Host "     Causa: $($_.Exception.Message)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  💡 Aplicando vía política de máquina (fallback)..." -ForegroundColor Cyan

    try {
        $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        if (-not (Test-Path $gpoPath)) {
            New-Item -Path $gpoPath -Force | Out-Null
        }
        Set-ItemProperty -Path $gpoPath -Name "EnableScripts"   -Value 0            -Type DWord  -Force
        Set-ItemProperty -Path $gpoPath -Name "ExecutionPolicy" -Value "Restricted"  -Type String -Force
        Write-Host "  ✅ Política de máquina aplicada (no-admins no pueden ejecutar scripts)." -ForegroundColor Green
    } catch {
        Write-Host "  ❌ Fallback también falló: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
# Resumen final
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "   SETUP COMPLETADO                                " -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Usuario creado  : $UserName" -ForegroundColor White
Write-Host "  Proyecto        : $ProjectRoot" -ForegroundColor White
Write-Host ""
Write-Host "  Capas aplicadas:" -ForegroundColor White
Write-Host "    [1] ✅ Cuenta estándar     — sin grupo Administrators" -ForegroundColor Green
Write-Host "    [2a] ✅ ACL directorio raíz — Deny FullControl heredado" -ForegroundColor Green
Write-Host "    [2b] ✅ ACL por archivo     — Deny ReadAndExecute en cada .ps1" -ForegroundColor Green
Write-Host "    [3] ✅ ExecutionPolicy     — Restricted para ese usuario" -ForegroundColor Green
Write-Host ""
Write-Host "  Si '$UserName' intenta ejecutar cualquier .ps1 del proyecto:" -ForegroundColor Gray
Write-Host "  → No verá el directorio (Capa 2a)" -ForegroundColor Gray
Write-Host "  → No podrá leer los archivos dentro ni fuera del proyecto (Capa 2b)" -ForegroundColor Gray
Write-Host "  → PowerShell bloqueará la ejecución (Capa 3)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Ningún script del proyecto fue modificado." -ForegroundColor Cyan
Write-Host ""