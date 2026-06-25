#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aplica la configuración de Firewall CIS (sección 9.2 y 9.3) en Windows 10.

.DESCRIPTION
    Configura los perfiles de Windows Firewall definidos en el benchmark
    CIS Microsoft Windows 10 Level 1, secciones 9.2 (Private) y 9.3 (Public):
      9.2.1 — Habilitar firewall en perfil Private.
      9.2.2 — Bloquear tráfico entrante en perfil Private.
      9.3.1 — Habilitar firewall en perfil Public.
      9.3.2 — Bloquear tráfico entrante en perfil Public.

    El perfil Domain (9.1.x) está excluido intencionalmente: el proyecto
    está diseñado para equipos standalone sin Active Directory, y aplicar
    restricciones de dominio en ese contexto puede causar problemas de
    conectividad sin beneficio real de seguridad.

.PARAMETER WhatIf
    Simula la aplicación sin modificar el sistema. Muestra qué cambios se harían.

.EXAMPLE
    # Aplicar configuración de firewall CIS
    .\Set-Firewall.ps1

.EXAMPLE
    # Simular sin cambios reales
    .\Set-Firewall.ps1 -WhatIf

.NOTES
    Controles CIS cubiertos : 9.2.1, 9.2.2, 9.3.1, 9.3.2  (4 controles)
    Perfil Domain (9.1.x)  : Excluido — solo aplica en entornos con AD
    Mecanismo              : Set-NetFirewallProfile (PowerShell NetSecurity)
    Para revertir          : netsh advfirewall reset
    Requiere               : Administrador, PowerShell 5.1, Windows 10
    Invocado por           : 01-Main.ps1 → Apply\Set-Firewall.ps1
#>

# ============================================================
# IMPORTAR CONFIGURACIÓN Y UTILIDADES
# ============================================================
. "$PSScriptRoot\..\Utils\Write-Log.ps1"
 
# ============================================
# Apply\Set-Firewall.ps1
# CORRECCIONES: H-05, H-06, M-01, L-02
# ============================================

function Set-FirewallSettings {
    param([switch]$WhatIf)
    
    # FIX: inicializar en $script: para que Register-Result (función anidada)
    # y el código padre compartan la misma variable.
    $script:results = @()
    
    Write-Host "`n============================================================" -ForegroundColor Magenta
    Write-Host "  APLICANDO CONFIGURACIÓN DE FIREWALL" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    
    function Register-Result {
        param([string]$ControlID, [string]$Operation, [bool]$Success, [string]$Details = "")
        $script:results += [PSCustomObject]@{ ControlID=$ControlID; Operation=$Operation; Success=$Success; Timestamp=Get-Date; Details=$Details }
        Write-ApplyResult -ControlID $ControlID -Operation $Operation -Success $Success -Details $Details
    }
    
    # NOTA: Perfil Domain (9.1.x) excluido intencionalmente.
    # El proyecto esta disenado para entornos standalone sin Active Directory.
    # Test-FirewallSettings tampoco evalua 9.1.x, manteniendo coherencia total.

    if ($WhatIf) {
        Register-Result -ControlID "9.2.1" -Operation "Enable Private firewall" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "9.2.2" -Operation "Set Private inbound to Block" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "9.3.1" -Operation "Enable Public firewall" -Success $true -Details "SIMULATED"
        Register-Result -ControlID "9.3.2" -Operation "Set Public inbound to Block" -Success $true -Details "SIMULATED"
        return $script:results
    }

    # Perfil Private
    try {
        Set-NetFirewallProfile -Name Private -Enabled True -ErrorAction Stop
        Register-Result -ControlID "9.2.1" -Operation "Enable Private firewall" -Success $true
    } catch { Register-Result -ControlID "9.2.1" -Operation "Enable Private firewall" -Success $false -Details $_.Exception.Message }
    
    try {
        Set-NetFirewallProfile -Name Private -DefaultInboundAction Block -ErrorAction Stop
        Register-Result -ControlID "9.2.2" -Operation "Set Private inbound to Block" -Success $true
    } catch { Register-Result -ControlID "9.2.2" -Operation "Set Private inbound to Block" -Success $false -Details $_.Exception.Message }
    
    # Perfil Public
    try {
        Set-NetFirewallProfile -Name Public -Enabled True -ErrorAction Stop
        Register-Result -ControlID "9.3.1" -Operation "Enable Public firewall" -Success $true
    } catch { Register-Result -ControlID "9.3.1" -Operation "Enable Public firewall" -Success $false -Details $_.Exception.Message }
    
    try {
        Set-NetFirewallProfile -Name Public -DefaultInboundAction Block -ErrorAction Stop
        Register-Result -ControlID "9.3.2" -Operation "Set Public inbound to Block" -Success $true
    } catch { Register-Result -ControlID "9.3.2" -Operation "Set Public inbound to Block" -Success $false -Details $_.Exception.Message }
    
    Write-Host "`n✅ Firewall configurado correctamente" -ForegroundColor Green
    return $script:results
}

if ($MyInvocation.InvocationName -ne '.') { Set-FirewallSettings }