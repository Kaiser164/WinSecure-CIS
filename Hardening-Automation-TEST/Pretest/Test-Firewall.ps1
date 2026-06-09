# ============================================
<#
.SYNOPSIS
    Evalua la configuracion de Firewall CIS (seccion 9.2 y 9.3) en Windows 10.

.DESCRIPTION
    Consulta Get-NetFirewallProfile para verificar el cumplimiento de los
    controles CIS Microsoft Windows 10 Level 1, secciones 9.2 y 9.3:
      9.2.1 - Firewall habilitado en perfil Private.
      9.2.2 - Trafico entrante bloqueado en perfil Private.
      9.3.1 - Firewall habilitado en perfil Public.
      9.3.2 - Trafico entrante bloqueado en perfil Public.

    El perfil Domain (9.1.x) esta excluido: el proyecto esta disenado para
    equipos standalone sin Active Directory. Incluir ese perfil generaria
    controles fantasma que nunca pueden cumplirse en este entorno.

.EXAMPLE
    # Ejecutar evaluacion standalone
    .\Test-Firewall.ps1

.EXAMPLE
    # Ver resultados como tabla
    .\Test-Firewall.ps1 | Format-Table -AutoSize

.NOTES
    Controles CIS evaluados : 9.2.1, 9.2.2, 9.3.1, 9.3.2  (4 controles)
    Perfil Domain (9.1.x)  : Excluido intencionalmente (standalone sin AD)
    Mecanismo              : Get-NetFirewallProfile
    Invocado por           : 01-Main.ps1 como Test-FirewallSettings
#>

#     No aplican en equipos standalone segun
#     CIS Benchmark Windows 10 Level 1
# ============================================

# Cargar Write-Log si no esta disponible (ejecucion standalone)
if (-not (Get-Command Write-TestResult -ErrorAction SilentlyContinue)) {
    $writeLogPath = "$PSScriptRoot\..\Utils\Write-Log.ps1"
    if (Test-Path $writeLogPath) { . $writeLogPath }
    else { Write-Warning "Write-Log.ps1 no encontrado en $writeLogPath" }
}

function Test-FirewallSettings {
    $results = @()

    Write-Host "=== INICIANDO TEST DE FIREWALL ===" -ForegroundColor Cyan
    Write-Host "    Scope: 4 controles CIS W10 L1 (Private + Public)" -ForegroundColor Gray
    Write-Host "    Nota: Perfil Domain (9.1.x) excluido - no aplica en standalone" -ForegroundColor DarkGray

    # ----------------------------------------------------------
    # Perfil Private (9.2) - CIS 9.2.1 y 9.2.2
    # ----------------------------------------------------------
    Write-Host "`nPERFIL PRIVATE (9.2.x)" -ForegroundColor Magenta

    try {
        $current   = (Get-NetFirewallProfile -Name Private).Enabled
        $compliant = ($current -eq $true)
        Write-TestResult -ControlID "9.2.1" -ControlName "Firewall Private ON" `
            -Compliant $compliant -CurrentValue $current -ExpectedValue "True"
        $results += [PSCustomObject]@{
            ControlID     = "9.2.1"
            Name          = "Firewall Private ON"
            Compliant     = $compliant
            CurrentValue  = $current
            ExpectedValue = $true
            Category      = "Firewall"
        }
    } catch {
        Write-TestResult -ControlID "9.2.1" -ControlName "Firewall Private ON" `
            -Compliant $false -CurrentValue "Error" -ExpectedValue "True" `
            -Details $_.Exception.Message
        $results += [PSCustomObject]@{
            ControlID     = "9.2.1"
            Name          = "Firewall Private ON"
            Compliant     = $false
            CurrentValue  = "Error"
            ExpectedValue = $true
            Category      = "Firewall"
        }
    }

    try {
        $current   = (Get-NetFirewallProfile -Name Private).DefaultInboundAction
        $compliant = ($current -eq "Block")
        Write-TestResult -ControlID "9.2.2" -ControlName "Firewall Private Inbound" `
            -Compliant $compliant -CurrentValue $current -ExpectedValue "Block"
        $results += [PSCustomObject]@{
            ControlID     = "9.2.2"
            Name          = "Firewall Private Inbound"
            Compliant     = $compliant
            CurrentValue  = $current
            ExpectedValue = "Block"
            Category      = "Firewall"
        }
    } catch {
        Write-TestResult -ControlID "9.2.2" -ControlName "Firewall Private Inbound" `
            -Compliant $false -CurrentValue "Error" -ExpectedValue "Block" `
            -Details $_.Exception.Message
        $results += [PSCustomObject]@{
            ControlID     = "9.2.2"
            Name          = "Firewall Private Inbound"
            Compliant     = $false
            CurrentValue  = "Error"
            ExpectedValue = "Block"
            Category      = "Firewall"
        }
    }

    # ----------------------------------------------------------
    # Perfil Public (9.3) - CIS 9.3.1 y 9.3.2
    # ----------------------------------------------------------
    Write-Host "`nPERFIL PUBLIC (9.3.x)" -ForegroundColor Magenta

    try {
        $current   = (Get-NetFirewallProfile -Name Public).Enabled
        $compliant = ($current -eq $true)
        Write-TestResult -ControlID "9.3.1" -ControlName "Firewall Public ON" `
            -Compliant $compliant -CurrentValue $current -ExpectedValue "True"
        $results += [PSCustomObject]@{
            ControlID     = "9.3.1"
            Name          = "Firewall Public ON"
            Compliant     = $compliant
            CurrentValue  = $current
            ExpectedValue = $true
            Category      = "Firewall"
        }
    } catch {
        Write-TestResult -ControlID "9.3.1" -ControlName "Firewall Public ON" `
            -Compliant $false -CurrentValue "Error" -ExpectedValue "True" `
            -Details $_.Exception.Message
        $results += [PSCustomObject]@{
            ControlID     = "9.3.1"
            Name          = "Firewall Public ON"
            Compliant     = $false
            CurrentValue  = "Error"
            ExpectedValue = $true
            Category      = "Firewall"
        }
    }

    try {
        $current   = (Get-NetFirewallProfile -Name Public).DefaultInboundAction
        $compliant = ($current -eq "Block")
        Write-TestResult -ControlID "9.3.2" -ControlName "Firewall Public Inbound" `
            -Compliant $compliant -CurrentValue $current -ExpectedValue "Block"
        $results += [PSCustomObject]@{
            ControlID     = "9.3.2"
            Name          = "Firewall Public Inbound"
            Compliant     = $compliant
            CurrentValue  = $current
            ExpectedValue = "Block"
            Category      = "Firewall"
        }
    } catch {
        Write-TestResult -ControlID "9.3.2" -ControlName "Firewall Public Inbound" `
            -Compliant $false -CurrentValue "Error" -ExpectedValue "Block" `
            -Details $_.Exception.Message
        $results += [PSCustomObject]@{
            ControlID     = "9.3.2"
            Name          = "Firewall Public Inbound"
            Compliant     = $false
            CurrentValue  = "Error"
            ExpectedValue = "Block"
            Category      = "Firewall"
        }
    }

    Write-Host "`n=== FIN TEST FIREWALL - $($results.Count) controles evaluados ===" -ForegroundColor Cyan
    return $results
}

if ($MyInvocation.InvocationName -ne '.') { Test-FirewallSettings | Format-Table -AutoSize }