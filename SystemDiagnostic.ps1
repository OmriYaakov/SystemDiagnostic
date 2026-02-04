#Requires -Version 5.1
<#
.SYNOPSIS
    On-demand Windows system diagnostic tool that generates an HTML health report.

.DESCRIPTION
    Performs comprehensive system analysis covering CPU, memory, disk, network,
    startup programs, processes, event logs, thermal status, and disk health.
    Generates a self-contained HTML report with severity indicators and recommendations.

.PARAMETER OutputPath
    Path for the HTML report file. Defaults to Desktop with timestamped filename.

.PARAMETER Elevate
    Re-launch the script as administrator for deeper diagnostics (SMART, event logs, thermal events).

.PARAMETER SampleDurationSeconds
    How long to sample performance counters (default: 3 seconds).

.PARAMETER SkipBrowserOpen
    Do not open the report in the default browser after generation.

.EXAMPLE
    .\SystemDiagnostic.ps1
    Runs diagnostics as current user and opens the HTML report.

.EXAMPLE
    .\SystemDiagnostic.ps1 -Elevate
    Re-launches as administrator for full diagnostics.

.EXAMPLE
    .\SystemDiagnostic.ps1 -OutputPath "C:\Reports\diag.html" -SkipBrowserOpen
    Saves report to a custom path without opening it.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = [System.IO.Path]::Combine(
        [Environment]::GetFolderPath('Desktop'),
        "SystemDiag_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    ),

    [Parameter()]
    [switch]$Elevate,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$SampleDurationSeconds = 3,

    [Parameter()]
    [switch]$SkipBrowserOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --- Script-scoped state ---
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$script:SkippedDiagnostics = [System.Collections.Generic.List[string]]::new()
$script:DiagResults = [ordered]@{}
$script:CollectionStart = Get-Date

# --- Elevation logic ---
if ($Elevate -and -not $script:IsAdmin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-OutputPath', "`"$OutputPath`"",
        '-SampleDurationSeconds', $SampleDurationSeconds)
    if ($SkipBrowserOpen) { $argList += '-SkipBrowserOpen' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
    exit
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Format-Bytes {
    param([int64]$Bytes)
    if ($Bytes -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N2} MB' -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return '{0:N2} KB' -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Get-Severity {
    param(
        [double]$Value,
        [double]$YellowThreshold,
        [double]$RedThreshold,
        [switch]$LowerIsBetter
    )
    if ($LowerIsBetter) {
        if ($Value -le $YellowThreshold) { return 'green' }
        if ($Value -le $RedThreshold) { return 'yellow' }
        return 'red'
    }
    else {
        if ($Value -lt $YellowThreshold) { return 'green' }
        if ($Value -lt $RedThreshold) { return 'yellow' }
        return 'red'
    }
}

function Get-WorstSeverity {
    param([string[]]$Severities)
    if ($Severities -contains 'red') { return 'red' }
    if ($Severities -contains 'yellow') { return 'yellow' }
    return 'green'
}

function Write-DiagProgress {
    param([string]$Status, [int]$PercentComplete)
    Write-Progress -Activity 'System Diagnostics' -Status $Status -PercentComplete $PercentComplete
}

function Test-HasKey {
    param([hashtable]$Hash, [string]$Key)
    return ($null -ne $Hash -and $Hash.ContainsKey($Key) -and $Hash[$Key])
}

# ============================================================================
# COLLECTOR FUNCTIONS
# ============================================================================

function Get-SystemInfoDiagnostics {
    $result = @{ Severity = 'green'; Errors = @() }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

        $uptime = (Get-Date) - $os.LastBootUpTime
        $uptimeDays = [math]::Floor($uptime.TotalDays)

        $result.ComputerName = $cs.Name
        $result.Domain = $cs.Domain
        $result.Manufacturer = $cs.Manufacturer
        $result.Model = $cs.Model
        $result.OSName = $os.Caption
        $result.OSVersion = $os.Version
        $result.BuildNumber = $os.BuildNumber
        $result.Architecture = $os.OSArchitecture
        $result.InstallDate = $os.InstallDate
        $result.LastBootTime = $os.LastBootUpTime
        $result.Uptime = $uptime
        $result.UptimeText = '{0}d {1}h {2}m' -f $uptimeDays, $uptime.Hours, $uptime.Minutes
        $result.CPUModel = $cpu.Name
        $result.CPUCores = $cpu.NumberOfCores
        $result.CPULogical = $cpu.NumberOfLogicalProcessors
        $result.CPUMaxMHz = $cpu.MaxClockSpeed
        $result.TotalRAMGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        $result.BIOSVersion = if ($bios) { $bios.SMBIOSBIOSVersion } else { 'N/A' }

        # Uptime severity
        $result.Severity = Get-Severity -Value $uptimeDays -YellowThreshold 7 -RedThreshold 30
    }
    catch {
        $result.Errors += "System info collection failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-CpuDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); PerCoreUsage = @(); TopProcesses = @(); SustainedHighCpu = @() }

    # Performance counters
    try {
        $counters = Get-Counter -Counter @(
            '\Processor(_Total)\% Processor Time'
        ) -SampleInterval 1 -MaxSamples $SampleDurationSeconds -ErrorAction Stop
        $samples = $counters.CounterSamples | Where-Object { $_.Path -like '*_total*' }
        $result.OverallUsage = [math]::Round(($samples | Measure-Object -Property CookedValue -Average).Average, 1)
    }
    catch {
        $result.Errors += "CPU counter failed: $($_.Exception.Message)"
        try {
            $result.OverallUsage = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop).LoadPercentage
        }
        catch {
            $result.OverallUsage = -1
            $result.Errors += "CIM CPU fallback also failed"
        }
    }

    # Per-core usage
    try {
        $coreCounters = Get-Counter -Counter '\Processor(*)\% Processor Time' -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
        $result.PerCoreUsage = $coreCounters.CounterSamples |
            Where-Object { $_.InstanceName -ne '_total' } |
            Sort-Object { [int]$_.InstanceName } |
            ForEach-Object {
                @{ Core = $_.InstanceName; Usage = [math]::Round($_.CookedValue, 1) }
            }
    }
    catch {
        $result.Errors += "Per-core counters failed: $($_.Exception.Message)"
    }

    # Top CPU processes with delta sampling
    try {
        $snap1 = Get-Process -ErrorAction Stop | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } |
            Select-Object Id, ProcessName, CPU, WorkingSet64, HandleCount, @{N = 'ThreadCount'; E = { $_.Threads.Count } }
        Start-Sleep -Seconds 1
        $snap2 = Get-Process -ErrorAction Stop | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } |
            Select-Object Id, ProcessName, CPU, WorkingSet64, HandleCount, @{N = 'ThreadCount'; E = { $_.Threads.Count } }

        $deltas = foreach ($p2 in $snap2) {
            $p1 = $snap1 | Where-Object { $_.Id -eq $p2.Id } | Select-Object -First 1
            if ($p1 -and $null -ne $p2.CPU -and $null -ne $p1.CPU) {
                $cpuDelta = $p2.CPU - $p1.CPU
                [PSCustomObject]@{
                    PID         = $p2.Id
                    Name        = $p2.ProcessName
                    CPUPctEst   = [math]::Round($cpuDelta * 100, 1)
                    CPUTotal    = [math]::Round($p2.CPU, 2)
                    MemoryMB    = [math]::Round($p2.WorkingSet64 / 1MB, 1)
                    Handles     = $p2.HandleCount
                    Threads     = $p2.ThreadCount
                }
            }
        }
        $result.TopProcesses = $deltas | Sort-Object CPUPctEst -Descending | Select-Object -First 10
        $result.SustainedHighCpu = @($deltas | Where-Object { $_.CPUPctEst -gt 80 })
    }
    catch {
        $result.Errors += "Process sampling failed: $($_.Exception.Message)"
    }

    # Severity
    $sevList = @()
    if ($result.OverallUsage -ge 0) {
        $sevList += Get-Severity -Value $result.OverallUsage -YellowThreshold 60 -RedThreshold 85
    }
    if ($result.SustainedHighCpu.Count -gt 0) { $sevList += 'red' }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    return $result
}

function Get-MemoryDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); TopProcesses = @() }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $totalKB = $os.TotalVisibleMemorySize
        $freeKB = $os.FreePhysicalMemory
        $usedKB = $totalKB - $freeKB
        $result.TotalBytes = $totalKB * 1KB
        $result.UsedBytes = $usedKB * 1KB
        $result.FreeBytes = $freeKB * 1KB
        $result.UsedPct = [math]::Round(($usedKB / $totalKB) * 100, 1)
        $result.CommitTotalKB = $os.TotalVirtualMemorySize
        $result.CommitFreeKB = $os.FreeVirtualMemory
        $result.CommitUsedPct = [math]::Round((($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / $os.TotalVirtualMemorySize) * 100, 1)
    }
    catch {
        $result.Errors += "Memory CIM failed: $($_.Exception.Message)"
        $result.UsedPct = -1
    }

    # Page file
    try {
        $pf = Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue
        if ($pf) {
            $result.PageFiles = @($pf | ForEach-Object {
                    @{
                        Name          = $_.Name
                        AllocatedMB   = $_.AllocatedBaseSize
                        CurrentUseMB  = $_.CurrentUsage
                        PeakUseMB     = $_.PeakUsage
                        UsedPct       = if ($_.AllocatedBaseSize -gt 0) { [math]::Round(($_.CurrentUsage / $_.AllocatedBaseSize) * 100, 1) } else { 0 }
                    }
                })
        }
        else { $result.PageFiles = @() }
    }
    catch {
        $result.PageFiles = @()
        $result.Errors += "Page file query failed: $($_.Exception.Message)"
    }

    # Memory counters
    try {
        $memCounters = Get-Counter -Counter @(
            '\Memory\Pages/sec',
            '\Memory\Available Bytes',
            '\Memory\Committed Bytes',
            '\Memory\Commit Limit',
            '\Memory\Cache Bytes'
        ) -ErrorAction Stop
        foreach ($s in $memCounters.CounterSamples) {
            $name = ($s.Path -split '\\')[-1]
            switch ($name) {
                'pages/sec' { $result.PagesPerSec = [math]::Round($s.CookedValue, 1) }
                'available bytes' { $result.AvailableBytes = [int64]$s.CookedValue }
                'committed bytes' { $result.CommittedBytes = [int64]$s.CookedValue }
                'commit limit' { $result.CommitLimitBytes = [int64]$s.CookedValue }
                'cache bytes' { $result.CacheBytes = [int64]$s.CookedValue }
            }
        }
    }
    catch {
        $result.Errors += "Memory counters failed: $($_.Exception.Message)"
    }

    # Top memory processes
    try {
        $result.TopProcesses = Get-Process -ErrorAction Stop |
            Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } |
            Sort-Object WorkingSet64 -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                [PSCustomObject]@{
                    PID          = $_.Id
                    Name         = $_.ProcessName
                    WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
                    PrivateMB    = [math]::Round($_.PrivateMemorySize64 / 1MB, 1)
                }
            }
    }
    catch {
        $result.Errors += "Process memory enumeration failed: $($_.Exception.Message)"
    }

    # Severity
    $sevList = @()
    if ($result.UsedPct -ge 0) {
        $sevList += Get-Severity -Value $result.UsedPct -YellowThreshold 70 -RedThreshold 90
    }
    if ($null -ne $result.PagesPerSec) {
        $sevList += Get-Severity -Value $result.PagesPerSec -YellowThreshold 100 -RedThreshold 1000
    }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    return $result
}

function Get-DiskIoDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); DiskMetrics = @(); Volumes = @() }

    # Volume space
    try {
        $result.Volumes = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop |
                ForEach-Object {
                    $usedPct = if ($_.Size -gt 0) { [math]::Round(($_.Size - $_.FreeSpace) / $_.Size * 100, 1) } else { 0 }
                    @{
                        Drive   = $_.DeviceID
                        Label   = $_.VolumeName
                        FS      = $_.FileSystem
                        SizeGB  = [math]::Round($_.Size / 1GB, 2)
                        FreeGB  = [math]::Round($_.FreeSpace / 1GB, 2)
                        UsedPct = $usedPct
                        Severity = Get-Severity -Value $usedPct -YellowThreshold 80 -RedThreshold 90
                    }
                })
    }
    catch {
        $result.Errors += "Volume enumeration failed: $($_.Exception.Message)"
    }

    # Disk I/O counters
    try {
        $diskCounters = Get-Counter -Counter @(
            '\PhysicalDisk(*)\Disk Read Bytes/sec',
            '\PhysicalDisk(*)\Disk Write Bytes/sec',
            '\PhysicalDisk(*)\Avg. Disk Queue Length',
            '\PhysicalDisk(*)\Avg. Disk sec/Read',
            '\PhysicalDisk(*)\Avg. Disk sec/Write',
            '\PhysicalDisk(*)\% Disk Time'
        ) -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop

        $diskInstances = $diskCounters.CounterSamples |
            Where-Object { $_.InstanceName -ne '_total' } |
            Group-Object InstanceName

        $result.DiskMetrics = @(foreach ($group in $diskInstances) {
                $metrics = @{ DiskName = $group.Name }
                foreach ($s in $group.Group) {
                    $counterName = ($s.Path -split '\\')[-1]
                    switch -Wildcard ($counterName) {
                        'disk read bytes/sec' { $metrics.ReadBytesPerSec = [int64]$s.CookedValue }
                        'disk write bytes/sec' { $metrics.WriteBytesPerSec = [int64]$s.CookedValue }
                        'avg. disk queue length' { $metrics.AvgQueueLength = [math]::Round($s.CookedValue, 2) }
                        'avg. disk sec/read' { $metrics.AvgReadLatencyMs = [math]::Round($s.CookedValue * 1000, 2) }
                        'avg. disk sec/write' { $metrics.AvgWriteLatencyMs = [math]::Round($s.CookedValue * 1000, 2) }
                        '% disk time' { $metrics.DiskTimePct = [math]::Round($s.CookedValue, 1) }
                    }
                }
                $metrics
            })
    }
    catch {
        $result.Errors += "Disk I/O counters failed: $($_.Exception.Message)"
    }

    # Severity
    $sevList = @()
    foreach ($v in $result.Volumes) { $sevList += $v.Severity }
    foreach ($d in $result.DiskMetrics) {
        if ($null -ne $d.AvgQueueLength) { $sevList += Get-Severity -Value $d.AvgQueueLength -YellowThreshold 2 -RedThreshold 5 }
        if ($null -ne $d.AvgReadLatencyMs) { $sevList += Get-Severity -Value $d.AvgReadLatencyMs -YellowThreshold 10 -RedThreshold 20 }
        if ($null -ne $d.AvgWriteLatencyMs) { $sevList += Get-Severity -Value $d.AvgWriteLatencyMs -YellowThreshold 10 -RedThreshold 20 }
    }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    return $result
}

function Get-DiskHealthDiagnostics {
    if (-not $script:IsAdmin) {
        $script:SkippedDiagnostics.Add('Disk Health (SMART) - requires administrator privileges')
        return @{ Skipped = $true; Reason = 'Requires administrator privileges'; Severity = 'green' }
    }
    $result = @{ Severity = 'green'; Errors = @(); Disks = @() }
    try {
        $physDisks = Get-PhysicalDisk -ErrorAction Stop
        $result.Disks = @(foreach ($disk in $physDisks) {
                $info = @{
                    DeviceId     = $disk.DeviceId
                    FriendlyName = $disk.FriendlyName
                    MediaType    = "$($disk.MediaType)"
                    BusType      = "$($disk.BusType)"
                    HealthStatus = "$($disk.HealthStatus)"
                    SizeGB       = [math]::Round($disk.Size / 1GB, 2)
                    Model        = $disk.Model
                }
                try {
                    $rel = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
                    $info.Temperature = $rel.Temperature
                    $info.TemperatureMax = $rel.TemperatureMax
                    $info.Wear = $rel.Wear
                    $info.PowerOnHours = $rel.PowerOnHours
                    $info.ReadErrorsTotal = $rel.ReadErrorsTotal
                    $info.ReadErrorsUncorrected = $rel.ReadErrorsUncorrected
                    $info.WriteErrorsTotal = $rel.WriteErrorsTotal
                    $info.WriteErrorsUncorrected = $rel.WriteErrorsUncorrected
                }
                catch {
                    $info.ReliabilityError = $_.Exception.Message
                }
                $info
            })
    }
    catch {
        $result.Errors += "Physical disk enumeration failed: $($_.Exception.Message)"
    }

    # Severity
    $sevList = @()
    foreach ($d in $result.Disks) {
        if ($d.HealthStatus -and $d.HealthStatus -ne 'Healthy') {
            $sevList += if ($d.HealthStatus -eq 'Warning') { 'yellow' } else { 'red' }
        }
        if ($null -ne $d.Temperature -and $d.Temperature -gt 0) {
            $sevList += Get-Severity -Value $d.Temperature -YellowThreshold 45 -RedThreshold 55
        }
        if ($null -ne $d.Wear -and $d.Wear -gt 0) {
            $sevList += Get-Severity -Value $d.Wear -YellowThreshold 80 -RedThreshold 95
        }
        if ($null -ne $d.ReadErrorsUncorrected -and $d.ReadErrorsUncorrected -gt 0) { $sevList += 'red' }
        if ($null -ne $d.WriteErrorsUncorrected -and $d.WriteErrorsUncorrected -gt 0) { $sevList += 'red' }
    }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    return $result
}

function Get-NetworkDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); Adapters = @(); Connections = @{} }
    try {
        $result.Adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } |
                ForEach-Object {
                    @{
                        Name        = $_.Name
                        Description = $_.InterfaceDescription
                        LinkSpeed   = $_.LinkSpeed
                        MacAddress  = $_.MacAddress
                    }
                })
    }
    catch {
        $result.Errors += "Network adapter query failed: $($_.Exception.Message)"
    }

    # Throughput counters
    try {
        $netCounters = Get-Counter -Counter @(
            '\Network Interface(*)\Bytes Total/sec',
            '\Network Interface(*)\Bytes Received/sec',
            '\Network Interface(*)\Bytes Sent/sec',
            '\Network Interface(*)\Packets Received Errors',
            '\Network Interface(*)\Packets Outbound Errors',
            '\Network Interface(*)\Output Queue Length'
        ) -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop

        $ifGroups = $netCounters.CounterSamples |
            Where-Object { $_.InstanceName -ne '' } |
            Group-Object InstanceName

        $result.InterfaceMetrics = @(foreach ($group in $ifGroups) {
                $m = @{ InterfaceName = $group.Name }
                foreach ($s in $group.Group) {
                    $cname = ($s.Path -split '\\')[-1]
                    switch ($cname) {
                        'bytes total/sec' { $m.BytesTotalPerSec = [int64]$s.CookedValue }
                        'bytes received/sec' { $m.BytesRecvPerSec = [int64]$s.CookedValue }
                        'bytes sent/sec' { $m.BytesSentPerSec = [int64]$s.CookedValue }
                        'packets received errors' { $m.RecvErrors = [int64]$s.CookedValue }
                        'packets outbound errors' { $m.SendErrors = [int64]$s.CookedValue }
                        'output queue length' { $m.OutputQueueLen = [int64]$s.CookedValue }
                    }
                }
                $m
            })
    }
    catch {
        $result.Errors += "Network counters failed: $($_.Exception.Message)"
    }

    # TCP connections
    try {
        $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue
        $result.Connections = @{
            Established = @($tcp | Where-Object { $_.State -eq 'Established' }).Count
            Listening   = @($tcp | Where-Object { $_.State -eq 'Listen' }).Count
            TimeWait    = @($tcp | Where-Object { $_.State -eq 'TimeWait' }).Count
            CloseWait   = @($tcp | Where-Object { $_.State -eq 'CloseWait' }).Count
            Total       = @($tcp).Count
        }
    }
    catch {
        $result.Errors += "TCP connection query failed: $($_.Exception.Message)"
    }

    # Severity
    $sevList = @()
    if ($result.Connections -and $result.Connections.ContainsKey('Established') -and $result.Connections.Established) {
        $sevList += Get-Severity -Value $result.Connections.Established -YellowThreshold 200 -RedThreshold 500
    }
    if ($result.ContainsKey('InterfaceMetrics') -and $result.InterfaceMetrics) {
        foreach ($m in $result.InterfaceMetrics) {
            $totalErrors = ($m.RecvErrors, 0 | Measure-Object -Maximum).Maximum + ($m.SendErrors, 0 | Measure-Object -Maximum).Maximum
            if ($totalErrors -gt 0) {
                $sevList += Get-Severity -Value $totalErrors -YellowThreshold 1 -RedThreshold 100
            }
        }
    }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    return $result
}

function Get-ProcessDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); TopCpu = @(); TopMemory = @(); HighHandles = @(); TotalCount = 0 }
    try {
        $procs = Get-Process -ErrorAction Stop | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }
        $result.TotalCount = $procs.Count

        # Filter processes that have accessible CPU time and sort by it
        $procsWithCpu = @($procs | ForEach-Object {
            try {
                $cpuTime = $_.CPU
                if ($null -ne $cpuTime) {
                    [PSCustomObject]@{
                        Process = $_
                        CPUTime = $cpuTime
                    }
                }
            } catch { }
        } | Where-Object { $_ })

        $result.TopCpu = @($procsWithCpu | Sort-Object CPUTime -Descending | Select-Object -First 10 |
                ForEach-Object {
                    $p = $_.Process
                    [PSCustomObject]@{
                        PID          = $p.Id
                        Name         = $p.ProcessName
                        CPUSec       = [math]::Round($_.CPUTime, 2)
                        WorkingSetMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
                        Handles      = $p.HandleCount
                        Threads      = $p.Threads.Count
                    }
                })

        $result.TopMemory = @($procs | Where-Object { $null -ne $_.WorkingSet64 } | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 |
                ForEach-Object {
                    [PSCustomObject]@{
                        PID          = $_.Id
                        Name         = $_.ProcessName
                        WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
                        PrivateMB    = [math]::Round($_.PrivateMemorySize64 / 1MB, 1)
                        Handles      = $_.HandleCount
                        Threads      = $_.Threads.Count
                    }
                })

        $result.HighHandles = @($procs | Where-Object { $null -ne $_.HandleCount -and ($_.HandleCount -gt 1000 -or $_.Threads.Count -gt 100) } |
                ForEach-Object {
                    [PSCustomObject]@{
                        PID          = $_.Id
                        Name         = $_.ProcessName
                        Handles      = $_.HandleCount
                        Threads      = $_.Threads.Count
                        WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
                    }
                } | Sort-Object Handles -Descending)
    }
    catch {
        $result.Errors += "Process enumeration failed: $($_.Exception.Message)"
    }

    # Severity
    $sevList = @()
    $sevList += Get-Severity -Value $result.TotalCount -YellowThreshold 200 -RedThreshold 400
    foreach ($p in $result.HighHandles) {
        if ($p.Handles -gt 10000) { $sevList += 'red' }
        elseif ($p.Handles -gt 5000) { $sevList += 'yellow' }
    }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    return $result
}

function Get-StartupProgramDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); RegistryItems = @(); FolderItems = @(); ScheduledTasks = @() }

    # Registry Run keys
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    try {
        foreach ($key in $runKeys) {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($items) {
                $items.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                    $result.RegistryItems += @{
                        Source  = $key
                        Name    = $_.Name
                        Command = "$($_.Value)"
                    }
                }
            }
        }
    }
    catch {
        $result.Errors += "Registry startup query failed: $($_.Exception.Message)"
    }

    # Startup folders
    try {
        $startupFolders = @(
            [Environment]::GetFolderPath('Startup'),
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        foreach ($folder in $startupFolders) {
            if (Test-Path $folder) {
                Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | ForEach-Object {
                    $result.FolderItems += @{
                        Folder        = $folder
                        Name          = $_.Name
                        FullName      = $_.FullName
                        LastWriteTime = $_.LastWriteTime
                    }
                }
            }
        }
    }
    catch {
        $result.Errors += "Startup folder query failed: $($_.Exception.Message)"
    }

    # Scheduled tasks with logon/boot triggers
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
        foreach ($task in $tasks) {
            $isLogon = $false
            foreach ($trigger in $task.Triggers) {
                if ($trigger.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -or
                    $trigger.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger') {
                    $isLogon = $true; break
                }
            }
            if ($isLogon) {
                $result.ScheduledTasks += @{
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    State    = "$($task.State)"
                    Author   = $task.Author
                }
            }
        }
    }
    catch {
        $result.Errors += "Scheduled task query failed: $($_.Exception.Message)"
    }

    $totalItems = $result.RegistryItems.Count + $result.FolderItems.Count + $result.ScheduledTasks.Count
    $result.TotalCount = $totalItems
    $result.Severity = Get-Severity -Value $totalItems -YellowThreshold 10 -RedThreshold 20
    return $result
}

function Get-EventLogDiagnostics {
    if (-not $script:IsAdmin) {
        $script:SkippedDiagnostics.Add('Windows Event Log - requires administrator privileges')
        return @{ Skipped = $true; Reason = 'Requires administrator privileges'; Severity = 'green' }
    }
    $result = @{ Severity = 'green'; Errors = @(); SystemEvents = @(); AppEvents = @() }
    $startTime = (Get-Date).AddHours(-24)

    foreach ($logName in @('System', 'Application')) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Level     = @(1, 2)
                StartTime = $startTime
            } -MaxEvents 25 -ErrorAction SilentlyContinue

            $formatted = @($events | ForEach-Object {
                    $msgPreview = if ($_.Message) {
                        $firstLine = ($_.Message -split "`n")[0]
                        if ($firstLine.Length -gt 200) { $firstLine.Substring(0, 200) + '...' } else { $firstLine }
                    }
                    else { '(no message)' }
                    @{
                        TimeCreated    = $_.TimeCreated
                        EventId        = $_.Id
                        Level          = $_.LevelDisplayName
                        Source         = $_.ProviderName
                        MessagePreview = $msgPreview
                    }
                })

            if ($logName -eq 'System') { $result.SystemEvents = $formatted }
            else { $result.AppEvents = $formatted }
        }
        catch {
            $result.Errors += "$logName event log query failed: $($_.Exception.Message)"
        }
    }

    # Severity
    $criticalCount = @($result.SystemEvents + $result.AppEvents | Where-Object { $_.Level -eq 'Critical' }).Count
    $errorCount = ($result.SystemEvents.Count + $result.AppEvents.Count) - $criticalCount
    $sevList = @()
    if ($criticalCount -gt 0) { $sevList += 'red' }
    if ($errorCount -gt 0) { $sevList += Get-Severity -Value $errorCount -YellowThreshold 5 -RedThreshold 20 }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    $result.CriticalCount = $criticalCount
    $result.ErrorCount = $errorCount
    return $result
}

function Get-ThermalDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); PerfLimit = $null; MaxFreqPct = $null; ThermalEvents = @() }

    # Performance counters (no admin needed)
    try {
        $thermalCounters = Get-Counter -Counter @(
            '\Processor Information(_Total)\% Performance Limit',
            '\Processor Information(_Total)\% of Maximum Frequency'
        ) -ErrorAction Stop
        foreach ($s in $thermalCounters.CounterSamples) {
            $cname = ($s.Path -split '\\')[-1]
            switch ($cname) {
                '% performance limit' { $result.PerfLimit = [math]::Round($s.CookedValue, 1) }
                '% of maximum frequency' { $result.MaxFreqPct = [math]::Round($s.CookedValue, 1) }
            }
        }
    }
    catch {
        $result.Errors += "Thermal counters failed: $($_.Exception.Message)"
    }

    # Event log thermal events (admin only)
    if ($script:IsAdmin) {
        try {
            $startTime = (Get-Date).AddDays(-7)
            $thermalEvents = @()
            $providers = @(
                @{ Provider = 'Microsoft-Windows-Kernel-Power'; Ids = @(86) },
                @{ Provider = 'Microsoft-Windows-Kernel-Processor-Power'; Ids = @(37, 12) }
            )
            foreach ($p in $providers) {
                try {
                    $evts = Get-WinEvent -FilterHashtable @{
                        LogName      = 'System'
                        ProviderName = $p.Provider
                        Id           = $p.Ids
                        StartTime    = $startTime
                    } -MaxEvents 10 -ErrorAction SilentlyContinue
                    if ($evts) { $thermalEvents += $evts }
                }
                catch { }
            }
            $result.ThermalEvents = @($thermalEvents | ForEach-Object {
                    @{
                        TimeCreated = $_.TimeCreated
                        EventId     = $_.Id
                        Source      = $_.ProviderName
                        Message     = if ($_.Message.Length -gt 200) { $_.Message.Substring(0, 200) + '...' } else { $_.Message }
                    }
                })
        }
        catch {
            $result.Errors += "Thermal event log query failed: $($_.Exception.Message)"
        }
    }
    else {
        $script:SkippedDiagnostics.Add('Thermal event log analysis - requires administrator privileges')
    }

    # Severity
    $sevList = @()
    if ($null -ne $result.PerfLimit) {
        if ($result.PerfLimit -lt 95) { $sevList += 'red' }
        elseif ($result.PerfLimit -lt 100) { $sevList += 'yellow' }
    }
    if ($null -ne $result.MaxFreqPct) {
        if ($result.MaxFreqPct -lt 80) { $sevList += 'red' }
        elseif ($result.MaxFreqPct -lt 95) { $sevList += 'yellow' }
    }
    if ($result.ThermalEvents.Count -gt 3) { $sevList += 'red' }
    elseif ($result.ThermalEvents.Count -gt 0) { $sevList += 'yellow' }
    $result.Severity = if ($sevList.Count -gt 0) { Get-WorstSeverity $sevList } else { 'green' }
    return $result
}

# ============================================================================
# NEW OPTIMIZATION COLLECTORS
# ============================================================================

function Get-PowerPlanDiagnostics {
    $result = @{ Severity = 'green'; Errors = @() }
    try {
        # Active power plan
        $activePlan = powercfg /getactivescheme 2>$null
        if ($activePlan -match 'GUID:\s*(\S+)\s+\((.+)\)') {
            $result.ActivePlanGuid = $Matches[1]
            $result.ActivePlanName = $Matches[2].Trim()
        }

        # All available plans
        $allPlans = powercfg /list 2>$null
        $result.AvailablePlans = @($allPlans | Where-Object { $_ -match 'GUID:\s*(\S+)\s+\((.+)\)' } | ForEach-Object {
            if ($_ -match 'GUID:\s*(\S+)\s+\((.+)\)') {
                @{ Guid = $Matches[1]; Name = $Matches[2].Trim(); IsActive = ($_ -match '\*$') }
            }
        })

        # Check if High Performance or Ultimate Performance exists
        $result.HasHighPerf = $result.AvailablePlans | Where-Object { $_.Name -match 'High [Pp]erformance' }
        $result.HasUltimatePerf = $result.AvailablePlans | Where-Object { $_.Name -match 'Ultimate' }

        # Battery status (for laptops)
        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        if ($battery) {
            $result.IsLaptop = $true
            $result.BatteryStatus = switch ($battery.BatteryStatus) {
                1 { 'Discharging' } 2 { 'AC Power' } 3 { 'Fully Charged' } 4 { 'Low' } 5 { 'Critical' }
                6 { 'Charging' } 7 { 'Charging/High' } 8 { 'Charging/Low' } 9 { 'Charging/Critical' }
                default { 'Unknown' }
            }
            $result.BatteryPercent = $battery.EstimatedChargeRemaining
            $result.IsPluggedIn = $battery.BatteryStatus -in @(2, 3, 6, 7, 8, 9)
        } else {
            $result.IsLaptop = $false
        }

        # Processor power settings
        try {
            $procPower = powercfg /query SCHEME_CURRENT SUB_PROCESSOR 2>$null
            if ($procPower -match 'Minimum processor state.*?(\d+)%') { $result.MinProcState = [int]$Matches[1] }
            if ($procPower -match 'Maximum processor state.*?(\d+)%') { $result.MaxProcState = [int]$Matches[1] }
        } catch {}

        # Severity: yellow if not on High Performance when plugged in
        if ($result.ActivePlanName -notmatch 'High|Ultimate|Performance') {
            if (-not $result.IsLaptop -or $result.IsPluggedIn) {
                $result.Severity = 'yellow'
            }
        }
    }
    catch {
        $result.Errors += "Power plan query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-VisualEffectsDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); Effects = @() }
    try {
        $visualFxKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
        $advancedKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        $dwmKey = 'HKCU:\Software\Microsoft\Windows\DWM'

        # Visual Effects setting
        $vfx = Get-ItemProperty -Path $visualFxKey -ErrorAction SilentlyContinue
        $result.VisualFxSetting = if ($vfx) { $vfx.VisualFXSetting } else { 0 }
        $result.VisualFxMode = switch ($result.VisualFxSetting) {
            0 { 'Let Windows choose' }
            1 { 'Best appearance' }
            2 { 'Best performance' }
            3 { 'Custom' }
            default { 'Unknown' }
        }

        # Individual effects from Advanced key
        $adv = Get-ItemProperty -Path $advancedKey -ErrorAction SilentlyContinue
        if ($adv) {
            $result.Effects += @{ Name = 'Animate windows when minimizing'; Enabled = ($adv.MinAnimate -ne 0); Registry = 'MinAnimate' }
            $result.Effects += @{ Name = 'Show shadows under windows'; Enabled = ($adv.ListviewShadow -ne 0); Registry = 'ListviewShadow' }
            $result.Effects += @{ Name = 'Animate taskbar'; Enabled = ($adv.TaskbarAnimations -ne 0); Registry = 'TaskbarAnimations' }
        }

        # DWM (Desktop Window Manager) settings
        $dwm = Get-ItemProperty -Path $dwmKey -ErrorAction SilentlyContinue
        if ($dwm) {
            $result.TransparencyEnabled = if ($null -ne $dwm.EnableAeroPeek) { $dwm.EnableAeroPeek -eq 1 } else { $true }
        }

        # System transparency setting
        $personalize = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction SilentlyContinue
        if ($personalize) {
            $result.TransparencyEffects = $personalize.EnableTransparency -eq 1
        }

        # Count enabled effects
        $enabledCount = ($result.Effects | Where-Object { $_.Enabled }).Count
        $result.EnabledEffectsCount = $enabledCount

        if ($result.VisualFxSetting -eq 1) { $result.Severity = 'yellow' }  # Best appearance
    }
    catch {
        $result.Errors += "Visual effects query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-WindowsFeaturesDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); Features = @(); Bloatware = @() }

    # Check for resource-heavy optional features
    try {
        $features = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Enabled' } |
            Select-Object FeatureName, State

        $heavyFeatures = @('HypervisorPlatform', 'VirtualMachinePlatform', 'Microsoft-Windows-Subsystem-Linux',
                          'Containers', 'Microsoft-Hyper-V-All', 'Microsoft-Hyper-V')

        $result.Features = @($features | ForEach-Object {
            $isHeavy = $_.FeatureName -in $heavyFeatures
            @{ Name = $_.FeatureName; IsHeavy = $isHeavy }
        })

        $result.HeavyFeaturesEnabled = @($result.Features | Where-Object { $_.IsHeavy })
    }
    catch {
        $result.Errors += "Optional features query failed: $($_.Exception.Message)"
    }

    # Check for common bloatware/preinstalled apps
    try {
        $bloatwarePatterns = @(
            '*Candy*', '*Bubble*', '*Solitaire*', '*Disney*', '*Dolby*',
            '*Facebook*', '*Flipboard*', '*Twitter*', '*TikTok*', '*Spotify*',
            '*McAfee*', '*Norton*', '*ExpressVPN*', '*Booking*', '*Amazon*',
            '*LinkedIn*', '*Skype*', '*Xbox*', '*Zune*', '*3DBuilder*',
            '*BingWeather*', '*BingNews*', '*BingFinance*', '*BingSports*',
            '*MixedReality*', '*Paint3D*', '*People*', '*Print3D*',
            '*Microsoft.549981C3F5F10*', '*Clipchamp*'
        )

        $installedApps = Get-AppxPackage -ErrorAction SilentlyContinue
        $result.Bloatware = @($installedApps | Where-Object {
            $name = $_.Name
            $bloatwarePatterns | Where-Object { $name -like $_ }
        } | Select-Object -ExpandProperty Name -Unique)

        $result.BloatwareCount = $result.Bloatware.Count
        if ($result.BloatwareCount -gt 5) { $result.Severity = 'yellow' }
    }
    catch {
        $result.Errors += "Bloatware check failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-ServicesDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); DisableableServices = @(); RunningServices = @() }

    # Services that can often be safely disabled for performance
    $disableableSvcs = @{
        'DiagTrack' = @{ Name = 'Connected User Experiences and Telemetry'; Impact = 'High'; Risk = 'Low' }
        'dmwappushservice' = @{ Name = 'Device Management WAP Push'; Impact = 'Low'; Risk = 'Low' }
        'SysMain' = @{ Name = 'Superfetch/SysMain'; Impact = 'Medium'; Risk = 'Medium' }
        'WSearch' = @{ Name = 'Windows Search Indexer'; Impact = 'High'; Risk = 'Medium' }
        'XblAuthManager' = @{ Name = 'Xbox Live Auth Manager'; Impact = 'Low'; Risk = 'Low' }
        'XblGameSave' = @{ Name = 'Xbox Live Game Save'; Impact = 'Low'; Risk = 'Low' }
        'XboxGipSvc' = @{ Name = 'Xbox Accessory Management'; Impact = 'Low'; Risk = 'Low' }
        'XboxNetApiSvc' = @{ Name = 'Xbox Live Networking'; Impact = 'Low'; Risk = 'Low' }
        'Fax' = @{ Name = 'Fax Service'; Impact = 'Low'; Risk = 'Low' }
        'PrintNotify' = @{ Name = 'Printer Extensions'; Impact = 'Low'; Risk = 'Low' }
        'RemoteRegistry' = @{ Name = 'Remote Registry'; Impact = 'Low'; Risk = 'Low' }
        'RetailDemo' = @{ Name = 'Retail Demo Service'; Impact = 'Low'; Risk = 'Low' }
        'WbioSrvc' = @{ Name = 'Windows Biometric Service'; Impact = 'Low'; Risk = 'Medium' }
        'wisvc' = @{ Name = 'Windows Insider Service'; Impact = 'Low'; Risk = 'Low' }
        'MapsBroker' = @{ Name = 'Downloaded Maps Manager'; Impact = 'Low'; Risk = 'Low' }
        'lfsvc' = @{ Name = 'Geolocation Service'; Impact = 'Low'; Risk = 'Low' }
    }

    try {
        $services = Get-Service -ErrorAction SilentlyContinue
        $result.TotalRunning = @($services | Where-Object { $_.Status -eq 'Running' }).Count
        $result.TotalServices = $services.Count

        foreach ($svcName in $disableableSvcs.Keys) {
            $svc = $services | Where-Object { $_.Name -eq $svcName }
            if ($svc) {
                $info = $disableableSvcs[$svcName]
                $result.DisableableServices += @{
                    ServiceName = $svcName
                    DisplayName = $info.Name
                    Status = "$($svc.Status)"
                    StartType = "$($svc.StartType)"
                    Impact = $info.Impact
                    Risk = $info.Risk
                    CanDisable = ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled')
                }
            }
        }

        $canDisableCount = ($result.DisableableServices | Where-Object { $_.CanDisable }).Count
        if ($canDisableCount -gt 5) { $result.Severity = 'yellow' }
    }
    catch {
        $result.Errors += "Services query failed: $($_.Exception.Message)"
    }

    return $result
}

function Get-IndexingDiagnostics {
    $result = @{ Severity = 'green'; Errors = @() }
    try {
        # Windows Search service status
        $searchSvc = Get-Service -Name 'WSearch' -ErrorAction SilentlyContinue
        $result.SearchServiceStatus = if ($searchSvc) { "$($searchSvc.Status)" } else { 'Not Found' }
        $result.SearchServiceStartType = if ($searchSvc) { "$($searchSvc.StartType)" } else { 'N/A' }

        # Indexed locations count
        try {
            $indexerStatus = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -ErrorAction SilentlyContinue
            if ($indexerStatus) {
                $result.SetupCompleted = $indexerStatus.SetupCompletedSuccessfully -eq 1
            }
        } catch {}

        # Check index size
        $indexPath = "$env:ProgramData\Microsoft\Search\Data\Applications\Windows"
        try {
            if (Test-Path $indexPath -ErrorAction SilentlyContinue) {
                $indexSize = (Get-ChildItem -Path $indexPath -Recurse -ErrorAction SilentlyContinue |
                             Measure-Object -Property Length -Sum).Sum
                $result.IndexSizeBytes = $indexSize
                $result.IndexSizeMB = [math]::Round($indexSize / 1MB, 2)
            }
        } catch { }

        if ($result.SearchServiceStatus -eq 'Running') { $result.Severity = 'yellow' }
    }
    catch {
        $result.Errors += "Indexing query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-DefenderDiagnostics {
    $result = @{ Severity = 'green'; Errors = @() }
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $result.RealTimeEnabled = $defenderStatus.RealTimeProtectionEnabled
            $result.BehaviorMonitor = $defenderStatus.BehaviorMonitorEnabled
            $result.IoavProtection = $defenderStatus.IoavProtectionEnabled
            $result.OnAccessProtection = $defenderStatus.OnAccessProtectionEnabled
            $result.AntivirusEnabled = $defenderStatus.AntivirusEnabled
            $result.LastFullScan = $defenderStatus.FullScanEndTime
            $result.LastQuickScan = $defenderStatus.QuickScanEndTime
            $result.SignatureAge = $defenderStatus.AntivirusSignatureAge

            # Check for third-party AV
            $result.ThirdPartyAV = -not $defenderStatus.AntivirusEnabled -and $defenderStatus.RealTimeProtectionEnabled -eq $false
        }

        # Exclusions count (can impact performance if too few for dev work)
        try {
            $prefs = Get-MpPreference -ErrorAction SilentlyContinue
            if ($prefs) {
                $result.ExcludedPaths = @($prefs.ExclusionPath).Count
                $result.ExcludedProcesses = @($prefs.ExclusionProcess).Count
                $result.ExcludedExtensions = @($prefs.ExclusionExtension).Count
                $result.ScanAvgCPULoad = $prefs.ScanAvgCPULoadFactor
            }
        } catch {}

    }
    catch {
        $result.Errors += "Defender query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-StorageDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); TempFiles = @(); TotalTempSizeMB = 0; TotalTempSizeGB = 0; RecycleBinSizeMB = 0; StorageSenseEnabled = $false }
    try {
        # Temp folder sizes
        $tempPaths = @(
            @{ Name = 'User Temp'; Path = $env:TEMP }
            @{ Name = 'Windows Temp'; Path = "$env:SystemRoot\Temp" }
            @{ Name = 'Prefetch'; Path = "$env:SystemRoot\Prefetch" }
            @{ Name = 'SoftwareDistribution'; Path = "$env:SystemRoot\SoftwareDistribution\Download" }
            @{ Name = 'Windows Update Cleanup'; Path = "$env:SystemRoot\WinSxS\Backup" }
        )

        foreach ($tp in $tempPaths) {
            if (Test-Path $tp.Path) {
                $size = (Get-ChildItem -Path $tp.Path -Recurse -Force -ErrorAction SilentlyContinue |
                        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                $result.TempFiles += @{
                    Name = $tp.Name
                    Path = $tp.Path
                    SizeBytes = if ($size) { $size } else { 0 }
                    SizeMB = if ($size) { [math]::Round($size / 1MB, 2) } else { 0 }
                }
            }
        }

        # Calculate total - handle empty array
        if ($result.TempFiles.Count -gt 0) {
            $totalTempMB = 0
            foreach ($tf in $result.TempFiles) { $totalTempMB += $tf.SizeMB }
            $result.TotalTempSizeMB = [math]::Round($totalTempMB, 2)
            $result.TotalTempSizeGB = [math]::Round($totalTempMB / 1024, 2)
        }

        # Recycle Bin size
        try {
            $shell = New-Object -ComObject Shell.Application
            $recycleBin = $shell.NameSpace(0x0a)
            $rbItems = $recycleBin.Items()
            if ($rbItems -and $rbItems.Count -gt 0) {
                $rbSize = 0
                foreach ($item in $rbItems) { if ($item.Size) { $rbSize += $item.Size } }
                $result.RecycleBinSizeMB = [math]::Round($rbSize / 1MB, 2)
            }
        } catch { $result.RecycleBinSizeMB = 0 }

        # Storage Sense status
        try {
            $ssKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
            $ss = Get-ItemProperty -Path $ssKey -ErrorAction SilentlyContinue
            $result.StorageSenseEnabled = if ($ss -and $ss.'01') { $ss.'01' -eq 1 } else { $false }
        } catch { $result.StorageSenseEnabled = $false }

        if ($result.TotalTempSizeGB -gt 2) { $result.Severity = 'yellow' }
        if ($result.TotalTempSizeGB -gt 5) { $result.Severity = 'red' }
    }
    catch {
        $result.Errors += "Storage query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-BackgroundAppsDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); Apps = @() }
    try {
        # Background apps permission (Windows 10/11)
        $bgAppsKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
        if (Test-Path $bgAppsKey) {
            $bgApps = Get-ChildItem -Path $bgAppsKey -ErrorAction SilentlyContinue
            $enabledCount = 0
            foreach ($app in $bgApps) {
                $props = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
                if ($props -and $props.Disabled -eq 0) {
                    $enabledCount++
                    $result.Apps += @{ Name = $app.PSChildName; Enabled = $true }
                }
            }
            $result.EnabledBackgroundApps = $enabledCount
        }

        # Global background apps setting
        $globalKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
        $global = Get-ItemProperty -Path $globalKey -ErrorAction SilentlyContinue
        $result.GlobalBackgroundAppsEnabled = if ($global -and $null -ne $global.GlobalUserDisabled) { $global.GlobalUserDisabled -eq 0 } else { $true }

        if ($result.EnabledBackgroundApps -gt 10) { $result.Severity = 'yellow' }
    }
    catch {
        $result.Errors += "Background apps query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-GameModeDiagnostics {
    $result = @{ Severity = 'green'; Errors = @() }
    try {
        # Game Mode
        $gameModeKey = 'HKCU:\Software\Microsoft\GameBar'
        $gm = Get-ItemProperty -Path $gameModeKey -ErrorAction SilentlyContinue
        $result.GameModeEnabled = if ($gm -and $null -ne $gm.AllowAutoGameMode) { $gm.AllowAutoGameMode -eq 1 } else { $true }
        $result.GameBarEnabled = if ($gm -and $null -ne $gm.UseNexusForGameBarEnabled) { $gm.UseNexusForGameBarEnabled -eq 1 } else { $true }

        # Game DVR (background recording)
        $gameDVRKey = 'HKCU:\System\GameConfigStore'
        $gdvr = Get-ItemProperty -Path $gameDVRKey -ErrorAction SilentlyContinue
        $result.GameDVREnabled = if ($gdvr -and $null -ne $gdvr.GameDVR_Enabled) { $gdvr.GameDVR_Enabled -eq 1 } else { $true }

        # Hardware-accelerated GPU scheduling
        $gpuSchedKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        $gpuSched = Get-ItemProperty -Path $gpuSchedKey -ErrorAction SilentlyContinue
        $result.HwGpuScheduling = if ($gpuSched -and $null -ne $gpuSched.HwSchMode) { $gpuSched.HwSchMode -eq 2 } else { $false }

        # Check for dedicated GPU
        $gpu = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notmatch 'Microsoft|Basic|Standard' } | Select-Object -First 1
        $result.HasDedicatedGPU = $null -ne $gpu
        $result.GPUName = if ($gpu) { $gpu.Name } else { 'Integrated/Basic' }

    }
    catch {
        $result.Errors += "Game mode query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-PrivacyDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); Settings = @(); EnabledPrivacyImpactCount = 0 }
    try {
        $privacySettings = @(
            @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Value = 'Enabled'; Name = 'Advertising ID'; OffValue = 0 }
            @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Value = 'SubscribedContent-338389Enabled'; Name = 'Windows Tips'; OffValue = 0 }
            @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Value = 'SoftLandingEnabled'; Name = 'App Suggestions'; OffValue = 0 }
            @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Value = 'RotatingLockScreenEnabled'; Name = 'Lock Screen Suggestions'; OffValue = 0 }
            @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Value = 'Start_TrackDocs'; Name = 'Recent Files Tracking'; OffValue = 0 }
            @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Value = 'Start_TrackProgs'; Name = 'Recent Programs Tracking'; OffValue = 0 }
            @{ Key = 'HKCU:\Software\Microsoft\Siuf\Rules'; Value = 'NumberOfSIUFInPeriod'; Name = 'Feedback Frequency'; OffValue = 0 }
            @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Value = 'AllowTelemetry'; Name = 'Telemetry Level'; OffValue = 0 }
        )

        foreach ($setting in $privacySettings) {
            $current = Get-ItemProperty -Path $setting.Key -ErrorAction SilentlyContinue
            $isEnabled = if ($current -and $null -ne $current.$($setting.Value)) {
                $current.$($setting.Value) -ne $setting.OffValue
            } else { $true }  # Assume enabled if not set

            $result.Settings += @{
                Name = $setting.Name
                Enabled = $isEnabled
                CanDisable = $isEnabled
            }
        }

        $enabledCount = ($result.Settings | Where-Object { $_.Enabled }).Count
        $result.EnabledPrivacyImpactCount = $enabledCount
        if ($enabledCount -gt 4) { $result.Severity = 'yellow' }
    }
    catch {
        $result.Errors += "Privacy settings query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-VirtualMemoryDiagnostics {
    $result = @{ Severity = 'green'; Errors = @() }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $pf = Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue
        $pfUsage = Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue

        $totalRAMGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        $result.TotalRAMGB = $totalRAMGB
        $result.RecommendedPageFileMB = [math]::Round($totalRAMGB * 1.5 * 1024)  # 1.5x RAM
        $result.MaxRecommendedPageFileMB = [math]::Round($totalRAMGB * 3 * 1024)  # 3x RAM max

        if ($pf) {
            $result.PageFileSettings = @($pf | ForEach-Object {
                @{
                    Path = $_.Name
                    InitialSizeMB = $_.InitialSize
                    MaxSizeMB = $_.MaximumSize
                    IsSystemManaged = ($_.InitialSize -eq 0 -and $_.MaximumSize -eq 0)
                }
            })
        }

        if ($pfUsage) {
            $result.CurrentPageFileMB = $pfUsage.AllocatedBaseSize
            $result.CurrentUsageMB = $pfUsage.CurrentUsage
            $result.PeakUsageMB = $pfUsage.PeakUsage
        }

        # Check if system managed (usually fine, but custom can be better)
        $result.IsSystemManaged = -not $pf -or ($pf | Where-Object { $_.InitialSize -eq 0 })

        # Check if page file is on SSD
        $sysDrive = $env:SystemDrive
        $disk = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object -First 1
        $result.PageFileOnSSD = if ($disk) { $disk.MediaType -eq 'SSD' } else { $false }

    }
    catch {
        $result.Errors += "Virtual memory query failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-BrowserDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); Browsers = @(); InstalledBrowserCount = 0; RunningBrowserProcesses = 0; BrowserMemoryMB = 0 }
    try {
        # Detect installed browsers
        $browserPaths = @(
            @{ Name = 'Chrome'; Path = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"; AltPath = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" }
            @{ Name = 'Firefox'; Path = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"; AltPath = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe" }
            @{ Name = 'Edge'; Path = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"; AltPath = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" }
            @{ Name = 'Brave'; Path = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe"; AltPath = "${env:LocalAppData}\BraveSoftware\Brave-Browser\Application\brave.exe" }
            @{ Name = 'Opera'; Path = "$env:LocalAppData\Programs\Opera\opera.exe" }
        )

        foreach ($browser in $browserPaths) {
            $installed = (Test-Path $browser.Path) -or ($browser.AltPath -and (Test-Path $browser.AltPath))
            if ($installed) {
                $result.Browsers += @{ Name = $browser.Name; Installed = $true }
            }
        }

        # Check for multiple browsers (can consume RAM in background)
        $result.InstalledBrowserCount = $result.Browsers.Count

        # Check browser processes running
        $browserProcs = @('chrome', 'firefox', 'msedge', 'brave', 'opera', 'iexplore')
        $runningBrowsers = @(Get-Process -Name $browserProcs -ErrorAction SilentlyContinue)
        $result.RunningBrowserProcesses = $runningBrowsers.Count
        if ($runningBrowsers.Count -gt 0) {
            $totalMem = 0
            foreach ($proc in $runningBrowsers) { $totalMem += $proc.WorkingSet64 }
            $result.BrowserMemoryMB = [math]::Round($totalMem / 1MB, 0)
        }

        if ($result.BrowserMemoryMB -gt 2000) { $result.Severity = 'yellow' }
        if ($result.BrowserMemoryMB -gt 4000) { $result.Severity = 'red' }
    }
    catch {
        $result.Errors += "Browser diagnostics failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-DriverDiagnostics {
    $result = @{ Severity = 'green'; Errors = @(); ProblematicDrivers = @(); OldDrivers = @() }
    try {
        # Check for problem devices
        $problemDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
                         Where-Object { $_.ConfigManagerErrorCode -ne 0 }

        $result.ProblematicDrivers = @($problemDevices | ForEach-Object {
            @{
                Name = $_.Name
                DeviceID = $_.DeviceID
                ErrorCode = $_.ConfigManagerErrorCode
                Status = $_.Status
            }
        })

        $result.ProblemDeviceCount = $result.ProblematicDrivers.Count

        # Check for old drivers (optional - can be slow)
        if ($script:IsAdmin) {
            $drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                      Where-Object { $_.DriverDate } |
                      Sort-Object DriverDate |
                      Select-Object -First 10

            $result.OldDrivers = @($drivers | ForEach-Object {
                $ageYears = [math]::Round(((Get-Date) - $_.DriverDate).TotalDays / 365, 1)
                @{
                    Name = $_.DeviceName
                    DriverVersion = $_.DriverVersion
                    DriverDate = $_.DriverDate
                    AgeYears = $ageYears
                }
            } | Where-Object { $_.AgeYears -gt 3 })
        }

        if ($result.ProblemDeviceCount -gt 0) { $result.Severity = 'red' }
        elseif ($result.OldDrivers.Count -gt 3) { $result.Severity = 'yellow' }
    }
    catch {
        $result.Errors += "Driver diagnostics failed: $($_.Exception.Message)"
    }
    return $result
}

function Get-WindowsUpdateDiagnostics {
    $result = @{ Severity = 'green'; Errors = @() }
    try {
        # Check Windows Update service
        $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
        $result.UpdateServiceStatus = if ($wuSvc) { "$($wuSvc.Status)" } else { 'Not Found' }

        # Pending updates
        if ($script:IsAdmin) {
            try {
                $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
                $updateSearcher = $updateSession.CreateUpdateSearcher()
                $pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates
                $result.PendingUpdateCount = $pendingUpdates.Count
                $result.PendingUpdates = @($pendingUpdates | Select-Object -First 5 | ForEach-Object {
                    @{ Title = $_.Title; KBArticleIDs = ($_.KBArticleIDs -join ', ') }
                })
            }
            catch {
                $result.PendingUpdateCount = -1
            }
        }

        # Last update check (from registry)
        try {
            $wuKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
            $lastCheck = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
            if ($lastCheck -and $lastCheck.LastSuccessTime) {
                $result.LastUpdateCheck = [datetime]::Parse($lastCheck.LastSuccessTime)
                $daysSinceCheck = ((Get-Date) - $result.LastUpdateCheck).Days
                $result.DaysSinceUpdateCheck = $daysSinceCheck
                if ($daysSinceCheck -gt 30) { $result.Severity = 'yellow' }
            }
        } catch {}

        # Delivery Optimization
        try {
            $doKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
            $do = Get-ItemProperty -Path $doKey -ErrorAction SilentlyContinue
            $result.DeliveryOptimizationEnabled = if ($do -and $null -ne $do.DODownloadMode) { $do.DODownloadMode -ne 0 } else { $true }
        } catch { $result.DeliveryOptimizationEnabled = $true }

    }
    catch {
        $result.Errors += "Windows Update diagnostics failed: $($_.Exception.Message)"
    }
    return $result
}

# ============================================================================
# ANALYSIS FUNCTIONS
# ============================================================================

function Get-HealthScores {
    param([System.Collections.Specialized.OrderedDictionary]$AllResults)
    $scores = [ordered]@{}
    foreach ($key in $AllResults.Keys) {
        $section = $AllResults[$key]
        $scores[$key] = if (Test-HasKey $section 'Skipped') { 'skipped' } else { $section.Severity }
    }
    $activeSeverities = @($scores.Values | Where-Object { $_ -ne 'skipped' })
    $scores['Overall'] = if ($activeSeverities.Count -gt 0) { Get-WorstSeverity $activeSeverities } else { 'green' }
    return $scores
}

function Get-Recommendations {
    param([System.Collections.Specialized.OrderedDictionary]$AllResults)
    $recs = [System.Collections.Generic.List[PSCustomObject]]::new()

    # CPU recommendations
    $cpu = $AllResults['CPU']
    if ($cpu -and -not (Test-HasKey $cpu 'Skipped')) {
        if ($cpu.OverallUsage -ge 85) {
            $topProc = if ($cpu.TopProcesses.Count -gt 0) { $cpu.TopProcesses[0].Name } else { 'unknown' }
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'CPU'; Title = 'High CPU Usage'
                    Detail = "Overall CPU at $($cpu.OverallUsage)%. Top process: $topProc."
                    Action = 'Investigate the top CPU-consuming process. Close unnecessary applications or check for runaway processes.' })
        }
        elseif ($cpu.OverallUsage -ge 60) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'CPU'; Title = 'Elevated CPU Usage'
                    Detail = "Overall CPU at $($cpu.OverallUsage)%."
                    Action = 'Monitor CPU usage. Consider closing background applications if system feels sluggish.' })
        }
        if ($cpu.SustainedHighCpu -and $cpu.SustainedHighCpu.Count -gt 0) {
            foreach ($p in $cpu.SustainedHighCpu) {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'CPU'; Title = "Sustained high CPU: $($p.Name)"
                        Detail = "Process $($p.Name) (PID $($p.PID)) consuming ~$($p.CPUPctEst)% CPU during sampling."
                        Action = "Investigate whether $($p.Name) is functioning correctly. Consider restarting the application." })
            }
        }
    }

    # Memory recommendations
    $mem = $AllResults['Memory']
    if ($mem -and -not (Test-HasKey $mem 'Skipped')) {
        if ($mem.UsedPct -ge 90) {
            $topProc = if ($mem.TopProcesses.Count -gt 0) { "$($mem.TopProcesses[0].Name) ($($mem.TopProcesses[0].WorkingSetMB) MB)" } else { 'unknown' }
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Memory'; Title = 'Critical Memory Usage'
                    Detail = "RAM usage at $($mem.UsedPct)% ($(Format-Bytes $mem.FreeBytes) free). Top consumer: $topProc."
                    Action = 'Close memory-heavy applications. If persistent, consider adding more RAM.' })
        }
        elseif ($mem.UsedPct -ge 70) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Memory'; Title = 'Elevated Memory Usage'
                    Detail = "RAM usage at $($mem.UsedPct)% ($(Format-Bytes $mem.FreeBytes) free)."
                    Action = 'Monitor memory usage. Close unnecessary browser tabs and applications.' })
        }
        if ($null -ne $mem.PagesPerSec -and $mem.PagesPerSec -ge 1000) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Memory'; Title = 'Excessive Paging'
                    Detail = "Pages/sec at $($mem.PagesPerSec). The system is heavily paging to disk."
                    Action = 'The system needs more physical RAM or fewer memory-consuming applications.' })
        }
    }

    # Disk I/O recommendations
    $disk = $AllResults['DiskIO']
    if ($disk -and -not (Test-HasKey $disk 'Skipped')) {
        foreach ($v in $disk.Volumes) {
            if ($v.UsedPct -ge 90) {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Disk'; Title = "Drive $($v.Drive) critically full"
                        Detail = "Drive $($v.Drive) is $($v.UsedPct)% full ($($v.FreeGB) GB free of $($v.SizeGB) GB)."
                        Action = "Free up space on $($v.Drive) by removing temporary files, clearing recycle bin, or moving data." })
            }
            elseif ($v.UsedPct -ge 80) {
                $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Disk'; Title = "Drive $($v.Drive) getting full"
                        Detail = "Drive $($v.Drive) is $($v.UsedPct)% full ($($v.FreeGB) GB free)."
                        Action = "Consider freeing up space on $($v.Drive) to maintain performance." })
            }
        }
        foreach ($d in $disk.DiskMetrics) {
            if ($null -ne $d.AvgQueueLength -and $d.AvgQueueLength -gt 5) {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Disk'; Title = "High disk queue: $($d.DiskName)"
                        Detail = "Disk queue length at $($d.AvgQueueLength). The disk is a bottleneck."
                        Action = 'Reduce disk I/O load. If using HDD, consider upgrading to an SSD.' })
            }
            if ($null -ne $d.AvgReadLatencyMs -and $d.AvgReadLatencyMs -gt 20) {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Disk'; Title = "High read latency: $($d.DiskName)"
                        Detail = "Average read latency at $($d.AvgReadLatencyMs) ms."
                        Action = 'Disk read performance is degraded. Check for hardware issues or consider an SSD upgrade.' })
            }
        }
    }

    # Disk Health recommendations
    $dHealth = $AllResults['DiskHealth']
    if ($dHealth -and -not (Test-HasKey $dHealth 'Skipped')) {
        foreach ($d in $dHealth.Disks) {
            if ($d.HealthStatus -and $d.HealthStatus -ne 'Healthy') {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Disk Health'; Title = "Disk $($d.FriendlyName) health: $($d.HealthStatus)"
                        Detail = "Physical disk reports status: $($d.HealthStatus)."
                        Action = 'Back up your data immediately. Plan to replace this drive.' })
            }
            if ($null -ne $d.Wear -and $d.Wear -gt 80) {
                $sevLvl = if ($d.Wear -gt 95) { 'red' } else { 'yellow' }
                $recs.Add([PSCustomObject]@{ Severity = $sevLvl; Category = 'Disk Health'; Title = "SSD wear: $($d.FriendlyName)"
                        Detail = "SSD wear level at $($d.Wear)%."
                        Action = 'Plan to replace this SSD. Ensure backups are current.' })
            }
            if ($null -ne $d.ReadErrorsUncorrected -and $d.ReadErrorsUncorrected -gt 0) {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Disk Health'; Title = "Uncorrected read errors: $($d.FriendlyName)"
                        Detail = "$($d.ReadErrorsUncorrected) uncorrected read errors detected."
                        Action = 'This disk may be failing. Back up data immediately and plan replacement.' })
            }
            if ($null -ne $d.Temperature -and $d.Temperature -gt 55) {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Disk Health'; Title = "Disk overheating: $($d.FriendlyName)"
                        Detail = "Disk temperature at $($d.Temperature) C."
                        Action = 'Check case airflow and cooling. High temperatures reduce disk lifespan.' })
            }
        }
    }

    # Network recommendations
    $net = $AllResults['Network']
    if ($net -and -not (Test-HasKey $net 'Skipped')) {
        if ($net.ContainsKey('InterfaceMetrics') -and $net.InterfaceMetrics) {
            foreach ($m in $net.InterfaceMetrics) {
                $recvErr = if ($m.ContainsKey('RecvErrors') -and $m.RecvErrors) { [int]$m.RecvErrors } else { 0 }
                $sendErr = if ($m.ContainsKey('SendErrors') -and $m.SendErrors) { [int]$m.SendErrors } else { 0 }
                $totalErrors = $recvErr + $sendErr
                if ($totalErrors -gt 100) {
                    $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Network'; Title = "Packet errors: $($m.InterfaceName)"
                            Detail = "$totalErrors packet errors on $($m.InterfaceName)."
                            Action = 'Check network cable, driver, or switch port. Packet errors indicate physical or driver issues.' })
                }
            }
        }
        if ($net.ContainsKey('Connections') -and $net.Connections.ContainsKey('Established') -and $net.Connections.Established -ge 500) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Network'; Title = 'High connection count'
                    Detail = "$($net.Connections.Established) established TCP connections."
                    Action = 'Investigate which processes are opening many connections. This may indicate a misbehaving application.' })
        }
    }

    # Startup recommendations
    $startup = $AllResults['StartupPrograms']
    if ($startup -and -not (Test-HasKey $startup 'Skipped')) {
        if ($startup.TotalCount -ge 20) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Startup'; Title = 'Excessive startup programs'
                    Detail = "$($startup.TotalCount) programs configured to run at startup."
                    Action = 'Review startup programs in Task Manager and disable those not needed. This significantly impacts boot time.' })
        }
        elseif ($startup.TotalCount -ge 10) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Startup'; Title = 'Many startup programs'
                    Detail = "$($startup.TotalCount) programs configured to run at startup."
                    Action = 'Consider disabling unnecessary startup programs to improve boot time.' })
        }
    }

    # Process recommendations
    $proc = $AllResults['Processes']
    if ($proc -and -not (Test-HasKey $proc 'Skipped')) {
        if ($proc.TotalCount -ge 400) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Processes'; Title = 'Very high process count'
                    Detail = "$($proc.TotalCount) processes running."
                    Action = 'Too many processes may consume excessive resources. Review and close unnecessary applications.' })
        }
        foreach ($p in $proc.HighHandles) {
            if ($p.Handles -gt 10000) {
                $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Processes'; Title = "Possible handle leak: $($p.Name)"
                        Detail = "$($p.Name) (PID $($p.PID)) has $($p.Handles) handles."
                        Action = "This may indicate a handle leak. Consider restarting $($p.Name)." })
            }
        }
    }

    # Event Log recommendations
    $evtLog = $AllResults['EventLog']
    if ($evtLog -and -not (Test-HasKey $evtLog 'Skipped')) {
        if ($evtLog.CriticalCount -gt 0) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Events'; Title = 'Critical system events detected'
                    Detail = "$($evtLog.CriticalCount) critical events in the last 24 hours."
                    Action = 'Review the Event Log section for details. Critical events may indicate hardware failures or system instability.' })
        }
        elseif ($evtLog.ErrorCount -gt 20) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Events'; Title = 'Many error events'
                    Detail = "$($evtLog.ErrorCount) error events in the last 24 hours."
                    Action = 'Review the Event Log section. Frequent errors may indicate recurring issues.' })
        }
    }

    # Thermal recommendations
    $thermal = $AllResults['Thermal']
    if ($thermal -and -not (Test-HasKey $thermal 'Skipped')) {
        if ($null -ne $thermal.PerfLimit -and $thermal.PerfLimit -lt 95) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Thermal'; Title = 'CPU performance throttled'
                    Detail = "Processor performance limited to $($thermal.PerfLimit)%."
                    Action = 'The CPU is being throttled due to power or thermal constraints. Check cooling and ventilation.' })
        }
        if ($thermal.ThermalEvents.Count -gt 3) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Thermal'; Title = 'Frequent thermal events'
                    Detail = "$($thermal.ThermalEvents.Count) thermal events in the last 7 days."
                    Action = 'Clean dust from fans and vents. Ensure adequate airflow around the computer.' })
        }
    }

    # Uptime recommendation
    $sysInfo = $AllResults['SystemInfo']
    if ($sysInfo -and -not (Test-HasKey $sysInfo 'Skipped') -and $sysInfo.Uptime) {
        $uptimeDays = [math]::Floor($sysInfo.Uptime.TotalDays)
        if ($uptimeDays -ge 30) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'System'; Title = 'Very long uptime'
                    Detail = "System has been running for $uptimeDays days without restart."
                    Action = 'Restart the computer to apply pending updates and clear accumulated state.' })
        }
        elseif ($uptimeDays -ge 7) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'System'; Title = 'Extended uptime'
                    Detail = "System has been running for $uptimeDays days."
                    Action = 'Consider restarting to apply pending updates.' })
        }
    }

    # ========== NEW OPTIMIZATION RECOMMENDATIONS ==========

    # Power Plan recommendations
    $power = $AllResults['PowerPlan']
    if ($power -and -not (Test-HasKey $power 'Skipped')) {
        if ($power.ContainsKey('ActivePlanName') -and $power.ActivePlanName -notmatch 'High|Ultimate|Performance') {
            $sev = if ($power.IsLaptop -and -not $power.IsPluggedIn) { 'yellow' } else { 'yellow' }
            $recs.Add([PSCustomObject]@{ Severity = $sev; Category = 'Power'; Title = 'Not using High Performance power plan'
                    Detail = "Current plan: $($power.ActivePlanName). High Performance provides better responsiveness."
                    Action = 'Open Settings > System > Power & battery > Power mode, select "Best performance". Or run: powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' })
        }
        if (-not $power.HasUltimatePerf) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Power'; Title = 'Ultimate Performance plan not available'
                    Detail = 'The hidden Ultimate Performance power plan provides maximum performance for workstations.'
                    Action = 'Enable it by running in Admin PowerShell: powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61' })
        }
        if ($power.ContainsKey('MaxProcState') -and $power.MaxProcState -lt 100) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Power'; Title = 'CPU throttled by power settings'
                    Detail = "Maximum processor state is set to $($power.MaxProcState)%. CPU cannot reach full speed."
                    Action = 'Open Power Options > Change plan settings > Change advanced > Processor power management > Maximum processor state = 100%' })
        }
    }

    # Visual Effects recommendations
    $visual = $AllResults['VisualEffects']
    if ($visual -and -not (Test-HasKey $visual 'Skipped')) {
        if ($visual.VisualFxSetting -eq 1) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Visual'; Title = 'Visual effects set to Best Appearance'
                    Detail = 'Animations and visual effects consume CPU/GPU resources.'
                    Action = 'Open sysdm.cpl > Advanced > Performance Settings > Adjust for best performance (or Custom to keep some)' })
        }
        if ($visual.ContainsKey('TransparencyEffects') -and $visual.TransparencyEffects) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Visual'; Title = 'Transparency effects enabled'
                    Detail = 'Window transparency adds GPU overhead.'
                    Action = 'Settings > Personalization > Colors > Transparency effects = Off' })
        }
    }

    # Windows Features recommendations
    $features = $AllResults['WindowsFeatures']
    if ($features -and -not (Test-HasKey $features 'Skipped')) {
        if ($features.ContainsKey('HeavyFeaturesEnabled') -and $features.HeavyFeaturesEnabled.Count -gt 0) {
            $featureNames = ($features.HeavyFeaturesEnabled | ForEach-Object { $_.Name }) -join ', '
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Features'; Title = 'Resource-heavy features enabled'
                    Detail = "These features consume memory even when idle: $featureNames"
                    Action = 'If not needed, disable via: Settings > Apps > Optional features, or Turn Windows features on/off' })
        }
        if ($features.BloatwareCount -gt 5) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Bloatware'; Title = "$($features.BloatwareCount) preinstalled apps detected"
                    Detail = 'Bloatware apps can run background processes and consume resources.'
                    Action = 'Uninstall unwanted apps: Settings > Apps > Installed apps. Or use: Get-AppxPackage *AppName* | Remove-AppxPackage' })
        }
    }

    # Services recommendations
    $services = $AllResults['Services']
    if ($services -and -not (Test-HasKey $services 'Skipped')) {
        $disableable = @($services.DisableableServices | Where-Object { $_.CanDisable -and $_.Impact -eq 'High' })
        if ($disableable.Count -gt 0) {
            $svcNames = ($disableable | ForEach-Object { $_.DisplayName }) -join ', '
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Services'; Title = 'High-impact services can be disabled'
                    Detail = "These services impact performance and may not be needed: $svcNames"
                    Action = 'Open services.msc, find the service, set Startup type to Disabled. DiagTrack (telemetry) is safe to disable.' })
        }
        $xboxSvcs = @($services.DisableableServices | Where-Object { $_.ServiceName -match 'Xbox|Xbl' -and $_.CanDisable })
        if ($xboxSvcs.Count -gt 0) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Services'; Title = "Xbox services running ($($xboxSvcs.Count) services)"
                    Detail = 'Xbox services run in background even if you dont use Xbox features.'
                    Action = 'If not gaming, disable Xbox services in services.msc: XblAuthManager, XblGameSave, XboxGipSvc, XboxNetApiSvc' })
        }
    }

    # Indexing recommendations
    $indexing = $AllResults['Indexing']
    if ($indexing -and -not (Test-HasKey $indexing 'Skipped')) {
        if ($indexing.SearchServiceStatus -eq 'Running') {
            $sizeMB = if ($indexing.ContainsKey('IndexSizeMB')) { $indexing.IndexSizeMB } else { 'unknown' }
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Indexing'; Title = 'Windows Search Indexer is running'
                    Detail = "Search indexing consumes disk I/O and CPU. Index size: $sizeMB MB."
                    Action = 'Disable: services.msc > Windows Search > Startup type: Disabled. Or limit indexed locations in Indexing Options.' })
        }
    }

    # Defender recommendations
    $defender = $AllResults['Defender']
    if ($defender -and -not (Test-HasKey $defender 'Skipped')) {
        if ($defender.ContainsKey('ScanAvgCPULoad') -and $defender.ScanAvgCPULoad -gt 50) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Defender'; Title = 'Defender scan CPU limit is high'
                    Detail = "Defender is allowed to use $($defender.ScanAvgCPULoad)% CPU during scans."
                    Action = 'Lower it: Windows Security > Virus & threat > Manage settings > Scan options. Or via: Set-MpPreference -ScanAvgCPULoadFactor 25' })
        }
        if ($defender.ContainsKey('ExcludedPaths') -and $defender.ExcludedPaths -eq 0) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Defender'; Title = 'No Defender exclusions configured'
                    Detail = 'Developers should exclude project folders, IDEs, and compilers from real-time scanning.'
                    Action = 'Add exclusions: Windows Security > Virus & threat > Manage settings > Add or remove exclusions. Exclude: node_modules, .git, IDE folders.' })
        }
    }

    # Storage recommendations
    $storage = $AllResults['Storage']
    if ($storage -and -not (Test-HasKey $storage 'Skipped')) {
        if ($storage.ContainsKey('TotalTempSizeGB') -and $storage.TotalTempSizeGB -gt 1) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Storage'; Title = "Temp files using $($storage.TotalTempSizeGB) GB"
                    Detail = 'Temporary files accumulate and waste disk space.'
                    Action = 'Run Disk Cleanup (cleanmgr.exe) or Settings > System > Storage > Temporary files. Delete: Temp, Windows Update Cleanup, Previous Windows.' })
        }
        if ($storage.ContainsKey('RecycleBinSizeMB') -and $storage.RecycleBinSizeMB -gt 1000) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Storage'; Title = "Recycle Bin contains $([math]::Round($storage.RecycleBinSizeMB / 1024, 1)) GB"
                    Detail = 'Empty the Recycle Bin to free disk space.'
                    Action = 'Right-click Recycle Bin > Empty Recycle Bin' })
        }
        if ($storage.ContainsKey('StorageSenseEnabled') -and -not $storage.StorageSenseEnabled) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Storage'; Title = 'Storage Sense is disabled'
                    Detail = 'Storage Sense automatically cleans temp files and old downloads.'
                    Action = 'Enable: Settings > System > Storage > Storage Sense = On. Configure to run weekly.' })
        }
    }

    # Background Apps recommendations
    $bgApps = $AllResults['BackgroundApps']
    if ($bgApps -and -not (Test-HasKey $bgApps 'Skipped')) {
        if ($bgApps.ContainsKey('EnabledBackgroundApps') -and $bgApps.EnabledBackgroundApps -gt 10) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Background'; Title = "$($bgApps.EnabledBackgroundApps) apps can run in background"
                    Detail = 'Background apps consume memory and CPU even when not in use.'
                    Action = 'Settings > Apps > Installed apps > click each app > Advanced options > Background apps permissions = Never. Or disable globally in Privacy settings.' })
        }
        if ($bgApps.ContainsKey('GlobalBackgroundAppsEnabled') -and $bgApps.GlobalBackgroundAppsEnabled) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Background'; Title = 'Background apps are globally enabled'
                    Detail = 'You can disable all background apps at once.'
                    Action = 'Settings > Privacy & security > Background apps > Let apps run in background = Off (Win10). On Win11, disable per-app.' })
        }
    }

    # Game Mode recommendations
    $game = $AllResults['GameMode']
    if ($game -and -not (Test-HasKey $game 'Skipped')) {
        if ($game.ContainsKey('GameDVREnabled') -and $game.GameDVREnabled) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Gaming'; Title = 'Game DVR (background recording) is enabled'
                    Detail = 'Game DVR constantly records gameplay, using GPU and disk resources.'
                    Action = 'Disable: Settings > Gaming > Captures > Record in the background = Off. Or Xbox Game Bar > Settings > Capturing.' })
        }
        if ($game.ContainsKey('GameBarEnabled') -and $game.GameBarEnabled) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Gaming'; Title = 'Xbox Game Bar is enabled'
                    Detail = 'Game Bar overlay uses resources. Disable if you dont use it.'
                    Action = 'Settings > Gaming > Xbox Game Bar = Off' })
        }
        if ($game.ContainsKey('HwGpuScheduling') -and -not $game.HwGpuScheduling -and $game.HasDedicatedGPU) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Gaming'; Title = 'Hardware-accelerated GPU scheduling is off'
                    Detail = 'This feature can improve GPU performance on modern systems.'
                    Action = 'Enable: Settings > System > Display > Graphics > Change default graphics settings > Hardware-accelerated GPU scheduling = On. Requires restart.' })
        }
    }

    # Privacy/Telemetry recommendations
    $privacy = $AllResults['Privacy']
    if ($privacy -and -not (Test-HasKey $privacy 'Skipped')) {
        if ($privacy.ContainsKey('EnabledPrivacyImpactCount') -and $privacy.EnabledPrivacyImpactCount -gt 3) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Privacy'; Title = "$($privacy.EnabledPrivacyImpactCount) telemetry/tracking features enabled"
                    Detail = 'Windows telemetry and suggestions features use network and CPU.'
                    Action = 'Settings > Privacy & security > General > Turn off: Advertising ID, suggested content, app launch tracking. Also: Diagnostics & feedback > Diagnostic data = Basic.' })
        }
        if ($privacy.ContainsKey('Settings') -and $privacy.Settings.Count -gt 0) {
            $tips = @($privacy.Settings | Where-Object { $_.Name -match 'Tips|Suggestions' -and $_.Enabled })
            if ($tips.Count -gt 0) {
                $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Privacy'; Title = 'Windows tips and suggestions enabled'
                        Detail = 'Tips/suggestions cause pop-ups and background activity.'
                        Action = 'Settings > System > Notifications > Additional settings > uncheck all suggestion options. Also check Settings > Personalization > Start.' })
            }
        }
    }

    # Virtual Memory recommendations
    $vmem = $AllResults['VirtualMemory']
    if ($vmem -and -not (Test-HasKey $vmem 'Skipped')) {
        if ($vmem.ContainsKey('IsSystemManaged') -and $vmem.IsSystemManaged -and $vmem.TotalRAMGB -ge 16) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Memory'; Title = 'Page file is system-managed'
                    Detail = "With $($vmem.TotalRAMGB) GB RAM, a fixed page file size may perform better."
                    Action = 'Advanced System Settings > Performance > Advanced > Virtual Memory > Change > Set custom size: Initial = 1.5x RAM, Maximum = 3x RAM (in MB).' })
        }
    }

    # Browser recommendations
    $browser = $AllResults['Browsers']
    if ($browser -and -not (Test-HasKey $browser 'Skipped')) {
        if ($browser.ContainsKey('BrowserMemoryMB') -and $browser.BrowserMemoryMB -gt 2000) {
            $procCount = if ($browser.ContainsKey('RunningBrowserProcesses')) { $browser.RunningBrowserProcesses } else { 0 }
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Browser'; Title = "Browsers using $($browser.BrowserMemoryMB) MB RAM"
                    Detail = "$procCount browser processes are running."
                    Action = 'Close unnecessary tabs. Use extensions like Auto Tab Discard, OneTab, or The Great Suspender. Consider using Edge (better memory management) or Brave.' })
        }
        if ($browser.ContainsKey('InstalledBrowserCount') -and $browser.InstalledBrowserCount -gt 2) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Browser'; Title = "$($browser.InstalledBrowserCount) browsers installed"
                    Detail = 'Multiple browsers can have background processes competing for resources.'
                    Action = 'Uninstall browsers you dont use. Check each browsers settings to disable background running and startup launch.' })
        }
    }

    # Driver recommendations
    $drivers = $AllResults['Drivers']
    if ($drivers -and -not (Test-HasKey $drivers 'Skipped')) {
        if ($drivers.ProblemDeviceCount -gt 0) {
            $recs.Add([PSCustomObject]@{ Severity = 'red'; Category = 'Drivers'; Title = "$($drivers.ProblemDeviceCount) devices have driver problems"
                    Detail = 'Problem devices can cause system instability and performance issues.'
                    Action = 'Open Device Manager (devmgmt.msc), find devices with yellow warning icons, right-click > Update driver or Uninstall.' })
        }
        if ($drivers.OldDrivers -and $drivers.OldDrivers.Count -gt 0) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Drivers'; Title = "$($drivers.OldDrivers.Count) drivers are very old (3+ years)"
                    Detail = 'Old drivers may have bugs or miss performance optimizations.'
                    Action = 'Update drivers through Device Manager or download from manufacturer website (especially GPU, chipset, storage drivers).' })
        }
    }

    # Windows Update recommendations
    $wupdate = $AllResults['WindowsUpdate']
    if ($wupdate -and -not (Test-HasKey $wupdate 'Skipped')) {
        if ($wupdate.ContainsKey('PendingUpdateCount') -and $wupdate.PendingUpdateCount -gt 0) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Updates'; Title = "$($wupdate.PendingUpdateCount) Windows updates pending"
                    Detail = 'Pending updates may include performance and security fixes.'
                    Action = 'Settings > Windows Update > Check for updates > Install all pending updates, then restart.' })
        }
        if ($wupdate.ContainsKey('DaysSinceUpdateCheck') -and $wupdate.DaysSinceUpdateCheck -gt 14) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Updates'; Title = "Haven''t checked for updates in $($wupdate.DaysSinceUpdateCheck) days"
                    Detail = 'Regular updates include performance improvements.'
                    Action = 'Settings > Windows Update > Check for updates' })
        }
        if ($wupdate.ContainsKey('DeliveryOptimizationEnabled') -and $wupdate.DeliveryOptimizationEnabled) {
            $recs.Add([PSCustomObject]@{ Severity = 'yellow'; Category = 'Updates'; Title = 'Delivery Optimization is uploading to other PCs'
                    Detail = 'Windows shares updates with other PCs, using your bandwidth.'
                    Action = 'Settings > Windows Update > Advanced options > Delivery Optimization > Allow downloads from other PCs = Off (or Local network only).' })
        }
    }

    # ========== GENERAL OPTIMIZATION TIPS (always show some) ==========

    # SSD optimization check
    $diskIO = $AllResults['DiskIO']
    if ($diskIO -and $diskIO.ContainsKey('Volumes')) {
        $recs.Add([PSCustomObject]@{ Severity = 'green'; Category = 'Tip'; Title = 'SSD Optimization Checklist'
                Detail = 'If using SSD: ensure TRIM is enabled, AHCI mode in BIOS, and disable defragmentation for SSDs.'
                Action = 'Run: fsutil behavior query DisableDeleteNotify (0 = TRIM enabled). SSDs should NOT be defragmented - Windows handles this automatically.' })
    }

    # Always suggest these fundamental tips
    $recs.Add([PSCustomObject]@{ Severity = 'green'; Category = 'Tip'; Title = 'Disable unnecessary startup programs'
            Detail = 'Every startup program delays boot and consumes ongoing resources.'
            Action = 'Ctrl+Shift+Esc > Startup tab > Right-click and Disable anything not essential. Keep only: antivirus, cloud sync (if needed), audio drivers.' })

    $recs.Add([PSCustomObject]@{ Severity = 'green'; Category = 'Tip'; Title = 'Keep Windows and drivers updated'
            Detail = 'Updates often include performance optimizations and bug fixes.'
            Action = 'Settings > Windows Update. For GPU: use GeForce Experience (NVIDIA), AMD Software, or Intel Driver Support Assistant.' })

    $recs.Add([PSCustomObject]@{ Severity = 'green'; Category = 'Tip'; Title = 'Use built-in Disk Cleanup monthly'
            Detail = 'Removes Windows Update cache, temp files, and system junk.'
            Action = 'Run cleanmgr.exe as Admin, select all options including "Clean up system files". Consider also: DISM /Online /Cleanup-Image /StartComponentCleanup' })

    $recs.Add([PSCustomObject]@{ Severity = 'green'; Category = 'Tip'; Title = 'Check for malware regularly'
            Detail = 'Malware often causes unexplained slowdowns.'
            Action = 'Run Windows Security full scan. Also try: Malwarebytes (free), HitmanPro, or ESET Online Scanner for second opinion.' })

    $recs.Add([PSCustomObject]@{ Severity = 'green'; Category = 'Tip'; Title = 'Recommended performance software'
            Detail = 'Free tools that help maintain and optimize Windows.'
            Action = 'Consider: BleachBit (disk cleanup), Autoruns (startup control), Process Explorer (better Task Manager), CrystalDiskInfo (disk health), HWiNFO (hardware monitoring).' })

    return $recs
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

function ConvertTo-HtmlTable {
    param(
        [object[]]$Data,
        [string[]]$Properties,
        [string[]]$Headers
    )
    if (-not $Data -or $Data.Count -eq 0) { return '<p class="muted">No data available.</p>' }
    if (-not $Headers) { $Headers = $Properties }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($h in $Headers) { [void]$sb.Append("<th>$h</th>") }
    [void]$sb.Append('</tr></thead><tbody>')

    foreach ($item in $Data) {
        [void]$sb.Append('<tr>')
        foreach ($prop in $Properties) {
            $val = if ($item -is [hashtable]) { $item[$prop] } else { $item.$prop }
            if ($null -eq $val) { $val = '-' }
            [void]$sb.Append("<td>$([System.Web.HttpUtility]::HtmlEncode("$val"))</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function New-ProgressBar {
    param([double]$Pct, [string]$Color)
    if (-not $Color) {
        $Color = if ($Pct -ge 90) { 'var(--red)' } elseif ($Pct -ge 70) { 'var(--yellow)' } else { 'var(--green)' }
    }
    $clamped = [math]::Max(0, [math]::Min(100, $Pct))
    return "<div class='progress'><div class='progress-fill' style='width:${clamped}%;background:$Color'></div><span class='progress-text'>${Pct}%</span></div>"
}

function New-SeverityBadge {
    param([string]$Text, [string]$Severity)
    return "<span class='badge badge-$Severity'>$([System.Web.HttpUtility]::HtmlEncode($Text))</span>"
}

function New-HtmlReport {
    param(
        [System.Collections.Specialized.OrderedDictionary]$DiagResults,
        [System.Collections.Specialized.OrderedDictionary]$HealthScores,
        [System.Collections.Generic.List[PSCustomObject]]$Recommendations,
        [System.Collections.Generic.List[string]]$SkippedDiagnostics,
        [bool]$IsAdmin
    )

    # Load System.Web for HtmlEncode
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $overallSev = $HealthScores['Overall']
    $overallLabel = switch ($overallSev) { 'green' { 'Good' } 'yellow' { 'Warning' } 'red' { 'Critical' } default { 'Unknown' } }
    $collectionDuration = (Get-Date) - $script:CollectionStart
    $computerName = $env:COMPUTERNAME
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # --- Build each diagnostic section ---
    $sectionsHtml = [System.Text.StringBuilder]::new()

    # System Info Section
    $sysInfo = $DiagResults['SystemInfo']
    if ($sysInfo -and -not (Test-HasKey $sysInfo 'Error')) {
        $sysHtml = @"
<table class="kv-table">
<tr><th>Computer Name</th><td>$($sysInfo.ComputerName)</td><th>Domain</th><td>$($sysInfo.Domain)</td></tr>
<tr><th>OS</th><td>$($sysInfo.OSName)</td><th>Version</th><td>$($sysInfo.OSVersion) (Build $($sysInfo.BuildNumber))</td></tr>
<tr><th>Architecture</th><td>$($sysInfo.Architecture)</td><th>BIOS</th><td>$($sysInfo.BIOSVersion)</td></tr>
<tr><th>Manufacturer</th><td>$($sysInfo.Manufacturer)</td><th>Model</th><td>$($sysInfo.Model)</td></tr>
<tr><th>CPU</th><td>$($sysInfo.CPUModel)</td><th>Cores / Logical</th><td>$($sysInfo.CPUCores) / $($sysInfo.CPULogical)</td></tr>
<tr><th>Total RAM</th><td>$($sysInfo.TotalRAMGB) GB</td><th>CPU Max Speed</th><td>$($sysInfo.CPUMaxMHz) MHz</td></tr>
<tr><th>Last Boot</th><td>$($sysInfo.LastBootTime)</td><th>Uptime</th><td>$(New-SeverityBadge $sysInfo.UptimeText $sysInfo.Severity)</td></tr>
</table>
"@
    }
    else { $sysHtml = '<div class="alert alert-warning">System information collection failed.</div>' }
    $sysInfoSev = if ($sysInfo -and $sysInfo.ContainsKey('Severity')) { $sysInfo.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section' open><summary>System Information $(New-SeverityBadge $overallLabel $sysInfoSev)</summary><div class='section-body'>$sysHtml</div></details>")

    # CPU Section
    $cpuData = $DiagResults['CPU']
    $cpuHtml = [System.Text.StringBuilder]::new()
    if ($cpuData -and -not (Test-HasKey $cpuData 'Error')) {
        if ($cpuData.ContainsKey('OverallUsage') -and $cpuData.OverallUsage -ge 0) {
            [void]$cpuHtml.Append("<h4>Overall CPU Usage</h4>")
            [void]$cpuHtml.Append((New-ProgressBar $cpuData.OverallUsage))
        }
        if ($cpuData.ContainsKey('PerCoreUsage') -and $cpuData.PerCoreUsage.Count -gt 0) {
            [void]$cpuHtml.Append('<h4>Per-Core Usage</h4><div class="core-grid">')
            foreach ($core in $cpuData.PerCoreUsage) {
                $cSev = Get-Severity -Value $core.Usage -YellowThreshold 80 -RedThreshold 95
                $cColor = "var(--$cSev)"
                [void]$cpuHtml.Append("<div class='core-card'><span class='core-label'>Core $($core.Core)</span>$(New-ProgressBar $core.Usage $cColor)</div>")
            }
            [void]$cpuHtml.Append('</div>')
        }
        if ($cpuData.ContainsKey('SustainedHighCpu') -and $cpuData.SustainedHighCpu -and $cpuData.SustainedHighCpu.Count -gt 0) {
            [void]$cpuHtml.Append('<div class="alert alert-danger">Sustained high CPU detected in the following processes during sampling:</div>')
            [void]$cpuHtml.Append((ConvertTo-HtmlTable -Data $cpuData.SustainedHighCpu -Properties 'PID', 'Name', 'CPUPctEst', 'MemoryMB' -Headers 'PID', 'Process', 'CPU % (est)', 'Memory MB'))
        }
        if ($cpuData.ContainsKey('TopProcesses') -and $cpuData.TopProcesses.Count -gt 0) {
            [void]$cpuHtml.Append('<h4>Top Processes by CPU (sampled)</h4>')
            [void]$cpuHtml.Append((ConvertTo-HtmlTable -Data $cpuData.TopProcesses -Properties 'PID', 'Name', 'CPUPctEst', 'CPUTotal', 'MemoryMB', 'Handles', 'Threads' -Headers 'PID', 'Process', 'CPU % (est)', 'CPU Total (s)', 'Memory MB', 'Handles', 'Threads'))
        }
        if ($cpuData.ContainsKey('Errors') -and $cpuData.Errors.Count -gt 0) {
            [void]$cpuHtml.Append("<div class='alert alert-warning'>Some data unavailable: $($cpuData.Errors -join '; ')</div>")
        }
    }
    else { [void]$cpuHtml.Append('<div class="alert alert-warning">CPU diagnostic collection failed.</div>') }
    $cpuUsageBadge = if ($cpuData -and $cpuData.ContainsKey('OverallUsage')) { '{0}%' -f $cpuData.OverallUsage } else { 'N/A' }
    $cpuSevLocal = if ($cpuData -and $cpuData.ContainsKey('Severity')) { $cpuData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>CPU Diagnostics $(New-SeverityBadge $cpuUsageBadge $cpuSevLocal)</summary><div class='section-body'>$($cpuHtml.ToString())</div></details>")

    # Memory Section
    $memData = $DiagResults['Memory']
    $memHtml = [System.Text.StringBuilder]::new()
    if ($memData -and -not (Test-HasKey $memData 'Error')) {
        if ($memData.ContainsKey('UsedPct') -and $memData.UsedPct -ge 0) {
            [void]$memHtml.Append('<h4>RAM Usage</h4>')
            [void]$memHtml.Append((New-ProgressBar $memData.UsedPct))
            $usedB = if ($memData.ContainsKey('UsedBytes')) { Format-Bytes $memData.UsedBytes } else { 'N/A' }
            $totalB = if ($memData.ContainsKey('TotalBytes')) { Format-Bytes $memData.TotalBytes } else { 'N/A' }
            $freeB = if ($memData.ContainsKey('FreeBytes')) { Format-Bytes $memData.FreeBytes } else { 'N/A' }
            [void]$memHtml.Append("<p>$usedB used / $totalB total ($freeB free)</p>")
        }
        $memMetrics = @()
        if ($memData.ContainsKey('CommitUsedPct') -and $null -ne $memData.CommitUsedPct) { $memMetrics += @{ Metric = 'Commit Charge'; Value = "$($memData.CommitUsedPct)%" } }
        if ($memData.ContainsKey('PagesPerSec') -and $null -ne $memData.PagesPerSec) { $memMetrics += @{ Metric = 'Pages/sec'; Value = $memData.PagesPerSec } }
        if ($memData.ContainsKey('CacheBytes') -and $null -ne $memData.CacheBytes) { $memMetrics += @{ Metric = 'Cache'; Value = Format-Bytes $memData.CacheBytes } }
        if ($memMetrics.Count -gt 0) {
            [void]$memHtml.Append('<h4>Key Metrics</h4>')
            [void]$memHtml.Append((ConvertTo-HtmlTable -Data $memMetrics -Properties 'Metric', 'Value' -Headers 'Metric', 'Value'))
        }
        if ($memData.ContainsKey('PageFiles') -and $memData.PageFiles.Count -gt 0) {
            [void]$memHtml.Append('<h4>Page File</h4>')
            [void]$memHtml.Append((ConvertTo-HtmlTable -Data $memData.PageFiles -Properties 'Name', 'AllocatedMB', 'CurrentUseMB', 'PeakUseMB', 'UsedPct' -Headers 'File', 'Allocated MB', 'Current Use MB', 'Peak Use MB', 'Used %'))
        }
        if ($memData.ContainsKey('TopProcesses') -and $memData.TopProcesses.Count -gt 0) {
            [void]$memHtml.Append('<h4>Top Processes by Memory</h4>')
            [void]$memHtml.Append((ConvertTo-HtmlTable -Data $memData.TopProcesses -Properties 'PID', 'Name', 'WorkingSetMB', 'PrivateMB' -Headers 'PID', 'Process', 'Working Set MB', 'Private MB'))
        }
    }
    else { [void]$memHtml.Append('<div class="alert alert-warning">Memory diagnostic collection failed.</div>') }
    $memBadge = if ($memData -and $memData.ContainsKey('UsedPct') -and $memData.UsedPct -ge 0) { '{0}%' -f $memData.UsedPct } else { 'N/A' }
    $memSevLocal = if ($memData -and $memData.ContainsKey('Severity')) { $memData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Memory Diagnostics $(New-SeverityBadge $memBadge $memSevLocal)</summary><div class='section-body'>$($memHtml.ToString())</div></details>")

    # Disk I/O Section
    $diskData = $DiagResults['DiskIO']
    $diskHtml = [System.Text.StringBuilder]::new()
    if ($diskData -and -not (Test-HasKey $diskData 'Error')) {
        if ($diskData.ContainsKey('Volumes') -and $diskData.Volumes.Count -gt 0) {
            [void]$diskHtml.Append('<h4>Volume Space Usage</h4>')
            $volRows = [System.Text.StringBuilder]::new()
            [void]$volRows.Append('<table><thead><tr><th>Drive</th><th>Label</th><th>FS</th><th>Size GB</th><th>Free GB</th><th>Usage</th></tr></thead><tbody>')
            foreach ($v in $diskData.Volumes) {
                $vColor = "var(--$($v.Severity))"
                [void]$volRows.Append("<tr><td>$($v.Drive)</td><td>$($v.Label)</td><td>$($v.FS)</td><td>$($v.SizeGB)</td><td>$($v.FreeGB)</td><td>$(New-ProgressBar $v.UsedPct $vColor)</td></tr>")
            }
            [void]$volRows.Append('</tbody></table>')
            [void]$diskHtml.Append($volRows.ToString())
        }
        if ($diskData.ContainsKey('DiskMetrics') -and $diskData.DiskMetrics.Count -gt 0) {
            [void]$diskHtml.Append('<h4>Physical Disk I/O</h4>')
            $ioRows = @($diskData.DiskMetrics | ForEach-Object {
                    @{
                        Disk         = $_.DiskName
                        ReadRate     = if ($_.ContainsKey('ReadBytesPerSec') -and $_.ReadBytesPerSec) { Format-Bytes $_.ReadBytesPerSec } else { '-' }
                        WriteRate    = if ($_.ContainsKey('WriteBytesPerSec') -and $_.WriteBytesPerSec) { Format-Bytes $_.WriteBytesPerSec } else { '-' }
                        QueueLen     = if ($_.ContainsKey('AvgQueueLength')) { $_.AvgQueueLength } else { '-' }
                        ReadLatMs    = if ($_.ContainsKey('AvgReadLatencyMs')) { $_.AvgReadLatencyMs } else { '-' }
                        WriteLatMs   = if ($_.ContainsKey('AvgWriteLatencyMs')) { $_.AvgWriteLatencyMs } else { '-' }
                        DiskTimePct  = if ($_.ContainsKey('DiskTimePct')) { $_.DiskTimePct } else { '-' }
                    }
                })
            [void]$diskHtml.Append((ConvertTo-HtmlTable -Data $ioRows -Properties 'Disk', 'ReadRate', 'WriteRate', 'QueueLen', 'ReadLatMs', 'WriteLatMs', 'DiskTimePct' -Headers 'Disk', 'Read/s', 'Write/s', 'Queue Len', 'Read Lat ms', 'Write Lat ms', '% Disk Time'))
        }
    }
    else { [void]$diskHtml.Append('<div class="alert alert-warning">Disk I/O collection failed.</div>') }
    $worstVol = if ($diskData -and $diskData.ContainsKey('Volumes') -and $diskData.Volumes.Count -gt 0) { ($diskData.Volumes | Sort-Object UsedPct -Descending | Select-Object -First 1).UsedPct } else { 0 }
    $diskIoSev = if ($diskData -and $diskData.ContainsKey('Severity')) { $diskData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Disk I/O $(New-SeverityBadge ('worst {0}%' -f $worstVol) $diskIoSev)</summary><div class='section-body'>$($diskHtml.ToString())</div></details>")

    # Disk Health Section
    $dhData = $DiagResults['DiskHealth']
    $dhHtml = [System.Text.StringBuilder]::new()
    if (Test-HasKey $dhData 'Skipped') {
        [void]$dhHtml.Append('<div class="alert alert-info">Requires administrator privileges. Re-run with <code>-Elevate</code> to unlock.</div>')
    }
    elseif ($dhData.ContainsKey('Disks') -and $dhData.Disks.Count -gt 0) {
        foreach ($d in $dhData.Disks) {
            $hsBadge = New-SeverityBadge $d.HealthStatus $(if ($d.HealthStatus -eq 'Healthy') { 'green' } elseif ($d.HealthStatus -eq 'Warning') { 'yellow' } else { 'red' })
            [void]$dhHtml.Append("<h4>$($d.FriendlyName) ($($d.MediaType)) $hsBadge</h4>")
            $diskInfo = @(
                @{ Metric = 'Model'; Value = $d.Model }
                @{ Metric = 'Size'; Value = "$($d.SizeGB) GB" }
                @{ Metric = 'Bus Type'; Value = $d.BusType }
            )
            if ($null -ne $d.Temperature -and $d.Temperature -gt 0) { $diskInfo += @{ Metric = 'Temperature'; Value = "$($d.Temperature) C" } }
            if ($null -ne $d.Wear) { $diskInfo += @{ Metric = 'Wear Level'; Value = "$($d.Wear)%" } }
            if ($null -ne $d.PowerOnHours) { $diskInfo += @{ Metric = 'Power-On Hours'; Value = $d.PowerOnHours } }
            if ($null -ne $d.ReadErrorsTotal) { $diskInfo += @{ Metric = 'Read Errors (total)'; Value = $d.ReadErrorsTotal } }
            if ($null -ne $d.ReadErrorsUncorrected) { $diskInfo += @{ Metric = 'Read Errors (uncorrected)'; Value = $d.ReadErrorsUncorrected } }
            if ($null -ne $d.WriteErrorsTotal) { $diskInfo += @{ Metric = 'Write Errors (total)'; Value = $d.WriteErrorsTotal } }
            if ($null -ne $d.WriteErrorsUncorrected) { $diskInfo += @{ Metric = 'Write Errors (uncorrected)'; Value = $d.WriteErrorsUncorrected } }
            if ($d.ContainsKey('ReliabilityError')) { $diskInfo += @{ Metric = 'Note'; Value = "Reliability data unavailable: $($d.ReliabilityError)" } }
            [void]$dhHtml.Append((ConvertTo-HtmlTable -Data $diskInfo -Properties 'Metric', 'Value'))
        }
    }
    else { [void]$dhHtml.Append('<p class="muted">No physical disks found.</p>') }
    $dhIsSkipped = Test-HasKey $dhData 'Skipped'
    $dhSeverity = if ($dhData -and $dhData.ContainsKey('Severity')) { $dhData.Severity } else { 'green' }
    $dhSevLabel = if ($dhIsSkipped) { 'N/A' } else { switch ($dhSeverity) { 'green' { 'Healthy' } 'yellow' { 'Warning' } 'red' { 'Critical' } default { 'Unknown' } } }
    $dhBadgeSev = if ($dhIsSkipped) { 'skipped' } else { $dhSeverity }
    [void]$sectionsHtml.Append("<details class='section'><summary>Disk Health (SMART) $(New-SeverityBadge $dhSevLabel $dhBadgeSev)</summary><div class='section-body'>$($dhHtml.ToString())</div></details>")

    # Network Section
    $netData = $DiagResults['Network']
    $netHtml = [System.Text.StringBuilder]::new()
    if ($netData -and -not (Test-HasKey $netData 'Error')) {
        if ($netData.ContainsKey('Adapters') -and $netData.Adapters.Count -gt 0) {
            [void]$netHtml.Append('<h4>Active Adapters</h4>')
            [void]$netHtml.Append((ConvertTo-HtmlTable -Data $netData.Adapters -Properties 'Name', 'Description', 'LinkSpeed' -Headers 'Name', 'Description', 'Link Speed'))
        }
        if ($netData.ContainsKey('InterfaceMetrics') -and $netData.InterfaceMetrics) {
            [void]$netHtml.Append('<h4>Interface Throughput</h4>')
            $ifRows = @($netData.InterfaceMetrics | ForEach-Object {
                    @{
                        Interface = $_.InterfaceName
                        Recv      = if ($_.ContainsKey('BytesRecvPerSec') -and $_.BytesRecvPerSec) { Format-Bytes $_.BytesRecvPerSec } else { '-' }
                        Sent      = if ($_.ContainsKey('BytesSentPerSec') -and $_.BytesSentPerSec) { Format-Bytes $_.BytesSentPerSec } else { '-' }
                        Total     = if ($_.ContainsKey('BytesTotalPerSec') -and $_.BytesTotalPerSec) { Format-Bytes $_.BytesTotalPerSec } else { '-' }
                        RxErr     = if ($_.ContainsKey('RecvErrors')) { $_.RecvErrors } else { '-' }
                        TxErr     = if ($_.ContainsKey('SendErrors')) { $_.SendErrors } else { '-' }
                    }
                })
            [void]$netHtml.Append((ConvertTo-HtmlTable -Data $ifRows -Properties 'Interface', 'Recv', 'Sent', 'Total', 'RxErr', 'TxErr' -Headers 'Interface', 'Recv/s', 'Sent/s', 'Total/s', 'Rx Errors', 'Tx Errors'))
        }
        if ($netData.ContainsKey('Connections') -and $netData.Connections -and $netData.Connections.Count -gt 0) {
            [void]$netHtml.Append('<h4>TCP Connections</h4>')
            $connEstab = if ($netData.Connections.ContainsKey('Established')) { $netData.Connections.Established } else { 0 }
            $connListen = if ($netData.Connections.ContainsKey('Listening')) { $netData.Connections.Listening } else { 0 }
            $connTimeWait = if ($netData.Connections.ContainsKey('TimeWait')) { $netData.Connections.TimeWait } else { 0 }
            $connCloseWait = if ($netData.Connections.ContainsKey('CloseWait')) { $netData.Connections.CloseWait } else { 0 }
            $connTotal = if ($netData.Connections.ContainsKey('Total')) { $netData.Connections.Total } else { 0 }
            $connRows = @(
                @{ State = 'Established'; Count = $connEstab }
                @{ State = 'Listening'; Count = $connListen }
                @{ State = 'Time Wait'; Count = $connTimeWait }
                @{ State = 'Close Wait'; Count = $connCloseWait }
                @{ State = 'Total'; Count = $connTotal }
            )
            [void]$netHtml.Append((ConvertTo-HtmlTable -Data $connRows -Properties 'State', 'Count'))
        }
    }
    else { [void]$netHtml.Append('<div class="alert alert-warning">Network diagnostic collection failed.</div>') }
    $netAdapterCount = if ($netData -and $netData.ContainsKey('Adapters') -and $netData.Adapters) { $netData.Adapters.Count } else { 0 }
    $netSev = if ($netData -and $netData.ContainsKey('Severity')) { $netData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Network $(New-SeverityBadge $(if ($netAdapterCount -gt 0) { "$netAdapterCount adapters" } else { 'N/A' }) $netSev)</summary><div class='section-body'>$($netHtml.ToString())</div></details>")

    # Processes Section
    $procData = $DiagResults['Processes']
    $procHtml = [System.Text.StringBuilder]::new()
    $procTotal = if ($procData -and $procData.ContainsKey('TotalCount')) { $procData.TotalCount } else { 0 }
    if ($procData -and -not (Test-HasKey $procData 'Error')) {
        [void]$procHtml.Append("<p><strong>Total processes: $procTotal</strong></p>")
        if ($procData.ContainsKey('TopCpu') -and $procData.TopCpu.Count -gt 0) {
            [void]$procHtml.Append('<h4>Top 10 by CPU Time</h4>')
            [void]$procHtml.Append((ConvertTo-HtmlTable -Data $procData.TopCpu -Properties 'PID', 'Name', 'CPUSec', 'WorkingSetMB', 'Handles', 'Threads' -Headers 'PID', 'Process', 'CPU (s)', 'Memory MB', 'Handles', 'Threads'))
        }
        if ($procData.ContainsKey('TopMemory') -and $procData.TopMemory.Count -gt 0) {
            [void]$procHtml.Append('<h4>Top 10 by Memory</h4>')
            [void]$procHtml.Append((ConvertTo-HtmlTable -Data $procData.TopMemory -Properties 'PID', 'Name', 'WorkingSetMB', 'PrivateMB', 'Handles', 'Threads' -Headers 'PID', 'Process', 'Working Set MB', 'Private MB', 'Handles', 'Threads'))
        }
        if ($procData.ContainsKey('HighHandles') -and $procData.HighHandles.Count -gt 0) {
            [void]$procHtml.Append('<h4>High Handle / Thread Count</h4>')
            [void]$procHtml.Append((ConvertTo-HtmlTable -Data $procData.HighHandles -Properties 'PID', 'Name', 'Handles', 'Threads', 'WorkingSetMB' -Headers 'PID', 'Process', 'Handles', 'Threads', 'Memory MB'))
        }
    }
    else { [void]$procHtml.Append('<div class="alert alert-warning">Process diagnostic collection failed.</div>') }
    $procSev = if ($procData -and $procData.ContainsKey('Severity')) { $procData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Running Processes $(New-SeverityBadge "$procTotal procs" $procSev)</summary><div class='section-body'>$($procHtml.ToString())</div></details>")

    # Startup Programs Section
    $startData = $DiagResults['StartupPrograms']
    $startHtml = [System.Text.StringBuilder]::new()
    $startTotal = if ($startData -and $startData.ContainsKey('TotalCount')) { $startData.TotalCount } else { 0 }
    if ($startData -and -not (Test-HasKey $startData 'Error')) {
        [void]$startHtml.Append("<p><strong>Total startup items: $startTotal</strong></p>")
        if ($startData.ContainsKey('RegistryItems') -and $startData.RegistryItems.Count -gt 0) {
            [void]$startHtml.Append('<h4>Registry Run Keys</h4>')
            [void]$startHtml.Append((ConvertTo-HtmlTable -Data $startData.RegistryItems -Properties 'Source', 'Name', 'Command' -Headers 'Registry Key', 'Name', 'Command'))
        }
        if ($startData.ContainsKey('FolderItems') -and $startData.FolderItems.Count -gt 0) {
            [void]$startHtml.Append('<h4>Startup Folder Items</h4>')
            [void]$startHtml.Append((ConvertTo-HtmlTable -Data $startData.FolderItems -Properties 'Folder', 'Name', 'LastWriteTime' -Headers 'Folder', 'Name', 'Last Modified'))
        }
        if ($startData.ContainsKey('ScheduledTasks') -and $startData.ScheduledTasks.Count -gt 0) {
            [void]$startHtml.Append('<h4>Logon/Boot Scheduled Tasks</h4>')
            [void]$startHtml.Append((ConvertTo-HtmlTable -Data $startData.ScheduledTasks -Properties 'TaskName', 'TaskPath', 'State', 'Author' -Headers 'Task', 'Path', 'State', 'Author'))
        }
    }
    else { [void]$startHtml.Append('<div class="alert alert-warning">Startup program collection failed.</div>') }
    $startSev = if ($startData -and $startData.ContainsKey('Severity')) { $startData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Startup Programs $(New-SeverityBadge "$startTotal items" $startSev)</summary><div class='section-body'>$($startHtml.ToString())</div></details>")

    # Event Log Section
    $evtData = $DiagResults['EventLog']
    $evtHtml = [System.Text.StringBuilder]::new()
    $evtCritical = if ($evtData -and $evtData.ContainsKey('CriticalCount')) { $evtData.CriticalCount } else { 0 }
    $evtError = if ($evtData -and $evtData.ContainsKey('ErrorCount')) { $evtData.ErrorCount } else { 0 }
    if (Test-HasKey $evtData 'Skipped') {
        [void]$evtHtml.Append('<div class="alert alert-info">Requires administrator privileges. Re-run with <code>-Elevate</code> to unlock.</div>')
    }
    elseif ($evtData -and -not (Test-HasKey $evtData 'Error')) {
        [void]$evtHtml.Append("<p>Last 24 hours: <strong>$evtCritical</strong> critical, <strong>$evtError</strong> errors</p>")
        if ($evtData.ContainsKey('SystemEvents') -and $evtData.SystemEvents.Count -gt 0) {
            [void]$evtHtml.Append('<h4>System Log Events</h4>')
            [void]$evtHtml.Append((ConvertTo-HtmlTable -Data $evtData.SystemEvents -Properties 'TimeCreated', 'EventId', 'Level', 'Source', 'MessagePreview' -Headers 'Time', 'ID', 'Level', 'Source', 'Message'))
        }
        if ($evtData.ContainsKey('AppEvents') -and $evtData.AppEvents.Count -gt 0) {
            [void]$evtHtml.Append('<h4>Application Log Events</h4>')
            [void]$evtHtml.Append((ConvertTo-HtmlTable -Data $evtData.AppEvents -Properties 'TimeCreated', 'EventId', 'Level', 'Source', 'MessagePreview' -Headers 'Time', 'ID', 'Level', 'Source', 'Message'))
        }
        $sysEvtCount = if ($evtData.ContainsKey('SystemEvents')) { $evtData.SystemEvents.Count } else { 0 }
        $appEvtCount = if ($evtData.ContainsKey('AppEvents')) { $evtData.AppEvents.Count } else { 0 }
        if ($sysEvtCount -eq 0 -and $appEvtCount -eq 0) {
            [void]$evtHtml.Append('<p class="muted">No critical or error events in the last 24 hours.</p>')
        }
    }
    else { [void]$evtHtml.Append('<div class="alert alert-warning">Event log collection failed.</div>') }
    $evtIsSkipped = Test-HasKey $evtData 'Skipped'
    $evtBadgeText = if ($evtIsSkipped) { 'N/A' } else { "$($evtCritical + $evtError) events" }
    $evtBadgeSev = if ($evtIsSkipped) { 'skipped' } elseif ($evtData -and $evtData.ContainsKey('Severity')) { $evtData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Windows Event Log $(New-SeverityBadge $evtBadgeText $evtBadgeSev)</summary><div class='section-body'>$($evtHtml.ToString())</div></details>")

    # Thermal Section
    $thermData = $DiagResults['Thermal']
    $thermHtml = [System.Text.StringBuilder]::new()
    if ($thermData -and -not (Test-HasKey $thermData 'Error')) {
        $thermMetrics = @()
        if ($thermData.ContainsKey('PerfLimit') -and $null -ne $thermData.PerfLimit) {
            $plSev = if ($thermData.PerfLimit -lt 95) { 'red' } elseif ($thermData.PerfLimit -lt 100) { 'yellow' } else { 'green' }
            $plLabel = switch ($plSev) { 'green' { 'OK' } 'yellow' { 'Throttled' } 'red' { 'Heavily Throttled' } default { 'Unknown' } }
            $thermMetrics += @{ Metric = 'Performance Limit'; Value = "$($thermData.PerfLimit)%"; Status = (New-SeverityBadge $plLabel $plSev) }
        }
        if ($thermData.ContainsKey('MaxFreqPct') -and $null -ne $thermData.MaxFreqPct) {
            $thermMetrics += @{ Metric = 'Max Frequency'; Value = "$($thermData.MaxFreqPct)%" }
        }
        if ($thermMetrics.Count -gt 0) {
            [void]$thermHtml.Append('<h4>Current Status</h4>')
            [void]$thermHtml.Append((ConvertTo-HtmlTable -Data $thermMetrics -Properties 'Metric', 'Value', 'Status' -Headers 'Metric', 'Value', 'Status'))
        }
        if ($thermData.ContainsKey('ThermalEvents') -and $thermData.ThermalEvents.Count -gt 0) {
            [void]$thermHtml.Append('<h4>Thermal Events (last 7 days)</h4>')
            [void]$thermHtml.Append((ConvertTo-HtmlTable -Data $thermData.ThermalEvents -Properties 'TimeCreated', 'EventId', 'Source', 'Message' -Headers 'Time', 'Event ID', 'Source', 'Message'))
        }
        elseif ($script:IsAdmin) {
            [void]$thermHtml.Append('<p class="muted">No thermal events in the last 7 days.</p>')
        }
        if (-not $script:IsAdmin) {
            [void]$thermHtml.Append('<div class="alert alert-info">Thermal event log analysis requires administrator privileges. Re-run with <code>-Elevate</code> for full data.</div>')
        }
    }
    else { [void]$thermHtml.Append('<div class="alert alert-warning">Thermal diagnostic collection failed.</div>') }
    $thermBadge = if ($thermData -and $thermData.ContainsKey('PerfLimit') -and $null -ne $thermData.PerfLimit) { "$($thermData.PerfLimit)% limit" } else { 'N/A' }
    $thermSev = if ($thermData -and $thermData.ContainsKey('Severity')) { $thermData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Thermal / Throttling $(New-SeverityBadge $thermBadge $thermSev)</summary><div class='section-body'>$($thermHtml.ToString())</div></details>")

    # ========== NEW OPTIMIZATION SECTIONS ==========

    # Power Plan Section
    $powerData = $DiagResults['PowerPlan']
    $powerHtml = [System.Text.StringBuilder]::new()
    if ($powerData -and -not (Test-HasKey $powerData 'Error')) {
        $powerInfo = @()
        if ($powerData.ContainsKey('ActivePlanName')) { $powerInfo += @{ Setting = 'Active Power Plan'; Value = $powerData.ActivePlanName } }
        if ($powerData.ContainsKey('IsLaptop')) { $powerInfo += @{ Setting = 'Device Type'; Value = if ($powerData.IsLaptop) { 'Laptop' } else { 'Desktop' } } }
        if ($powerData.ContainsKey('BatteryStatus') -and $powerData.ContainsKey('BatteryPercent')) { $powerInfo += @{ Setting = 'Battery Status'; Value = "$($powerData.BatteryStatus) ($($powerData.BatteryPercent)%)" } }
        if ($powerData.ContainsKey('MinProcState')) { $powerInfo += @{ Setting = 'Min Processor State'; Value = "$($powerData.MinProcState)%" } }
        if ($powerData.ContainsKey('MaxProcState')) { $powerInfo += @{ Setting = 'Max Processor State'; Value = "$($powerData.MaxProcState)%" } }
        [void]$powerHtml.Append((ConvertTo-HtmlTable -Data $powerInfo -Properties 'Setting', 'Value'))
        if ($powerData.ContainsKey('AvailablePlans') -and $powerData.AvailablePlans.Count -gt 0) {
            [void]$powerHtml.Append('<h4>Available Power Plans</h4>')
            [void]$powerHtml.Append((ConvertTo-HtmlTable -Data $powerData.AvailablePlans -Properties 'Name', 'IsActive' -Headers 'Plan Name', 'Active'))
        }
    }
    else { [void]$powerHtml.Append('<div class="alert alert-warning">Power plan collection failed.</div>') }
    $powerBadge = if ($powerData -and $powerData.ContainsKey('ActivePlanName')) { $powerData.ActivePlanName } else { 'N/A' }
    $powerSev = if ($powerData -and $powerData.ContainsKey('Severity')) { $powerData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Power Plan $(New-SeverityBadge $powerBadge $powerSev)</summary><div class='section-body'>$($powerHtml.ToString())</div></details>")

    # Visual Effects Section
    $visualData = $DiagResults['VisualEffects']
    $visualHtml = [System.Text.StringBuilder]::new()
    if ($visualData -and -not (Test-HasKey $visualData 'Error')) {
        $visualInfo = @()
        if ($visualData.ContainsKey('VisualFxMode')) { $visualInfo += @{ Setting = 'Visual Effects Mode'; Value = $visualData.VisualFxMode } }
        if ($visualData.ContainsKey('TransparencyEffects')) { $visualInfo += @{ Setting = 'Transparency Effects'; Value = if ($visualData.TransparencyEffects) { 'Enabled' } else { 'Disabled' } } }
        if ($visualData.ContainsKey('EnabledEffectsCount')) { $visualInfo += @{ Setting = 'Enabled Effects Count'; Value = $visualData.EnabledEffectsCount } }
        [void]$visualHtml.Append((ConvertTo-HtmlTable -Data $visualInfo -Properties 'Setting', 'Value'))
    }
    else { [void]$visualHtml.Append('<div class="alert alert-warning">Visual effects collection failed.</div>') }
    $visualSev = if ($visualData -and $visualData.ContainsKey('Severity')) { $visualData.Severity } else { 'green' }
    $visualFxBadge = if ($visualData -and $visualData.ContainsKey('VisualFxMode')) { $visualData.VisualFxMode } else { 'N/A' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Visual Effects $(New-SeverityBadge $visualFxBadge $visualSev)</summary><div class='section-body'>$($visualHtml.ToString())</div></details>")

    # Services Section
    $servicesData = $DiagResults['Services']
    $servicesHtml = [System.Text.StringBuilder]::new()
    $svcTotal = if ($servicesData -and $servicesData.ContainsKey('TotalServices')) { $servicesData.TotalServices } else { 0 }
    $svcRunning = if ($servicesData -and $servicesData.ContainsKey('TotalRunning')) { $servicesData.TotalRunning } else { 0 }
    if ($servicesData -and -not (Test-HasKey $servicesData 'Error')) {
        [void]$servicesHtml.Append("<p><strong>Total services: $svcTotal</strong> | Running: $svcRunning</p>")
        if ($servicesData.ContainsKey('DisableableServices') -and $servicesData.DisableableServices) {
            $disableable = @($servicesData.DisableableServices | Where-Object { $_.CanDisable })
            if ($disableable.Count -gt 0) {
                [void]$servicesHtml.Append('<h4>Services That Can Be Disabled</h4>')
                [void]$servicesHtml.Append((ConvertTo-HtmlTable -Data $disableable -Properties 'DisplayName', 'ServiceName', 'Status', 'Impact', 'Risk' -Headers 'Service', 'Name', 'Status', 'Performance Impact', 'Disable Risk'))
            }
        }
    }
    else { [void]$servicesHtml.Append('<div class="alert alert-warning">Services collection failed.</div>') }
    $svcSev = if ($servicesData -and $servicesData.ContainsKey('Severity')) { $servicesData.Severity } else { 'green' }
    $svcCount = if ($servicesData -and $servicesData.ContainsKey('DisableableServices') -and $servicesData.DisableableServices) { @($servicesData.DisableableServices | Where-Object { $_.CanDisable }).Count } else { 0 }
    [void]$sectionsHtml.Append("<details class='section'><summary>Services $(New-SeverityBadge "$svcCount optimizable" $svcSev)</summary><div class='section-body'>$($servicesHtml.ToString())</div></details>")

    # Storage/Temp Files Section
    $storageData = $DiagResults['Storage']
    $storageHtml = [System.Text.StringBuilder]::new()
    $storageTempGB = if ($storageData -and $storageData.ContainsKey('TotalTempSizeGB')) { $storageData.TotalTempSizeGB } else { 0 }
    $storageRbMB = if ($storageData -and $storageData.ContainsKey('RecycleBinSizeMB')) { $storageData.RecycleBinSizeMB } else { 0 }
    $storageSenseOn = if ($storageData -and $storageData.ContainsKey('StorageSenseEnabled')) { $storageData.StorageSenseEnabled } else { $false }
    if ($storageData -and -not (Test-HasKey $storageData 'Error')) {
        [void]$storageHtml.Append("<p><strong>Total temp/junk files: $storageTempGB GB</strong> | Recycle Bin: $storageRbMB MB</p>")
        [void]$storageHtml.Append("<p>Storage Sense: $(if ($storageSenseOn) { '<span class=''badge badge-green''>Enabled</span>' } else { '<span class=''badge badge-yellow''>Disabled</span>' })</p>")
        if ($storageData.ContainsKey('TempFiles') -and $storageData.TempFiles.Count -gt 0) {
            [void]$storageHtml.Append('<h4>Temp File Locations</h4>')
            [void]$storageHtml.Append((ConvertTo-HtmlTable -Data $storageData.TempFiles -Properties 'Name', 'SizeMB', 'Path' -Headers 'Location', 'Size (MB)', 'Path'))
        }
    }
    else { [void]$storageHtml.Append('<div class="alert alert-warning">Storage collection failed.</div>') }
    $storageSev = if ($storageData -and $storageData.ContainsKey('Severity')) { $storageData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Temp Files & Storage $(New-SeverityBadge "$storageTempGB GB" $storageSev)</summary><div class='section-body'>$($storageHtml.ToString())</div></details>")

    # Bloatware Section
    $featuresData = $DiagResults['WindowsFeatures']
    $bloatHtml = [System.Text.StringBuilder]::new()
    $bloatCount = if ($featuresData -and $featuresData.ContainsKey('BloatwareCount')) { $featuresData.BloatwareCount } else { 0 }
    if ($featuresData -and -not (Test-HasKey $featuresData 'Error')) {
        if ($featuresData.ContainsKey('Bloatware') -and $featuresData.Bloatware.Count -gt 0) {
            [void]$bloatHtml.Append("<p><strong>$bloatCount preinstalled/bloatware apps detected</strong></p>")
            [void]$bloatHtml.Append('<p>These apps can be safely uninstalled if not needed:</p>')
            $bloatList = $featuresData.Bloatware | ForEach-Object { @{ AppName = $_ } }
            [void]$bloatHtml.Append((ConvertTo-HtmlTable -Data $bloatList -Properties 'AppName' -Headers 'App Package Name'))
        } else {
            [void]$bloatHtml.Append('<p class="muted">No common bloatware detected.</p>')
        }
        if ($featuresData.ContainsKey('HeavyFeaturesEnabled') -and $featuresData.HeavyFeaturesEnabled -and $featuresData.HeavyFeaturesEnabled.Count -gt 0) {
            [void]$bloatHtml.Append('<h4>Resource-Heavy Features Enabled</h4>')
            $heavyList = $featuresData.HeavyFeaturesEnabled | ForEach-Object { @{ Feature = $_.Name } }
            [void]$bloatHtml.Append((ConvertTo-HtmlTable -Data $heavyList -Properties 'Feature' -Headers 'Feature Name'))
        }
    }
    else { [void]$bloatHtml.Append('<div class="alert alert-warning">Features/bloatware collection failed.</div>') }
    $bloatSev = if ($featuresData -and $featuresData.ContainsKey('Severity')) { $featuresData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Bloatware & Features $(New-SeverityBadge "$bloatCount apps" $bloatSev)</summary><div class='section-body'>$($bloatHtml.ToString())</div></details>")

    # Background Apps Section
    $bgData = $DiagResults['BackgroundApps']
    $bgHtml = [System.Text.StringBuilder]::new()
    if ($bgData -and -not (Test-HasKey $bgData 'Error')) {
        $bgCount = if ($bgData.ContainsKey('EnabledBackgroundApps')) { $bgData.EnabledBackgroundApps } else { 0 }
        [void]$bgHtml.Append("<p><strong>$bgCount apps</strong> can run in the background</p>")
        $globalStatus = if ($bgData.ContainsKey('GlobalBackgroundAppsEnabled') -and $bgData.GlobalBackgroundAppsEnabled) { 'Enabled (apps can run in background)' } else { 'Restricted' }
        [void]$bgHtml.Append("<p>Global setting: $globalStatus</p>")
    }
    else { [void]$bgHtml.Append('<div class="alert alert-warning">Background apps collection failed.</div>') }
    $bgSev = if ($bgData) { $bgData.Severity } else { 'green' }
    $bgBadge = if ($bgData.ContainsKey('EnabledBackgroundApps')) { "$($bgData.EnabledBackgroundApps) apps" } else { 'N/A' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Background Apps $(New-SeverityBadge $bgBadge $bgSev)</summary><div class='section-body'>$($bgHtml.ToString())</div></details>")

    # Privacy/Telemetry Section
    $privacyData = $DiagResults['Privacy']
    $privacyHtml = [System.Text.StringBuilder]::new()
    if ($privacyData -and -not (Test-HasKey $privacyData 'Error') -and $privacyData.Settings.Count -gt 0) {
        $enabledSettings = @($privacyData.Settings | Where-Object { $_.Enabled })
        [void]$privacyHtml.Append("<p><strong>$($enabledSettings.Count) tracking/telemetry features enabled</strong></p>")
        [void]$privacyHtml.Append((ConvertTo-HtmlTable -Data $privacyData.Settings -Properties 'Name', 'Enabled', 'CanDisable' -Headers 'Setting', 'Enabled', 'Can Disable'))
    }
    else { [void]$privacyHtml.Append('<div class="alert alert-warning">Privacy settings collection failed.</div>') }
    $privSev = if ($privacyData) { $privacyData.Severity } else { 'green' }
    $privBadge = if ($privacyData.ContainsKey('EnabledPrivacyImpactCount')) { "$($privacyData.EnabledPrivacyImpactCount) enabled" } else { 'N/A' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Privacy & Telemetry $(New-SeverityBadge $privBadge $privSev)</summary><div class='section-body'>$($privacyHtml.ToString())</div></details>")

    # Game Mode Section
    $gameData = $DiagResults['GameMode']
    $gameHtml = [System.Text.StringBuilder]::new()
    if ($gameData -and -not (Test-HasKey $gameData 'Error')) {
        $gameInfo = @()
        if ($gameData.ContainsKey('GPUName')) { $gameInfo += @{ Setting = 'GPU'; Value = $gameData.GPUName } }
        if ($gameData.ContainsKey('GameModeEnabled')) { $gameInfo += @{ Setting = 'Game Mode'; Value = if ($gameData.GameModeEnabled) { 'Enabled' } else { 'Disabled' } } }
        if ($gameData.ContainsKey('GameBarEnabled')) { $gameInfo += @{ Setting = 'Xbox Game Bar'; Value = if ($gameData.GameBarEnabled) { 'Enabled' } else { 'Disabled' } } }
        if ($gameData.ContainsKey('GameDVREnabled')) { $gameInfo += @{ Setting = 'Game DVR (Recording)'; Value = if ($gameData.GameDVREnabled) { 'Enabled' } else { 'Disabled' } } }
        if ($gameData.ContainsKey('HwGpuScheduling')) { $gameInfo += @{ Setting = 'HW GPU Scheduling'; Value = if ($gameData.HwGpuScheduling) { 'Enabled' } else { 'Disabled' } } }
        [void]$gameHtml.Append((ConvertTo-HtmlTable -Data $gameInfo -Properties 'Setting', 'Value'))
    }
    else { [void]$gameHtml.Append('<div class="alert alert-warning">Game mode collection failed.</div>') }
    $gameSev = if ($gameData) { $gameData.Severity } else { 'green' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Gaming Settings $(New-SeverityBadge 'Settings' $gameSev)</summary><div class='section-body'>$($gameHtml.ToString())</div></details>")

    # Browser Section
    $browserData = $DiagResults['Browsers']
    $browserHtml = [System.Text.StringBuilder]::new()
    $browserProcs = if ($browserData -and $browserData.ContainsKey('RunningBrowserProcesses')) { $browserData.RunningBrowserProcesses } else { 0 }
    $browserMemMB = if ($browserData -and $browserData.ContainsKey('BrowserMemoryMB')) { $browserData.BrowserMemoryMB } else { 0 }
    if ($browserData -and -not (Test-HasKey $browserData 'Error')) {
        [void]$browserHtml.Append("<p><strong>$browserProcs browser processes</strong> using <strong>$browserMemMB MB</strong> RAM</p>")
        if ($browserData.ContainsKey('Browsers') -and $browserData.Browsers.Count -gt 0) {
            [void]$browserHtml.Append('<h4>Installed Browsers</h4>')
            [void]$browserHtml.Append((ConvertTo-HtmlTable -Data $browserData.Browsers -Properties 'Name', 'Installed' -Headers 'Browser', 'Installed'))
        }
    }
    else { [void]$browserHtml.Append('<div class="alert alert-warning">Browser diagnostics failed.</div>') }
    $browserSev = if ($browserData -and $browserData.ContainsKey('Severity')) { $browserData.Severity } else { 'green' }
    $browserBadge = if ($browserData -and $browserData.ContainsKey('BrowserMemoryMB')) { "$browserMemMB MB" } else { 'N/A' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Browsers $(New-SeverityBadge $browserBadge $browserSev)</summary><div class='section-body'>$($browserHtml.ToString())</div></details>")

    # Drivers Section
    $driverData = $DiagResults['Drivers']
    $driverHtml = [System.Text.StringBuilder]::new()
    $driverProblemCount = if ($driverData -and $driverData.ContainsKey('ProblemDeviceCount')) { $driverData.ProblemDeviceCount } else { 0 }
    if ($driverData -and -not (Test-HasKey $driverData 'Error')) {
        if ($driverProblemCount -gt 0) {
            [void]$driverHtml.Append("<div class='alert alert-danger'>$driverProblemCount devices have driver problems!</div>")
            if ($driverData.ContainsKey('ProblematicDrivers') -and $driverData.ProblematicDrivers) {
                [void]$driverHtml.Append((ConvertTo-HtmlTable -Data $driverData.ProblematicDrivers -Properties 'Name', 'ErrorCode', 'Status' -Headers 'Device', 'Error Code', 'Status'))
            }
        } else {
            [void]$driverHtml.Append('<p class="muted">No driver problems detected.</p>')
        }
        if ($driverData.ContainsKey('OldDrivers') -and $driverData.OldDrivers -and $driverData.OldDrivers.Count -gt 0) {
            [void]$driverHtml.Append('<h4>Old Drivers (3+ years)</h4>')
            [void]$driverHtml.Append((ConvertTo-HtmlTable -Data $driverData.OldDrivers -Properties 'Name', 'DriverVersion', 'AgeYears' -Headers 'Device', 'Version', 'Age (years)'))
        }
    }
    else { [void]$driverHtml.Append('<div class="alert alert-warning">Driver diagnostics failed.</div>') }
    $driverSev = if ($driverData -and $driverData.ContainsKey('Severity')) { $driverData.Severity } else { 'green' }
    $driverBadge = if ($driverProblemCount -gt 0) { "$driverProblemCount problems" } else { 'OK' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Drivers $(New-SeverityBadge $driverBadge $driverSev)</summary><div class='section-body'>$($driverHtml.ToString())</div></details>")

    # Windows Update Section
    $updateData = $DiagResults['WindowsUpdate']
    $updateHtml = [System.Text.StringBuilder]::new()
    if ($updateData -and -not (Test-HasKey $updateData 'Error')) {
        $updateInfo = @()
        if ($updateData.ContainsKey('UpdateServiceStatus')) { $updateInfo += @{ Setting = 'Update Service'; Value = $updateData.UpdateServiceStatus } }
        if ($updateData.ContainsKey('PendingUpdateCount') -and $updateData.PendingUpdateCount -ge 0) { $updateInfo += @{ Setting = 'Pending Updates'; Value = $updateData.PendingUpdateCount } }
        if ($updateData.ContainsKey('DaysSinceUpdateCheck')) { $updateInfo += @{ Setting = 'Days Since Check'; Value = $updateData.DaysSinceUpdateCheck } }
        if ($updateData.ContainsKey('DeliveryOptimizationEnabled')) { $updateInfo += @{ Setting = 'Delivery Optimization'; Value = if ($updateData.DeliveryOptimizationEnabled) { 'Enabled (sharing with other PCs)' } else { 'Disabled' } } }
        [void]$updateHtml.Append((ConvertTo-HtmlTable -Data $updateInfo -Properties 'Setting', 'Value'))
        if ($updateData.ContainsKey('PendingUpdates') -and $updateData.PendingUpdates -and $updateData.PendingUpdates.Count -gt 0) {
            [void]$updateHtml.Append('<h4>Pending Updates</h4>')
            [void]$updateHtml.Append((ConvertTo-HtmlTable -Data $updateData.PendingUpdates -Properties 'Title', 'KBArticleIDs' -Headers 'Update', 'KB'))
        }
    }
    else { [void]$updateHtml.Append('<div class="alert alert-warning">Windows Update diagnostics failed.</div>') }
    $updateSev = if ($updateData -and $updateData.ContainsKey('Severity')) { $updateData.Severity } else { 'green' }
    $updateBadge = if ($updateData -and $updateData.ContainsKey('PendingUpdateCount') -and $updateData.PendingUpdateCount -gt 0) { "$($updateData.PendingUpdateCount) pending" } else { 'Up to date' }
    [void]$sectionsHtml.Append("<details class='section'><summary>Windows Update $(New-SeverityBadge $updateBadge $updateSev)</summary><div class='section-body'>$($updateHtml.ToString())</div></details>")

    # --- Skipped Diagnostics ---
    $skippedHtml = ''
    if ($SkippedDiagnostics.Count -gt 0) {
        $skippedList = ($SkippedDiagnostics | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join "`n"
        $skippedHtml = @"
<div class="skipped-notice">
<h3>Skipped Diagnostics</h3>
<p>The following diagnostics were skipped because the script is not running as administrator:</p>
<ul>$skippedList</ul>
<p>Re-run with <code>-Elevate</code> to unlock these diagnostics.</p>
</div>
"@
    }

    # --- Recommendations ---
    $recsHtml = [System.Text.StringBuilder]::new()
    [void]$recsHtml.Append('<div class="recommendations">')
    $recNum = 0
    foreach ($rec in ($Recommendations | Sort-Object { switch ($_.Severity) { 'red' { 0 } 'yellow' { 1 } 'green' { 2 } default { 3 } } })) {
        $recNum++
        $icon = switch ($rec.Severity) { 'red' { '&#9888;' } 'yellow' { '&#9888;' } 'green' { '&#10004;' } default { '&#8226;' } }
        [void]$recsHtml.Append(@"
<div class="rec rec-$($rec.Severity)">
<div class="rec-header">$icon <strong>$recNum. $([System.Web.HttpUtility]::HtmlEncode($rec.Title))</strong> $(New-SeverityBadge $rec.Category $rec.Severity)</div>
<p class="rec-detail">$([System.Web.HttpUtility]::HtmlEncode($rec.Detail))</p>
<p class="rec-action"><strong>Action:</strong> $([System.Web.HttpUtility]::HtmlEncode($rec.Action))</p>
</div>
"@)
    }
    [void]$recsHtml.Append('</div>')

    # --- Dashboard Cards ---
    $cpuBadge = if ($cpuData -and $cpuData.ContainsKey('OverallUsage') -and $cpuData.OverallUsage -ge 0) { "$($cpuData.OverallUsage)%" } else { 'N/A' }
    $memBadge2 = if ($memData -and $memData.ContainsKey('UsedPct') -and $memData.UsedPct -ge 0) { "$($memData.UsedPct)%" } else { 'N/A' }
    $diskBadge = if ($diskData -and $diskData.ContainsKey('Volumes') -and $diskData.Volumes.Count -gt 0) { "$worstVol%" } else { 'N/A' }
    $netBadge = if ($netData -and $netData.ContainsKey('Adapters') -and $netData.Adapters.Count -gt 0) { "$($netData.Adapters.Count) up" } else { 'N/A' }
    $evtCrit = if ($evtData -and $evtData.ContainsKey('CriticalCount')) { $evtData.CriticalCount } else { 0 }
    $evtErr = if ($evtData -and $evtData.ContainsKey('ErrorCount')) { $evtData.ErrorCount } else { 0 }
    $evtBadge2 = if ($evtIsSkipped) { 'N/A' } else { "$($evtCrit + $evtErr)" }
    $uptimeBadge = if ($sysInfo -and $sysInfo.ContainsKey('UptimeText') -and $sysInfo.UptimeText) { $sysInfo.UptimeText } else { 'N/A' }
    $startBadge = if ($startData -and $startData.ContainsKey('TotalCount')) { "$($startData.TotalCount)" } else { 'N/A' }
    $procBadge = if ($procData -and $procData.ContainsKey('TotalCount')) { "$($procData.TotalCount)" } else { 'N/A' }

    $cpuSev = if ($cpuData -and $cpuData.ContainsKey('Severity')) { $cpuData.Severity } else { 'green' }
    $memSev2 = if ($memData -and $memData.ContainsKey('Severity')) { $memData.Severity } else { 'green' }
    $diskSev2 = if ($diskData -and $diskData.ContainsKey('Severity')) { $diskData.Severity } else { 'green' }
    $netSev2 = if ($netData -and $netData.ContainsKey('Severity')) { $netData.Severity } else { 'green' }
    $evtSev2 = if ($evtData -and $evtData.ContainsKey('Severity')) { $evtData.Severity } else { 'green' }
    $sysSev = if ($sysInfo -and $sysInfo.ContainsKey('Severity')) { $sysInfo.Severity } else { 'green' }
    $startSev2 = if ($startData -and $startData.ContainsKey('Severity')) { $startData.Severity } else { 'green' }

    $dashboardHtml = @"
<div class="dashboard">
<div class="card card-$overallSev card-overall"><div class="card-label">Overall</div><div class="card-value">$overallLabel</div></div>
<div class="card card-$cpuSev"><div class="card-label">CPU</div><div class="card-value">$cpuBadge</div></div>
<div class="card card-$memSev2"><div class="card-label">Memory</div><div class="card-value">$memBadge2</div></div>
<div class="card card-$diskSev2"><div class="card-label">Disk</div><div class="card-value">$diskBadge</div></div>
<div class="card card-$netSev2"><div class="card-label">Network</div><div class="card-value">$netBadge</div></div>
<div class="card card-$(if ($evtIsSkipped) { 'skipped' } else { $evtSev2 })"><div class="card-label">Events</div><div class="card-value">$evtBadge2</div></div>
<div class="card card-$sysSev"><div class="card-label">Uptime</div><div class="card-value">$uptimeBadge</div></div>
<div class="card card-$startSev2"><div class="card-label">Startup</div><div class="card-value">$startBadge</div></div>
</div>
"@

    # --- Full HTML document ---
    $html = @"
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>System Diagnostic - $computerName - $timestamp</title>
<style>
:root {
    --green: #28a745;
    --yellow: #ffc107;
    --red: #dc3545;
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Code', 'Consolas', monospace;
    --radius: 8px;
}

/* Dark mode (default) */
[data-theme="dark"] {
    --bg: #0d1117;
    --card-bg: #161b22;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --border: #30363d;
    --shadow: 0 1px 3px rgba(0,0,0,0.3);
    --hover-bg: #21262d;
    --table-header-bg: #21262d;
    --table-row-hover: #1c2128;
    --progress-bg: #30363d;
    --progress-text: #e6edf3;
    --alert-warning-bg: #3d2e00;
    --alert-warning-border: #9e7700;
    --alert-warning-text: #f0c000;
    --alert-danger-bg: #3d1418;
    --alert-danger-border: #9e2a2f;
    --alert-danger-text: #f08086;
    --alert-info-bg: #0d2d3d;
    --alert-info-border: #1f6f8b;
    --alert-info-text: #58a6c7;
    --badge-green-bg: #1a4d2e;
    --badge-green-text: #3fb950;
    --badge-yellow-bg: #3d2e00;
    --badge-yellow-text: #d29922;
    --badge-red-bg: #3d1418;
    --badge-red-text: #f85149;
    --badge-skipped-bg: #21262d;
    --badge-skipped-text: #8b949e;
}

/* Light mode */
[data-theme="light"] {
    --bg: #f4f6f9;
    --card-bg: #ffffff;
    --text: #212529;
    --text-muted: #6c757d;
    --border: #dee2e6;
    --shadow: 0 1px 3px rgba(0,0,0,0.08);
    --hover-bg: #f8f9fa;
    --table-header-bg: #f8f9fa;
    --table-row-hover: #f8f9fa;
    --progress-bg: #e9ecef;
    --progress-text: #333;
    --alert-warning-bg: #fff3cd;
    --alert-warning-border: #ffc107;
    --alert-warning-text: #856404;
    --alert-danger-bg: #f8d7da;
    --alert-danger-border: #dc3545;
    --alert-danger-text: #721c24;
    --alert-info-bg: #d1ecf1;
    --alert-info-border: #0dcaf0;
    --alert-info-text: #0c5460;
    --badge-green-bg: #d4edda;
    --badge-green-text: #155724;
    --badge-yellow-bg: #fff3cd;
    --badge-yellow-text: #856404;
    --badge-red-bg: #f8d7da;
    --badge-red-text: #721c24;
    --badge-skipped-bg: #e9ecef;
    --badge-skipped-text: #6c757d;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.6; padding: 0; transition: background 0.3s, color 0.3s; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
header { background: #0d1117; color: #fff; padding: 24px 0; margin-bottom: 24px; }
[data-theme="light"] header { background: #1a1a2e; }
header .container { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
header h1 { font-size: 1.5rem; font-weight: 600; }
header .meta { font-size: 0.85rem; opacity: 0.85; text-align: right; }
.admin-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }
.admin-badge.admin-yes { background: var(--green); color: #fff; }
.admin-badge.admin-no { background: var(--yellow); color: #000; }
.admin-notice { background: var(--alert-warning-bg); border: 1px solid var(--alert-warning-border); color: var(--alert-warning-text); border-radius: var(--radius); padding: 12px 16px; margin-bottom: 20px; font-size: 0.9rem; }
.admin-notice code { background: var(--hover-bg); padding: 2px 6px; border-radius: 4px; font-family: var(--mono); }

/* Theme toggle */
.theme-toggle { background: var(--card-bg); border: 1px solid var(--border); border-radius: 20px; padding: 4px 12px; font-size: 0.8rem; cursor: pointer; font-family: var(--font); color: var(--text); display: inline-flex; align-items: center; gap: 6px; transition: all 0.2s; }
.theme-toggle:hover { background: var(--hover-bg); }
.theme-toggle .icon { font-size: 1rem; }

/* Dashboard */
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card { background: var(--card-bg); border-radius: var(--radius); padding: 16px; text-align: center; box-shadow: var(--shadow); border-top: 4px solid var(--border); transition: transform 0.15s, background 0.3s; }
.card:hover { transform: translateY(-2px); }
.card-green { border-top-color: var(--green); }
.card-yellow { border-top-color: var(--yellow); }
.card-red { border-top-color: var(--red); }
.card-skipped { border-top-color: #adb5bd; }
.card-overall { grid-column: span 1; }
.card-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 4px; }
.card-value { font-size: 1.4rem; font-weight: 700; }
.card-green .card-value { color: var(--green); }
.card-yellow .card-value { color: var(--yellow); }
.card-red .card-value { color: var(--red); }
.card-skipped .card-value { color: #adb5bd; }

/* Sections */
.section { background: var(--card-bg); border-radius: var(--radius); margin-bottom: 12px; box-shadow: var(--shadow); overflow: hidden; transition: background 0.3s; }
.section > summary { padding: 14px 20px; font-size: 1rem; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 10px; user-select: none; list-style: none; border-left: 4px solid var(--border); }
.section > summary::-webkit-details-marker { display: none; }
.section > summary::before { content: '\25B6'; font-size: 0.7rem; transition: transform 0.2s; color: var(--text-muted); }
.section[open] > summary::before { transform: rotate(90deg); }
.section > summary:hover { background: var(--hover-bg); }
.section-body { padding: 16px 20px; border-top: 1px solid var(--border); }

/* Badges */
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; margin-left: auto; }
.badge-green { background: var(--badge-green-bg); color: var(--badge-green-text); }
.badge-yellow { background: var(--badge-yellow-bg); color: var(--badge-yellow-text); }
.badge-red { background: var(--badge-red-bg); color: var(--badge-red-text); }
.badge-skipped { background: var(--badge-skipped-bg); color: var(--badge-skipped-text); }

/* Tables */
table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 0.85rem; }
th { background: var(--table-header-bg); padding: 8px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid var(--border); white-space: nowrap; }
td { padding: 6px 12px; border-bottom: 1px solid var(--border); word-break: break-word; }
tr:hover td { background: var(--table-row-hover); }
.kv-table th { width: 15%; font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.3px; }
.kv-table td { width: 35%; }

/* Progress bars */
.progress { background: var(--progress-bg); border-radius: 4px; height: 22px; position: relative; overflow: hidden; min-width: 100px; }
.progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.progress-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 0.75rem; font-weight: 600; color: var(--progress-text); text-shadow: 0 0 2px rgba(0,0,0,0.5); }

/* Core grid */
.core-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 8px; margin: 8px 0 16px; }
.core-card { background: var(--hover-bg); border-radius: 6px; padding: 8px 12px; }
.core-label { font-size: 0.75rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 4px; }

/* Alerts */
.alert { padding: 10px 14px; border-radius: 6px; margin: 8px 0; font-size: 0.85rem; }
.alert-warning { background: var(--alert-warning-bg); border: 1px solid var(--alert-warning-border); color: var(--alert-warning-text); }
.alert-danger { background: var(--alert-danger-bg); border: 1px solid var(--alert-danger-border); color: var(--alert-danger-text); }
.alert-info { background: var(--alert-info-bg); border: 1px solid var(--alert-info-border); color: var(--alert-info-text); }

/* Muted text */
.muted { color: var(--text-muted); font-style: italic; }

/* Skipped notice */
.skipped-notice { background: var(--alert-warning-bg); border: 1px solid var(--alert-warning-border); color: var(--alert-warning-text); border-radius: var(--radius); padding: 16px 20px; margin: 20px 0; }
.skipped-notice h3 { font-size: 1rem; margin-bottom: 8px; }
.skipped-notice ul { margin: 8px 0 8px 20px; }
.skipped-notice code { background: var(--hover-bg); padding: 2px 6px; border-radius: 4px; font-family: var(--mono); }

/* Recommendations */
.recommendations { margin: 20px 0; }
.rec { background: var(--card-bg); border-radius: var(--radius); padding: 14px 18px; margin-bottom: 10px; box-shadow: var(--shadow); border-left: 4px solid var(--border); transition: background 0.3s; }
.rec-red { border-left-color: var(--red); }
.rec-yellow { border-left-color: var(--yellow); }
.rec-green { border-left-color: var(--green); }
.rec-header { font-size: 0.95rem; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rec-detail { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px; }
.rec-action { font-size: 0.85rem; }

/* Footer */
footer { text-align: center; padding: 20px; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 24px; }

/* Headings inside sections */
.section-body h4 { font-size: 0.9rem; color: var(--text-muted); margin: 16px 0 8px; text-transform: uppercase; letter-spacing: 0.3px; }
.section-body h4:first-child { margin-top: 0; }

/* Expand/collapse all */
.controls { text-align: right; margin-bottom: 12px; display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }
.controls button { background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 6px 14px; font-size: 0.8rem; cursor: pointer; font-family: var(--font); color: var(--text); transition: background 0.2s; }
.controls button:hover { background: var(--hover-bg); }

/* Print styles */
@media print {
    body { background: #fff; color: #000; }
    header { background: #333; }
    .card:hover { transform: none; }
    details[open] > summary::before { content: ''; }
    .section { break-inside: avoid; }
    .controls { display: none; }
    .theme-toggle { display: none; }
}
</style>
<script>
function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateToggleIcon();
}
function updateToggleIcon() {
    const theme = document.documentElement.getAttribute('data-theme');
    const btn = document.getElementById('themeToggle');
    if (btn) {
        btn.innerHTML = theme === 'dark'
            ? '<svg style="width:14px;height:14px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>Light'
            : '<svg style="width:14px;height:14px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>Dark';
    }
}
document.addEventListener('DOMContentLoaded', function() {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    updateToggleIcon();
});
</script>
</head>
<body>
<header>
<div class="container">
<h1>&#128269; System Diagnostic Report</h1>
<div class="meta">
<div>$computerName</div>
<div>$timestamp</div>
<div><span class="admin-badge $(if ($IsAdmin) { 'admin-yes' } else { 'admin-no' })">$(if ($IsAdmin) { 'Administrator' } else { 'Standard User' })</span></div>
</div>
</div>
</header>
<div class="container">
$(if (-not $IsAdmin) { '<div class="admin-notice">Some diagnostics require administrator privileges and were skipped. Re-run with <code>-Elevate</code> for the full report (Disk Health, Event Logs, Thermal Events).</div>' })
$dashboardHtml
<div class="controls"><button id="themeToggle" class="theme-toggle" onclick="toggleTheme()"><svg style="width:14px;height:14px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>Light</button> <button onclick="document.querySelectorAll('details.section').forEach(d=>d.open=true)">Expand All</button> <button onclick="document.querySelectorAll('details.section').forEach(d=>d.open=false)">Collapse All</button></div>
$($sectionsHtml.ToString())
$skippedHtml
<h2 style="margin:24px 0 12px;font-size:1.2rem;">Recommendations</h2>
$($recsHtml.ToString())
</div>
<footer>
Generated by Windows System Diagnostic Script v1.0 | Collection time: $([math]::Round($collectionDuration.TotalSeconds, 1))s | PowerShell $($PSVersionTable.PSVersion)
</footer>
</body>
</html>
"@

    return $html
}

# ============================================================================
# ORCHESTRATOR
# ============================================================================

function Export-DiagReport {
    $collectors = [ordered]@{
        'SystemInfo'       = { Get-SystemInfoDiagnostics }
        'CPU'              = { Get-CpuDiagnostics }
        'Memory'           = { Get-MemoryDiagnostics }
        'DiskIO'           = { Get-DiskIoDiagnostics }
        'DiskHealth'       = { Get-DiskHealthDiagnostics }
        'Network'          = { Get-NetworkDiagnostics }
        'Processes'        = { Get-ProcessDiagnostics }
        'StartupPrograms'  = { Get-StartupProgramDiagnostics }
        'EventLog'         = { Get-EventLogDiagnostics }
        'Thermal'          = { Get-ThermalDiagnostics }
        'PowerPlan'        = { Get-PowerPlanDiagnostics }
        'VisualEffects'    = { Get-VisualEffectsDiagnostics }
        'WindowsFeatures'  = { Get-WindowsFeaturesDiagnostics }
        'Services'         = { Get-ServicesDiagnostics }
        'Indexing'         = { Get-IndexingDiagnostics }
        'Defender'         = { Get-DefenderDiagnostics }
        'Storage'          = { Get-StorageDiagnostics }
        'BackgroundApps'   = { Get-BackgroundAppsDiagnostics }
        'GameMode'         = { Get-GameModeDiagnostics }
        'Privacy'          = { Get-PrivacyDiagnostics }
        'VirtualMemory'    = { Get-VirtualMemoryDiagnostics }
        'Browsers'         = { Get-BrowserDiagnostics }
        'Drivers'          = { Get-DriverDiagnostics }
        'WindowsUpdate'    = { Get-WindowsUpdateDiagnostics }
    }

    $totalSteps = $collectors.Count
    $currentStep = 0

    foreach ($name in $collectors.Keys) {
        $currentStep++
        Write-DiagProgress -Status "Gathering $name data..." -PercentComplete (($currentStep / $totalSteps) * 100)

        try {
            $script:DiagResults[$name] = & $collectors[$name]
        }
        catch {
            $script:DiagResults[$name] = @{
                Error    = $true
                Message  = $_.Exception.Message
                Severity = 'yellow'
            }
            Write-Warning "Failed to collect ${name}: $($_.Exception.Message)"
        }
    }

    Write-Progress -Activity 'System Diagnostics' -Completed

    Write-Host 'Analyzing results...' -ForegroundColor Cyan
    $healthScores = Get-HealthScores -AllResults $script:DiagResults
    $recommendations = Get-Recommendations -AllResults $script:DiagResults

    Write-Host 'Generating HTML report...' -ForegroundColor Cyan
    $html = New-HtmlReport -DiagResults $script:DiagResults `
        -HealthScores $healthScores `
        -Recommendations $recommendations `
        -SkippedDiagnostics $script:SkippedDiagnostics `
        -IsAdmin $script:IsAdmin

    # Ensure output directory exists
    $outputDir = Split-Path -Path $OutputPath -Parent
    if ($outputDir -and -not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

    Write-Host ''
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Green

    if (-not $SkipBrowserOpen) {
        Start-Process $OutputPath
    }
}

# ============================================================================
# ENTRY POINT
# ============================================================================

Write-Host ''
Write-Host '  Windows System Diagnostic Tool v1.0' -ForegroundColor Cyan
Write-Host '  ====================================' -ForegroundColor DarkCyan
Write-Host ''
if ($script:IsAdmin) {
    Write-Host '  Running as Administrator - full diagnostics enabled' -ForegroundColor Green
}
else {
    Write-Host '  Running as Standard User - some diagnostics will be skipped' -ForegroundColor Yellow
    Write-Host '  Tip: Re-run with -Elevate for full diagnostics' -ForegroundColor DarkYellow
}
Write-Host ''

Export-DiagReport
