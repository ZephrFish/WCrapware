# Windows Crap Remover - Ultimate Edition
# Comprehensive Windows 10/11 Debloater with Safety Features
# Version: 2.1

param(
    [switch]$AutoMode = $false,
    [switch]$SafeMode = $false,
    [switch]$DryRun = $false,
    [switch]$Silent = $false,
    [string]$Profile = "",
    [string]$ConfigFile = "",
    [string]$LogFile = "$env:TEMP\WindowsCrapRemover_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    # Quick Fix shortcuts - run directly without menu
    [switch]$FixBoot = $false,
    [switch]$FixCPU = $false,
    [switch]$FixDisk = $false,
    [switch]$FixPrivacy = $false,
    [switch]$FixAll = $false,
    [switch]$QuickStart = $false
)

# Initialize script variables
$script:Changes = @()
$script:BackupPath = "$env:LOCALAPPDATA\WindowsCrapRemover\Backups\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$script:ConfigPath = "$env:LOCALAPPDATA\WindowsCrapRemover\Config"
$script:AllowlistPath = "$script:ConfigPath\allowlist.txt"
$script:DenylistPath = "$script:ConfigPath\denylist.txt"

# Create necessary directories
New-Item -ItemType Directory -Force -Path $script:BackupPath | Out-Null
New-Item -ItemType Directory -Force -Path $script:ConfigPath | Out-Null

# Store initial benchmark data
$script:BenchmarkData = @{
    StartTime = Get-Date
    InitialCPU = $null
    InitialRAM = $null
    InitialDisk = $null
    InitialBootTime = $null
    InitialProcessCount = $null
    InitialServiceCount = $null
}

# =============================================================================
# SYSTEM HEALTH MONITORING DASHBOARD
# =============================================================================

function Get-SystemHealth {
    <#
    .SYNOPSIS
    Gets comprehensive system health metrics
    #>

    $health = @{}

    # CPU Usage
    try {
        $cpuCounter = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
        $health.CPUUsage = [math]::Round($cpuCounter.CounterSamples[0].CookedValue, 1)
    } catch {
        $health.CPUUsage = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    }

    # RAM Usage
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeRAM = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedRAM = $totalRAM - $freeRAM
    $health.RAMTotal = $totalRAM
    $health.RAMUsed = $usedRAM
    $health.RAMFree = $freeRAM
    $health.RAMPercent = [math]::Round(($usedRAM / $totalRAM) * 100, 1)

    # Disk Usage (System Drive)
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $health.DiskTotal = [math]::Round($disk.Size / 1GB, 2)
    $health.DiskFree = [math]::Round($disk.FreeSpace / 1GB, 2)
    $health.DiskUsed = $health.DiskTotal - $health.DiskFree
    $health.DiskPercent = [math]::Round(($health.DiskUsed / $health.DiskTotal) * 100, 1)

    # Boot Time
    try {
        $bootEvent = Get-WinEvent -FilterHashtable @{LogName='System'; ID=6005} -MaxEvents 1 -ErrorAction Stop
        $lastBoot = $bootEvent.TimeCreated
        $health.LastBoot = $lastBoot
        $health.Uptime = (Get-Date) - $lastBoot
    } catch {
        $health.LastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $health.Uptime = (Get-Date) - $health.LastBoot
    }

    # Process and Service counts
    $health.ProcessCount = (Get-Process).Count
    $health.ServiceCount = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count

    # Startup programs count
    $startupCount = 0
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $startupCount += ($items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
        }
    }
    $health.StartupCount = $startupCount

    # Installed apps count
    $health.InstalledAppsCount = (Get-AppxPackage -AllUsers).Count

    # Calculate health score (0-100)
    $score = 100
    if ($health.CPUUsage -gt 80) { $score -= 15 }
    elseif ($health.CPUUsage -gt 50) { $score -= 5 }

    if ($health.RAMPercent -gt 90) { $score -= 20 }
    elseif ($health.RAMPercent -gt 70) { $score -= 10 }

    if ($health.DiskPercent -gt 90) { $score -= 20 }
    elseif ($health.DiskPercent -gt 80) { $score -= 10 }

    if ($health.ProcessCount -gt 200) { $score -= 10 }
    if ($health.ServiceCount -gt 150) { $score -= 5 }
    if ($health.StartupCount -gt 15) { $score -= 5 }

    $health.HealthScore = [math]::Max(0, $score)

    return $health
}

function Show-ProgressBar {
    param(
        [int]$Percent,
        [int]$Width = 20,
        [string]$FillChar = [char]0x2588,
        [string]$EmptyChar = [char]0x2591
    )

    $filled = [math]::Floor($Width * $Percent / 100)
    $empty = $Width - $filled

    $bar = ($FillChar * $filled) + ($EmptyChar * $empty)
    return $bar
}

function Show-HealthDashboard {
    <#
    .SYNOPSIS
    Displays a real-time system health monitoring dashboard
    #>

    Clear-Host
    $health = Get-SystemHealth

    # Determine colors based on values
    $cpuColor = if ($health.CPUUsage -gt 80) { "Red" } elseif ($health.CPUUsage -gt 50) { "Yellow" } else { "Green" }
    $ramColor = if ($health.RAMPercent -gt 90) { "Red" } elseif ($health.RAMPercent -gt 70) { "Yellow" } else { "Green" }
    $diskColor = if ($health.DiskPercent -gt 90) { "Red" } elseif ($health.DiskPercent -gt 80) { "Yellow" } else { "Green" }
    $scoreColor = if ($health.HealthScore -lt 50) { "Red" } elseif ($health.HealthScore -lt 75) { "Yellow" } else { "Green" }

    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |                    SYSTEM HEALTH DASHBOARD                  |" -ForegroundColor Cyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host ""

    # Health Score
    Write-Host "    OVERALL HEALTH SCORE: " -NoNewline
    Write-Host "$($health.HealthScore)/100" -ForegroundColor $scoreColor
    Write-Host "    $(Show-ProgressBar -Percent $health.HealthScore -Width 40)" -ForegroundColor $scoreColor
    Write-Host ""

    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  RESOURCE USAGE                                            |" -ForegroundColor Yellow
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray

    # CPU
    Write-Host "    CPU Usage:    " -NoNewline
    Write-Host "$(Show-ProgressBar -Percent $health.CPUUsage)" -NoNewline -ForegroundColor $cpuColor
    Write-Host "  $($health.CPUUsage)%" -ForegroundColor $cpuColor

    # RAM
    Write-Host "    RAM Usage:    " -NoNewline
    Write-Host "$(Show-ProgressBar -Percent $health.RAMPercent)" -NoNewline -ForegroundColor $ramColor
    Write-Host "  $($health.RAMPercent)% ($($health.RAMUsed)GB / $($health.RAMTotal)GB)" -ForegroundColor $ramColor

    # Disk
    Write-Host "    Disk Usage:   " -NoNewline
    Write-Host "$(Show-ProgressBar -Percent $health.DiskPercent)" -NoNewline -ForegroundColor $diskColor
    Write-Host "  $($health.DiskPercent)% ($($health.DiskUsed)GB / $($health.DiskTotal)GB)" -ForegroundColor $diskColor

    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  SYSTEM STATS                                              |" -ForegroundColor Yellow
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray

    Write-Host "    Running Processes:    $($health.ProcessCount)" -ForegroundColor White
    Write-Host "    Running Services:     $($health.ServiceCount)" -ForegroundColor White
    Write-Host "    Startup Programs:     $($health.StartupCount)" -ForegroundColor White
    Write-Host "    Installed Apps:       $($health.InstalledAppsCount)" -ForegroundColor White

    $uptimeStr = "{0}d {1}h {2}m" -f $health.Uptime.Days, $health.Uptime.Hours, $health.Uptime.Minutes
    Write-Host "    System Uptime:        $uptimeStr" -ForegroundColor White

    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan

    return $health
}

# =============================================================================
# SYSTEM REQUIREMENTS CHECKER
# =============================================================================

function Test-SystemRequirements {
    <#
    .SYNOPSIS
    Checks system requirements and compatibility before running optimizations
    #>

    $results = @{
        Passed = $true
        Warnings = @()
        Errors = @()
        Info = @()
    }

    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |              SYSTEM REQUIREMENTS CHECK                      |" -ForegroundColor Cyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host ""

    # Check Windows version
    Write-Host "  [*] Checking Windows version..." -ForegroundColor White
    $osVersion = [System.Environment]::OSVersion.Version
    $buildNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber

    if ([int]$buildNumber -lt 17763) {
        $results.Errors += "Windows version too old. Requires Windows 10 1809 (Build 17763) or later."
        $results.Passed = $false
        Write-Host "      [X] FAILED: Build $buildNumber is not supported" -ForegroundColor Red
    } else {
        Write-Host "      [OK] Windows Build $buildNumber is supported" -ForegroundColor Green
    }

    # Check disk space
    Write-Host "  [*] Checking disk space..." -ForegroundColor White
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)

    if ($freeGB -lt 1) {
        $results.Errors += "Insufficient disk space. At least 1GB free space required."
        $results.Passed = $false
        Write-Host "      [X] FAILED: Only $freeGB GB free (minimum 1GB required)" -ForegroundColor Red
    } elseif ($freeGB -lt 5) {
        $results.Warnings += "Low disk space ($freeGB GB). Consider freeing up space."
        Write-Host "      [!] WARNING: Only $freeGB GB free" -ForegroundColor Yellow
    } else {
        Write-Host "      [OK] $freeGB GB free disk space" -ForegroundColor Green
    }

    # Check RAM
    Write-Host "  [*] Checking system memory..." -ForegroundColor White
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeRAM = [math]::Round($os.FreePhysicalMemory / 1MB, 2)

    if ($totalRAM -lt 2) {
        $results.Warnings += "Low total RAM ($totalRAM GB). Some optimizations may not be effective."
        Write-Host "      [!] WARNING: Only $totalRAM GB total RAM" -ForegroundColor Yellow
    } else {
        Write-Host "      [OK] $totalRAM GB total RAM ($freeRAM GB free)" -ForegroundColor Green
    }

    # Check for WSL
    Write-Host "  [*] Checking for WSL (Windows Subsystem for Linux)..." -ForegroundColor White
    $wslInstalled = $false
    try {
        $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
        if ($wslFeature -and $wslFeature.State -eq "Enabled") {
            $wslInstalled = $true
            $results.Warnings += "WSL is installed. Some optimizations may affect WSL functionality."
            Write-Host "      [!] WARNING: WSL detected - some features may be affected" -ForegroundColor Yellow
        } else {
            Write-Host "      [OK] WSL not detected" -ForegroundColor Green
        }
    } catch {
        Write-Host "      [OK] WSL not detected" -ForegroundColor Green
    }

    # Check for Docker
    Write-Host "  [*] Checking for Docker..." -ForegroundColor White
    $dockerInstalled = $false
    if (Get-Service -Name "Docker*" -ErrorAction SilentlyContinue) {
        $dockerInstalled = $true
        $results.Warnings += "Docker is installed. Hyper-V optimizations will be skipped."
        Write-Host "      [!] WARNING: Docker detected - Hyper-V will be preserved" -ForegroundColor Yellow
    } else {
        Write-Host "      [OK] Docker not detected" -ForegroundColor Green
    }

    # Check for Hyper-V
    Write-Host "  [*] Checking for Hyper-V..." -ForegroundColor White
    try {
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
        if ($hyperv -and $hyperv.State -eq "Enabled") {
            $results.Warnings += "Hyper-V is enabled. Virtualization features will be preserved."
            Write-Host "      [!] WARNING: Hyper-V enabled - virtualization preserved" -ForegroundColor Yellow
        } else {
            Write-Host "      [OK] Hyper-V not enabled" -ForegroundColor Green
        }
    } catch {
        Write-Host "      [OK] Hyper-V not detected" -ForegroundColor Green
    }

    # Check for development tools
    Write-Host "  [*] Checking for development tools..." -ForegroundColor White
    $devTools = @()

    if (Test-Path "$env:ProgramFiles\Microsoft Visual Studio") { $devTools += "Visual Studio" }
    if (Test-Path "$env:ProgramFiles\Microsoft VS Code") { $devTools += "VS Code" }
    if (Test-Path "$env:LocalAppData\Programs\Microsoft VS Code") { $devTools += "VS Code" }
    if (Get-Command git -ErrorAction SilentlyContinue) { $devTools += "Git" }
    if (Get-Command node -ErrorAction SilentlyContinue) { $devTools += "Node.js" }
    if (Get-Command python -ErrorAction SilentlyContinue) { $devTools += "Python" }

    if ($devTools.Count -gt 0) {
        $devToolsUnique = $devTools | Select-Object -Unique
        $results.Info += "Development tools detected: $($devToolsUnique -join ', ')"
        Write-Host "      [i] INFO: Dev tools found: $($devToolsUnique -join ', ')" -ForegroundColor Cyan
    } else {
        Write-Host "      [OK] No development tools requiring protection" -ForegroundColor Green
    }

    # Check for pending Windows updates
    Write-Host "  [*] Checking for pending reboots..." -ForegroundColor White
    $pendingReboot = $false

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $pendingReboot = $true
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $pendingReboot = $true
    }

    if ($pendingReboot) {
        $results.Warnings += "A system reboot is pending. Consider rebooting before proceeding."
        Write-Host "      [!] WARNING: System reboot pending" -ForegroundColor Yellow
    } else {
        Write-Host "      [OK] No pending reboots" -ForegroundColor Green
    }

    # Summary
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  SUMMARY                                                   |" -ForegroundColor Yellow
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray

    if ($results.Passed) {
        Write-Host "    Status: " -NoNewline
        Write-Host "READY TO PROCEED" -ForegroundColor Green
    } else {
        Write-Host "    Status: " -NoNewline
        Write-Host "CANNOT PROCEED" -ForegroundColor Red
    }

    Write-Host "    Errors:   $($results.Errors.Count)" -ForegroundColor $(if ($results.Errors.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "    Warnings: $($results.Warnings.Count)" -ForegroundColor $(if ($results.Warnings.Count -gt 0) { "Yellow" } else { "Green" })

    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan

    return $results
}

# =============================================================================
# BENCHMARK / BEFORE-AFTER COMPARISON
# =============================================================================

function Start-Benchmark {
    <#
    .SYNOPSIS
    Captures initial system state for before/after comparison
    #>

    Write-Host "  [*] Capturing initial system benchmark..." -ForegroundColor Cyan

    $script:BenchmarkData.InitialCPU = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average

    $os = Get-CimInstance Win32_OperatingSystem
    $script:BenchmarkData.InitialRAM = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)

    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $script:BenchmarkData.InitialDisk = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)

    $script:BenchmarkData.InitialProcessCount = (Get-Process).Count
    $script:BenchmarkData.InitialServiceCount = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count

    # Count startup items
    $startupCount = 0
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $startupCount += ($items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
        }
    }
    $script:BenchmarkData.InitialStartupCount = $startupCount

    # Count installed apps
    $script:BenchmarkData.InitialAppsCount = (Get-AppxPackage -AllUsers).Count

    # Get temp files size
    $tempSize = 0
    $tempPaths = @("$env:TEMP", "$env:LOCALAPPDATA\Temp", "$env:SystemRoot\Temp")
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            $tempSize += (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        }
    }
    $script:BenchmarkData.InitialTempSize = [math]::Round($tempSize / 1MB, 2)

    Write-Host "  [OK] Initial benchmark captured" -ForegroundColor Green
}

function Show-BenchmarkComparison {
    <#
    .SYNOPSIS
    Shows before/after comparison of system metrics
    #>

    Clear-Host

    # Get current values
    $currentCPU = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average

    $os = Get-CimInstance Win32_OperatingSystem
    $currentRAM = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)

    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $currentDisk = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)

    $currentProcessCount = (Get-Process).Count
    $currentServiceCount = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count

    # Count startup items
    $currentStartupCount = 0
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $currentStartupCount += ($items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
        }
    }

    $currentAppsCount = (Get-AppxPackage -AllUsers).Count

    # Get temp files size
    $tempSize = 0
    $tempPaths = @("$env:TEMP", "$env:LOCALAPPDATA\Temp", "$env:SystemRoot\Temp")
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            $tempSize += (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        }
    }
    $currentTempSize = [math]::Round($tempSize / 1MB, 2)

    # Calculate duration
    $duration = (Get-Date) - $script:BenchmarkData.StartTime

    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |              BENCHMARK COMPARISON RESULTS                   |" -ForegroundColor Cyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Session Duration: $($duration.Minutes) minutes $($duration.Seconds) seconds" -ForegroundColor White
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  METRIC                    BEFORE      AFTER      CHANGE   |" -ForegroundColor Yellow
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray

    # Helper function to format change
    function Format-Change {
        param($before, $after, $unit, $lowerIsBetter = $true)
        $diff = $after - $before
        $diffStr = if ($diff -ge 0) { "+$diff" } else { "$diff" }
        $color = if ($lowerIsBetter) {
            if ($diff -lt 0) { "Green" } elseif ($diff -gt 0) { "Red" } else { "White" }
        } else {
            if ($diff -gt 0) { "Green" } elseif ($diff -lt 0) { "Red" } else { "White" }
        }
        return @{ Text = "$diffStr $unit"; Color = $color }
    }

    # Display metrics
    $metrics = @(
        @{ Name = "RAM Usage (GB)"; Before = $script:BenchmarkData.InitialRAM; After = $currentRAM; Unit = "GB"; LowerBetter = $true },
        @{ Name = "Disk Used (GB)"; Before = $script:BenchmarkData.InitialDisk; After = $currentDisk; Unit = "GB"; LowerBetter = $true },
        @{ Name = "Running Processes"; Before = $script:BenchmarkData.InitialProcessCount; After = $currentProcessCount; Unit = ""; LowerBetter = $true },
        @{ Name = "Running Services"; Before = $script:BenchmarkData.InitialServiceCount; After = $currentServiceCount; Unit = ""; LowerBetter = $true },
        @{ Name = "Startup Programs"; Before = $script:BenchmarkData.InitialStartupCount; After = $currentStartupCount; Unit = ""; LowerBetter = $true },
        @{ Name = "Installed Apps"; Before = $script:BenchmarkData.InitialAppsCount; After = $currentAppsCount; Unit = ""; LowerBetter = $true },
        @{ Name = "Temp Files (MB)"; Before = $script:BenchmarkData.InitialTempSize; After = $currentTempSize; Unit = "MB"; LowerBetter = $true }
    )

    foreach ($metric in $metrics) {
        $change = Format-Change -before $metric.Before -after $metric.After -unit $metric.Unit -lowerIsBetter $metric.LowerBetter
        $beforeStr = "{0,10}" -f $metric.Before
        $afterStr = "{0,10}" -f $metric.After
        $nameStr = "{0,-22}" -f $metric.Name

        Write-Host "    $nameStr $beforeStr $afterStr  " -NoNewline
        Write-Host $change.Text -ForegroundColor $change.Color
    }

    # Summary
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  SUMMARY                                                   |" -ForegroundColor Yellow
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray

    $appsRemoved = $script:BenchmarkData.InitialAppsCount - $currentAppsCount
    $servicesReduced = $script:BenchmarkData.InitialServiceCount - $currentServiceCount
    $diskFreed = $script:BenchmarkData.InitialDisk - $currentDisk
    $tempCleaned = $script:BenchmarkData.InitialTempSize - $currentTempSize

    if ($appsRemoved -gt 0) {
        Write-Host "    [+] Removed $appsRemoved bloatware apps" -ForegroundColor Green
    }
    if ($servicesReduced -gt 0) {
        Write-Host "    [+] Reduced $servicesReduced running services" -ForegroundColor Green
    }
    if ($diskFreed -gt 0) {
        Write-Host "    [+] Freed $diskFreed GB disk space" -ForegroundColor Green
    }
    if ($tempCleaned -gt 0) {
        Write-Host "    [+] Cleaned $tempCleaned MB temp files" -ForegroundColor Green
    }

    if ($appsRemoved -le 0 -and $servicesReduced -le 0 -and $diskFreed -le 0 -and $tempCleaned -le 0) {
        Write-Host "    [i] No significant changes detected yet" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry
    
    # Display to console if not silent
    if (-not $Silent) {
        switch ($Level) {
            "ERROR" { Write-Host $Message -ForegroundColor Red }
            "WARNING" { Write-Host $Message -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $Message -ForegroundColor Green }
            "INFO" { Write-Host $Message -ForegroundColor White }
            "DEBUG" { if ($VerbosePreference -eq "Continue") { Write-Host $Message -ForegroundColor Gray } }
        }
    }
}

# Check Administrator privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Restarting with Administrator privileges..." -ForegroundColor Yellow

    # Build arguments from bound parameters
    $argList = @("-File", "`"$PSCommandPath`"")
    if ($AutoMode) { $argList += "-AutoMode" }
    if ($SafeMode) { $argList += "-SafeMode" }
    if ($DryRun) { $argList += "-DryRun" }
    if ($Silent) { $argList += "-Silent" }
    if ($Profile) { $argList += "-Profile"; $argList += $Profile }
    if ($ConfigFile) { $argList += "-ConfigFile"; $argList += "`"$ConfigFile`"" }
    if ($LogFile -ne "$env:TEMP\WindowsCrapRemover_$(Get-Date -Format 'yyyyMMdd_HHmmss').log") {
        $argList += "-LogFile"; $argList += "`"$LogFile`""
    }

    Start-Process PowerShell -Verb RunAs -ArgumentList $argList -Wait
    exit
}

# Detect Windows version
$OSVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
$OSName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
$IsWindows11 = [int]$OSVersion -ge 22000
$WindowsVersion = if ($IsWindows11) { "Windows 11" } else { "Windows 10" }

Write-Log "==================================================" "INFO"
Write-Log "    Windows Crap Remover - Ultimate Edition" "INFO"
Write-Log "==================================================" "INFO"
Write-Log "Detected OS: $WindowsVersion (Build $OSVersion)" "INFO"
Write-Log "OS Name: $OSName" "INFO"
Write-Log "Dry Run Mode: $DryRun" "INFO"
Write-Log "Log File: $LogFile" "INFO"
Write-Log "" "INFO"

# Capture initial benchmark data
Start-Benchmark

# Function to create system restore point
function Create-SystemRestorePoint {
    param([string]$Description)
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would create restore point: $Description" "INFO"
        return
    }
    
    try {
        Write-Log "Creating system restore point: $Description" "INFO"
        Enable-ComputerRestore -Drive "$env:SystemDrive\"
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "System restore point created successfully" "SUCCESS"
    }
    catch {
        Write-Log "Failed to create restore point: $_" "ERROR"
        $continue = Read-Host "Continue without restore point? (Y/N)"
        if ($continue -ne 'Y') {
            Write-Log "Operation aborted by user" "WARNING"
            exit
        }
    }
}

# Function to backup registry
function Backup-RegistryKey {
    param([string]$KeyPath)
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would backup registry key: $KeyPath" "DEBUG"
        return
    }
    
    try {
        $backupFile = Join-Path $script:BackupPath "Registry_$(($KeyPath -replace '[\\/:]', '_')).reg"
        reg export $KeyPath $backupFile /y | Out-Null
        Write-Log "Backed up registry key: $KeyPath" "DEBUG"
        
        # Record the change
        $script:Changes += @{
            Type = "Registry"
            Action = "Modified"
            Path = $KeyPath
            BackupFile = $backupFile
            Timestamp = Get-Date
        }
    }
    catch {
        Write-Log "Failed to backup registry key $KeyPath : $_" "ERROR"
    }
}

# Load configuration
function Load-Configuration {
    param([string]$ConfigFile)
    
    $config = @{
        RemoveApps = $true
        DisableTelemetry = $true
        RemoveOneDrive = $true
        DisableCortana = $true
        CleanScheduledTasks = $true
        DisableWindowsSearch = $false
        RemoveEdge = $false
        OptimizePerformance = $true
        EnhancePrivacy = $true
        CleanupNetwork = $true
        ManageStartup = $true
        CleanTempFiles = $true
        DisableDefender = $false
    }
    
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        Write-Log "Loading configuration from: $ConfigFile" "INFO"
        $loadedConfig = Get-Content $ConfigFile | ConvertFrom-Json
        foreach ($key in $loadedConfig.PSObject.Properties) {
            $config[$key.Name] = $key.Value
        }
    }
    
    return $config
}

# Profile definitions
$Profiles = @{
    "Minimal" = @{
        RemoveApps = $true
        DisableTelemetry = $true
        RemoveOneDrive = $false
        DisableCortana = $true
        CleanScheduledTasks = $true
        DisableWindowsSearch = $false
        RemoveEdge = $false
        OptimizePerformance = $false
        EnhancePrivacy = $true
        CleanupNetwork = $false
        ManageStartup = $false
        CleanTempFiles = $true
        DisableDefender = $false
    }
    "Gaming" = @{
        RemoveApps = $true
        DisableTelemetry = $true
        RemoveOneDrive = $true
        DisableCortana = $true
        CleanScheduledTasks = $true
        DisableWindowsSearch = $true
        RemoveEdge = $false
        OptimizePerformance = $true
        EnhancePrivacy = $false
        CleanupNetwork = $true
        ManageStartup = $true
        CleanTempFiles = $true
        DisableDefender = $false
    }
    "Work" = @{
        RemoveApps = $false
        DisableTelemetry = $true
        RemoveOneDrive = $false
        DisableCortana = $false
        CleanScheduledTasks = $false
        DisableWindowsSearch = $false
        RemoveEdge = $false
        OptimizePerformance = $true
        EnhancePrivacy = $true
        CleanupNetwork = $false
        ManageStartup = $true
        CleanTempFiles = $true
        DisableDefender = $false
    }
    "Privacy" = @{
        RemoveApps = $true
        DisableTelemetry = $true
        RemoveOneDrive = $true
        DisableCortana = $true
        CleanScheduledTasks = $true
        DisableWindowsSearch = $false
        RemoveEdge = $true
        OptimizePerformance = $false
        EnhancePrivacy = $true
        CleanupNetwork = $true
        ManageStartup = $false
        CleanTempFiles = $true
        DisableDefender = $false
    }
    "Ultimate" = @{
        RemoveApps = $true
        DisableTelemetry = $true
        RemoveOneDrive = $true
        DisableCortana = $true
        CleanScheduledTasks = $true
        DisableWindowsSearch = $true
        RemoveEdge = $true
        OptimizePerformance = $true
        EnhancePrivacy = $true
        CleanupNetwork = $true
        ManageStartup = $true
        CleanTempFiles = $true
        DisableDefender = $false
    }
}

# Load allowlist and denylist
function Load-AppLists {
    $allowlist = @()
    $denylist = @()
    
    if (Test-Path $script:AllowlistPath) {
        $allowlist = Get-Content $script:AllowlistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
        Write-Log "Loaded allowlist with $($allowlist.Count) entries" "DEBUG"
    }
    
    if (Test-Path $script:DenylistPath) {
        $denylist = Get-Content $script:DenylistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
        Write-Log "Loaded denylist with $($denylist.Count) entries" "DEBUG"
    }
    
    return @{
        Allowlist = $allowlist
        Denylist = $denylist
    }
}

# Enhanced menu system
function Show-MainMenu {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║          Windows Crap Remover - Ultimate Edition               ║" -ForegroundColor Cyan
    Write-Host "║                    Version 2.1                                 ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  >>>  Q.  QUICK START (Recommended Safe Cleanup)  <<<          ║" -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "║  >>>  F.  QUICK FIX   (One-Click Problem Solvers) <<<          ║" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ MAIN MENU                                                      ║" -ForegroundColor Yellow
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ 1.  Quick Actions (Common tasks)                               ║" -ForegroundColor White
    Write-Host "║ 2.  App Management                                             ║" -ForegroundColor White
    Write-Host "║ 3.  Privacy & Telemetry                                        ║" -ForegroundColor White
    Write-Host "║ 4.  Performance Optimization                                   ║" -ForegroundColor White
    Write-Host "║ 5.  System Cleanup                                             ║" -ForegroundColor White
    Write-Host "║ 6.  Advanced Options                                           ║" -ForegroundColor White
    Write-Host "║ 7.  Load Profile                                               ║" -ForegroundColor White
    Write-Host "║ 8.  Backup & Restore                                           ║" -ForegroundColor White
    Write-Host "║ 9.  View Changes Log                                           ║" -ForegroundColor White
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ MONITORING & DIAGNOSTICS                                       ║" -ForegroundColor Magenta
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ H.  System Health Dashboard                                    ║" -ForegroundColor Green
    Write-Host "║ R.  System Requirements Check                                  ║" -ForegroundColor Green
    Write-Host "║ B.  View Benchmark Comparison                                  ║" -ForegroundColor Green
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ ADDITIONAL TOOLS                                               ║" -ForegroundColor Magenta
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ T.  Tools (Store Repair, Drivers, Maintenance, Portable)       ║" -ForegroundColor Green
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ 0.  Exit                                                       ║" -ForegroundColor Red
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Quick Start function - Multi-profile safe cleanup
function Start-QuickStart {
    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Green
    Write-Host "  |                    QUICK START                              |" -ForegroundColor Green
    Write-Host "  +============================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Select a profile:" -ForegroundColor White
    Write-Host ""
    Write-Host "    [G] Gaming (DEFAULT) - Keeps Xbox, Game Bar, Gaming Services" -ForegroundColor Cyan
    Write-Host "    [P] Privacy          - Maximum privacy, removes more apps" -ForegroundColor Magenta
    Write-Host "    [W] Work             - Keeps productivity apps, minimal cleanup" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray

    $profileChoice = Read-Host "  Choose profile (G/P/W) [default: G]"
    if ([string]::IsNullOrWhiteSpace($profileChoice)) { $profileChoice = "G" }

    # Profile-specific allowlists (Gaming uses $script:GamingAllowlist defined globally)
    $privacyAllowlist = @(
        "Microsoft.WindowsStore",
        "Microsoft.StorePurchaseApp"
    )

    $workAllowlist = @(
        "Microsoft.WindowsStore",
        "Microsoft.StorePurchaseApp",
        "Microsoft.Office*",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.OutlookForWindows",
        "Microsoft.Todos",
        "Microsoft.PowerAutomateDesktop",
        "Microsoft.OneNote",
        "Microsoft.SkypeApp"
    )

    # Set profile settings
    $profileName = ""
    $profileAllowlist = @()
    $doEnhancePrivacy = $false
    $doOptimizePerformance = $false
    $doDisableCortana = $false

    switch ($profileChoice.ToUpper()) {
        'G' {
            $profileName = "Gaming"
            $profileAllowlist = $script:GamingAllowlist
            $doOptimizePerformance = $true
        }
        'P' {
            $profileName = "Privacy"
            $profileAllowlist = $privacyAllowlist
            $doEnhancePrivacy = $true
            $doDisableCortana = $true
        }
        'W' {
            $profileName = "Work"
            $profileAllowlist = $workAllowlist
            $doEnhancePrivacy = $true
        }
        default {
            $profileName = "Gaming"
            $profileAllowlist = $script:GamingAllowlist
            $doOptimizePerformance = $true
        }
    }

    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Green
    Write-Host "  |                    QUICK START                              |" -ForegroundColor Green
    Write-Host "  |                Profile: $($profileName.PadRight(10))                        |" -ForegroundColor Green
    Write-Host "  +============================================================+" -ForegroundColor Green
    Write-Host ""

    $appLists = Load-AppLists
    $combinedAllowlist = $appLists.Allowlist + $profileAllowlist + $SafeApps

    # Build list of apps that WILL be removed
    Write-Host "  Scanning installed apps..." -ForegroundColor Gray
    $installedApps = Get-AppxPackage -AllUsers | Select-Object -ExpandProperty Name | Sort-Object -Unique
    $appsToRemove = @()

    $allBloatware = $CommonBloatware + $ThirdPartyBloatware + $appLists.Denylist
    # Only include Xbox bloatware for non-Gaming profiles
    if ($profileName -ne "Gaming") {
        $allBloatware += $XboxBloatware
    }

    foreach ($app in $installedApps) {
        $isBloatware = $false
        $isAllowed = $false

        # Check if it's bloatware
        foreach ($bloat in $allBloatware) {
            if ($null -eq $bloat -or $bloat -eq "") { continue }
            if ($bloat.Contains("*")) {
                $pattern = "^" + ($bloat -replace "\*", ".*") + "$"
                if ($app -match $pattern) { $isBloatware = $true; break }
            } else {
                if ($app -eq $bloat) { $isBloatware = $true; break }
            }
        }

        # Check if it's allowlisted
        foreach ($white in $combinedAllowlist) {
            if ($null -eq $white -or $white -eq "") { continue }
            if ($white.Contains("*")) {
                $pattern = "^" + ($white -replace "\*", ".*") + "$"
                if ($app -match $pattern) { $isAllowed = $true; break }
            } else {
                if ($app -eq $white) { $isAllowed = $true; break }
            }
        }

        if ($isBloatware -and -not $isAllowed) {
            $appsToRemove += $app
        }
    }

    # Show preview
    Write-Host ""
    Write-Host "  APPS TO BE REMOVED ($($appsToRemove.Count) found):" -ForegroundColor Red
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    if ($appsToRemove.Count -eq 0) {
        Write-Host "    (No bloatware apps found to remove)" -ForegroundColor Gray
    } else {
        foreach ($app in $appsToRemove | Sort-Object) {
            Write-Host "    [-] $app" -ForegroundColor Yellow
        }
    }
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  OTHER ACTIONS:" -ForegroundColor Cyan
    Write-Host "    [*] Disable telemetry and data collection" -ForegroundColor White
    Write-Host "    [*] Clean temporary files" -ForegroundColor White
    Write-Host "    [*] Disable P2P Windows Updates" -ForegroundColor White
    if ($doOptimizePerformance) {
        Write-Host "    [*] Optimize performance (visual effects, services)" -ForegroundColor White
    }
    if ($doEnhancePrivacy) {
        Write-Host "    [*] Enhance privacy settings" -ForegroundColor White
    }
    if ($doDisableCortana) {
        Write-Host "    [*] Disable Cortana" -ForegroundColor White
    }
    Write-Host ""

    # Show preserved apps based on profile
    switch ($profileName) {
        "Gaming" {
            Write-Host "  PRESERVED (Gaming Profile):" -ForegroundColor Green
            Write-Host "    + Xbox App, Game Bar, Game DVR" -ForegroundColor DarkGreen
            Write-Host "    + Xbox Identity & Services" -ForegroundColor DarkGreen
            Write-Host "    + Windows Store (for game installs)" -ForegroundColor DarkGreen
        }
        "Privacy" {
            Write-Host "  PRESERVED (Privacy Profile):" -ForegroundColor Magenta
            Write-Host "    + Windows Store (minimal)" -ForegroundColor DarkMagenta
            Write-Host "    - Removes most Microsoft apps" -ForegroundColor DarkMagenta
        }
        "Work" {
            Write-Host "  PRESERVED (Work Profile):" -ForegroundColor Yellow
            Write-Host "    + Microsoft Office apps" -ForegroundColor DarkYellow
            Write-Host "    + Outlook, OneNote, To-Do" -ForegroundColor DarkYellow
            Write-Host "    + Windows Store" -ForegroundColor DarkYellow
        }
    }
    Write-Host ""

    Write-Host "  This will NOT:" -ForegroundColor Yellow
    Write-Host "    - Remove OneDrive or Edge" -ForegroundColor DarkGray
    Write-Host "    - Disable Windows Defender" -ForegroundColor DarkGray
    Write-Host "    - Disable Windows Search" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray

    $confirm = Read-Host "  Proceed with Quick Start? (Y/N)"

    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
        Write-Host ""
        Write-Host "  Starting Quick Start cleanup ($profileName Profile)..." -ForegroundColor Green
        Write-Host ""

        # Step 1: Remove bloatware
        Write-Host "  [1/5] Removing bloatware..." -ForegroundColor Cyan
        $includeXbox = ($profileName -ne "Gaming")
        Remove-Bloatware -SafeModeEnabled $true -CustomAllowlist $combinedAllowlist -CustomDenylist $appLists.Denylist -IncludeXboxBloatware $includeXbox

        # Step 2: Disable telemetry
        Write-Host ""
        Write-Host "  [2/5] Disabling telemetry..." -ForegroundColor Cyan
        $preserveXbox = ($profileName -eq "Gaming")
        Disable-Telemetry -PreserveXboxServices $preserveXbox

        # Step 3: Profile-specific actions
        Write-Host ""
        if ($doOptimizePerformance) {
            Write-Host "  [3/5] Optimizing performance..." -ForegroundColor Cyan
            Optimize-Performance
        } elseif ($doEnhancePrivacy) {
            Write-Host "  [3/5] Enhancing privacy..." -ForegroundColor Cyan
            Enhance-Privacy
        } else {
            Write-Host "  [3/5] Skipped (not applicable for this profile)" -ForegroundColor Gray
        }

        # Step 4: Clean temp files
        Write-Host ""
        Write-Host "  [4/5] Cleaning temporary files..." -ForegroundColor Cyan
        Clean-TempFiles

        # Step 5: Disable P2P updates + optional Cortana
        Write-Host ""
        Write-Host "  [5/5] Disabling P2P Windows Updates..." -ForegroundColor Cyan
        Disable-P2PUpdates

        if ($doDisableCortana) {
            Write-Host ""
            Write-Host "  [Bonus] Disabling Cortana..." -ForegroundColor Cyan
            Disable-Cortana
        }

        Write-Host ""
        Write-Host "  +============================================================+" -ForegroundColor Green
        Write-Host "  |              QUICK START COMPLETED!                        |" -ForegroundColor Green
        Write-Host "  |              Profile: $($profileName.PadRight(10))                        |" -ForegroundColor Green
        Write-Host "  +============================================================+" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Press 'B' to view benchmark comparison of changes made." -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host ""
        Write-Host "  Quick Start cancelled." -ForegroundColor Yellow
    }
}

# Define all bloatware lists
$CommonBloatware = @(
    "Microsoft.BingWeather",
    "Microsoft.BingNews",
    "Microsoft.BingFinance",
    "Microsoft.BingSports",
    "Microsoft.BingTranslator",
    "Microsoft.BingFoodAndDrink",
    "Microsoft.BingHealthAndFitness",
    "Microsoft.BingTravel",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Office.OneNote",
    "Microsoft.OneConnect",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.WebMediaExtensions",
    "Microsoft.WebpImageExtension",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    # Xbox apps moved to $XboxBloatware - only removed when NOT using Gaming profile
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.WindowsFeedback",
    "Microsoft.Advertising.Xaml",
    "Microsoft.People",
    "Microsoft.CommsPhone",
    "Microsoft.ConnectivityStore",
    "Microsoft.Office.Sway",
    "Microsoft.WindowsReadingList",
    "Microsoft.MicrosoftPowerBIForWindows",
    "Microsoft.NetworkSpeedTest",
    "Microsoft.RemoteDesktop",
    "Microsoft.MinecraftUWP",
    "Microsoft.MicrosoftJigsaw",
    "Microsoft.MicrosoftMahjong",
    "Microsoft.MicrosoftSudoku",
    "Microsoft.WindowsPhone",
    "Microsoft.WindowsCamera",
    "microsoft.windowscommunicationsapps",
    "Windows.ContactSupport",
    "Microsoft.Whiteboard",
    "ActiproSoftware",
    "EclipseManager",
    
    # Third-party bloatware
    "PandoraMedia",
    "AdobeSystemIncorporated.AdobePhotoshop",
    "Duolingo",
    "SpotifyAB.SpotifyMusic",
    "king.com.*",
    "CandyCrush*",
    "Facebook*",
    "Twitter*",
    "Flipboard*",
    "Netflix*",
    "Amazon*",
    "Hulu*",
    "Disney*",
    "TikTok*",
    "Instagram*",
    "WhatsApp*",
    "Spotify*",
    "Minecraft*",
    "Royal Revolt*",
    "Sway*",
    "Speed Test*",
    "Dolby*",
    "Office*",
    "Sling*",
    "Candy*",
    "Bubble*",
    "Keeper*",
    "Plex*",
    "iHeartRadio*",
    "Shazam*",
    "LinkedInforWindows*",
    "HiddenCity*",
    "AdobePhotoshopExpress*",
    "HotspotShieldFreeVPN*",
    "PicsArt-PhotoStudio*",
    "EclipseManager*",
    "PolarrPhotoEditorAcademicEdition*",
    "Wunderlist*",
    "XING*",
    "Viber*",
    "ACGMediaPlayer*",
    "OneCalendar*",
    "Studio.CocktailFlow*",
    "TuneInRadio*",
    "GAMELOFTSA*",
    "ThumbmunkeysLtd*",
    "NORDCURRENT*",
    "AdobeSystemsIncorporated*",
    "A278AB0D*",
    "828B5831*",
    "WinZipComputing*"
)

# Xbox/Gaming apps - only removed when NOT using Gaming profile
$XboxBloatware = @(
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.GamingApp",
    "Microsoft.GamingServices"
)

$Windows11Specific = @(
    "Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.News",
    # Microsoft.GamingApp moved to $XboxBloatware
    "Microsoft.WindowsTerminal.Preview",
    "Microsoft.ClipChamp",
    "Clipchamp.Clipchamp",
    "Microsoft.Teams",
    "MicrosoftTeams",
    "Microsoft.DevHome",
    "Microsoft.OutlookForWindows",
    "Microsoft.Windows.DevHome",
    "Microsoft.Windows.Ai.Copilot.Provider",
    "Microsoft.Copilot",
    "Microsoft.Family",
    "Microsoft.QuickAssist",
    "Microsoft.Widgets",
    "MicrosoftCorporationII.MicrosoftFamily"
)

$SafeApps = @(
    "Microsoft.WindowsStore",
    "Microsoft.StorePurchaseApp",
    "Microsoft.WindowsCalculator",
    "Microsoft.Windows.Photos",
    "Microsoft.ScreenSketch",
    "Microsoft.MSPaint",
    "Microsoft.Paint",
    "Microsoft.WindowsNotepad",
    "Microsoft.WindowsTerminal",
    "Microsoft.HEIFImageExtension",
    "Microsoft.VP9VideoExtensions",
    "Microsoft.WebpImageExtension",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.XboxGameCallableUI",
    # Framework packages (required by other apps)
    "Microsoft.Services.Store.Engagement",
    "Microsoft.NET.*",
    "Microsoft.VCLibs.*",
    "Microsoft.UI.Xaml.*"
)

# Gaming allowlist - apps preserved when using Gaming profile (single source of truth)
$script:GamingAllowlist = @(
    "Microsoft.Xbox*",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameCallableUI",
    "Microsoft.GamingApp",
    "Microsoft.GamingServices",
    "Microsoft.WindowsStore",
    "Microsoft.StorePurchaseApp"
)

# Function to remove bloatware with enhanced features
function Remove-Bloatware {
    param(
        [bool]$SafeModeEnabled = $false,
        [array]$CustomAllowlist = @(),
        [array]$CustomDenylist = @(),
        [bool]$IncludeXboxBloatware = $true  # Set to false for Gaming profile
    )

    Write-Log "Starting bloatware removal..." "INFO"

    # Combine lists
    $appsToRemove = $CommonBloatware + $CustomDenylist
    if ($IsWindows11) {
        $appsToRemove += $Windows11Specific
    }
    # Only include Xbox bloatware if requested (not for Gaming profile)
    if ($IncludeXboxBloatware) {
        $appsToRemove += $XboxBloatware
    }
    
    # Remove duplicates
    $appsToRemove = $appsToRemove | Select-Object -Unique
    
    # Apply allowlist
    if ($SafeModeEnabled) {
        $allowlistApps = $SafeApps + $CustomAllowlist
    } else {
        $allowlistApps = $CustomAllowlist
    }
    
    $totalApps = $appsToRemove.Count
    $removed = 0
    $failed = 0

    # Cache all installed packages once (instead of querying for each app)
    Write-Log "Caching installed packages..." "DEBUG"
    $allInstalledPackages = Get-AppxPackage -AllUsers

    foreach ($app in $appsToRemove) {
        if ($null -eq $app -or $app -eq "") { continue }

        # Check if allowlisted (check both directions for wildcard matching)
        $isAllowed = $false
        foreach ($allowedApp in $allowlistApps) {
            if ($null -eq $allowedApp -or $allowedApp -eq "") { continue }
            # Check if allowlist pattern matches app OR app matches allowlist pattern
            if ($app -like $allowedApp -or $allowedApp -like $app) {
                $isAllowed = $true
                break
            }
        }

        if ($isAllowed) {
            Write-Log "Skipping allowlisted app: $app" "DEBUG"
            continue
        }

        # Find matching apps from cached list (much faster than querying each time)
        $packages = $allInstalledPackages | Where-Object { $_.Name -like $app }

        # Double-check each package against allowlist before removing
        $filteredPackages = @()
        foreach ($pkg in $packages) {
            $pkgAllowed = $false
            foreach ($allowedApp in $allowlistApps) {
                if ($null -eq $allowedApp -or $allowedApp -eq "") { continue }
                if ($pkg.Name -like $allowedApp) {
                    $pkgAllowed = $true
                    Write-Log "Skipping allowlisted package: $($pkg.Name)" "DEBUG"
                    break
                }
            }
            if (-not $pkgAllowed) {
                $filteredPackages += $pkg
            }
        }
        $packages = $filteredPackages
        
        foreach ($package in $packages) {
            if ($DryRun) {
                Write-Log "[DRY RUN] Would remove: $($package.Name)" "INFO"
                $removed++
            } else {
                try {
                    Write-Log "Removing: $($package.Name)" "INFO"
                    Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
                    
                    # Also remove provisioned package
                    $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $package.Name }
                    if ($provisioned) {
                        Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction SilentlyContinue
                    }
                    
                    Write-Log "Successfully removed: $($package.Name)" "SUCCESS"
                    $removed++
                    
                    # Record the change
                    $script:Changes += @{
                        Type = "App"
                        Action = "Removed"
                        Name = $package.Name
                        PackageFullName = $package.PackageFullName
                        Timestamp = Get-Date
                    }
                } catch {
                    Write-Log "Failed to remove $($package.Name): $_" "ERROR"
                    $failed++
                }
            }
        }
    }
    
    Write-Log "Bloatware removal completed. Removed: $removed, Failed: $failed" "INFO"
}

# Enhanced telemetry disabling
function Disable-Telemetry {
    param(
        [bool]$PreserveXboxServices = $false  # Set to true for Gaming profile
    )

    Write-Log "Disabling telemetry and data collection..." "INFO"

    # Backup registry before changes
    Backup-RegistryKey "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"

    # Disable telemetry services
    $telemetryServices = @(
        "DiagTrack",
        "dmwappushservice",
        "WMPNetworkSvc",
        "WerSvc",
        "OneSyncSvc",
        "MessagingService",
        "wercplsupport",
        "PcaSvc",
        "InstallService",
        "wisvc",
        "RetailDemo",
        "diagsvc",
        "shpamsvc",
        "TermService",
        "UmRdpService",
        "SessionEnv",
        "TroubleshootingSvc",
        "diagnosticshub.standardcollector.service",
        "AppVClient",
        "MsKeyboardFilter",
        "NetTcpPortSharing",
        "ssh-agent",
        "SensorDataService",
        "SensrSvc",
        "SensorService",
        "WalletService",
        "WdiServiceHost",
        "WdiSystemHost",
        "PhoneSvc",
        "WaaSMedicSvc",
        "WbioSrvc",
        "WinDefend",
        "WinHttpAutoProxySvc",
        "WinRM"
    )

    # Xbox services - only disable if NOT preserving for Gaming profile
    $xboxServices = @(
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "XboxNetApiSvc"
    )

    if (-not $PreserveXboxServices) {
        $telemetryServices += $xboxServices
    } else {
        Write-Log "Preserving Xbox services for Gaming profile" "INFO"
    }
    
    foreach ($service in $telemetryServices) {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable service: $service" "DEBUG"
        } else {
            try {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled service: $service" "SUCCESS"
            } catch {
                Write-Log "Failed to disable service ${service}: $_" "DEBUG"
            }
        }
    }
    
    # Disable telemetry in registry
    $telemetryKeys = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableInventory"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableUAR"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableSoftLanding"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name = "DisabledByGroupPolicy"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation"; Name = "Value"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowLocation"; Name = "Value"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry"; Name = "Value"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowSyncProviderNotifications"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowSyncProviderNotifications"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities"; Value = 0}
    )
    
    foreach ($key in $telemetryKeys) {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set registry: $($key.Path)\$($key.Name) = $($key.Value)" "DEBUG"
        } else {
            if (!(Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
            Write-Log "Set registry: $($key.Path)\$($key.Name) = $($key.Value)" "DEBUG"
        }
    }
    
    # Disable telemetry hosts
    $telemetryHosts = @(
        "vortex.data.microsoft.com",
        "vortex-win.data.microsoft.com",
        "telecommand.telemetry.microsoft.com",
        "telecommand.telemetry.microsoft.com.nsatc.net",
        "oca.telemetry.microsoft.com",
        "oca.telemetry.microsoft.com.nsatc.net",
        "sqm.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com.nsatc.net",
        "watson.telemetry.microsoft.com",
        "watson.telemetry.microsoft.com.nsatc.net",
        "redir.metaservices.microsoft.com",
        "choice.microsoft.com",
        "choice.microsoft.com.nsatc.net",
        "df.telemetry.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com",
        "wes.df.telemetry.microsoft.com",
        "services.wes.df.telemetry.microsoft.com",
        "sqm.df.telemetry.microsoft.com",
        "telemetry.microsoft.com",
        "watson.ppe.telemetry.microsoft.com",
        "telemetry.appex.bing.net",
        "telemetry.urs.microsoft.com",
        "telemetry.appex.bing.net:443",
        "settings-sandbox.data.microsoft.com",
        "vortex-sandbox.data.microsoft.com",
        "survey.watson.microsoft.com",
        "watson.live.com",
        "watson.microsoft.com",
        "statsfe2.update.microsoft.com.akadns.net",
        "sls.update.microsoft.com.akadns.net",
        "fe2.update.microsoft.com.akadns.net",
        "diagnostics.support.microsoft.com",
        "corp.sts.microsoft.com",
        "statsfe1.ws.microsoft.com",
        "pre.footprintpredict.com",
        "i1.services.social.microsoft.com",
        "i1.services.social.microsoft.com.nsatc.net",
        "feedback.windows.com",
        "feedback.microsoft-hohm.com",
        "feedback.search.microsoft.com",
        "rad.msn.com",
        "preview.msn.com",
        "ad.doubleclick.net",
        "ads.msn.com",
        "ads1.msads.net",
        "ads1.msn.com",
        "a.ads1.msn.com",
        "a.ads2.msn.com",
        "adnexus.net",
        "adnxs.com",
        "az361816.vo.msecnd.net",
        "az512334.vo.msecnd.net"
    )
    
    if (-not $DryRun) {
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        $currentHosts = Get-Content $hostsFile -ErrorAction SilentlyContinue
        
        # Add header if not present
        if ($currentHosts -notcontains "# Windows Telemetry Blocking") {
            Add-Content $hostsFile "`n# Windows Telemetry Blocking"
            Add-Content $hostsFile "# Added by Windows Crap Remover on $(Get-Date)"
        }
        
        foreach ($telemetryHost in $telemetryHosts) {
            $entry = "0.0.0.0 $telemetryHost"
            if ($currentHosts -notcontains $entry) {
                Add-Content $hostsFile $entry
            }
        }
        
        Write-Log "Added $($telemetryHosts.Count) telemetry hosts to block list" "SUCCESS"
    }
    
    # Disable scheduled telemetry tasks
    $telemetryTasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\DiskFootprint\Diagnostics",
        "\Microsoft\Windows\FileHistory\File History (maintenance mode)",
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\NetTrace\GatherNetworkInfo",
        "\Microsoft\Windows\PI\Sqm-Tasks",
        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser",
        "\Microsoft\Windows\Application Experience\AitAgent",
        "\Microsoft\Windows\Application Experience\PcaPatchDbTask",
        "\Microsoft\Windows\Application Experience\SdbinstMergeDbTask",
        "\Microsoft\Windows\Application Experience\StartupAppTask"
    )
    
    foreach ($task in $telemetryTasks) {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable task: $task" "DEBUG"
        } else {
            try {
                Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
                Write-Log "Disabled task: $task" "DEBUG"
            } catch {
                Write-Log "Failed to disable task ${task}: $_" "DEBUG"
            }
        }
    }
    
    Write-Log "Telemetry disabled successfully!" "SUCCESS"
}

# Function to optimize performance
function Optimize-Performance {
    Write-Log "Optimizing system performance..." "INFO"
    
    # Visual effects optimization
    if (-not $DryRun) {
        Backup-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
    }
    
    # Disable animations
    $animationKeys = @(
        @{Path = "HKCU:\Control Panel\Desktop"; Name = "MenuShowDelay"; Value = "0"},
        @{Path = "HKCU:\Control Panel\Desktop"; Name = "UserPreferencesMask"; Value = ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))},
        @{Path = "HKCU:\Control Panel\Desktop\WindowMetrics"; Name = "MinAnimate"; Value = "0"},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ListviewAlphaSelect"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarAnimations"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ListviewShadow"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\DWM"; Name = "AlwaysHibernateThumbnails"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\DWM"; Name = "EnableAeroPeek"; Value = 0}
    )
    
    foreach ($key in $animationKeys) {
        if (-not $DryRun) {
            if (!(Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
        }
        Write-Log "Set performance key: $($key.Path)\$($key.Name)" "DEBUG"
    }
    
    # Optimize services for performance
    $performanceServices = @(
        @{Name = "SysMain"; StartupType = "Disabled"},  # Superfetch
        @{Name = "WSearch"; StartupType = "Manual"},    # Windows Search
        @{Name = "FontCache"; StartupType = "Manual"},  # Font Cache
        @{Name = "Themes"; StartupType = "Manual"},     # Themes
        @{Name = "SysMain"; StartupType = "Disabled"}   # Prefetch
    )
    
    foreach ($service in $performanceServices) {
        if (-not $DryRun) {
            try {
                Set-Service -Name $service.Name -StartupType $service.StartupType -ErrorAction Stop
                Write-Log "Optimized service: $($service.Name) -> $($service.StartupType)" "DEBUG"
            } catch {
                Write-Log "Failed to optimize service $($service.Name): $_" "DEBUG"
            }
        }
    }
    
    # Disable background apps
    if (-not $DryRun) {
        Backup-RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Value 2 -Force
    }
    
    # Optimize virtual memory
    if (-not $DryRun) {
        try {
            # Disable automatic pagefile management using CIM
            $computerSystem = Get-CimInstance Win32_ComputerSystem
            Set-CimInstance -CimInstance $computerSystem -Property @{AutomaticManagedPagefile = $false} -ErrorAction SilentlyContinue
            Write-Log "Disabled automatic pagefile management" "DEBUG"
        } catch {
            Write-Log "Could not modify pagefile settings: $_" "DEBUG"
        }
    }
    
    Write-Log "Performance optimization completed!" "SUCCESS"
}

# Function to clean temporary files
function Clean-TempFiles {
    Write-Log "Cleaning temporary files..." "INFO"
    
    $tempPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\Prefetch",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\ThumbCacheToDelete",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
        "$env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*.default-release\cache2"
    )
    
    $totalSize = 0
    $cleaned = 0
    
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            try {
                $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                $pathSize = ($items | Measure-Object -Property Length -Sum).Sum
                $totalSize += $pathSize
                
                if (-not $DryRun) {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    $cleaned += $pathSize
                }
                
                $sizeMB = '{0:N2}' -f ($pathSize / 1MB)
                Write-Log "Cleaned: $path - $sizeMB MB" "DEBUG"
            } catch {
                Write-Log "Failed to clean $path : $_" "DEBUG"
            }
        }
    }
    
    # Clean Windows Update cache
    if (-not $DryRun) {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    }
    
    # Clean thumbnail cache
    if (-not $DryRun) {
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
        Start-Process explorer
    }
    
    $cleanedMB = '{0:N2}' -f ($cleaned / 1MB)
    Write-Log "Temp file cleanup completed! Cleaned $cleanedMB MB" "SUCCESS"
}

# Function to manage startup programs
function Manage-StartupPrograms {
    Write-Log "Managing startup programs..." "INFO"
    
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    $startupPrograms = @()
    
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $startupPrograms += @{
                    Name = $_.Name
                    Value = $_.Value
                    Path = $path
                }
            }
        }
    }
    
    Write-Host "`nCurrent Startup Programs:" -ForegroundColor Yellow
    $index = 1
    foreach ($program in $startupPrograms) {
        Write-Host "$index. $($program.Name): $($program.Value)" -ForegroundColor White
        $index++
    }
    
    if (-not $Silent -and -not $AutoMode) {
        Write-Host "`nEnter numbers to disable (comma-separated), or press Enter to skip:" -ForegroundColor Cyan
        $selection = Read-Host
        
        if ($selection) {
            $selections = $selection -split ',' | ForEach-Object { [int]$_.Trim() - 1 }
            
            foreach ($idx in $selections) {
                if ($idx -ge 0 -and $idx -lt $startupPrograms.Count) {
                    $program = $startupPrograms[$idx]
                    
                    if (-not $DryRun) {
                        Backup-RegistryKey $program.Path
                        Remove-ItemProperty -Path $program.Path -Name $program.Name -Force
                        Write-Log "Disabled startup program: $($program.Name)" "SUCCESS"
                    } else {
                        Write-Log "[DRY RUN] Would disable startup program: $($program.Name)" "INFO"
                    }
                }
            }
        }
    }
}

# Function to disable P2P Windows Update
function Disable-P2PUpdates {
    Write-Log "Disabling P2P Windows Updates..." "INFO"
    
    $p2pKeys = @(
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"; Name = "DODownloadMode"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization"; Name = "SystemSettingsDownloadMode"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"; Name = "DODownloadMode"; Value = 0}
    )
    
    foreach ($key in $p2pKeys) {
        if (-not $DryRun) {
            if (!(Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
        }
        Write-Log "Disabled P2P updates at: $($key.Path)" "DEBUG"
    }
    
    Write-Log "P2P Windows Updates disabled!" "SUCCESS"
}

# =============================================================================
# QUICK FIX FUNCTIONS - One-click solutions for common issues
# =============================================================================

function Fix-SlowBoot {
    <#
    .SYNOPSIS
    One-click fix for slow boot times
    #>
    Write-Host "`n  Fixing slow boot..." -ForegroundColor Cyan
    Write-Log "Running slow boot fix..." "INFO"

    # Disable startup programs that slow boot
    $slowStartupApps = @(
        "OneDrive", "Spotify", "Discord", "Steam", "EpicGamesLauncher",
        "Adobe", "Skype", "Teams", "Slack", "Zoom"
    )

    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )

    $disabled = 0
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -notlike "PS*") {
                    foreach ($slowApp in $slowStartupApps) {
                        if ($prop.Value -like "*$slowApp*") {
                            if (-not $DryRun) {
                                Remove-ItemProperty -Path $path -Name $prop.Name -Force -ErrorAction SilentlyContinue
                                $disabled++
                                Write-Log "Disabled startup: $($prop.Name)" "SUCCESS"
                            } else {
                                Write-Log "[DRY RUN] Would disable: $($prop.Name)" "INFO"
                                $disabled++
                            }
                        }
                    }
                }
            }
        }
    }

    # Disable fast startup issues (can cause problems)
    if (-not $DryRun) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
    }

    # Clean prefetch
    if (-not $DryRun) {
        Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue
    }

    Write-Host "  [OK] Disabled $disabled startup programs" -ForegroundColor Green
    Write-Host "  [OK] Cleaned prefetch cache" -ForegroundColor Green
    Write-Log "Slow boot fix completed! Disabled $disabled items." "SUCCESS"
}

function Fix-HighCPU {
    <#
    .SYNOPSIS
    One-click fix for high CPU usage
    #>
    Write-Host "`n  Fixing high CPU usage..." -ForegroundColor Cyan
    Write-Log "Running high CPU fix..." "INFO"

    # Services known to cause high CPU
    $cpuHogServices = @(
        "SysMain",           # Superfetch
        "DiagTrack",         # Telemetry
        "WSearch",           # Windows Search
        "wuauserv"           # Windows Update (temporarily)
    )

    foreach ($svc in $cpuHogServices) {
        if (-not $DryRun) {
            try {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Manual -ErrorAction SilentlyContinue
                Write-Host "  [OK] Stopped and set to Manual: $svc" -ForegroundColor Green
            } catch {
                Write-Host "  [!] Could not modify: $svc" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [DRY RUN] Would stop: $svc" -ForegroundColor Yellow
        }
    }

    # Kill known CPU hog processes
    $cpuHogProcesses = @("SearchIndexer", "MsMpEng", "WmiPrvSE")
    foreach ($proc in $cpuHogProcesses) {
        if (-not $DryRun) {
            Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Log "High CPU fix completed!" "SUCCESS"
}

function Fix-DiskSpace {
    <#
    .SYNOPSIS
    One-click fix for disk space issues
    #>
    Write-Host "`n  Fixing disk space issues..." -ForegroundColor Cyan
    Write-Log "Running disk space fix..." "INFO"

    $totalCleaned = 0

    # Clean temp files
    $tempPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\SoftwareDistribution\Download",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    )

    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            $size = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            if (-not $DryRun) {
                Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
            $totalCleaned += $size
        }
    }

    # Clear Windows Update cache
    if (-not $DryRun) {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    }

    # Clear thumbnail cache
    if (-not $DryRun) {
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    }

    # Run Windows Disk Cleanup silently
    if (-not $DryRun) {
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/d C: /sagerun:1" -WindowStyle Hidden -ErrorAction SilentlyContinue
    }

    $cleanedMB = [math]::Round($totalCleaned / 1MB, 2)
    Write-Host "  [OK] Cleaned approximately $cleanedMB MB" -ForegroundColor Green
    Write-Log "Disk space fix completed! Cleaned $cleanedMB MB" "SUCCESS"
}

function Fix-Privacy {
    <#
    .SYNOPSIS
    One-click privacy fix
    #>
    Write-Host "`n  Applying privacy fixes..." -ForegroundColor Cyan
    Write-Log "Running privacy fix..." "INFO"

    # Quick privacy registry fixes
    $privacyFixes = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name = "DisabledByGroupPolicy"; Value = 1},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackProgs"; Value = 0}
    )

    foreach ($fix in $privacyFixes) {
        if (-not $DryRun) {
            if (!(Test-Path $fix.Path)) {
                New-Item -Path $fix.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $fix.Path -Name $fix.Name -Value $fix.Value -Force -ErrorAction SilentlyContinue
        }
    }

    # Clear activity history
    if (-not $DryRun) {
        Remove-Item -Path "$env:LOCALAPPDATA\ConnectedDevicesPlatform\*" -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "  [OK] Disabled advertising ID" -ForegroundColor Green
    Write-Host "  [OK] Disabled telemetry" -ForegroundColor Green
    Write-Host "  [OK] Cleared activity history" -ForegroundColor Green
    Write-Log "Privacy fix completed!" "SUCCESS"
}

function Show-QuickFixMenu {
    <#
    .SYNOPSIS
    Shows the Quick Fix menu with one-click solutions
    #>
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                      QUICK FIX                                 ║" -ForegroundColor Yellow
    Write-Host "║              One-Click Solutions for Common Issues             ║" -ForegroundColor DarkGray
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  1.  Fix Slow Boot         - Disable startup bloat             ║" -ForegroundColor White
    Write-Host "║  2.  Fix High CPU          - Stop resource hogs                ║" -ForegroundColor White
    Write-Host "║  3.  Fix Disk Space        - Clean temp & cache files          ║" -ForegroundColor White
    Write-Host "║  4.  Fix Privacy           - Disable tracking & telemetry      ║" -ForegroundColor White
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  A.  FIX ALL               - Run all fixes above               ║" -ForegroundColor Green
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  0.  Back to Main Menu                                         ║" -ForegroundColor Red
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $choice = Read-Host "  Select fix"

    switch ($choice.ToUpper()) {
        '1' { Fix-SlowBoot; Read-Host "`n  Press Enter to continue" }
        '2' { Fix-HighCPU; Read-Host "`n  Press Enter to continue" }
        '3' { Fix-DiskSpace; Read-Host "`n  Press Enter to continue" }
        '4' { Fix-Privacy; Read-Host "`n  Press Enter to continue" }
        'A' {
            Write-Host "`n  Running ALL fixes..." -ForegroundColor Green
            Fix-SlowBoot
            Fix-HighCPU
            Fix-DiskSpace
            Fix-Privacy
            Write-Host "`n  ========================================" -ForegroundColor Green
            Write-Host "  ALL FIXES COMPLETED!" -ForegroundColor Green
            Write-Host "  ========================================" -ForegroundColor Green
            Read-Host "`n  Press Enter to continue"
        }
    }
}

# =============================================================================
# WINDOWS STORE REPAIR FUNCTIONALITY
# =============================================================================

function Repair-WindowsStore {
    <#
    .SYNOPSIS
    Repairs Windows Store and related components
    #>
    Write-Host "`n  Repairing Windows Store..." -ForegroundColor Cyan
    Write-Log "Starting Windows Store repair..." "INFO"

    if ($DryRun) {
        Write-Host "  [DRY RUN] Would repair Windows Store" -ForegroundColor Yellow
        Write-Log "[DRY RUN] Would repair Windows Store" "INFO"
        return
    }

    $steps = 0
    $totalSteps = 5

    # Step 1: Clear Windows Store cache
    $steps++
    Write-Host "  [$steps/$totalSteps] Clearing Windows Store cache..." -ForegroundColor White
    try {
        Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue
        # Run wsreset silently
        Start-Process "wsreset.exe" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-Host "      [OK] Cache cleared" -ForegroundColor Green
    } catch {
        Write-Host "      [!] Could not clear cache: $_" -ForegroundColor Yellow
    }

    # Step 2: Re-register Windows Store
    $steps++
    Write-Host "  [$steps/$totalSteps] Re-registering Windows Store..." -ForegroundColor White
    try {
        $manifest = (Get-AppxPackage Microsoft.WindowsStore).InstallLocation + "\AppxManifest.xml"
        Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction Stop
        Write-Host "      [OK] Store re-registered" -ForegroundColor Green
    } catch {
        Write-Host "      [!] Could not re-register: $_" -ForegroundColor Yellow
    }

    # Step 3: Reset Windows Store app
    $steps++
    Write-Host "  [$steps/$totalSteps] Resetting Windows Store app..." -ForegroundColor White
    try {
        Get-AppxPackage -AllUsers Microsoft.WindowsStore | ForEach-Object {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
        }
        Write-Host "      [OK] Store app reset" -ForegroundColor Green
    } catch {
        Write-Host "      [!] Could not reset app: $_" -ForegroundColor Yellow
    }

    # Step 4: Repair Windows Store dependencies
    $steps++
    Write-Host "  [$steps/$totalSteps] Repairing Store dependencies..." -ForegroundColor White
    try {
        # Re-register store purchase app
        Get-AppxPackage -AllUsers Microsoft.StorePurchaseApp | ForEach-Object {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
        }
        # Re-register Xbox Identity (needed for game installs)
        Get-AppxPackage -AllUsers Microsoft.XboxIdentityProvider | ForEach-Object {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
        }
        Write-Host "      [OK] Dependencies repaired" -ForegroundColor Green
    } catch {
        Write-Host "      [!] Could not repair dependencies: $_" -ForegroundColor Yellow
    }

    # Step 5: Restart Windows Store service
    $steps++
    Write-Host "  [$steps/$totalSteps] Restarting Store services..." -ForegroundColor White
    try {
        Restart-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Start-Service -Name "InstallService" -ErrorAction SilentlyContinue
        Write-Host "      [OK] Services restarted" -ForegroundColor Green
    } catch {
        Write-Host "      [!] Could not restart services: $_" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  Windows Store repair completed!" -ForegroundColor Green
    Write-Host "  Note: You may need to restart your PC for all changes to take effect." -ForegroundColor Yellow
    Write-Log "Windows Store repair completed" "SUCCESS"
}

# =============================================================================
# DRIVER CLEANUP FUNCTIONALITY
# =============================================================================

function Clean-OldDrivers {
    <#
    .SYNOPSIS
    Removes old/unused driver packages from the driver store
    #>
    Write-Host "`n  Cleaning old driver packages..." -ForegroundColor Cyan
    Write-Log "Starting driver cleanup..." "INFO"

    if ($DryRun) {
        Write-Host "  [DRY RUN] Would clean old drivers" -ForegroundColor Yellow
        Write-Log "[DRY RUN] Would clean old drivers" "INFO"
    }

    # Get all third-party drivers
    Write-Host "  Scanning driver store..." -ForegroundColor White

    try {
        $drivers = Get-WindowsDriver -Online -All | Where-Object {
            $_.Driver -like "oem*.inf" -and $_.OriginalFileName -notlike "*windows*"
        }

        if ($drivers.Count -eq 0) {
            Write-Host "  No old drivers found to clean." -ForegroundColor Green
            return
        }

        # Group by class to find duplicates
        $driverGroups = $drivers | Group-Object -Property ClassName

        $totalCleaned = 0
        $totalSize = 0

        foreach ($group in $driverGroups) {
            # Sort by version and date, keep newest
            $sortedDrivers = $group.Group | Sort-Object -Property @{Expression={[version]$_.Version}; Descending=$true}, Date -Descending

            # Skip the newest one, mark others for removal
            $oldDrivers = $sortedDrivers | Select-Object -Skip 1

            foreach ($driver in $oldDrivers) {
                if ($DryRun) {
                    Write-Host "  [DRY RUN] Would remove: $($driver.Driver) - $($driver.ProviderName) v$($driver.Version)" -ForegroundColor Yellow
                    $totalCleaned++
                } else {
                    try {
                        # Use pnputil to remove old driver
                        $result = & pnputil /delete-driver $driver.Driver /force 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "  [OK] Removed: $($driver.Driver) - $($driver.ProviderName)" -ForegroundColor Green
                            $totalCleaned++
                        }
                    } catch {
                        Write-Log "Could not remove driver $($driver.Driver): $_" "DEBUG"
                    }
                }
            }
        }

        Write-Host ""
        Write-Host "  Driver cleanup completed!" -ForegroundColor Green
        Write-Host "  Removed $totalCleaned old driver package(s)" -ForegroundColor Cyan
        Write-Log "Driver cleanup completed. Removed $totalCleaned packages." "SUCCESS"

    } catch {
        Write-Host "  [!] Error scanning drivers: $_" -ForegroundColor Red
        Write-Log "Driver cleanup failed: $_" "ERROR"
    }
}

function Show-DriverInfo {
    <#
    .SYNOPSIS
    Shows information about installed drivers
    #>
    Write-Host "`n  Driver Information" -ForegroundColor Cyan
    Write-Host "  ==================" -ForegroundColor Cyan

    try {
        $drivers = Get-WindowsDriver -Online -All | Where-Object { $_.Driver -like "oem*.inf" }

        $grouped = $drivers | Group-Object -Property ClassName | Sort-Object -Property Count -Descending

        Write-Host ""
        Write-Host "  Driver packages by category:" -ForegroundColor White
        Write-Host ""

        foreach ($group in $grouped | Select-Object -First 10) {
            $count = $group.Count
            $name = if ($group.Name) { $group.Name } else { "Unknown" }
            Write-Host "    $name" -ForegroundColor Yellow -NoNewline
            Write-Host ": $count package(s)" -ForegroundColor Gray
        }

        $totalCount = $drivers.Count
        Write-Host ""
        Write-Host "  Total third-party driver packages: $totalCount" -ForegroundColor Cyan

    } catch {
        Write-Host "  [!] Could not retrieve driver information: $_" -ForegroundColor Red
    }
}

# =============================================================================
# SCHEDULED MAINTENANCE
# =============================================================================

function Enable-ScheduledMaintenance {
    <#
    .SYNOPSIS
    Creates a scheduled task for automatic maintenance
    #>
    Write-Host "`n  Setting up scheduled maintenance..." -ForegroundColor Cyan
    Write-Log "Setting up scheduled maintenance..." "INFO"

    if ($DryRun) {
        Write-Host "  [DRY RUN] Would create scheduled maintenance task" -ForegroundColor Yellow
        return
    }

    $taskName = "WindowsCrapRemover_Maintenance"
    $scriptPath = $PSCommandPath

    # Check if task already exists
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

    if ($existingTask) {
        Write-Host "  Scheduled task already exists." -ForegroundColor Yellow
        $choice = Read-Host "  Update existing task? (Y/N)"
        if ($choice -ne 'Y' -and $choice -ne 'y') {
            return
        }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    try {
        # Create action - run cleanup weekly
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -FixDisk -FixPrivacy -Silent"

        # Create trigger - weekly on Sunday at 3 AM
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3AM

        # Create settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false

        # Create principal (run as SYSTEM with highest privileges)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # Register the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Weekly system maintenance by Windows Crap Remover"

        Write-Host ""
        Write-Host "  [OK] Scheduled maintenance task created!" -ForegroundColor Green
        Write-Host "  Task: $taskName" -ForegroundColor White
        Write-Host "  Schedule: Every Sunday at 3:00 AM" -ForegroundColor White
        Write-Host "  Actions: Clean temp files, Apply privacy fixes" -ForegroundColor White
        Write-Log "Scheduled maintenance task created" "SUCCESS"

    } catch {
        Write-Host "  [!] Failed to create scheduled task: $_" -ForegroundColor Red
        Write-Log "Failed to create scheduled task: $_" "ERROR"
    }
}

function Disable-ScheduledMaintenance {
    <#
    .SYNOPSIS
    Removes the scheduled maintenance task
    #>
    $taskName = "WindowsCrapRemover_Maintenance"

    try {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

        if ($existingTask) {
            if (-not $DryRun) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            Write-Host "  [OK] Scheduled maintenance task removed" -ForegroundColor Green
            Write-Log "Scheduled maintenance task removed" "SUCCESS"
        } else {
            Write-Host "  No scheduled maintenance task found" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [!] Failed to remove scheduled task: $_" -ForegroundColor Red
    }
}

# =============================================================================
# PORTABLE VERSION GENERATOR
# =============================================================================

function New-PortableVersion {
    <#
    .SYNOPSIS
    Creates a portable version of the script with embedded config
    #>
    Write-Host "`n  Creating portable version..." -ForegroundColor Cyan
    Write-Log "Creating portable version..." "INFO"

    $outputDir = Read-Host "  Enter output directory (or press Enter for Desktop)"

    if ([string]::IsNullOrWhiteSpace($outputDir)) {
        $outputDir = [Environment]::GetFolderPath("Desktop")
    }

    if (-not (Test-Path $outputDir)) {
        Write-Host "  [!] Directory does not exist: $outputDir" -ForegroundColor Red
        return
    }

    $timestamp = Get-Date -Format "yyyyMMdd"
    $portableName = "WCrapware_Portable_$timestamp.ps1"
    $portablePath = Join-Path $outputDir $portableName

    try {
        # Read current script
        $scriptContent = Get-Content -Path $PSCommandPath -Raw

        # Add portable header
        $portableHeader = @"
# ============================================================================
# WINDOWS CRAP REMOVER - PORTABLE VERSION
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# This is a standalone portable version with no external dependencies
# ============================================================================

"@

        # Embed current allowlist/denylist if they exist
        $embeddedConfig = ""

        if (Test-Path $script:AllowlistPath) {
            $allowlistContent = Get-Content $script:AllowlistPath -Raw -ErrorAction SilentlyContinue
            if ($allowlistContent) {
                $embeddedConfig += @"

# Embedded Allowlist
`$script:EmbeddedAllowlist = @'
$allowlistContent
'@

"@
            }
        }

        if (Test-Path $script:DenylistPath) {
            $denylistContent = Get-Content $script:DenylistPath -Raw -ErrorAction SilentlyContinue
            if ($denylistContent) {
                $embeddedConfig += @"

# Embedded Denylist
`$script:EmbeddedDenylist = @'
$denylistContent
'@

"@
            }
        }

        # Write portable version
        $portableContent = $portableHeader + $embeddedConfig + $scriptContent
        $portableContent | Out-File -FilePath $portablePath -Encoding UTF8 -Force

        Write-Host ""
        Write-Host "  [OK] Portable version created!" -ForegroundColor Green
        Write-Host "  Location: $portablePath" -ForegroundColor White
        Write-Host "  Size: $([math]::Round((Get-Item $portablePath).Length / 1KB, 2)) KB" -ForegroundColor White
        Write-Log "Portable version created at $portablePath" "SUCCESS"

    } catch {
        Write-Host "  [!] Failed to create portable version: $_" -ForegroundColor Red
        Write-Log "Failed to create portable version: $_" "ERROR"
    }
}

# =============================================================================
# TOOLS MENU
# =============================================================================

function Show-ToolsMenu {
    <#
    .SYNOPSIS
    Shows the additional tools menu
    #>
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                      ADDITIONAL TOOLS                          ║" -ForegroundColor Yellow
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  REPAIR                                                        ║" -ForegroundColor Magenta
    Write-Host "║  1.  Repair Windows Store        - Fix Store issues            ║" -ForegroundColor White
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  DRIVERS                                                       ║" -ForegroundColor Magenta
    Write-Host "║  2.  Show Driver Info            - List installed drivers      ║" -ForegroundColor White
    Write-Host "║  3.  Clean Old Drivers           - Remove unused drivers       ║" -ForegroundColor White
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  MAINTENANCE                                                   ║" -ForegroundColor Magenta
    Write-Host "║  4.  Enable Auto-Maintenance     - Weekly scheduled cleanup    ║" -ForegroundColor White
    Write-Host "║  5.  Disable Auto-Maintenance    - Remove scheduled task       ║" -ForegroundColor White
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  EXPORT                                                        ║" -ForegroundColor Magenta
    Write-Host "║  6.  Create Portable Version     - Standalone script           ║" -ForegroundColor White
    Write-Host "║                                                                ║" -ForegroundColor Cyan
    Write-Host "║  0.  Back to Main Menu                                         ║" -ForegroundColor Red
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $choice = Read-Host "  Select option"

    switch ($choice) {
        '1' { Repair-WindowsStore; Read-Host "`n  Press Enter to continue" }
        '2' { Show-DriverInfo; Read-Host "`n  Press Enter to continue" }
        '3' { Clean-OldDrivers; Read-Host "`n  Press Enter to continue" }
        '4' { Enable-ScheduledMaintenance; Read-Host "`n  Press Enter to continue" }
        '5' { Disable-ScheduledMaintenance; Read-Host "`n  Press Enter to continue" }
        '6' { New-PortableVersion; Read-Host "`n  Press Enter to continue" }
    }
}

# Enhanced privacy settings
function Enhance-Privacy {
    Write-Log "Enhancing privacy settings..." "INFO"
    
    # Disable activity tracking
    $privacyKeys = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableActivityFeed"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackProgs"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackDocs"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat"; Name = "Value"; Value = "Deny"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"; Name = "Value"; Value = "Deny"}
    )
    
    foreach ($key in $privacyKeys) {
        if (-not $DryRun) {
            if (!(Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
        }
        Write-Log "Set privacy setting: $($key.Path)\$($key.Name)" "DEBUG"
    }
    
    # Disable WiFi Sense
    if (-not $DryRun) {
        $wifiSensePath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        if (!(Test-Path $wifiSensePath)) {
            New-Item -Path $wifiSensePath -Force | Out-Null
        }
        Set-ItemProperty -Path $wifiSensePath -Name "AutoConnectAllowedOEM" -Value 0 -Force
        Set-ItemProperty -Path $wifiSensePath -Name "WiFISenseAllowed" -Value 0 -Force
    }
    
    # Clear activity history
    if (-not $DryRun) {
        Remove-Item -Path "$env:LOCALAPPDATA\ConnectedDevicesPlatform\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\History\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Write-Log "Privacy enhancements completed!" "SUCCESS"
}

# Function to save changes log
function Save-ChangesLog {
    $logPath = Join-Path $script:BackupPath "changes.json"
    $script:Changes | ConvertTo-Json -Depth 10 | Out-File -FilePath $logPath -Force
    Write-Log "Changes log saved to: $logPath" "INFO"
}

# Function to undo changes
function Undo-Changes {
    Write-Host "`nAvailable backups:" -ForegroundColor Yellow
    
    $backups = Get-ChildItem -Path "$env:LOCALAPPDATA\WindowsCrapRemover\Backups" -Directory | Sort-Object Name -Descending
    
    if ($backups.Count -eq 0) {
        Write-Log "No backups found!" "WARNING"
        return
    }
    
    $index = 1
    foreach ($backup in $backups) {
        Write-Host "$index. $($backup.Name)" -ForegroundColor White
        $index++
    }
    
    $selection = Read-Host "`nSelect backup to restore (number)"
    
    if ($selection -match '^\d+$' -and [int]$selection -le $backups.Count) {
        $selectedBackup = $backups[[int]$selection - 1]
        $changesFile = Join-Path $selectedBackup.FullName "changes.json"
        
        if (Test-Path $changesFile) {
            $changes = Get-Content $changesFile | ConvertFrom-Json
            
            Write-Log "Restoring from backup: $($selectedBackup.Name)" "INFO"
            
            foreach ($change in $changes) {
                switch ($change.Type) {
                    "Registry" {
                        if (Test-Path $change.BackupFile) {
                            reg import $change.BackupFile /y | Out-Null
                            Write-Log "Restored registry: $($change.Path)" "SUCCESS"
                        }
                    }
                    "App" {
                        Write-Log "Note: Cannot automatically restore removed app: $($change.Name)" "WARNING"
                        Write-Log "Please reinstall from Microsoft Store if needed" "INFO"
                    }
                }
            }
            
            Write-Log "Restore completed!" "SUCCESS"
        } else {
            Write-Log "No changes file found in backup!" "ERROR"
        }
    }
}

# Enhanced Remove-OneDrive function
function Remove-OneDrive {
    Write-Log "Removing OneDrive..." "INFO"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would remove OneDrive" "INFO"
        return
    }
    
    # Stop OneDrive process
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    
    # Uninstall OneDrive
    if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
        & "$env:SystemRoot\System32\OneDriveSetup.exe" /uninstall
    }
    elseif (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
        & "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall
    }
    
    # Remove OneDrive leftovers
    $onedriveDirectories = @(
        "$env:UserProfile\OneDrive",
        "$env:LocalAppData\Microsoft\OneDrive",
        "$env:ProgramData\Microsoft OneDrive",
        "C:\OneDriveTemp"
    )
    
    foreach ($dir in $onedriveDirectories) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Force -Recurse -ErrorAction SilentlyContinue
            Write-Log "Removed: $dir" "DEBUG"
        }
    }
    
    # Remove OneDrive from Explorer
    $explorerKeys = @(
        "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    )
    
    foreach ($key in $explorerKeys) {
        if (Test-Path $key) {
            Backup-RegistryKey $key
            Set-ItemProperty -Path $key -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force
        }
    }
    
    # Remove run hook
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
    
    Write-Log "OneDrive removed successfully!" "SUCCESS"
}

# Enhanced Disable-Cortana function
function Disable-Cortana {
    Write-Log "Disabling Cortana..." "INFO"
    
    $cortanaPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana"
    )
    
    foreach ($path in $cortanaPaths) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        if (-not $DryRun) {
            Backup-RegistryKey $path
            Set-ItemProperty -Path $path -Name "AllowCortana" -Value 0 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $path -Name "BingSearchEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $path -Name "CortanaConsent" -Value 0 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $path -Name "AllowSearchToUseLocation" -Value 0 -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Disable Cortana process
    Get-Process -Name "Cortana" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Rename Cortana folder (prevents it from running)
    if (-not $DryRun) {
        $cortanaPath = "$env:SystemRoot\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy"
        if (Test-Path $cortanaPath) {
            Rename-Item -Path $cortanaPath -NewName "Microsoft.Windows.Cortana_cw5n1h2txyewy.bak" -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Log "Cortana disabled successfully!" "SUCCESS"
}

# Function to disable Windows Defender
function Disable-WindowsDefender {
    Write-Log "WARNING: Disabling Windows Defender will leave your system vulnerable!" "WARNING"
    
    if (-not $Silent -and -not $AutoMode) {
        $confirm = Read-Host "Are you absolutely sure you want to disable Windows Defender? (type 'YES' to confirm)"
        if ($confirm -ne "YES") {
            Write-Log "Windows Defender disable cancelled." "INFO"
            return
        }
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would disable Windows Defender" "INFO"
        return
    }
    
    # Disable Windows Defender via Group Policy
    $defenderKeys = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "SpynetReporting"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"; Name = "SubmitSamplesConsent"; Value = 2}
    )
    
    foreach ($key in $defenderKeys) {
        if (!(Test-Path $key.Path)) {
            New-Item -Path $key.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
    }
    
    # Disable Windows Defender services
    $defenderServices = @(
        "WdNisSvc",
        "WinDefend",
        "Sense",
        "SecurityHealthService"
    )
    
    foreach ($service in $defenderServices) {
        try {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled service: $service" "SUCCESS"
        } catch {
            Write-Log "Failed to disable service ${service}: $_" "DEBUG"
        }
    }

    Write-Log "Windows Defender disabled!" "WARNING"
}

# Enhanced Clean-ScheduledTasks function
function Clean-ScheduledTasks {
    Write-Log "Cleaning up scheduled tasks..." "INFO"
    
    $tasksToDisable = @(
        "\Microsoft\Windows\AppID\SmartScreenSpecific",
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskCleanup\SilentCleanup",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\DiskFootprint\Diagnostics",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\FileHistory\File History (maintenance mode)",
        "\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures",
        "\Microsoft\Windows\InstallService\ScanForUpdates",
        "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser",
        "\Microsoft\Windows\InstallService\SmartRetry",
        "\Microsoft\Windows\LanguageComponentsInstaller\Installation",
        "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources",
        "\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation",
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\Management\Provisioning\Cellular",
        "\Microsoft\Windows\Management\Provisioning\Logon",
        "\Microsoft\Windows\Maps\MapsToastTask",
        "\Microsoft\Windows\Maps\MapsUpdateTask",
        "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser",
        "\Microsoft\Windows\NetTrace\GatherNetworkInfo",
        "\Microsoft\Windows\Offline Files\Background Synchronization",
        "\Microsoft\Windows\Offline Files\Logon Synchronization",
        "\Microsoft\Windows\PI\Sqm-Tasks",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "\Microsoft\Windows\Ras\MobilityManager",
        "\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE",
        "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask",
        "\Microsoft\Windows\RetailDemo\CleanupOfflineContent",
        "\Microsoft\Windows\SettingSync\BackgroundUploadTask",
        "\Microsoft\Windows\SettingSync\BackupTask",
        "\Microsoft\Windows\SettingSync\NetworkStateChangeTask",
        "\Microsoft\Windows\Setup\SetupCleanupTask",
        "\Microsoft\Windows\Setup\SnapshotCleanupTask",
        "\Microsoft\Windows\Shell\FamilySafetyMonitor",
        "\Microsoft\Windows\Shell\FamilySafetyRefresh",
        "\Microsoft\Windows\Shell\FamilySafetyUpload",
        "\Microsoft\Windows\SpacePort\SpaceAgentTask",
        "\Microsoft\Windows\SpacePort\SpaceManagerTask",
        "\Microsoft\Windows\Speech\SpeechModelDownloadTask",
        "\Microsoft\Windows\UpdateOrchestrator\Report policies",
        "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
        "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task",
        "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask",
        "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
        "\Microsoft\Windows\UPnP\UPnPHostConfig",
        "\Microsoft\Windows\User Profile Service\HiveUploadTask",
        "\Microsoft\Windows\WDI\ResolutionHost",
        "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
        "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
        "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
        "\Microsoft\Windows\Windows Defender\Windows Defender Verification",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange",
        "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary",
        "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
        "\Microsoft\Windows\WOF\WIM-Hash-Management",
        "\Microsoft\Windows\WOF\WIM-Hash-Validation",
        "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization",
        "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"
    )
    
    $disabled = 0
    $failed = 0
    
    foreach ($task in $tasksToDisable) {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable task: $task" "DEBUG"
            $disabled++
        } else {
            try {
                Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
                Write-Log "Disabled task: $task" "DEBUG"
                $disabled++
            } catch {
                Write-Log "Failed to disable task ${task}: $_" "DEBUG"
                $failed++
            }
        }
    }

    Write-Log "Scheduled task cleanup completed! Disabled: $disabled, Failed: $failed" "SUCCESS"
}

# Enhanced Disable-WindowsSearch function
function Disable-WindowsSearch {
    Write-Log "Disabling Windows Search and Indexing..." "INFO"
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would disable Windows Search" "INFO"
        return
    }
    
    try {
        # Stop and disable search service
        Stop-Service -Name "WSearch" -Force -ErrorAction Stop
        Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction Stop
        Write-Log "Windows Search service disabled!" "SUCCESS"
        
        # Disable indexing
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingService" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -Force
        
        # Clear search index
        Remove-Item -Path "$env:ProgramData\Microsoft\Search\Data\*" -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Log "Windows Search and Indexing disabled!" "SUCCESS"
    } catch {
        Write-Log "Failed to disable Windows Search: $_" "ERROR"
    }
}

# Enhanced Remove-Edge function
function Remove-Edge {
    if (!$IsWindows11) {
        Write-Log "Edge removal is only available for Windows 11" "WARNING"
        return
    }
    
    Write-Log "Removing Microsoft Edge..." "WARNING"
    Write-Log "WARNING: This may break some Windows features!" "WARNING"
    
    if (-not $Silent -and -not $AutoMode) {
        $confirm = Read-Host "Are you absolutely sure? (type 'YES' to confirm)"
        if ($confirm -ne "YES") {
            Write-Log "Edge removal cancelled." "INFO"
            return
        }
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would remove Microsoft Edge" "INFO"
        return
    }
    
    # Stop Edge processes
    Get-Process -Name "MicrosoftEdge*" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "Edge*" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "msedge*" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    # Remove Edge via PowerShell
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "*MicrosoftEdge*"} | ForEach-Object {
        try {
            Remove-AppxPackage -Package $_.PackageFullName -AllUsers
            Write-Log "Removed Edge package: $($_.Name)" "SUCCESS"
        } catch {
            Write-Log "Failed to remove Edge package: $($_.Name)" "ERROR"
        }
    }
    
    # Remove Edge directories
    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeCore",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView",
        "$env:ProgramFiles\Microsoft\Edge",
        "$env:LocalAppData\Microsoft\Edge",
        "$env:ProgramData\Microsoft\Edge",
        "$env:UserProfile\MicrosoftEdgeBackups"
    )
    
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Log "Removed: $path" "SUCCESS"
            } catch {
                Write-Log "Failed to remove: $path" "ERROR"
            }
        }
    }
    
    # Prevent Edge reinstallation
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -Force
    
    # Remove Edge shortcuts
    Remove-Item -Path "$env:Public\Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
    
    Write-Log "Edge removal completed!" "SUCCESS"
}

# =============================================================================
# COMMAND-LINE QUICK FIX HANDLING
# =============================================================================

# Handle Quick Fix command-line switches (run and exit)
if ($FixBoot -or $FixCPU -or $FixDisk -or $FixPrivacy -or $FixAll) {
    Write-Host ""
    Write-Host "  Windows Crap Remover - Quick Fix Mode" -ForegroundColor Cyan
    Write-Host "  =====================================" -ForegroundColor Cyan
    Write-Host ""

    if ($FixAll -or $FixBoot) { Fix-SlowBoot }
    if ($FixAll -or $FixCPU) { Fix-HighCPU }
    if ($FixAll -or $FixDisk) { Fix-DiskSpace }
    if ($FixAll -or $FixPrivacy) { Fix-Privacy }

    Write-Host ""
    Write-Host "  Quick Fix completed!" -ForegroundColor Green
    Write-Host ""
    exit 0
}

# Handle QuickStart command-line switch
if ($QuickStart) {
    Start-QuickStart
    exit 0
}

# Main execution logic
if ($Profile) {
    if ($Profiles.ContainsKey($Profile)) {
        $config = $Profiles[$Profile]
        Write-Log "Loading profile: $Profile" "INFO"
    } else {
        Write-Log "Invalid profile: $Profile" "ERROR"
        Write-Log "Available profiles: $($Profiles.Keys -join ', ')" "INFO"
        exit
    }
} elseif ($ConfigFile) {
    $config = Load-Configuration -ConfigFile $ConfigFile
} else {
    $config = Load-Configuration -ConfigFile ""
}

# Create restore point if not in dry run mode
if (-not $DryRun) {
    Create-SystemRestorePoint -Description "Windows Crap Remover - Before Changes"
}

# Auto mode execution
if ($AutoMode) {
    Write-Log "Running in AUTO MODE - Applying configuration..." "WARNING"
    
    if ($config.RemoveApps) {
        $appLists = Load-AppLists
        Remove-Bloatware -SafeModeEnabled $SafeMode -CustomAllowlist $appLists.Allowlist -CustomDenylist $appLists.Denylist
    }
    
    if ($config.DisableTelemetry) { Disable-Telemetry }
    if ($config.RemoveOneDrive) { Remove-OneDrive }
    if ($config.DisableCortana) { Disable-Cortana }
    if ($config.CleanScheduledTasks) { Clean-ScheduledTasks }
    if ($config.DisableWindowsSearch) { Disable-WindowsSearch }
    if ($config.OptimizePerformance) { Optimize-Performance }
    if ($config.EnhancePrivacy) { Enhance-Privacy }
    if ($config.CleanupNetwork) { Disable-P2PUpdates }
    if ($config.ManageStartup) { Manage-StartupPrograms }
    if ($config.CleanTempFiles) { Clean-TempFiles }
    if ($config.DisableDefender) { Disable-WindowsDefender }
    
    if ($IsWindows11 -and $config.RemoveEdge) {
        Remove-Edge
    }
    
    # Save changes log
    Save-ChangesLog
} else {
    # Interactive mode
    do {
        Show-MainMenu
        $choice = Read-Host "Enter your choice"
        
        switch ($choice) {
            '1' {
                # Quick Actions submenu
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                     QUICK ACTIONS                              ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ 1. Remove ALL bloatware (Aggressive)                           ║" -ForegroundColor White
                Write-Host "║ 2. Remove bloatware (Safe mode)                                ║" -ForegroundColor White
                Write-Host "║ 3. Disable ALL telemetry                                       ║" -ForegroundColor White
                Write-Host "║ 4. Apply Gaming Profile                                        ║" -ForegroundColor White
                Write-Host "║ 5. Apply Privacy Profile                                       ║" -ForegroundColor White
                Write-Host "║ 6. Apply Work Profile                                          ║" -ForegroundColor White
                Write-Host "║ 7. Apply Ultimate Profile (Everything)                         ║" -ForegroundColor Yellow
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' { 
                        $appLists = Load-AppLists
                        Remove-Bloatware -SafeModeEnabled $false -CustomAllowlist $appLists.Allowlist -CustomDenylist $appLists.Denylist
                    }
                    '2' { 
                        $appLists = Load-AppLists
                        Remove-Bloatware -SafeModeEnabled $true -CustomAllowlist $appLists.Allowlist -CustomDenylist $appLists.Denylist
                    }
                    '3' { Disable-Telemetry }
                    '4' {
                        $config = $Profiles["Gaming"]
                        Write-Log "Applying Gaming Profile..." "INFO"
                        # Use global gaming allowlist
                        $appLists = Load-AppLists
                        $combinedAllowlist = $appLists.Allowlist + $script:GamingAllowlist
                        if ($config.RemoveApps) { Remove-Bloatware -SafeModeEnabled $true -CustomAllowlist $combinedAllowlist -CustomDenylist $appLists.Denylist -IncludeXboxBloatware $false }
                        if ($config.DisableTelemetry) { Disable-Telemetry -PreserveXboxServices $true }
                        if ($config.OptimizePerformance) { Optimize-Performance }
                        if ($config.CleanupNetwork) { Disable-P2PUpdates }
                        if ($config.ManageStartup) { Manage-StartupPrograms }
                    }
                    '5' {
                        $config = $Profiles["Privacy"]
                        Write-Log "Applying Privacy Profile..." "INFO"
                        if ($config.RemoveApps) { Remove-Bloatware -SafeModeEnabled $false }
                        if ($config.DisableTelemetry) { Disable-Telemetry }
                        if ($config.EnhancePrivacy) { Enhance-Privacy }
                        if ($config.DisableCortana) { Disable-Cortana }
                    }
                    '6' {
                        $config = $Profiles["Work"]
                        Write-Log "Applying Work Profile..." "INFO"
                        if ($config.DisableTelemetry) { Disable-Telemetry }
                        if ($config.OptimizePerformance) { Optimize-Performance }
                        if ($config.EnhancePrivacy) { Enhance-Privacy }
                    }
                    '7' {
                        Write-Log "Applying Ultimate Profile..." "WARNING"
                        $confirm = Read-Host "This will apply ALL optimizations. Continue? (Y/N)"
                        if ($confirm -eq 'Y') {
                            $config = $Profiles["Ultimate"]
                            Remove-Bloatware -SafeModeEnabled $false
                            Disable-Telemetry
                            Remove-OneDrive
                            Disable-Cortana
                            Clean-ScheduledTasks
                            Disable-WindowsSearch
                            Optimize-Performance
                            Enhance-Privacy
                            Disable-P2PUpdates
                            Manage-StartupPrograms
                            Clean-TempFiles
                            if ($IsWindows11) { Remove-Edge }
                        }
                    }
                }
            }
            '2' {
                # App Management submenu
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                    APP MANAGEMENT                              ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ 1. Remove bloatware (Interactive)                              ║" -ForegroundColor White
                Write-Host "║ 2. Remove OneDrive                                             ║" -ForegroundColor White
                Write-Host "║ 3. Remove Edge (Windows 11 only)                               ║" -ForegroundColor White
                Write-Host "║ 4. Manage allowlist                                            ║" -ForegroundColor White
                Write-Host "║ 5. Manage denylist                                            ║" -ForegroundColor White
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' {
                        $appLists = Load-AppLists
                        Remove-Bloatware -SafeModeEnabled $false -CustomAllowlist $appLists.Allowlist -CustomDenylist $appLists.Denylist
                    }
                    '2' { Remove-OneDrive }
                    '3' { Remove-Edge }
                    '4' {
                        Write-Host "`nCurrent allowlist:" -ForegroundColor Yellow
                        if (Test-Path $script:AllowlistPath) {
                            Get-Content $script:AllowlistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
                        } else {
                            Write-Host "No allowlist found." -ForegroundColor Red
                        }
                        
                        Write-Host "`nEnter app name to add to allowlist (or press Enter to skip):" -ForegroundColor Cyan
                        $newApp = Read-Host
                        if ($newApp) {
                            Add-Content -Path $script:AllowlistPath -Value $newApp
                            Write-Log "Added to allowlist: $newApp" "SUCCESS"
                        }
                    }
                    '5' {
                        Write-Host "`nCurrent denylist:" -ForegroundColor Yellow
                        if (Test-Path $script:DenylistPath) {
                            Get-Content $script:DenylistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
                        } else {
                            Write-Host "No denylist found." -ForegroundColor Red
                        }
                        
                        Write-Host "`nEnter app name to add to denylist (or press Enter to skip):" -ForegroundColor Cyan
                        $newApp = Read-Host
                        if ($newApp) {
                            Add-Content -Path $script:DenylistPath -Value $newApp
                            Write-Log "Added to denylist: $newApp" "SUCCESS"
                        }
                    }
                }
            }
            '3' {
                # Privacy & Telemetry submenu
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                  PRIVACY & TELEMETRY                           ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ 1. Disable ALL telemetry                                       ║" -ForegroundColor White
                Write-Host "║ 2. Disable Cortana                                             ║" -ForegroundColor White
                Write-Host "║ 3. Enhance privacy settings                                    ║" -ForegroundColor White
                Write-Host "║ 4. Block telemetry hosts                                       ║" -ForegroundColor White
                Write-Host "║ 5. Clear activity history                                      ║" -ForegroundColor White
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' { Disable-Telemetry }
                    '2' { Disable-Cortana }
                    '3' { Enhance-Privacy }
                    '4' { Disable-Telemetry }  # This includes host blocking
                    '5' {
                        Remove-Item -Path "$env:LOCALAPPDATA\ConnectedDevicesPlatform\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\History\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log "Activity history cleared!" "SUCCESS"
                    }
                }
            }
            '4' {
                # Performance Optimization submenu
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                PERFORMANCE OPTIMIZATION                        ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ 1. Optimize visual effects                                     ║" -ForegroundColor White
                Write-Host "║ 2. Disable Windows Search                                      ║" -ForegroundColor White
                Write-Host "║ 3. Optimize services                                           ║" -ForegroundColor White
                Write-Host "║ 4. Disable background apps                                     ║" -ForegroundColor White
                Write-Host "║ 5. Apply ALL optimizations                                     ║" -ForegroundColor White
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' { Optimize-Performance }
                    '2' { Disable-WindowsSearch }
                    '3' { Optimize-Performance }
                    '4' { Optimize-Performance }
                    '5' { Optimize-Performance }
                }
            }
            '5' {
                # System Cleanup submenu
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                    SYSTEM CLEANUP                              ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ 1. Clean temporary files                                       ║" -ForegroundColor White
                Write-Host "║ 2. Clean scheduled tasks                                       ║" -ForegroundColor White
                Write-Host "║ 3. Manage startup programs                                     ║" -ForegroundColor White
                Write-Host "║ 4. Disable P2P Windows Updates                                 ║" -ForegroundColor White
                Write-Host "║ 5. Run ALL cleanup tasks                                       ║" -ForegroundColor White
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' { Clean-TempFiles }
                    '2' { Clean-ScheduledTasks }
                    '3' { Manage-StartupPrograms }
                    '4' { Disable-P2PUpdates }
                    '5' {
                        Clean-TempFiles
                        Clean-ScheduledTasks
                        Disable-P2PUpdates
                    }
                }
            }
            '6' {
                # Advanced Options submenu
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                   ADVANCED OPTIONS                             ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ 1. Disable Windows Defender (DANGEROUS)                        ║" -ForegroundColor Red
                Write-Host "║ 2. Export current configuration                                ║" -ForegroundColor White
                Write-Host "║ 3. Enable verbose logging                                      ║" -ForegroundColor White
                Write-Host "║ 4. Create system restore point                                 ║" -ForegroundColor White
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' { Disable-WindowsDefender }
                    '2' {
                        $exportPath = "$script:ConfigPath\config_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                        $currentConfig = @{
                            RemoveApps = $true
                            DisableTelemetry = $true
                            RemoveOneDrive = $true
                            DisableCortana = $true
                            CleanScheduledTasks = $true
                            DisableWindowsSearch = $false
                            RemoveEdge = $false
                            OptimizePerformance = $true
                            EnhancePrivacy = $true
                            CleanupNetwork = $true
                            ManageStartup = $true
                            CleanTempFiles = $true
                            DisableDefender = $false
                        }
                        $currentConfig | ConvertTo-Json | Out-File -FilePath $exportPath -Force
                        Write-Log "Configuration exported to: $exportPath" "SUCCESS"
                    }
                    '3' { 
                        $VerbosePreference = "Continue"
                        Write-Log "Verbose logging enabled" "SUCCESS"
                    }
                    '4' { Create-SystemRestorePoint -Description "Windows Crap Remover - Manual Restore Point" }
                }
            }
            '7' {
                # Load Profile
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                    LOAD PROFILE                                ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ Available Profiles:                                            ║" -ForegroundColor White
                Write-Host "║ 1. Minimal - Basic cleanup, keep most features                ║" -ForegroundColor White
                Write-Host "║ 2. Gaming - Optimized for gaming performance                   ║" -ForegroundColor White
                Write-Host "║ 3. Work - Keep productivity features                           ║" -ForegroundColor White
                Write-Host "║ 4. Privacy - Maximum privacy protection                        ║" -ForegroundColor White
                Write-Host "║ 5. Ultimate - Remove everything possible                       ║" -ForegroundColor Yellow
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $profileChoice = Read-Host "Select profile"
                
                $profileMap = @{
                    '1' = "Minimal"
                    '2' = "Gaming"
                    '3' = "Work"
                    '4' = "Privacy"
                    '5' = "Ultimate"
                }
                
                if ($profileMap.ContainsKey($profileChoice)) {
                    $selectedProfile = $profileMap[$profileChoice]
                    Write-Log "Loading profile: $selectedProfile" "INFO"
                    
                    $confirm = Read-Host "Apply $selectedProfile profile? (Y/N)"
                    if ($confirm -eq 'Y') {
                        & $PSCommandPath -Profile $selectedProfile -DryRun:$DryRun
                    }
                }
            }
            '8' {
                # Backup & Restore
                Clear-Host
                Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "║                   BACKUP & RESTORE                             ║" -ForegroundColor Yellow
                Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "║ 1. Create backup                                               ║" -ForegroundColor White
                Write-Host "║ 2. Restore from backup                                         ║" -ForegroundColor White
                Write-Host "║ 3. View available backups                                      ║" -ForegroundColor White
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' {
                        Create-SystemRestorePoint -Description "Windows Crap Remover - Manual Backup"
                        Save-ChangesLog
                    }
                    '2' { Undo-Changes }
                    '3' {
                        $backups = Get-ChildItem -Path "$env:LOCALAPPDATA\WindowsCrapRemover\Backups" -Directory | Sort-Object Name -Descending
                        
                        Write-Host "`nAvailable backups:" -ForegroundColor Yellow
                        foreach ($backup in $backups) {
                            Write-Host "- $($backup.Name)" -ForegroundColor White
                        }
                    }
                }
            }
            '9' {
                # View Changes Log
                Write-Host "`nRecent changes:" -ForegroundColor Yellow
                
                if ($script:Changes.Count -eq 0) {
                    Write-Host "No changes made in this session." -ForegroundColor Red
                } else {
                    $script:Changes | ForEach-Object {
                        $itemName = if ($_.Name) { $_.Name } else { $_.Path }
                        Write-Host "$($_.Timestamp): $($_.Type) - $($_.Action) - $itemName" -ForegroundColor White
                    }
                }
                
                Write-Host "`nPress Enter to continue..."
                Read-Host
            }
            '0' {
                Write-Log "Exiting..." "INFO"
                Save-ChangesLog
                break
            }
            'H' {
                # System Health Dashboard
                Show-HealthDashboard
            }
            'h' {
                # System Health Dashboard (lowercase)
                Show-HealthDashboard
            }
            'R' {
                # System Requirements Check
                Test-SystemRequirements
            }
            'r' {
                # System Requirements Check (lowercase)
                Test-SystemRequirements
            }
            'B' {
                # Benchmark Comparison
                Show-BenchmarkComparison
            }
            'b' {
                # Benchmark Comparison (lowercase)
                Show-BenchmarkComparison
            }
            'Q' {
                # Quick Start
                Start-QuickStart
            }
            'q' {
                # Quick Start (lowercase)
                Start-QuickStart
            }
            'F' {
                # Quick Fix
                Show-QuickFixMenu
            }
            'f' {
                # Quick Fix (lowercase)
                Show-QuickFixMenu
            }
            'T' {
                # Additional Tools
                Show-ToolsMenu
            }
            't' {
                # Additional Tools (lowercase)
                Show-ToolsMenu
            }
            default {
                Write-Log "Invalid choice. Please try again." "WARNING"
            }
        }
        
        if ($choice -ne '0') {
            Write-Host "`nPress Enter to continue..."
            Read-Host
        }
        
    } while ($choice -ne '0')
}

Write-Log "==================================================" "INFO"
Write-Log "         Windows Crap Remover Completed!          " "SUCCESS"
Write-Log "==================================================" "INFO"
Write-Log "Some changes may require a restart to take effect." "WARNING"
Write-Log "Log file saved to: $LogFile" "INFO"

if (-not $Silent -and -not $AutoMode) {
    $restart = Read-Host "`nWould you like to restart now? (Y/N)"
    if ($restart -eq 'Y') {
        Write-Log "Restarting in 10 seconds..." "WARNING"
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
}