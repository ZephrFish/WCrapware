# Windows Crap Remover - Ultimate Edition
# Comprehensive Windows 10/11 Debloater with Safety Features
# Version: 2.0

param(
    [switch]$AutoMode = $false,
    [switch]$SafeMode = $false,
    [switch]$DryRun = $false,
    [switch]$Silent = $false,
    [string]$Profile = "",
    [string]$ConfigFile = "",
    [string]$LogFile = "$env:TEMP\WindowsCrapRemover_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# Initialize script variables
$script:Changes = @()
$script:BackupPath = "$env:LOCALAPPDATA\WindowsCrapRemover\Backups\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$script:ConfigPath = "$env:LOCALAPPDATA\WindowsCrapRemover\Config"
$script:WhitelistPath = "$script:ConfigPath\whitelist.txt"
$script:BlacklistPath = "$script:ConfigPath\blacklist.txt"

# Create necessary directories
New-Item -ItemType Directory -Force -Path $script:BackupPath | Out-Null
New-Item -ItemType Directory -Force -Path $script:ConfigPath | Out-Null

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
    Write-Log "This script must be run as Administrator!" "ERROR"
    Write-Log "Restarting with Administrator privileges..." "INFO"
    Start-Process PowerShell -Verb RunAs "-File `"$PSCommandPath`" $($MyInvocation.Line.Substring($MyInvocation.Line.IndexOf($PSCommandPath) + $PSCommandPath.Length))" -Wait
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

# Load whitelist and blacklist
function Load-AppLists {
    $whitelist = @()
    $blacklist = @()
    
    if (Test-Path $script:WhitelistPath) {
        $whitelist = Get-Content $script:WhitelistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
        Write-Log "Loaded whitelist with $($whitelist.Count) entries" "DEBUG"
    }
    
    if (Test-Path $script:BlacklistPath) {
        $blacklist = Get-Content $script:BlacklistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
        Write-Log "Loaded blacklist with $($blacklist.Count) entries" "DEBUG"
    }
    
    return @{
        Whitelist = $whitelist
        Blacklist = $blacklist
    }
}

# Enhanced menu system
function Show-MainMenu {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║          Windows Crap Remover - Ultimate Edition               ║" -ForegroundColor Cyan
    Write-Host "║                    Version 2.0                                 ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ MAIN MENU                                                      ║" -ForegroundColor Yellow
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ 1. Quick Actions (Common tasks)                                ║" -ForegroundColor White
    Write-Host "║ 2. App Management                                              ║" -ForegroundColor White
    Write-Host "║ 3. Privacy & Telemetry                                         ║" -ForegroundColor White
    Write-Host "║ 4. Performance Optimization                                    ║" -ForegroundColor White
    Write-Host "║ 5. System Cleanup                                              ║" -ForegroundColor White
    Write-Host "║ 6. Advanced Options                                            ║" -ForegroundColor White
    Write-Host "║ 7. Load Profile                                                ║" -ForegroundColor White
    Write-Host "║ 8. Backup & Restore                                            ║" -ForegroundColor White
    Write-Host "║ 9. View Changes Log                                            ║" -ForegroundColor White
    Write-Host "║ 0. Exit                                                        ║" -ForegroundColor Red
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
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
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.WindowsFeedback",
    "Microsoft.Advertising.Xaml",
    "Microsoft.Services.Store.Engagement",
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
    "Microsoft.WindowsPhone",
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
    "Twitter*",
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

$Windows11Specific = @(
    "Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.News",
    "Microsoft.GamingApp",
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
    "Microsoft.XboxGameCallableUI"
)

# Function to remove bloatware with enhanced features
function Remove-Bloatware {
    param(
        [bool]$SafeModeEnabled = $false,
        [array]$CustomWhitelist = @(),
        [array]$CustomBlacklist = @()
    )
    
    Write-Log "Starting bloatware removal..." "INFO"
    
    # Combine lists
    $appsToRemove = $CommonBloatware + $CustomBlacklist
    if ($IsWindows11) {
        $appsToRemove += $Windows11Specific
    }
    
    # Remove duplicates
    $appsToRemove = $appsToRemove | Select-Object -Unique
    
    # Apply whitelist
    if ($SafeModeEnabled) {
        $whitelistApps = $SafeApps + $CustomWhitelist
    } else {
        $whitelistApps = $CustomWhitelist
    }
    
    $totalApps = $appsToRemove.Count
    $removed = 0
    $failed = 0
    
    foreach ($app in $appsToRemove) {
        # Check if whitelisted
        $isWhitelisted = $false
        foreach ($whiteApp in $whitelistApps) {
            if ($app -like $whiteApp) {
                $isWhitelisted = $true
                break
            }
        }
        
        if ($isWhitelisted) {
            Write-Log "Skipping whitelisted app: $app" "DEBUG"
            continue
        }
        
        # Find and remove apps
        $packages = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $app }
        
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
        "WinRM",
        "XblAuthManager",
        "XblGameSave",
        "XboxGipSvc",
        "XboxNetApiSvc"
    )
    
    foreach ($service in $telemetryServices) {
        if ($DryRun) {
            Write-Log "[DRY RUN] Would disable service: $service" "DEBUG"
        } else {
            try {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled service: $service" "SUCCESS"
            } catch {
                Write-Log "Failed to disable service $service: $_" "DEBUG"
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
        
        foreach ($host in $telemetryHosts) {
            $entry = "0.0.0.0 $host"
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
                Write-Log "Failed to disable task $task: $_" "DEBUG"
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
        $computerSystem = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
        $computerSystem.AutomaticManagedPagefile = $false
        $computerSystem.Put() | Out-Null
        
        $pageFile = Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='C:\\pagefile.sys'"
        if ($null -eq $pageFile) {
            Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name="C:\pagefile.sys"} | Out-Null
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
                
                Write-Log "Cleaned: $path ($('{0:N2}' -f ($pathSize / 1MB)) MB)" "DEBUG"
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
    
    Write-Log "Temp file cleanup completed! Cleaned $('{0:N2}' -f ($cleaned / 1MB)) MB" "SUCCESS"
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
            Write-Log "Failed to disable service $service: $_" "DEBUG"
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
                Write-Log "Failed to disable task $task: $_" "DEBUG"
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
        Remove-Bloatware -SafeModeEnabled $SafeMode -CustomWhitelist $appLists.Whitelist -CustomBlacklist $appLists.Blacklist
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
                        Remove-Bloatware -SafeModeEnabled $false -CustomWhitelist $appLists.Whitelist -CustomBlacklist $appLists.Blacklist
                    }
                    '2' { 
                        $appLists = Load-AppLists
                        Remove-Bloatware -SafeModeEnabled $true -CustomWhitelist $appLists.Whitelist -CustomBlacklist $appLists.Blacklist
                    }
                    '3' { Disable-Telemetry }
                    '4' {
                        $config = $Profiles["Gaming"]
                        Write-Log "Applying Gaming Profile..." "INFO"
                        if ($config.RemoveApps) { Remove-Bloatware -SafeModeEnabled $false }
                        if ($config.DisableTelemetry) { Disable-Telemetry }
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
                Write-Host "║ 4. Manage whitelist                                            ║" -ForegroundColor White
                Write-Host "║ 5. Manage blacklist                                            ║" -ForegroundColor White
                Write-Host "║ 0. Back to Main Menu                                           ║" -ForegroundColor Red
                Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                
                $subChoice = Read-Host "Enter your choice"
                
                switch ($subChoice) {
                    '1' {
                        $appLists = Load-AppLists
                        Remove-Bloatware -SafeModeEnabled $false -CustomWhitelist $appLists.Whitelist -CustomBlacklist $appLists.Blacklist
                    }
                    '2' { Remove-OneDrive }
                    '3' { Remove-Edge }
                    '4' {
                        Write-Host "`nCurrent whitelist:" -ForegroundColor Yellow
                        if (Test-Path $script:WhitelistPath) {
                            Get-Content $script:WhitelistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
                        } else {
                            Write-Host "No whitelist found." -ForegroundColor Red
                        }
                        
                        Write-Host "`nEnter app name to add to whitelist (or press Enter to skip):" -ForegroundColor Cyan
                        $newApp = Read-Host
                        if ($newApp) {
                            Add-Content -Path $script:WhitelistPath -Value $newApp
                            Write-Log "Added to whitelist: $newApp" "SUCCESS"
                        }
                    }
                    '5' {
                        Write-Host "`nCurrent blacklist:" -ForegroundColor Yellow
                        if (Test-Path $script:BlacklistPath) {
                            Get-Content $script:BlacklistPath | Where-Object { $_ -and $_ -notmatch '^\s*#' }
                        } else {
                            Write-Host "No blacklist found." -ForegroundColor Red
                        }
                        
                        Write-Host "`nEnter app name to add to blacklist (or press Enter to skip):" -ForegroundColor Cyan
                        $newApp = Read-Host
                        if ($newApp) {
                            Add-Content -Path $script:BlacklistPath -Value $newApp
                            Write-Log "Added to blacklist: $newApp" "SUCCESS"
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
                        Write-Host "$($_.Timestamp): $($_.Type) - $($_.Action) - $($_.Name ?? $_.Path)" -ForegroundColor White
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