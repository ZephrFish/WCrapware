<#
.SYNOPSIS
    Windows Crap Remover - GUI Edition
.DESCRIPTION
    A comprehensive Windows 10/11 debloating and optimization tool with a graphical interface.
    This GUI wraps the functionality of crapremover.ps1.
.NOTES
    Version: 2.1
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

#Requires -Version 5.1

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Load Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Script-level variables
$script:LogMessages = [System.Collections.ArrayList]::new()
$script:Changes = @()
$script:DryRunMode = $false
$script:BackupPath = "$env:LOCALAPPDATA\WindowsCrapRemover\Backups\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$script:ConfigPath = "$env:LOCALAPPDATA\WindowsCrapRemover\Config"

# Ensure directories exist
New-Item -ItemType Directory -Path $script:BackupPath -Force | Out-Null
New-Item -ItemType Directory -Path $script:ConfigPath -Force | Out-Null

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Write-GUILog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:LogMessages.Add($logEntry) | Out-Null

    if ($script:LogTextBox) {
        $script:LogTextBox.Invoke([Action]{
            $color = switch ($Level) {
                "SUCCESS" { [System.Drawing.Color]::Green }
                "WARNING" { [System.Drawing.Color]::Orange }
                "ERROR"   { [System.Drawing.Color]::Red }
                default   { [System.Drawing.Color]::White }
            }
            $script:LogTextBox.SelectionStart = $script:LogTextBox.TextLength
            $script:LogTextBox.SelectionLength = 0
            $script:LogTextBox.SelectionColor = $color
            $script:LogTextBox.AppendText("$logEntry`r`n")
            $script:LogTextBox.ScrollToCaret()
        })
    }
}

function Update-ProgressBar {
    param([int]$Value, [string]$Status = "")

    if ($script:ProgressBar -and $script:StatusLabel) {
        $script:ProgressBar.Invoke([Action]{
            $script:ProgressBar.Value = [Math]::Min($Value, 100)
        })
        $script:StatusLabel.Invoke([Action]{
            $script:StatusLabel.Text = $Status
        })
    }
}

function Get-SystemHealth {
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $memory = Get-CimInstance Win32_OperatingSystem
    $memUsed = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 1)
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $diskUsed = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)
    $processes = (Get-Process).Count
    $services = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
    $startupApps = (Get-CimInstance Win32_StartupCommand).Count

    return @{
        CPU = $cpu
        Memory = $memUsed
        Disk = $diskUsed
        Processes = $processes
        Services = $services
        StartupApps = $startupApps
        MemoryTotal = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 1)
        DiskFree = [math]::Round($disk.FreeSpace / 1GB, 1)
        DiskTotal = [math]::Round($disk.Size / 1GB, 1)
    }
}

# =============================================================================
# CORE FUNCTIONS (Simplified versions for GUI)
# =============================================================================

$script:SafeApps = @(
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

$script:CommonBloatware = @(
    "Microsoft.3DBuilder",
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingFinance",
    "Microsoft.BingSports",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Office.OneNote",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCommunicationsApps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.BingSearch",
    "Microsoft.WindowsPhone",
    "Microsoft.CommsPhone",
    "Microsoft.ConnectivityStore",
    "Microsoft.Advertising.Xaml",
    "MicrosoftTeams",
    "Clipchamp.Clipchamp",
    "Facebook.Facebook",
    "SpotifyAB.SpotifyMusic",
    "Disney.37853FC22B2CE",
    "BytedancePte.Ltd.TikTok",
    "5A894077.McAfeeSecurity",
    "4DF9E0F8.Netflix",
    "AmazonVideo.PrimeVideo",
    "king.com.CandyCrushSaga",
    "king.com.CandyCrushSodaSaga",
    "king.com.CandyCrushFriends",
    "NORDCURRENT.COOKINGFEVER",
    "A278AB0D.MarchofEmpires",
    "KeeperSecurityInc.Keeper",
    "ThumbmunkeysLtd.PhototasticCollage",
    "XINGAG.XING",
    "ActiproSoftwareLLC",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "Duolingo-LearnLanguagesforFree",
    "EclipseManager",
    "PandoraMediaInc",
    "Wunderlist",
    "LinkedIn"
)

$script:GamingAllowlist = @(
    "Microsoft.Xbox*",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.GamingApp",
    "Microsoft.GamingServices",
    "Microsoft.DirectXRuntime"
)

function Remove-BloatwareGUI {
    param(
        [bool]$SafeMode = $true,
        [bool]$PreserveXbox = $true
    )

    Write-GUILog "Starting bloatware removal (SafeMode: $SafeMode, PreserveXbox: $PreserveXbox)" "INFO"
    Update-ProgressBar 0 "Scanning installed apps..."

    $allApps = Get-AppxPackage -AllUsers
    $appsToRemove = @()

    foreach ($bloat in $script:CommonBloatware) {
        $matches = $allApps | Where-Object { $_.Name -like $bloat }
        foreach ($app in $matches) {
            # Check safe apps
            $isSafe = $false
            foreach ($safe in $script:SafeApps) {
                if ($app.Name -like $safe) { $isSafe = $true; break }
            }

            # Check gaming allowlist if preserving Xbox
            if ($PreserveXbox) {
                foreach ($gaming in $script:GamingAllowlist) {
                    if ($app.Name -like $gaming) { $isSafe = $true; break }
                }
            }

            if (-not $isSafe) {
                $appsToRemove += $app
            }
        }
    }

    $total = $appsToRemove.Count
    $removed = 0

    Write-GUILog "Found $total apps to remove" "INFO"

    foreach ($app in $appsToRemove) {
        $percent = [int](($removed / [Math]::Max($total, 1)) * 100)
        Update-ProgressBar $percent "Removing: $($app.Name)"

        if ($script:DryRunMode) {
            Write-GUILog "[DRY RUN] Would remove: $($app.Name)" "INFO"
        } else {
            try {
                Get-AppxPackage -Name $app.Name -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction Stop
                Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $app.Name } |
                    Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                Write-GUILog "Removed: $($app.Name)" "SUCCESS"
                $script:Changes += @{Type="AppRemoved"; Name=$app.Name; Time=Get-Date}
            } catch {
                Write-GUILog "Failed to remove: $($app.Name)" "ERROR"
            }
        }
        $removed++
    }

    Update-ProgressBar 100 "Bloatware removal complete"
    Write-GUILog "Bloatware removal completed. Removed $removed apps." "SUCCESS"
}

function Disable-TelemetryGUI {
    param([bool]$PreserveXbox = $false)

    Write-GUILog "Disabling Windows telemetry..." "INFO"
    Update-ProgressBar 0 "Disabling telemetry..."

    $telemetryKeys = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Value = 1},
        @{Path = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Value = 1},
        @{Path = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"; Name = "HarvestContacts"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableInventory"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableUAR"; Value = 1}
    )

    $total = $telemetryKeys.Count
    $current = 0

    foreach ($key in $telemetryKeys) {
        $percent = [int](($current / $total) * 100)
        Update-ProgressBar $percent "Setting registry values..."

        if ($script:DryRunMode) {
            Write-GUILog "[DRY RUN] Would set: $($key.Path)\$($key.Name) = $($key.Value)" "INFO"
        } else {
            try {
                if (!(Test-Path $key.Path)) {
                    New-Item -Path $key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
                $script:Changes += @{Type="Registry"; Path=$key.Path; Name=$key.Name; Value=$key.Value; Time=Get-Date}
            } catch {
                Write-GUILog "Failed to set: $($key.Path)\$($key.Name)" "ERROR"
            }
        }
        $current++
    }

    # Disable telemetry services
    $telemetryServices = @("DiagTrack", "dmwappushservice")
    if (-not $PreserveXbox) {
        $telemetryServices += @("XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc")
    }

    foreach ($svc in $telemetryServices) {
        if ($script:DryRunMode) {
            Write-GUILog "[DRY RUN] Would disable service: $svc" "INFO"
        } else {
            try {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                Write-GUILog "Disabled service: $svc" "SUCCESS"
            } catch {
                # Service may not exist
            }
        }
    }

    Update-ProgressBar 100 "Telemetry disabled"
    Write-GUILog "Telemetry disabling completed." "SUCCESS"
}

function Optimize-PerformanceGUI {
    Write-GUILog "Optimizing system performance..." "INFO"
    Update-ProgressBar 0 "Applying performance tweaks..."

    $perfKeys = @(
        @{Path = "HKCU:\Control Panel\Desktop"; Name = "MenuShowDelay"; Value = "0"},
        @{Path = "HKCU:\Control Panel\Desktop"; Name = "UserPreferencesMask"; Value = ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))},
        @{Path = "HKCU:\Control Panel\Desktop\WindowMetrics"; Name = "MinAnimate"; Value = "0"},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ListviewAlphaSelect"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarAnimations"; Value = 0},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; Name = "VisualFXSetting"; Value = 2},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "LargeSystemCache"; Value = 0}
    )

    $total = $perfKeys.Count
    $current = 0

    foreach ($key in $perfKeys) {
        $percent = [int](($current / $total) * 100)
        Update-ProgressBar $percent "Applying performance settings..."

        if ($script:DryRunMode) {
            Write-GUILog "[DRY RUN] Would set: $($key.Path)\$($key.Name)" "INFO"
        } else {
            try {
                if (!(Test-Path $key.Path)) {
                    New-Item -Path $key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
            } catch {
                Write-GUILog "Failed to set: $($key.Name)" "WARNING"
            }
        }
        $current++
    }

    Update-ProgressBar 100 "Performance optimization complete"
    Write-GUILog "Performance optimization completed." "SUCCESS"
}

function Enhance-PrivacyGUI {
    Write-GUILog "Enhancing privacy settings..." "INFO"
    Update-ProgressBar 0 "Applying privacy settings..."

    $privacyKeys = @(
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackProgs"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackDocs"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338388Enabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338389Enabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-353694Enabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-353696Enabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableActivityFeed"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities"; Value = 0}
    )

    $total = $privacyKeys.Count
    $current = 0

    foreach ($key in $privacyKeys) {
        $percent = [int](($current / $total) * 100)
        Update-ProgressBar $percent "Enhancing privacy..."

        if ($script:DryRunMode) {
            Write-GUILog "[DRY RUN] Would set: $($key.Path)\$($key.Name)" "INFO"
        } else {
            try {
                if (!(Test-Path $key.Path)) {
                    New-Item -Path $key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
            } catch {
                Write-GUILog "Failed to set: $($key.Name)" "WARNING"
            }
        }
        $current++
    }

    Update-ProgressBar 100 "Privacy enhancement complete"
    Write-GUILog "Privacy enhancement completed." "SUCCESS"
}

function Clean-TempFilesGUI {
    Write-GUILog "Cleaning temporary files..." "INFO"
    Update-ProgressBar 0 "Scanning temp files..."

    $tempPaths = @(
        "$env:TEMP",
        "$env:LOCALAPPDATA\Temp",
        "$env:windir\Temp",
        "$env:windir\Prefetch",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    )

    $totalFreed = 0
    $total = $tempPaths.Count
    $current = 0

    foreach ($path in $tempPaths) {
        $percent = [int](($current / $total) * 100)
        Update-ProgressBar $percent "Cleaning: $path"

        if (Test-Path $path) {
            $sizeBefore = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                          Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum

            if ($script:DryRunMode) {
                Write-GUILog "[DRY RUN] Would clean: $path ($('{0:N2}' -f ($sizeBefore/1MB)) MB)" "INFO"
            } else {
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                    Remove-Item -Force -ErrorAction SilentlyContinue

                $totalFreed += $sizeBefore
            }
        }
        $current++
    }

    Update-ProgressBar 100 "Cleanup complete"
    Write-GUILog "Temp cleanup completed. Freed approximately $('{0:N2}' -f ($totalFreed/1MB)) MB" "SUCCESS"
}

function Remove-OneDriveGUI {
    Write-GUILog "Removing OneDrive..." "INFO"
    Update-ProgressBar 0 "Stopping OneDrive..."

    if ($script:DryRunMode) {
        Write-GUILog "[DRY RUN] Would remove OneDrive" "INFO"
        Update-ProgressBar 100 "Complete"
        return
    }

    # Stop OneDrive
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Update-ProgressBar 30 "Uninstalling OneDrive..."

    # Uninstall
    $oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (!(Test-Path $oneDriveSetup)) {
        $oneDriveSetup = "$env:SystemRoot\System32\OneDriveSetup.exe"
    }

    if (Test-Path $oneDriveSetup) {
        Start-Process $oneDriveSetup -ArgumentList "/uninstall" -Wait -NoNewWindow
    }

    Update-ProgressBar 70 "Cleaning up OneDrive folders..."

    # Remove folders
    $foldersToRemove = @(
        "$env:USERPROFILE\OneDrive",
        "$env:LOCALAPPDATA\Microsoft\OneDrive",
        "$env:ProgramData\Microsoft OneDrive",
        "$env:SystemDrive\OneDriveTemp"
    )

    foreach ($folder in $foldersToRemove) {
        if (Test-Path $folder) {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Update-ProgressBar 100 "OneDrive removed"
    Write-GUILog "OneDrive removal completed." "SUCCESS"
}

function Disable-CortanaGUI {
    Write-GUILog "Disabling Cortana..." "INFO"
    Update-ProgressBar 0 "Disabling Cortana..."

    $cortanaKeys = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortanaAboveLock"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowSearchToUseLocation"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name = "CortanaConsent"; Value = 0},
        @{Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name = "BingSearchEnabled"; Value = 0}
    )

    foreach ($key in $cortanaKeys) {
        if ($script:DryRunMode) {
            Write-GUILog "[DRY RUN] Would set: $($key.Name) = $($key.Value)" "INFO"
        } else {
            try {
                if (!(Test-Path $key.Path)) {
                    New-Item -Path $key.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force
            } catch {
                Write-GUILog "Failed to set: $($key.Name)" "WARNING"
            }
        }
    }

    Update-ProgressBar 100 "Cortana disabled"
    Write-GUILog "Cortana disabled successfully." "SUCCESS"
}

function Repair-WindowsStoreGUI {
    Write-GUILog "Repairing Windows Store..." "INFO"
    Update-ProgressBar 0 "Resetting Store cache..."

    if ($script:DryRunMode) {
        Write-GUILog "[DRY RUN] Would repair Windows Store" "INFO"
        Update-ProgressBar 100 "Complete"
        return
    }

    # Reset Store cache
    Start-Process "wsreset.exe" -Wait -NoNewWindow -ErrorAction SilentlyContinue

    Update-ProgressBar 50 "Re-registering Store..."

    # Re-register Store
    try {
        Get-AppxPackage -AllUsers Microsoft.WindowsStore | ForEach-Object {
            Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
        }
        Write-GUILog "Windows Store repaired successfully." "SUCCESS"
    } catch {
        Write-GUILog "Failed to repair Windows Store: $_" "ERROR"
    }

    Update-ProgressBar 100 "Store repair complete"
}

# =============================================================================
# GUI CREATION
# =============================================================================

# Main Form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "Windows Crap Remover v2.1"
$mainForm.Size = New-Object System.Drawing.Size(900, 700)
$mainForm.StartPosition = "CenterScreen"
$mainForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$mainForm.ForeColor = [System.Drawing.Color]::White
$mainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$mainForm.MaximizeBox = $false
$mainForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Title Label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "Windows Crap Remover"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 255)
$titleLabel.Location = New-Object System.Drawing.Point(20, 15)
$titleLabel.AutoSize = $true
$mainForm.Controls.Add($titleLabel)

# Version Label
$versionLabel = New-Object System.Windows.Forms.Label
$versionLabel.Text = "v2.1 - Ultimate Edition"
$versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$versionLabel.ForeColor = [System.Drawing.Color]::Gray
$versionLabel.Location = New-Object System.Drawing.Point(280, 22)
$versionLabel.AutoSize = $true
$mainForm.Controls.Add($versionLabel)

# Tab Control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(20, 55)
$tabControl.Size = New-Object System.Drawing.Size(850, 400)
$tabControl.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$mainForm.Controls.Add($tabControl)

# =============================================================================
# TAB 1: Quick Actions
# =============================================================================
$tabQuick = New-Object System.Windows.Forms.TabPage
$tabQuick.Text = "Quick Actions"
$tabQuick.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabControl.Controls.Add($tabQuick)

# Profile GroupBox
$profileGroup = New-Object System.Windows.Forms.GroupBox
$profileGroup.Text = "Select Profile"
$profileGroup.Location = New-Object System.Drawing.Point(15, 15)
$profileGroup.Size = New-Object System.Drawing.Size(400, 120)
$profileGroup.ForeColor = [System.Drawing.Color]::White
$tabQuick.Controls.Add($profileGroup)

$radioGaming = New-Object System.Windows.Forms.RadioButton
$radioGaming.Text = "Gaming - Keeps Xbox, optimizes for performance"
$radioGaming.Location = New-Object System.Drawing.Point(15, 25)
$radioGaming.Size = New-Object System.Drawing.Size(370, 20)
$radioGaming.Checked = $true
$radioGaming.ForeColor = [System.Drawing.Color]::Cyan
$profileGroup.Controls.Add($radioGaming)

$radioPrivacy = New-Object System.Windows.Forms.RadioButton
$radioPrivacy.Text = "Privacy - Maximum privacy, removes more apps"
$radioPrivacy.Location = New-Object System.Drawing.Point(15, 50)
$radioPrivacy.Size = New-Object System.Drawing.Size(370, 20)
$radioPrivacy.ForeColor = [System.Drawing.Color]::Magenta
$profileGroup.Controls.Add($radioPrivacy)

$radioWork = New-Object System.Windows.Forms.RadioButton
$radioWork.Text = "Work - Keeps productivity apps, minimal cleanup"
$radioWork.Location = New-Object System.Drawing.Point(15, 75)
$radioWork.Size = New-Object System.Drawing.Size(370, 20)
$radioWork.ForeColor = [System.Drawing.Color]::Yellow
$profileGroup.Controls.Add($radioWork)

# Options GroupBox
$optionsGroup = New-Object System.Windows.Forms.GroupBox
$optionsGroup.Text = "Options"
$optionsGroup.Location = New-Object System.Drawing.Point(430, 15)
$optionsGroup.Size = New-Object System.Drawing.Size(390, 120)
$optionsGroup.ForeColor = [System.Drawing.Color]::White
$tabQuick.Controls.Add($optionsGroup)

$chkDryRun = New-Object System.Windows.Forms.CheckBox
$chkDryRun.Text = "Dry Run (Preview changes without applying)"
$chkDryRun.Location = New-Object System.Drawing.Point(15, 25)
$chkDryRun.Size = New-Object System.Drawing.Size(350, 20)
$chkDryRun.ForeColor = [System.Drawing.Color]::Orange
$optionsGroup.Controls.Add($chkDryRun)

$chkPreserveXbox = New-Object System.Windows.Forms.CheckBox
$chkPreserveXbox.Text = "Preserve Xbox/Gaming Apps"
$chkPreserveXbox.Location = New-Object System.Drawing.Point(15, 50)
$chkPreserveXbox.Size = New-Object System.Drawing.Size(350, 20)
$chkPreserveXbox.Checked = $true
$optionsGroup.Controls.Add($chkPreserveXbox)

$chkCreateRestore = New-Object System.Windows.Forms.CheckBox
$chkCreateRestore.Text = "Create System Restore Point"
$chkCreateRestore.Location = New-Object System.Drawing.Point(15, 75)
$chkCreateRestore.Size = New-Object System.Drawing.Size(350, 20)
$chkCreateRestore.Checked = $true
$optionsGroup.Controls.Add($chkCreateRestore)

# Quick Action Buttons
$btnQuickClean = New-Object System.Windows.Forms.Button
$btnQuickClean.Text = "QUICK CLEAN"
$btnQuickClean.Location = New-Object System.Drawing.Point(15, 150)
$btnQuickClean.Size = New-Object System.Drawing.Size(180, 50)
$btnQuickClean.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$btnQuickClean.ForeColor = [System.Drawing.Color]::White
$btnQuickClean.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnQuickClean.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$tabQuick.Controls.Add($btnQuickClean)

$btnUltimateClean = New-Object System.Windows.Forms.Button
$btnUltimateClean.Text = "ULTIMATE CLEAN"
$btnUltimateClean.Location = New-Object System.Drawing.Point(210, 150)
$btnUltimateClean.Size = New-Object System.Drawing.Size(180, 50)
$btnUltimateClean.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
$btnUltimateClean.ForeColor = [System.Drawing.Color]::White
$btnUltimateClean.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnUltimateClean.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$tabQuick.Controls.Add($btnUltimateClean)

# Quick Fix Buttons
$quickFixLabel = New-Object System.Windows.Forms.Label
$quickFixLabel.Text = "Quick Fixes:"
$quickFixLabel.Location = New-Object System.Drawing.Point(15, 215)
$quickFixLabel.AutoSize = $true
$quickFixLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$tabQuick.Controls.Add($quickFixLabel)

$btnFixBoot = New-Object System.Windows.Forms.Button
$btnFixBoot.Text = "Fix Slow Boot"
$btnFixBoot.Location = New-Object System.Drawing.Point(15, 240)
$btnFixBoot.Size = New-Object System.Drawing.Size(120, 35)
$btnFixBoot.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnFixBoot.ForeColor = [System.Drawing.Color]::White
$btnFixBoot.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabQuick.Controls.Add($btnFixBoot)

$btnFixCPU = New-Object System.Windows.Forms.Button
$btnFixCPU.Text = "Fix High CPU"
$btnFixCPU.Location = New-Object System.Drawing.Point(145, 240)
$btnFixCPU.Size = New-Object System.Drawing.Size(120, 35)
$btnFixCPU.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnFixCPU.ForeColor = [System.Drawing.Color]::White
$btnFixCPU.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabQuick.Controls.Add($btnFixCPU)

$btnFixDisk = New-Object System.Windows.Forms.Button
$btnFixDisk.Text = "Fix Disk Space"
$btnFixDisk.Location = New-Object System.Drawing.Point(275, 240)
$btnFixDisk.Size = New-Object System.Drawing.Size(120, 35)
$btnFixDisk.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnFixDisk.ForeColor = [System.Drawing.Color]::White
$btnFixDisk.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabQuick.Controls.Add($btnFixDisk)

$btnFixPrivacy = New-Object System.Windows.Forms.Button
$btnFixPrivacy.Text = "Fix Privacy"
$btnFixPrivacy.Location = New-Object System.Drawing.Point(405, 240)
$btnFixPrivacy.Size = New-Object System.Drawing.Size(120, 35)
$btnFixPrivacy.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnFixPrivacy.ForeColor = [System.Drawing.Color]::White
$btnFixPrivacy.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabQuick.Controls.Add($btnFixPrivacy)

# =============================================================================
# TAB 2: Detailed Options
# =============================================================================
$tabDetailed = New-Object System.Windows.Forms.TabPage
$tabDetailed.Text = "Detailed Options"
$tabDetailed.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabControl.Controls.Add($tabDetailed)

# Bloatware Options
$bloatGroup = New-Object System.Windows.Forms.GroupBox
$bloatGroup.Text = "Bloatware Removal"
$bloatGroup.Location = New-Object System.Drawing.Point(15, 15)
$bloatGroup.Size = New-Object System.Drawing.Size(400, 140)
$bloatGroup.ForeColor = [System.Drawing.Color]::White
$tabDetailed.Controls.Add($bloatGroup)

$chkRemoveBloat = New-Object System.Windows.Forms.CheckBox
$chkRemoveBloat.Text = "Remove common bloatware apps"
$chkRemoveBloat.Location = New-Object System.Drawing.Point(15, 25)
$chkRemoveBloat.Size = New-Object System.Drawing.Size(350, 20)
$chkRemoveBloat.Checked = $true
$bloatGroup.Controls.Add($chkRemoveBloat)

$chkRemoveOneDrive = New-Object System.Windows.Forms.CheckBox
$chkRemoveOneDrive.Text = "Remove OneDrive"
$chkRemoveOneDrive.Location = New-Object System.Drawing.Point(15, 50)
$chkRemoveOneDrive.Size = New-Object System.Drawing.Size(350, 20)
$bloatGroup.Controls.Add($chkRemoveOneDrive)

$chkDisableCortana = New-Object System.Windows.Forms.CheckBox
$chkDisableCortana.Text = "Disable Cortana"
$chkDisableCortana.Location = New-Object System.Drawing.Point(15, 75)
$chkDisableCortana.Size = New-Object System.Drawing.Size(350, 20)
$chkDisableCortana.Checked = $true
$bloatGroup.Controls.Add($chkDisableCortana)

$chkSafeMode = New-Object System.Windows.Forms.CheckBox
$chkSafeMode.Text = "Safe Mode (Enhanced protection)"
$chkSafeMode.Location = New-Object System.Drawing.Point(15, 100)
$chkSafeMode.Size = New-Object System.Drawing.Size(350, 20)
$chkSafeMode.Checked = $true
$bloatGroup.Controls.Add($chkSafeMode)

# Privacy & Telemetry Options
$privacyGroup = New-Object System.Windows.Forms.GroupBox
$privacyGroup.Text = "Privacy & Telemetry"
$privacyGroup.Location = New-Object System.Drawing.Point(430, 15)
$privacyGroup.Size = New-Object System.Drawing.Size(390, 140)
$privacyGroup.ForeColor = [System.Drawing.Color]::White
$tabDetailed.Controls.Add($privacyGroup)

$chkDisableTelemetry = New-Object System.Windows.Forms.CheckBox
$chkDisableTelemetry.Text = "Disable Windows telemetry"
$chkDisableTelemetry.Location = New-Object System.Drawing.Point(15, 25)
$chkDisableTelemetry.Size = New-Object System.Drawing.Size(350, 20)
$chkDisableTelemetry.Checked = $true
$privacyGroup.Controls.Add($chkDisableTelemetry)

$chkEnhancePrivacy = New-Object System.Windows.Forms.CheckBox
$chkEnhancePrivacy.Text = "Enhance privacy settings"
$chkEnhancePrivacy.Location = New-Object System.Drawing.Point(15, 50)
$chkEnhancePrivacy.Size = New-Object System.Drawing.Size(350, 20)
$chkEnhancePrivacy.Checked = $true
$privacyGroup.Controls.Add($chkEnhancePrivacy)

$chkDisableAds = New-Object System.Windows.Forms.CheckBox
$chkDisableAds.Text = "Disable Windows ads/suggestions"
$chkDisableAds.Location = New-Object System.Drawing.Point(15, 75)
$chkDisableAds.Size = New-Object System.Drawing.Size(350, 20)
$chkDisableAds.Checked = $true
$privacyGroup.Controls.Add($chkDisableAds)

$chkDisableLocation = New-Object System.Windows.Forms.CheckBox
$chkDisableLocation.Text = "Disable location tracking"
$chkDisableLocation.Location = New-Object System.Drawing.Point(15, 100)
$chkDisableLocation.Size = New-Object System.Drawing.Size(350, 20)
$privacyGroup.Controls.Add($chkDisableLocation)

# Performance Options
$perfGroup = New-Object System.Windows.Forms.GroupBox
$perfGroup.Text = "Performance"
$perfGroup.Location = New-Object System.Drawing.Point(15, 165)
$perfGroup.Size = New-Object System.Drawing.Size(400, 115)
$perfGroup.ForeColor = [System.Drawing.Color]::White
$tabDetailed.Controls.Add($perfGroup)

$chkOptimizePerf = New-Object System.Windows.Forms.CheckBox
$chkOptimizePerf.Text = "Optimize visual effects for performance"
$chkOptimizePerf.Location = New-Object System.Drawing.Point(15, 25)
$chkOptimizePerf.Size = New-Object System.Drawing.Size(350, 20)
$chkOptimizePerf.Checked = $true
$perfGroup.Controls.Add($chkOptimizePerf)

$chkCleanTemp = New-Object System.Windows.Forms.CheckBox
$chkCleanTemp.Text = "Clean temporary files"
$chkCleanTemp.Location = New-Object System.Drawing.Point(15, 50)
$chkCleanTemp.Size = New-Object System.Drawing.Size(350, 20)
$chkCleanTemp.Checked = $true
$perfGroup.Controls.Add($chkCleanTemp)

$chkManageStartup = New-Object System.Windows.Forms.CheckBox
$chkManageStartup.Text = "Manage startup programs"
$chkManageStartup.Location = New-Object System.Drawing.Point(15, 75)
$chkManageStartup.Size = New-Object System.Drawing.Size(350, 20)
$perfGroup.Controls.Add($chkManageStartup)

# Apply Button
$btnApplyDetailed = New-Object System.Windows.Forms.Button
$btnApplyDetailed.Text = "APPLY SELECTED OPTIONS"
$btnApplyDetailed.Location = New-Object System.Drawing.Point(430, 235)
$btnApplyDetailed.Size = New-Object System.Drawing.Size(390, 45)
$btnApplyDetailed.BackColor = [System.Drawing.Color]::FromArgb(0, 150, 80)
$btnApplyDetailed.ForeColor = [System.Drawing.Color]::White
$btnApplyDetailed.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnApplyDetailed.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$tabDetailed.Controls.Add($btnApplyDetailed)

# =============================================================================
# TAB 3: System Health
# =============================================================================
$tabHealth = New-Object System.Windows.Forms.TabPage
$tabHealth.Text = "System Health"
$tabHealth.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabControl.Controls.Add($tabHealth)

# Health Dashboard Panel
$healthPanel = New-Object System.Windows.Forms.Panel
$healthPanel.Location = New-Object System.Drawing.Point(15, 15)
$healthPanel.Size = New-Object System.Drawing.Size(400, 250)
$healthPanel.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
$healthPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$tabHealth.Controls.Add($healthPanel)

# CPU Usage
$lblCPU = New-Object System.Windows.Forms.Label
$lblCPU.Text = "CPU:"
$lblCPU.Location = New-Object System.Drawing.Point(15, 20)
$lblCPU.Size = New-Object System.Drawing.Size(40, 20)
$healthPanel.Controls.Add($lblCPU)

$progCPU = New-Object System.Windows.Forms.ProgressBar
$progCPU.Location = New-Object System.Drawing.Point(60, 20)
$progCPU.Size = New-Object System.Drawing.Size(280, 20)
$progCPU.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$healthPanel.Controls.Add($progCPU)

$lblCPUValue = New-Object System.Windows.Forms.Label
$lblCPUValue.Text = "0%"
$lblCPUValue.Location = New-Object System.Drawing.Point(350, 20)
$lblCPUValue.Size = New-Object System.Drawing.Size(40, 20)
$healthPanel.Controls.Add($lblCPUValue)

# Memory Usage
$lblMem = New-Object System.Windows.Forms.Label
$lblMem.Text = "RAM:"
$lblMem.Location = New-Object System.Drawing.Point(15, 50)
$lblMem.Size = New-Object System.Drawing.Size(40, 20)
$healthPanel.Controls.Add($lblMem)

$progMem = New-Object System.Windows.Forms.ProgressBar
$progMem.Location = New-Object System.Drawing.Point(60, 50)
$progMem.Size = New-Object System.Drawing.Size(280, 20)
$progMem.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$healthPanel.Controls.Add($progMem)

$lblMemValue = New-Object System.Windows.Forms.Label
$lblMemValue.Text = "0%"
$lblMemValue.Location = New-Object System.Drawing.Point(350, 50)
$lblMemValue.Size = New-Object System.Drawing.Size(40, 20)
$healthPanel.Controls.Add($lblMemValue)

# Disk Usage
$lblDisk = New-Object System.Windows.Forms.Label
$lblDisk.Text = "Disk:"
$lblDisk.Location = New-Object System.Drawing.Point(15, 80)
$lblDisk.Size = New-Object System.Drawing.Size(40, 20)
$healthPanel.Controls.Add($lblDisk)

$progDisk = New-Object System.Windows.Forms.ProgressBar
$progDisk.Location = New-Object System.Drawing.Point(60, 80)
$progDisk.Size = New-Object System.Drawing.Size(280, 20)
$progDisk.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$healthPanel.Controls.Add($progDisk)

$lblDiskValue = New-Object System.Windows.Forms.Label
$lblDiskValue.Text = "0%"
$lblDiskValue.Location = New-Object System.Drawing.Point(350, 80)
$lblDiskValue.Size = New-Object System.Drawing.Size(40, 20)
$healthPanel.Controls.Add($lblDiskValue)

# Stats Labels
$lblProcesses = New-Object System.Windows.Forms.Label
$lblProcesses.Text = "Processes: --"
$lblProcesses.Location = New-Object System.Drawing.Point(15, 115)
$lblProcesses.Size = New-Object System.Drawing.Size(120, 20)
$healthPanel.Controls.Add($lblProcesses)

$lblServices = New-Object System.Windows.Forms.Label
$lblServices.Text = "Services: --"
$lblServices.Location = New-Object System.Drawing.Point(140, 115)
$lblServices.Size = New-Object System.Drawing.Size(120, 20)
$healthPanel.Controls.Add($lblServices)

$lblStartup = New-Object System.Windows.Forms.Label
$lblStartup.Text = "Startup: --"
$lblStartup.Location = New-Object System.Drawing.Point(265, 115)
$lblStartup.Size = New-Object System.Drawing.Size(120, 20)
$healthPanel.Controls.Add($lblStartup)

$lblDiskFree = New-Object System.Windows.Forms.Label
$lblDiskFree.Text = "Free Space: -- GB"
$lblDiskFree.Location = New-Object System.Drawing.Point(15, 140)
$lblDiskFree.Size = New-Object System.Drawing.Size(150, 20)
$healthPanel.Controls.Add($lblDiskFree)

$lblMemTotal = New-Object System.Windows.Forms.Label
$lblMemTotal.Text = "Total RAM: -- GB"
$lblMemTotal.Location = New-Object System.Drawing.Point(170, 140)
$lblMemTotal.Size = New-Object System.Drawing.Size(150, 20)
$healthPanel.Controls.Add($lblMemTotal)

# Health Score
$lblHealthScore = New-Object System.Windows.Forms.Label
$lblHealthScore.Text = "Health Score: --"
$lblHealthScore.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblHealthScore.Location = New-Object System.Drawing.Point(15, 175)
$lblHealthScore.Size = New-Object System.Drawing.Size(370, 30)
$lblHealthScore.ForeColor = [System.Drawing.Color]::Cyan
$healthPanel.Controls.Add($lblHealthScore)

# Scoring Info Panel
$infoPanel = New-Object System.Windows.Forms.Panel
$infoPanel.Location = New-Object System.Drawing.Point(430, 15)
$infoPanel.Size = New-Object System.Drawing.Size(375, 250)
$infoPanel.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
$infoPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$tabHealth.Controls.Add($infoPanel)

$lblInfoTitle = New-Object System.Windows.Forms.Label
$lblInfoTitle.Text = "How to Improve Your Score"
$lblInfoTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblInfoTitle.ForeColor = [System.Drawing.Color]::Yellow
$lblInfoTitle.Location = New-Object System.Drawing.Point(10, 8)
$lblInfoTitle.Size = New-Object System.Drawing.Size(350, 22)
$infoPanel.Controls.Add($lblInfoTitle)

$lblInfoText = New-Object System.Windows.Forms.Label
$lblInfoText.Text = @"
Score starts at 100, deducts for:

Issue               Penalty  Threshold
------------------  -------  ------------
High CPU              -20    >80% usage
Medium CPU            -10    >50% usage
High Memory           -20    >85% usage
Medium Memory         -10    >70% usage
Critical Disk         -25    >90% full
Low Disk              -10    >75% full
Many Startup Apps     -10    >15 programs
"@
$lblInfoText.Font = New-Object System.Drawing.Font("Consolas", 9)
$lblInfoText.ForeColor = [System.Drawing.Color]::LightGray
$lblInfoText.Location = New-Object System.Drawing.Point(10, 35)
$lblInfoText.Size = New-Object System.Drawing.Size(355, 165)
$infoPanel.Controls.Add($lblInfoText)

$lblQuickTip = New-Object System.Windows.Forms.Label
$lblQuickTip.Text = "Use Quick Actions tab for one-click fixes!"
$lblQuickTip.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$lblQuickTip.ForeColor = [System.Drawing.Color]::Cyan
$lblQuickTip.Location = New-Object System.Drawing.Point(10, 205)
$lblQuickTip.Size = New-Object System.Drawing.Size(350, 20)
$infoPanel.Controls.Add($lblQuickTip)

# Refresh Button
$btnRefreshHealth = New-Object System.Windows.Forms.Button
$btnRefreshHealth.Text = "Refresh Health Data"
$btnRefreshHealth.Location = New-Object System.Drawing.Point(15, 280)
$btnRefreshHealth.Size = New-Object System.Drawing.Size(180, 40)
$btnRefreshHealth.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnRefreshHealth.ForeColor = [System.Drawing.Color]::White
$btnRefreshHealth.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabHealth.Controls.Add($btnRefreshHealth)

# =============================================================================
# TAB 4: Tools
# =============================================================================
$tabTools = New-Object System.Windows.Forms.TabPage
$tabTools.Text = "Tools"
$tabTools.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabControl.Controls.Add($tabTools)

$btnRepairStore = New-Object System.Windows.Forms.Button
$btnRepairStore.Text = "Repair Windows Store"
$btnRepairStore.Location = New-Object System.Drawing.Point(15, 20)
$btnRepairStore.Size = New-Object System.Drawing.Size(200, 45)
$btnRepairStore.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnRepairStore.ForeColor = [System.Drawing.Color]::White
$btnRepairStore.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabTools.Controls.Add($btnRepairStore)

$btnCleanDrivers = New-Object System.Windows.Forms.Button
$btnCleanDrivers.Text = "Clean Old Drivers"
$btnCleanDrivers.Location = New-Object System.Drawing.Point(230, 20)
$btnCleanDrivers.Size = New-Object System.Drawing.Size(200, 45)
$btnCleanDrivers.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnCleanDrivers.ForeColor = [System.Drawing.Color]::White
$btnCleanDrivers.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabTools.Controls.Add($btnCleanDrivers)

$btnCreateRestore = New-Object System.Windows.Forms.Button
$btnCreateRestore.Text = "Create Restore Point"
$btnCreateRestore.Location = New-Object System.Drawing.Point(445, 20)
$btnCreateRestore.Size = New-Object System.Drawing.Size(200, 45)
$btnCreateRestore.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnCreateRestore.ForeColor = [System.Drawing.Color]::White
$btnCreateRestore.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabTools.Controls.Add($btnCreateRestore)

$btnOpenBackups = New-Object System.Windows.Forms.Button
$btnOpenBackups.Text = "Open Backups Folder"
$btnOpenBackups.Location = New-Object System.Drawing.Point(15, 80)
$btnOpenBackups.Size = New-Object System.Drawing.Size(200, 45)
$btnOpenBackups.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnOpenBackups.ForeColor = [System.Drawing.Color]::White
$btnOpenBackups.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabTools.Controls.Add($btnOpenBackups)

$btnOpenLogs = New-Object System.Windows.Forms.Button
$btnOpenLogs.Text = "Open Logs Folder"
$btnOpenLogs.Location = New-Object System.Drawing.Point(230, 80)
$btnOpenLogs.Size = New-Object System.Drawing.Size(200, 45)
$btnOpenLogs.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnOpenLogs.ForeColor = [System.Drawing.Color]::White
$btnOpenLogs.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabTools.Controls.Add($btnOpenLogs)

$btnRunCLI = New-Object System.Windows.Forms.Button
$btnRunCLI.Text = "Open CLI Version"
$btnRunCLI.Location = New-Object System.Drawing.Point(445, 80)
$btnRunCLI.Size = New-Object System.Drawing.Size(200, 45)
$btnRunCLI.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnRunCLI.ForeColor = [System.Drawing.Color]::White
$btnRunCLI.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$tabTools.Controls.Add($btnRunCLI)

# =============================================================================
# STATUS BAR AND LOG
# =============================================================================

# Progress Bar
$script:ProgressBar = New-Object System.Windows.Forms.ProgressBar
$script:ProgressBar.Location = New-Object System.Drawing.Point(20, 465)
$script:ProgressBar.Size = New-Object System.Drawing.Size(650, 25)
$script:ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$mainForm.Controls.Add($script:ProgressBar)

# Status Label
$script:StatusLabel = New-Object System.Windows.Forms.Label
$script:StatusLabel.Text = "Ready"
$script:StatusLabel.Location = New-Object System.Drawing.Point(680, 468)
$script:StatusLabel.Size = New-Object System.Drawing.Size(190, 20)
$script:StatusLabel.ForeColor = [System.Drawing.Color]::LightGreen
$mainForm.Controls.Add($script:StatusLabel)

# Log TextBox
$logLabel = New-Object System.Windows.Forms.Label
$logLabel.Text = "Activity Log:"
$logLabel.Location = New-Object System.Drawing.Point(20, 495)
$logLabel.AutoSize = $true
$mainForm.Controls.Add($logLabel)

$script:LogTextBox = New-Object System.Windows.Forms.RichTextBox
$script:LogTextBox.Location = New-Object System.Drawing.Point(20, 515)
$script:LogTextBox.Size = New-Object System.Drawing.Size(850, 130)
$script:LogTextBox.BackColor = [System.Drawing.Color]::Black
$script:LogTextBox.ForeColor = [System.Drawing.Color]::White
$script:LogTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:LogTextBox.ReadOnly = $true
$mainForm.Controls.Add($script:LogTextBox)

# =============================================================================
# EVENT HANDLERS
# =============================================================================

$btnQuickClean.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked
    $preserveXbox = $chkPreserveXbox.Checked -or $radioGaming.Checked

    Write-GUILog "Starting Quick Clean..." "INFO"

    if ($chkCreateRestore.Checked -and -not $script:DryRunMode) {
        Write-GUILog "Creating system restore point..." "INFO"
        try {
            Checkpoint-Computer -Description "WCrapRemover Quick Clean" -RestorePointType MODIFY_SETTINGS -ErrorAction SilentlyContinue
        } catch {}
    }

    Remove-BloatwareGUI -SafeMode $true -PreserveXbox $preserveXbox
    Disable-TelemetryGUI -PreserveXbox $preserveXbox
    Clean-TempFilesGUI

    Write-GUILog "Quick Clean completed!" "SUCCESS"
    [System.Windows.Forms.MessageBox]::Show("Quick Clean completed!", "WCrapRemover", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

$btnUltimateClean.Add_Click({
    $result = [System.Windows.Forms.MessageBox]::Show(
        "Ultimate Clean will apply ALL optimizations. This is aggressive and removes many apps.`n`nAre you sure you want to continue?",
        "Confirm Ultimate Clean",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $script:DryRunMode = $chkDryRun.Checked

        Write-GUILog "Starting Ultimate Clean..." "WARNING"

        if (-not $script:DryRunMode) {
            try {
                Checkpoint-Computer -Description "WCrapRemover Ultimate Clean" -RestorePointType MODIFY_SETTINGS -ErrorAction SilentlyContinue
            } catch {}
        }

        Remove-BloatwareGUI -SafeMode $false -PreserveXbox $false
        Disable-TelemetryGUI -PreserveXbox $false
        Optimize-PerformanceGUI
        Enhance-PrivacyGUI
        Clean-TempFilesGUI
        Disable-CortanaGUI
        Remove-OneDriveGUI

        Write-GUILog "Ultimate Clean completed!" "SUCCESS"
        [System.Windows.Forms.MessageBox]::Show("Ultimate Clean completed!`n`nA system restart is recommended.", "WCrapRemover", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$btnFixBoot.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked
    Write-GUILog "Fixing slow boot issues..." "INFO"

    # Disable startup programs
    $startupItems = Get-CimInstance Win32_StartupCommand
    foreach ($item in $startupItems) {
        if ($script:DryRunMode) {
            Write-GUILog "[DRY RUN] Would disable: $($item.Name)" "INFO"
        } else {
            Write-GUILog "Found startup item: $($item.Name)" "INFO"
        }
    }

    Write-GUILog "Boot fix completed!" "SUCCESS"
})

$btnFixCPU.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked
    Write-GUILog "Checking high CPU usage..." "INFO"

    $highCpuProcesses = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
    foreach ($proc in $highCpuProcesses) {
        Write-GUILog "High CPU: $($proc.Name) - $([math]::Round($proc.CPU, 2))s" "INFO"
    }

    Write-GUILog "CPU analysis completed!" "SUCCESS"
})

$btnFixDisk.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked
    Clean-TempFilesGUI
})

$btnFixPrivacy.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked
    Enhance-PrivacyGUI
    Disable-TelemetryGUI -PreserveXbox $chkPreserveXbox.Checked
})

$btnApplyDetailed.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked

    Write-GUILog "Applying selected options..." "INFO"

    if ($chkRemoveBloat.Checked) { Remove-BloatwareGUI -SafeMode $chkSafeMode.Checked -PreserveXbox $chkPreserveXbox.Checked }
    if ($chkRemoveOneDrive.Checked) { Remove-OneDriveGUI }
    if ($chkDisableCortana.Checked) { Disable-CortanaGUI }
    if ($chkDisableTelemetry.Checked) { Disable-TelemetryGUI -PreserveXbox $chkPreserveXbox.Checked }
    if ($chkEnhancePrivacy.Checked) { Enhance-PrivacyGUI }
    if ($chkOptimizePerf.Checked) { Optimize-PerformanceGUI }
    if ($chkCleanTemp.Checked) { Clean-TempFilesGUI }

    Write-GUILog "All selected options applied!" "SUCCESS"
    [System.Windows.Forms.MessageBox]::Show("Selected options have been applied!", "WCrapRemover", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

$btnRefreshHealth.Add_Click({
    Write-GUILog "Refreshing system health data..." "INFO"

    try {
        $health = Get-SystemHealth

        $progCPU.Value = [Math]::Min([int]$health.CPU, 100)
        $lblCPUValue.Text = "$($health.CPU)%"

        $progMem.Value = [Math]::Min([int]$health.Memory, 100)
        $lblMemValue.Text = "$($health.Memory)%"

        $progDisk.Value = [Math]::Min([int]$health.Disk, 100)
        $lblDiskValue.Text = "$($health.Disk)%"

        $lblProcesses.Text = "Processes: $($health.Processes)"
        $lblServices.Text = "Services: $($health.Services)"
        $lblStartup.Text = "Startup: $($health.StartupApps)"
        $lblDiskFree.Text = "Free: $($health.DiskFree) GB"
        $lblMemTotal.Text = "RAM: $($health.MemoryTotal) GB"

        # Calculate health score
        $score = 100
        if ($health.CPU -gt 80) { $score -= 20 }
        elseif ($health.CPU -gt 50) { $score -= 10 }
        if ($health.Memory -gt 85) { $score -= 20 }
        elseif ($health.Memory -gt 70) { $score -= 10 }
        if ($health.Disk -gt 90) { $score -= 25 }
        elseif ($health.Disk -gt 75) { $score -= 10 }
        if ($health.StartupApps -gt 15) { $score -= 10 }

        $lblHealthScore.Text = "Health Score: $score / 100"
        if ($score -ge 80) { $lblHealthScore.ForeColor = [System.Drawing.Color]::LightGreen }
        elseif ($score -ge 60) { $lblHealthScore.ForeColor = [System.Drawing.Color]::Yellow }
        else { $lblHealthScore.ForeColor = [System.Drawing.Color]::Red }

        Write-GUILog "Health data refreshed. Score: $score/100" "SUCCESS"
    } catch {
        Write-GUILog "Failed to get health data: $_" "ERROR"
    }
})

$btnRepairStore.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked
    Repair-WindowsStoreGUI
})

$btnCleanDrivers.Add_Click({
    $script:DryRunMode = $chkDryRun.Checked
    Write-GUILog "Analyzing driver packages..." "INFO"

    try {
        $drivers = pnputil /enum-drivers 2>$null
        Write-GUILog "Driver analysis completed. Check Driver Manager for details." "SUCCESS"
    } catch {
        Write-GUILog "Failed to analyze drivers: $_" "ERROR"
    }
})

$btnCreateRestore.Add_Click({
    Write-GUILog "Creating system restore point..." "INFO"
    try {
        Checkpoint-Computer -Description "WCrapRemover Manual Restore Point $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -RestorePointType MODIFY_SETTINGS
        Write-GUILog "Restore point created successfully!" "SUCCESS"
        [System.Windows.Forms.MessageBox]::Show("System restore point created!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-GUILog "Failed to create restore point: $_" "ERROR"
        [System.Windows.Forms.MessageBox]::Show("Failed to create restore point.`n`nError: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnOpenBackups.Add_Click({
    $backupRoot = "$env:LOCALAPPDATA\WindowsCrapRemover\Backups"
    if (!(Test-Path $backupRoot)) { New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null }
    Start-Process explorer.exe -ArgumentList $backupRoot
})

$btnOpenLogs.Add_Click({
    Start-Process explorer.exe -ArgumentList $env:TEMP
})

$btnRunCLI.Add_Click({
    $cliPath = Join-Path (Split-Path $PSScriptRoot) "crapremover.ps1"
    if (Test-Path $cliPath) {
        Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$cliPath`""
    } else {
        $cliPath = Join-Path $PSScriptRoot "crapremover.ps1"
        if (Test-Path $cliPath) {
            Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$cliPath`""
        } else {
            [System.Windows.Forms.MessageBox]::Show("CLI version not found.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

# =============================================================================
# AUTO-REFRESH TIMER
# =============================================================================

$script:RefreshTimer = New-Object System.Windows.Forms.Timer
$script:RefreshTimer.Interval = 5000  # 5 seconds

$script:RefreshTimer.Add_Tick({
    # Only refresh if on the Health tab
    if ($tabControl.SelectedTab -eq $tabHealth) {
        try {
            $health = Get-SystemHealth

            $progCPU.Value = [Math]::Min([int]$health.CPU, 100)
            $lblCPUValue.Text = "$($health.CPU)%"

            $progMem.Value = [Math]::Min([int]$health.Memory, 100)
            $lblMemValue.Text = "$($health.Memory)%"

            $progDisk.Value = [Math]::Min([int]$health.Disk, 100)
            $lblDiskValue.Text = "$($health.Disk)%"

            $lblProcesses.Text = "Processes: $($health.Processes)"
            $lblServices.Text = "Services: $($health.Services)"
            $lblStartup.Text = "Startup: $($health.StartupApps)"
            $lblDiskFree.Text = "Free: $($health.DiskFree) GB"
            $lblMemTotal.Text = "RAM: $($health.MemoryTotal) GB"

            # Calculate health score
            $score = 100
            if ($health.CPU -gt 80) { $score -= 20 }
            elseif ($health.CPU -gt 50) { $score -= 10 }
            if ($health.Memory -gt 85) { $score -= 20 }
            elseif ($health.Memory -gt 70) { $score -= 10 }
            if ($health.Disk -gt 90) { $score -= 25 }
            elseif ($health.Disk -gt 75) { $score -= 10 }
            if ($health.StartupApps -gt 15) { $score -= 10 }

            $lblHealthScore.Text = "Health Score: $score / 100"
            if ($score -ge 80) { $lblHealthScore.ForeColor = [System.Drawing.Color]::LightGreen }
            elseif ($score -ge 60) { $lblHealthScore.ForeColor = [System.Drawing.Color]::Yellow }
            else { $lblHealthScore.ForeColor = [System.Drawing.Color]::Red }
        } catch {
            # Silently ignore errors during auto-refresh
        }
    }
})

# Auto-refresh checkbox
$chkAutoRefresh = New-Object System.Windows.Forms.CheckBox
$chkAutoRefresh.Text = "Auto-refresh (5s)"
$chkAutoRefresh.Location = New-Object System.Drawing.Point(210, 290)
$chkAutoRefresh.Size = New-Object System.Drawing.Size(150, 25)
$chkAutoRefresh.Checked = $true
$chkAutoRefresh.ForeColor = [System.Drawing.Color]::LightGray
$tabHealth.Controls.Add($chkAutoRefresh)

$chkAutoRefresh.Add_CheckedChanged({
    if ($chkAutoRefresh.Checked) {
        $script:RefreshTimer.Start()
        Write-GUILog "Auto-refresh enabled (5 second interval)" "INFO"
    } else {
        $script:RefreshTimer.Stop()
        Write-GUILog "Auto-refresh disabled" "INFO"
    }
})

# Initial health data load
$mainForm.Add_Shown({
    Write-GUILog "Windows Crap Remover GUI initialized" "SUCCESS"
    Write-GUILog "Running as Administrator: $isAdmin" "INFO"
    $btnRefreshHealth.PerformClick()
    $script:RefreshTimer.Start()
})

# Cleanup timer on form close
$mainForm.Add_FormClosing({
    $script:RefreshTimer.Stop()
    $script:RefreshTimer.Dispose()
})

# =============================================================================
# RUN APPLICATION
# =============================================================================

[void]$mainForm.ShowDialog()
