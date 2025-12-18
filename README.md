# WCrapware - Windows Crap Remover

A comprehensive Windows 10/11 debloating and optimisation tool with safety features, system monitoring, and backup/restore capabilities.

**Now available in both CLI and GUI versions!**


## Quick Start

### GUI Version (Recommended for beginners)
```powershell
# Launch the graphical interface
.\crapremover-gui.ps1
```

### CLI Version
```powershell
# Run interactively (requires Admin)
.\crapremover.ps1

# Dry run mode (preview changes without applying)
.\crapremover.ps1 -DryRun

# Auto mode with Gaming profile
.\crapremover.ps1 -AutoMode -Profile Gaming

# Silent auto mode
.\crapremover.ps1 -AutoMode -Profile Privacy -Silent
```


## Command-Line Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-AutoMode` | Switch | Run without interactive prompts |
| `-SafeMode` | Switch | Enhanced allowlist protection during bloatware removal |
| `-DryRun` | Switch | Preview changes without applying them |
| `-Silent` | Switch | Suppress console output |
| `-Profile` | String | Load predefined profile: `Minimal`, `Gaming`, `Work`, `Privacy`, `Ultimate` |
| `-ConfigFile` | String | Path to custom JSON configuration file |
| `-LogFile` | String | Custom log file location |
| `-FixBoot` | Switch | Quick fix: Disable slow startup programs |
| `-FixCPU` | Switch | Quick fix: Stop high CPU usage services |
| `-FixDisk` | Switch | Quick fix: Clean temp files and cache |
| `-FixPrivacy` | Switch | Quick fix: Disable tracking and telemetry |
| `-FixAll` | Switch | Quick fix: Run all fixes above |
| `-QuickStart` | Switch | Launch Quick Start directly |

### Quick Fix Examples

```powershell
# Fix slow boot (disables startup bloat)
.\crapremover.ps1 -FixBoot

# Fix disk space issues
.\crapremover.ps1 -FixDisk

# Run all quick fixes
.\crapremover.ps1 -FixAll

# Preview what fixes would do
.\crapremover.ps1 -FixAll -DryRun

# Quick Start with Gaming profile directly
.\crapremover.ps1 -QuickStart
```

## Features

### GUI Version
The graphical interface (`crapremover-gui.ps1`) provides:
- **Dark themed modern UI** with tabbed navigation
- **Quick Actions tab**: One-click profiles (Gaming, Privacy, Work) and Quick Fixes
- **Detailed Options tab**: Granular control over individual operations
- **System Health tab**: Real-time CPU, RAM, Disk monitoring with health score
- **Tools tab**: Windows Store repair, driver cleanup, restore points
- **Activity Log**: Live scrolling log with color-coded messages
- **Progress Bar**: Visual feedback during operations
- **Dry Run mode**: Preview changes before applying

### Core Functionality

- **Bloatware Removal**: 100+ Microsoft Store apps and third-party bloat
- **Telemetry Disabling**: 60+ telemetry hosts blocked, 40+ registry entries
- **Privacy Enhancement**: Activity tracking, location, webcam, microphone controls
- **Performance Optimization**: Visual effects, services, background apps
- **System Cleanup**: Temp files, scheduled tasks, startup programs

### New in v2.1: Monitoring & Diagnostics

#### System Health Dashboard (Menu: `H`)
Real-time monitoring with:
- CPU, RAM, Disk usage with visual progress bars
- Running processes/services count
- Startup programs count
- Installed apps count
- System uptime
- Overall health score (0-100)

#### System Requirements Checker (Menu: `R`)
Pre-execution compatibility check:
- Windows version validation (requires Build 17763+)
- Disk space verification
- RAM availability
- WSL/Docker/Hyper-V detection
- Development tools protection
- Pending reboot detection

#### Benchmark Comparison (Menu: `B`)
Before/after metrics comparison:
- RAM usage change
- Disk space freed
- Process/service reduction
- Apps removed
- Temp files cleaned


## Profiles

| Profile | Description | Best For |
|---------|-------------|----------|
| `Minimal` | Basic cleanup, keeps most features | New users |
| `Gaming` | Optimized for gaming performance | Gamers |
| `Work` | Keeps productivity features | Office/work machines |
| `Privacy` | Maximum privacy protection | Privacy-conscious users |
| `Ultimate` | Removes everything possible | Advanced users |

### Profile Configuration

```powershell
# Profile settings available:
$config = @{
    RemoveApps = $true           # Remove bloatware apps
    DisableTelemetry = $true     # Disable Windows telemetry
    RemoveOneDrive = $true       # Uninstall OneDrive
    DisableCortana = $true       # Disable Cortana
    CleanScheduledTasks = $true  # Clean telemetry tasks
    DisableWindowsSearch = $false # Disable Windows Search indexing
    RemoveEdge = $false          # Remove Microsoft Edge (Win11)
    OptimizePerformance = $true  # Apply performance tweaks
    EnhancePrivacy = $true       # Enable privacy settings
    CleanupNetwork = $true       # Disable P2P updates
    ManageStartup = $true        # Manage startup programs
    CleanTempFiles = $true       # Clean temporary files
    DisableDefender = $false     # Disable Windows Defender
}
```

### Data Locations

| Path | Purpose |
|------|---------|
| `%LOCALAPPDATA%\WindowsCrapRemover\Backups\` | Registry backups, change logs |
| `%LOCALAPPDATA%\WindowsCrapRemover\Config\` | allowlist/denylist files |
| `%TEMP%\WindowsCrapRemover_*.log` | Session log files |


## Architecture

### Key Functions

```powershell
# Monitoring & Diagnostics
Get-SystemHealth          # Returns hashtable of system metrics
Show-HealthDashboard      # Displays visual health dashboard
Test-SystemRequirements   # Checks compatibility, returns results
Start-Benchmark           # Captures initial system state
Show-BenchmarkComparison  # Displays before/after comparison

# Core Operations
Remove-Bloatware          # Remove apps with allowlist support
Disable-Telemetry         # Disable all telemetry
Optimize-Performance      # Apply performance tweaks
Enhance-Privacy           # Enable privacy settings
Clean-TempFiles           # Clean temporary files
Clean-ScheduledTasks      # Disable telemetry tasks

# System Management
Remove-OneDrive           # Complete OneDrive removal
Disable-Cortana           # Disable Cortana
Disable-WindowsSearch     # Disable Windows Search
Remove-Edge               # Remove Microsoft Edge (Win11 only)
Disable-WindowsDefender   # Disable Windows Defender (dangerous)

# Backup & Recovery
Create-SystemRestorePoint # Create restore point
Backup-RegistryKey        # Backup registry before changes
Save-ChangesLog           # Save changes to JSON
Undo-Changes              # Restore from backup

# Utility
Write-Log                 # Logging with severity levels
Load-Configuration        # Load JSON config
Load-AppLists             # Load allowlist/denylist
```

### Script Variables

```powershell
$script:Changes           # Array of changes made in session
$script:BackupPath        # Current backup directory
$script:ConfigPath        # Config directory
$script:AllowlistPath     # Path to allowlist.txt
$script:DenylistPath      # Path to denylist.txt
$script:BenchmarkData     # Initial benchmark metrics
```


## Allowlist / Denylist

### Creating an Allowlist

```
# %LOCALAPPDATA%\WindowsCrapRemover\Config\allowlist.txt
# Apps to preserve (one per line)
Microsoft.WindowsTerminal
Microsoft.PowerToys
```

### Creating a Denylist

```
# %LOCALAPPDATA%\WindowsCrapRemover\Config\denylist.txt
# Additional apps to remove (supports wildcards)
Company.UnwantedApp
Another.App*
```


## Safe Apps (Never Removed)

The following apps are protected by default:
- Microsoft.WindowsStore
- Microsoft.StorePurchaseApp
- Microsoft.WindowsCalculator
- Microsoft.Windows.Photos
- Microsoft.ScreenSketch
- Microsoft.MSPaint / Microsoft.Paint
- Microsoft.WindowsNotepad
- Microsoft.WindowsTerminal
- Microsoft.HEIFImageExtension
- Microsoft.VP9VideoExtensions
- Microsoft.WebpImageExtension
- Microsoft.DesktopAppInstaller
- Microsoft.XboxGameCallableUI


## Development

### Adding New Bloatware to Remove

Add to `$CommonBloatware` array (line ~816):
```powershell
$CommonBloatware = @(
    # ... existing entries
    "New.AppToRemove",
    "Another.Bloatware*"  # Wildcards supported
)
```

### Adding New Registry Tweaks

Add to relevant function's key array:
```powershell
$newKeys = @(
    @{Path = "HKLM:\PATH\TO\KEY"; Name = "ValueName"; Value = 0}
)
```

### Adding New Telemetry Hosts

Add to `$telemetryHosts` in `Disable-Telemetry` function:
```powershell
$telemetryHosts = @(
    # ... existing hosts
    "new.telemetry.host.com"
)
```


## Safety Features

1. **System Restore Points**: Created before changes
2. **Registry Backups**: Exported before modification
3. **Change Logging**: All changes tracked in JSON
4. **Dry Run Mode**: Preview without applying
5. **Safe Mode**: Enhanced allowlist protection
6. **Confirmation Prompts**: For destructive operations


## Troubleshooting

### Common Issues

**Script won't run**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Admin privileges required**
- Right-click PowerShell > Run as Administrator
- Script auto-elevates but may need manual elevation

**Unicode characters display incorrectly**
- Ensure PowerShell uses UTF-8: `$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.UTF8Encoding]::new()`

### Logs Location
```
%TEMP%\WindowsCrapRemover_YYYYMMDD_HHMMSS.log
```


## Roadmap

- [x] Real-time system health monitoring dashboard
- [x] System requirements checker
- [x] Benchmark/before-after comparison
- [x] One-click fix for common issues
- [x] Automatic driver updater/cleaner
- [x] Windows Store repair functionality
- [x] Automatic scheduled maintenance
- [x] Portable version generator
- [x] GUI version with Windows Forms
- [ ] Cloud backup integration
- [ ] Multi-language support
