# Microsoft Windows Update Fix Script by Murr 
# https://github.com/vtstv/WinFixers

<#
.SYNOPSIS
    Windows Update Fix Script for Error 0x800F081F (CBS_E_SOURCE_MISSING)

.DESCRIPTION
    This script performs a comprehensive fix for Windows Update issues, specifically
    targeting error 0x800F081F. It includes safety checks, logging, and rollback options.
    The script will automatically request administrator privileges if needed.

.PARAMETER SkipSFC
    Skip System File Checker scan (not recommended)

.PARAMETER SkipDISM
    Skip DISM repair operations (not recommended)

.PARAMETER CreateBackup
    Create backup of critical components before making changes (default: true)

.PARAMETER NoElevate
    Skip automatic elevation to administrator (for testing purposes)

.EXAMPLE
    .\Fix-WindowsUpdate.ps1
    Run with all default settings and safety checks

.EXAMPLE
    .\Fix-WindowsUpdate.ps1 -CreateBackup:$false
    Run without creating backups (faster but less safe)

.EXAMPLE
    .\Fix-WindowsUpdate.ps1 -NoElevate
    Run without automatic elevation (will fail if not already admin)
#>

param(
    [switch]$SkipSFC,
    [switch]$SkipDISM,
    [bool]$CreateBackup = $true,
    [switch]$NoElevate
)

# Initialize logging
$LogPath = "C:\Temp\WindowsUpdateFix_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$null = New-Item -Path "C:\Temp" -ItemType Directory -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage -ForegroundColor $(switch($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    })
    Add-Content -Path $LogPath -Value $logMessage
}

function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    param(
        [string]$ScriptPath,
        [array]$Arguments
    )
    
    Write-Host ""
    Write-Host "Administrator privileges are required to run this script." -ForegroundColor Yellow
    Write-Host "The script needs to:" -ForegroundColor Yellow
    Write-Host "  - Stop/start Windows services" -ForegroundColor Cyan
    Write-Host "  - Access system folders (SoftwareDistribution, catroot2)" -ForegroundColor Cyan
    Write-Host "  - Run system repair tools (SFC, DISM)" -ForegroundColor Cyan
    Write-Host "  - Modify Windows Update components" -ForegroundColor Cyan
    Write-Host ""
    
    $response = Read-Host "Would you like to restart this script with administrator privileges? (Y/N)"
    
    if ($response -match '^[Yy]') {
        try {
            Write-Host "Restarting script with administrator privileges..." -ForegroundColor Green
            
            # Build argument string for the elevated process
            $argumentString = ""
            if ($Arguments.Count -gt 0) {
                $escapedArgs = $Arguments | ForEach-Object { 
                    if ($_ -match '\s') { "`"$_`"" } else { $_ } 
                }
                $argumentString = " " + ($escapedArgs -join " ")
            }
            
            # Get the current script path and build the command
            $currentPath = (Get-Location).Path
            $command = "Write-Host 'Starting elevated session from: $currentPath' -ForegroundColor Green; cd '$currentPath'; & '$ScriptPath'$argumentString; Write-Host ''; Write-Host 'Script completed. Press Enter to close this window.' -ForegroundColor Yellow; Read-Host"
            
            # Start elevated PowerShell process
            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = "powershell.exe"
            $processInfo.Arguments = "-NoExit -Command `"$command`""
            $processInfo.UseShellExecute = $true
            $processInfo.Verb = "runas"
            $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
            
            $process = [System.Diagnostics.Process]::Start($processInfo)
            
            Write-Host "Script restarted with administrator privileges in a new window." -ForegroundColor Green
            Write-Host "You can close this window." -ForegroundColor Gray
            
            return $true
        }
        catch {
            Write-Host "Failed to restart with administrator privileges: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Please manually run PowerShell as Administrator and try again." -ForegroundColor Yellow
            return $false
        }
    }
    else {
        Write-Host "Script cancelled. Administrator privileges are required." -ForegroundColor Red
        return $false
    }
}

function Test-ServiceStatus {
    param([string]$ServiceName)
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return @{
            Exists = $true
            Status = $service.Status
            StartType = $service.StartType
        }
    }
    catch {
        return @{
            Exists = $false
            Status = "NotFound"
            StartType = "Unknown"
        }
    }
}

function Stop-WindowsUpdateServices {
    Write-Log "Stopping Windows Update services..."
    
    # Core Windows Update services
    $services = @("wuauserv", "cryptSvc", "bits", "msiserver")
    
    # Additional services that might lock catroot2 files
    $additionalServices = @("CryptSvc", "TrustedInstaller", "appidsvc")
    
    $serviceStates = @{}
    
    # Stop additional services first
    foreach ($service in $additionalServices) {
        $serviceInfo = Test-ServiceStatus -ServiceName $service
        if ($serviceInfo.Exists -and $serviceInfo.Status -eq "Running") {
            try {
                Write-Log "Stopping additional service: $service"
                Stop-Service -Name $service -Force -ErrorAction Stop
                Write-Log "Successfully stopped: $service" -Level "SUCCESS"
                $serviceStates[$service] = $serviceInfo
            }
            catch {
                Write-Log "Failed to stop service $service`: $($_.Exception.Message)" -Level "WARNING"
            }
        }
    }
    
    # Stop core services
    foreach ($service in $services) {
        $serviceInfo = Test-ServiceStatus -ServiceName $service
        $serviceStates[$service] = $serviceInfo
        
        if ($serviceInfo.Exists -and $serviceInfo.Status -eq "Running") {
            try {
                Write-Log "Stopping service: $service"
                Stop-Service -Name $service -Force -ErrorAction Stop
                Write-Log "Successfully stopped: $service" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to stop service $service`: $($_.Exception.Message)" -Level "ERROR"
            }
        }
        else {
            Write-Log "Service $service is already stopped or doesn't exist"
        }
    }
    
    # Give services time to fully stop
    Write-Log "Waiting for services to fully stop..."
    Start-Sleep -Seconds 5
    
    return $serviceStates
}

function Start-WindowsUpdateServices {
    param([hashtable]$OriginalStates)
    
    Write-Log "Starting Windows Update services..."
    
    # Start core services in proper order
    $services = @("msiserver", "bits", "cryptSvc", "wuauserv")
    
    foreach ($service in $services) {
        $originalState = $OriginalStates[$service]
        
        if ($originalState.Exists) {
            try {
                Write-Log "Starting service: $service"
                Start-Service -Name $service -ErrorAction Stop
                Write-Log "Successfully started: $service" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to start service $service`: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    
    # Start additional services that we may have stopped
    $additionalServices = @("appidsvc", "TrustedInstaller")
    
    foreach ($service in $additionalServices) {
        if ($OriginalStates.ContainsKey($service)) {
            $originalState = $OriginalStates[$service]
            if ($originalState.Exists -and $originalState.Status -eq "Running") {
                try {
                    Write-Log "Restarting additional service: $service"
                    Start-Service -Name $service -ErrorAction Stop
                    Write-Log "Successfully restarted: $service" -Level "SUCCESS"
                }
                catch {
                    Write-Log "Failed to restart service $service`: $($_.Exception.Message)" -Level "WARNING"
                }
            }
        }
    }
}

function Backup-CriticalFolders {
    if (-not $CreateBackup) {
        Write-Log "Backup creation skipped by user request"
        return
    }
    
    Write-Log "Creating backup of critical Windows Update folders..."
    
    $backupBase = "C:\Temp\WU_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $null = New-Item -Path $backupBase -ItemType Directory -Force
    
    $foldersToBackup = @{
        "SoftwareDistribution" = "C:\Windows\SoftwareDistribution"
        "catroot2" = "C:\Windows\System32\catroot2"
    }
    
    foreach ($folder in $foldersToBackup.GetEnumerator()) {
        if (Test-Path $folder.Value) {
            try {
                $backupPath = Join-Path $backupBase $folder.Key
                Write-Log "Backing up $($folder.Value) to $backupPath"
                
                # Use robocopy for better handling of locked files
                $robocopyArgs = @(
                    $folder.Value,
                    $backupPath,
                    "/E",           # Copy subdirectories including empty ones
                    "/R:1",         # Retry once on failed copies
                    "/W:1",         # Wait 1 second between retries
                    "/NFL",         # No file list
                    "/NDL",         # No directory list
                    "/NP",          # No progress
                    "/XJ"           # Exclude junction points
                )
                
                $robocopyResult = & robocopy @robocopyArgs 2>&1
                $exitCode = $LASTEXITCODE
                
                # Robocopy exit codes: 0-7 are success, 8+ are errors
                if ($exitCode -le 7) {
                    Write-Log "Backup completed: $($folder.Key)" -Level "SUCCESS"
                    if ($exitCode -gt 0) {
                        Write-Log "Robocopy completed with warnings (exit code: $exitCode)" -Level "WARNING"
                    }
                }
                else {
                    Write-Log "Robocopy failed with exit code: $exitCode" -Level "WARNING"
                    Write-Log "Some files may be locked - will continue with partial backup" -Level "WARNING"
                }
            }
            catch {
                Write-Log "Failed to backup $($folder.Key): $($_.Exception.Message)" -Level "ERROR"
                Write-Log "Attempting alternative backup method..." -Level "WARNING"
                
                # Fallback to PowerShell copy with error continuation
                try {
                    $backupPath = Join-Path $backupBase $folder.Key
                    Copy-Item -Path $folder.Value -Destination $backupPath -Recurse -Force -ErrorAction Continue
                    Write-Log "Partial backup completed using fallback method" -Level "WARNING"
                }
                catch {
                    Write-Log "Fallback backup also failed: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
    }
    
    Write-Log "Backup location: $backupBase" -Level "SUCCESS"
}

function Invoke-SystemFileChecker {
    if ($SkipSFC) {
        Write-Log "System File Checker scan skipped by user request"
        return
    }
    
    Write-Log "Running System File Checker (SFC)..."
    Write-Log "This may take 10-30 minutes depending on your system..."
    
    try {
        $sfcResult = & sfc /scannow 2>&1
        $exitCode = $LASTEXITCODE
        
        Write-Log "SFC scan completed with exit code: $exitCode"
        
        if ($exitCode -eq 0) {
            Write-Log "SFC scan completed successfully - no integrity violations found" -Level "SUCCESS"
        }
        elseif ($exitCode -eq 1) {
            Write-Log "SFC found and repaired corrupted files" -Level "SUCCESS"
        }
        else {
            Write-Log "SFC scan completed with warnings or errors (Exit code: $exitCode)" -Level "WARNING"
        }
    }
    catch {
        Write-Log "Error running SFC: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Invoke-DISMRepair {
    if ($SkipDISM) {
        Write-Log "DISM repair operations skipped by user request"
        return
    }
    
    Write-Log "Running DISM repair operations..."
    
    $dismCommands = @(
        @{ Name = "CheckHealth"; Command = "/Online /Cleanup-Image /CheckHealth" },
        @{ Name = "ScanHealth"; Command = "/Online /Cleanup-Image /ScanHealth" },
        @{ Name = "RestoreHealth"; Command = "/Online /Cleanup-Image /RestoreHealth" }
    )
    
    foreach ($dismOp in $dismCommands) {
        Write-Log "Running DISM $($dismOp.Name)..."
        
        try {
            $dismArgs = $dismOp.Command.Split(' ')
            $result = & DISM.exe $dismArgs 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -eq 0) {
                Write-Log "DISM $($dismOp.Name) completed successfully" -Level "SUCCESS"
            }
            else {
                Write-Log "DISM $($dismOp.Name) completed with warnings (Exit code: $exitCode)" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Error running DISM $($dismOp.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Reset-WindowsUpdateComponents {
    Write-Log "Resetting Windows Update components..."
    
    # Rename folders if they exist
    $foldersToRename = @{
        "C:\Windows\SoftwareDistribution" = "C:\Windows\SoftwareDistribution.old"
        "C:\Windows\System32\catroot2" = "C:\Windows\System32\catroot2.old"
    }
    
    foreach ($folder in $foldersToRename.GetEnumerator()) {
        if (Test-Path $folder.Key) {
            try {
                # Remove old backup if it exists
                if (Test-Path $folder.Value) {
                    Write-Log "Removing existing backup: $($folder.Value)"
                    Remove-Item -Path $folder.Value -Recurse -Force
                }
                
                Write-Log "Renaming $($folder.Key) to $($folder.Value)"
                Rename-Item -Path $folder.Key -NewName (Split-Path $folder.Value -Leaf) -Force
                Write-Log "Successfully renamed folder" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to rename $($folder.Key): $($_.Exception.Message)" -Level "ERROR"
            }
        }
        else {
            Write-Log "Folder not found: $($folder.Key)"
        }
    }
}

function Clear-WindowsUpdateCache {
    Write-Log "Clearing Windows Update download cache..."
    
    $downloadPath = "C:\Windows\SoftwareDistribution\Download"
    
    if (Test-Path $downloadPath) {
        try {
            $items = Get-ChildItem -Path $downloadPath -Force
            if ($items.Count -gt 0) {
                Write-Log "Removing $($items.Count) items from download cache"
                Remove-Item -Path "$downloadPath\*" -Recurse -Force
                Write-Log "Download cache cleared successfully" -Level "SUCCESS"
            }
            else {
                Write-Log "Download cache is already empty"
            }
        }
        catch {
            Write-Log "Failed to clear download cache: $($_.Exception.Message)" -Level "ERROR"
        }
    }
    else {
        Write-Log "Download cache folder not found"
    }
}

function Test-WindowsUpdateHealth {
    Write-Log "Testing Windows Update health..."
    
    try {
        # Test if Windows Update service can be reached
        $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
        Write-Log "Windows Update service status: $($wuService.Status)"
        
        # Test if we can create a Windows Update session
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        Write-Log "Testing Windows Update connectivity..."
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        Write-Log "Found $($searchResult.Updates.Count) available updates" -Level "SUCCESS"
        
        return $true
    }
    catch {
        Write-Log "Windows Update health check failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Show-Summary {
    param([bool]$Success)
    
    Write-Log "=== WINDOWS UPDATE FIX SUMMARY ===" -Level "SUCCESS"
    Write-Log "Log file location: $LogPath"
    
    if ($Success) {
        Write-Log "Windows Update fix completed successfully!" -Level "SUCCESS"
        Write-Log "Recommended next steps:" -Level "SUCCESS"
        Write-Log "1. Restart your computer"
        Write-Log "2. Check for Windows Updates"
        Write-Log "3. Try installing the failed update again"
    }
    else {
        Write-Log "Windows Update fix completed with errors" -Level "WARNING"
        Write-Log "Please review the log file for details"
        Write-Log "You may need to run Windows Update Troubleshooter or contact support"
    }
}

# Main execution
try {
    Write-Host "Windows Update Fix Script v1.1" -ForegroundColor Cyan
    Write-Host "Target error: 0x800F081F (CBS_E_SOURCE_MISSING)" -ForegroundColor Gray
    Write-Host ""
    
    # Check for administrator privileges
    if (-not (Test-AdminRights)) {
        if ($NoElevate) {
            Write-Host "This script requires Administrator privileges!" -ForegroundColor Red
            Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
            exit 1
        }
        else {
            # Attempt auto-elevation
            $scriptPath = $MyInvocation.MyCommand.Path
            $scriptArgs = @()
            
            # Preserve original parameters
            if ($SkipSFC) { $scriptArgs += "-SkipSFC" }
            if ($SkipDISM) { $scriptArgs += "-SkipDISM" }
            if (-not $CreateBackup) { $scriptArgs += "-CreateBackup:`$false" }
            
            $elevated = Request-Elevation -ScriptPath $scriptPath -Arguments $scriptArgs
            
            if ($elevated) {
                exit 0  # Exit this instance as we've started an elevated one
            }
            else {
                exit 1  # Exit with error if elevation failed or was declined
            }
        }
    }
    
    # Initialize logging (now that we're running as admin)
    Write-Log "Starting Windows Update Fix Script" -Level "SUCCESS"
    Write-Log "Script version: 1.1"
    Write-Log "Target error: 0x800F081F (CBS_E_SOURCE_MISSING)"
    Write-Log "Administrator privileges confirmed" -Level "SUCCESS"
    
    # Show what will be done
    Write-Log "=== PLANNED OPERATIONS ==="
    Write-Log "1. Create backup of critical folders: $CreateBackup"
    Write-Log "2. Stop Windows Update services"
    Write-Log "3. Run System File Checker: $(-not $SkipSFC)"
    Write-Log "4. Run DISM repair operations: $(-not $SkipDISM)"
    Write-Log "5. Reset Windows Update components"
    Write-Log "6. Clear update cache"
    Write-Log "7. Restart Windows Update services"
    Write-Log "8. Test Windows Update health"
    
    $response = Read-Host "Do you want to continue? (Y/N)"
    if ($response -notmatch '^[Yy]') {
        Write-Log "Operation cancelled by user"
        exit 0
    }
    
    # Execute fixes
    $serviceStates = Stop-WindowsUpdateServices
    Backup-CriticalFolders
    Invoke-SystemFileChecker
    Invoke-DISMRepair
    Reset-WindowsUpdateComponents
    Clear-WindowsUpdateCache
    Start-WindowsUpdateServices -OriginalStates $serviceStates
    
    # Wait for services to stabilize
    Write-Log "Waiting for services to stabilize..."
    Start-Sleep -Seconds 10
    
    $healthCheck = Test-WindowsUpdateHealth
    Show-Summary -Success $healthCheck
    
    Write-Log "Script execution completed" -Level "SUCCESS"
}
catch {
    Write-Log "Fatal error during script execution: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Show-Summary -Success $false
    exit 1
}