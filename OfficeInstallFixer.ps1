# Microsoft Office Installation Repair Script by Murr 
# https://github.com/vtstv/OfficeInstallFixer
# Run as Administrator

# Set information display preferences
$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"
$VerbosePreference = "Continue"

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    Write-Host $logMessage
    Add-Content -Path "$env:USERPROFILE\Desktop\Office_Repair_Log.txt" -Value $logMessage
}

# Function to check if script is running as administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

# Check for administrator rights
if (-not (Test-Admin)) {
    Write-Log "Script must be run as administrator!" "ERROR"
    Write-Log "Please restart PowerShell as administrator and run the script again." "ERROR"
    pause
    exit
}

Write-Log "Starting Microsoft Office installation diagnostics and repair" "INFO"

# Collect system information
Write-Log "Collecting system information..." "INFO"
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$diskInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeSpaceGB = [math]::Round($diskInfo.FreeSpace / 1GB, 2)

Write-Log "Operating System: $($osInfo.Caption) $($osInfo.Version)" "INFO"
Write-Log "Free space on drive C:: $freeSpaceGB GB" "INFO"

# Check internet connection
Write-Log "Checking internet connection..." "INFO"
try {
    $internetCheck = Test-NetConnection -ComputerName "www.microsoft.com" -InformationLevel Quiet
    if ($internetCheck) {
        Write-Log "Internet connection is working properly." "INFO"
    } else {
        Write-Log "Internet connection issues detected! Please check your connection." "WARNING"
    }
} catch {
    Write-Log "Failed to check internet connection" "ERROR"
}

# Check for installed Office versions
Write-Log "Checking installed Office products..." "INFO"
$installedOffice = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Office*" -or $_.Name -like "*Microsoft 365*" }

if ($installedOffice) {
    Write-Log "Found installed Office products:" "INFO"
    foreach ($product in $installedOffice) {
        Write-Log "- $($product.Name) (IdentifyingNumber: $($product.IdentifyingNumber))" "INFO"
    }
} else {
    Write-Log "No installed Office products found in registry." "INFO"
}

# Check for Office processes
Write-Log "Checking Office processes..." "INFO"
$officeProcesses = Get-Process | Where-Object { $_.Name -like "*outlook*" -or $_.Name -like "*word*" -or $_.Name -like "*excel*" -or $_.Name -like "*powerpnt*" -or $_.Name -like "*onenote*" -or $_.Name -like "*msaccess*" -or $_.Name -like "*publisher*" -or $_.Name -like "*onenotem*" -or $_.Name -like "*winword*" -or $_.Name -like "*officeclicktorun*" -or $_.Name -like "*appvshnotify*" -or $_.Name -like "*firstrun*" -or $_.Name -like "*groove*" -or $_.Name -like "*lync*" -or $_.Name -like "*msouc*" -or $_.Name -like "*msosync*" -or $_.Name -like "*SkypeApp*" -or $_.Name -like "*communicator*" }

if ($officeProcesses) {
    Write-Log "Found running Office processes. Attempting to terminate..." "WARNING"
    $officeProcesses | ForEach-Object {
        try {
            $processName = $_.Name
            $processId = $_.Id
            $_ | Stop-Process -Force
            Write-Log "Process $processName (ID: $processId) terminated." "INFO"
        } catch {
            Write-Log "Failed to terminate process" "ERROR"
        }
    }
} else {
    Write-Log "No running Office processes found." "INFO"
}

# Stop Office services
Write-Log "Stopping Office services..." "INFO"
$officeServices = Get-Service | Where-Object { $_.Name -like "*office*" -or $_.Name -like "*click*run*" -or $_.Name -like "*ClickToRunSvc*" }

if ($officeServices) {
    foreach ($service in $officeServices) {
        try {
            $serviceName = $service.Name
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Write-Log "Service $serviceName stopped." "INFO"
        } catch {
            Write-Log "Failed to stop service" "ERROR"
        }
    }
} else {
    Write-Log "No Office services found." "INFO"
}

# Path for temporary files
$tempFolder = "$env:TEMP\OfficeRepair"
New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

# Download Office removal tool 
Write-Log "Downloading Office setup support tool (SaRA)..." "INFO"
$setupProgramUrl = "https://aka.ms/SaRA_CommandLineVersionFiles"
$setupProgramPath = "$tempFolder\SaRACmd.zip"

try {
    Invoke-WebRequest -Uri $setupProgramUrl -OutFile $setupProgramPath
    Write-Log "SaRA tool downloaded successfully." "INFO"
    
    # Extract ZIP archive
    Write-Log "Extracting Office removal tool..." "INFO"
    Expand-Archive -Path $setupProgramPath -DestinationPath $tempFolder -Force
    
    # Run Office removal tool
    Write-Log "Running Office removal tool..." "INFO"
    $saraPath = "$tempFolder\SaRAcmd.exe"
    if (Test-Path $saraPath) {
        Start-Process -FilePath $saraPath -ArgumentList "/Silent /Action:OfficeUninstall /Product:Office" -Wait
        Write-Log "Office removal tool completed." "INFO"
    } else {
        Write-Log "SaRAcmd.exe file not found after extraction." "ERROR"
    }
} catch {
    Write-Log "Error downloading or running Office removal tool" "ERROR"
    Write-Log "Proceeding to manual removal of Office components..." "INFO"
}

# Manual removal of Office components
Write-Log "Removing remaining Office components from registry..." "INFO"

# Array of registry paths to remove
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Office",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office",
    "HKCU:\SOFTWARE\Microsoft\Office",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office*",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Office*",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*",
    "HKLM:\SOFTWARE\Classes\Installer\Products\*"
)

foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            # Get keys containing "Office" in name or data
            $keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | 
                    Where-Object { 
                        $_.Name -like "*Office*" -or 
                        $_.Name -like "*Microsoft 365*" -or 
                        ($props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                         foreach ($value in $props.PSObject.Properties) {
                             if ($value.Value -is [string] -and $value.Value -like "*Office*") {
                                 return $true
                             }
                         }
                         return $false)
                    }

            foreach ($key in $keys) {
                try {
                    $keyPath = $key.PSPath
                    Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed registry key: $keyPath" "INFO"
                } catch {
                    Write-Log "Failed to remove registry key" "ERROR"
                }
            }
        }
    } catch {
        Write-Log "Error processing registry path $path" "ERROR"
    }
}


# Remove Office folders
Write-Log "Removing Office folders..." "INFO"
$officeFolders = @(
    "$env:ProgramFiles\Microsoft Office",
    "${env:ProgramFiles(x86)}\Microsoft Office",
    "$env:ProgramData\Microsoft\Office",
    "$env:LOCALAPPDATA\Microsoft\Office",
    "$env:APPDATA\Microsoft\Office",
    "$env:ProgramFiles\Microsoft Office 15",
    "$env:ProgramFiles\Microsoft Office 16",
    "${env:ProgramFiles(x86)}\Microsoft Office 15",
    "${env:ProgramFiles(x86)}\Microsoft Office 16",
    "$env:ProgramFiles\Common Files\microsoft shared\ClickToRun",
    "${env:ProgramFiles(x86)}\Common Files\microsoft shared\ClickToRun",
    "$env:ProgramFiles\Microsoft Office\root",
    "${env:ProgramFiles(x86)}\Microsoft Office\root",
    "$env:ProgramData\Microsoft Help",
    "$env:LOCALAPPDATA\Microsoft\Office\15.0",
    "$env:LOCALAPPDATA\Microsoft\Office\16.0",
    "$env:APPDATA\Microsoft\Office\15.0",
    "$env:APPDATA\Microsoft\Office\16.0",
    "$env:LOCALAPPDATA\Microsoft\Office\OTele",
    "$env:LOCALAPPDATA\Microsoft\OneNote",
    "$env:APPDATA\Microsoft\Templates",
    "$env:LOCALAPPDATA\Microsoft\MSOIdentityCRL",
    "$env:LOCALAPPDATA\Microsoft\MSOTraceV4"
)

foreach ($folder in $officeFolders) {
    if (Test-Path $folder) {
        try {
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed folder: $folder" "INFO"
        } catch {
            Write-Log "Failed to remove folder $folder" "ERROR"
        }
    }
}

# Clean temporary files
Write-Log "Cleaning temporary files..." "INFO"
$tempFolders = @(
    "$env:TEMP\OfficeC2R*",
    "$env:TEMP\Microsoft Office*",
    "$env:TEMP\MSI*.tmp",
    "$env:TEMP\MSO*.tmp"
)

foreach ($folder in $tempFolders) {
    try {
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Removed temporary files: $folder" "INFO"
    } catch {
        Write-Log "Error removing temporary files $folder" "ERROR"
    }
}

# Reset Windows Installer settings
Write-Log "Resetting Windows Installer settings..." "INFO"
try {
    Stop-Service -Name "msiserver" -Force -ErrorAction SilentlyContinue
    Start-Service -Name "msiserver" -ErrorAction SilentlyContinue
    Write-Log "Windows Installer service restarted." "INFO"
} catch {
    Write-Log "Error restarting Windows Installer service" "ERROR"
}

# Check and repair system components
Write-Log "Running system file check (SFC)..." "INFO"
try {
    Start-Process -FilePath "sfc" -ArgumentList "/scannow" -Wait -NoNewWindow
    Write-Log "System file check completed." "INFO"
} catch {
    Write-Log "Error running SFC" "ERROR"
}

Write-Log "Running system image check (DISM)..." "INFO"
try {
    Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait -NoNewWindow
    Write-Log "System image check completed." "INFO"
} catch {
    Write-Log "Error running DISM" "ERROR"
}

# Reset Windows Update settings
Write-Log "Resetting Windows Update settings..." "INFO"
try {
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "bits" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "cryptsvc" -Force -ErrorAction SilentlyContinue
    
    # Clean SoftwareDistribution folder
    if (Test-Path "$env:SystemRoot\SoftwareDistribution") {
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    Start-Service -Name "bits" -ErrorAction SilentlyContinue
    Start-Service -Name "cryptsvc" -ErrorAction SilentlyContinue
    
    Write-Log "Windows Update settings reset." "INFO"
} catch {
    Write-Log "Error resetting Windows Update settings" "ERROR"
}

# Download Office Deployment Tool
Write-Log "Downloading Office Deployment Tool..." "INFO"
$odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_15330-20205.exe"
$odtPath = "$tempFolder\ODT.exe"

try {
    Invoke-WebRequest -Uri $odtUrl -OutFile $odtPath
    Write-Log "Office Deployment Tool downloaded successfully." "INFO"
    
    # Extract ODT
    Start-Process -FilePath $odtPath -ArgumentList "/extract:$tempFolder\ODT" -Wait -NoNewWindow
    Write-Log "Office Deployment Tool extracted." "INFO"
    
    # Create XML configuration file for ODT
    $configXml = @"
<Configuration>
  <Add OfficeClientEdition="64" Channel="Current">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-us" />
    </Product>
  </Add>
  <Updates Enabled="TRUE" />
  <Display Level="None" AcceptEULA="TRUE" />
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
  <Property Name="SharedComputerLicensing" Value="0" />
  <Property Name="PinIconsToTaskbar" Value="TRUE" />
  <Property Name="SCLCacheOverride" Value="0" />
  <RemoveMSI />
</Configuration>
"@
    
    Set-Content -Path "$tempFolder\ODT\configuration.xml" -Value $configXml
    
    Write-Log "Configuration file for Office Deployment Tool created." "INFO"
    Write-Log "ODT prepared for Microsoft 365 Apps installation." "INFO"
    Write-Log "To install Office run: $tempFolder\ODT\setup.exe /configure $tempFolder\ODT\configuration.xml" "INFO"
} catch {
    Write-Log "Error downloading or configuring Office Deployment Tool" "ERROR"
}

# Check hosts file for activation blocking
Write-Log "Checking hosts file for Office activation blocks..." "INFO"
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content -Path $hostsFile -ErrorAction SilentlyContinue

$officeDomains = @(
    "officecdn.microsoft.com",
    "officeclient.microsoft.com",
    "office.microsoft.com",
    "office.com",
    "office365.com",
    "odc.officeapps.live.com",
    "office15client.microsoft.com",
    "office.net",
    "outlook.com",
    "office.live.com",
    "activation.sls.microsoft.com"
)

$blockedDomains = @()
foreach ($domain in $officeDomains) {
    if ($hostsContent -match $domain) {
        $blockedDomains += $domain
    }
}

if ($blockedDomains.Count -gt 0) {
    Write-Log "Possible Office domain blocks found in hosts file:" "WARNING"
    foreach ($domain in $blockedDomains) {
        Write-Log "- $domain" "WARNING"
    }
    Write-Log "Recommend removing these entries from $hostsFile" "WARNING"
} else {
    Write-Log "No Office domain blocks found in hosts file." "INFO"
}

# Conclusion
Write-Log "Office installation troubleshooting and repair attempt completed." "INFO"
Write-Log "Log saved to: $env:USERPROFILE\Desktop\Office_Repair_Log.txt" "INFO"
Write-Log "For clean Office installation you can use the prepared Office Deployment Tool:" "INFO"
Write-Log "1. Run as administrator: $tempFolder\ODT\setup.exe /configure $tempFolder\ODT\configuration.xml" "INFO"
Write-Log "If Office installation problems persist, additional diagnostics or Windows reinstallation may be required." "INFO"

# Cleanup
Write-Log "Removing temporary files..." "INFO"
#Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`nScript completed. Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
