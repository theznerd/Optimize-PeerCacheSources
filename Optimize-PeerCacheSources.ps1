<#
.SYNOPSIS
A script to manage your Peer Cache Sources lifecycle.

.DESCRIPTION
Managing Peer Cache Sources in a large environment can be a challenge. Especially 
if you don't have good hardware lifecycle management practices or you are in a
complex environment with many different boundary groups (Peer Cache Sources serve
content to other members in their boundary group). 

The purpose of this script is to take an initial assessment of your environment 
and intelligently decide which devices should be Peer Cache Sources. It will then
lump these devices into a ConfigMgr collection that you define (to apply the proper
client policies to enable the devices as Peer Cache Sources) and monitor them
on a schedule that you set. 

After the initial assessment, the script will attempt to ping the devices to ensure
they are online. For each time the device is marked offline a count will be 
incremented and after reaching a configurable limit the device will be removed
from the group and will be replaced with a new device which matches the criteria.
If on a scheduled scan a device no longer reports a record in DNS (aged out or was 
scavenged out), it is automatically removed from the group and replaced with a new
device which matches the criteria.

The script should initially be run with the -WhatIf switch to give you a report of
the devices which would be confiured as Peer Cache Sources so that you can validate
this against any business criteria you may have. This script assumes that you have
created collections which relate to boundary groups you have configured or locations
that you want to ensure a minimum number of Peer Cache Sources.

.NOTES
#################################
## Optimize Peer Cache Sources ##
## Written By: Nathan Ziehnert ##
## Twitter: @theznerd          ##
## Email: nathan@z-nerd.com    ##
## Website: https://z-nerd.com ##
#################################

VERSIONS
- v1.0: Well... it's been tested. So I guess it's v1.0 now?

- v0.4: Some cleanup and bad gramer (yes, that was intentional). Also fixed
        a couple of the queries that weren't working as planned. Added more
        parameters to support multiple "databases" and blacklists for the
        script, because I'm testing this in an environment with five distinct
        markets, so yeah... probably a good idea.

- v0.3: Added criteria to better evaluate clients (Wireless vs Wired, SSD /
        NVME, Exclude VMs).

        SSD/NVME search requires Win32_DiskDriveToDiskPartition and
        Win32_LogicalDiskToPartition be enabledin the hardware inventory.
        These are not default classes and need to be imported. Details in
        the blog post.

- v0.2: Added functionality to use ConfigMgr for device status instead of ping
        to speed up the scan time. Thanks to Chad Simmons (@chadstech) for the
        idea.

        Added functionality to reconsider blacklist devices IF the threshold
        for Peer Cache Sources is not met. Thanks to Chad Simmons (@chadstech)
        and Glen McCellan (@Glenn_McClellan) for the idea.

- v0.1: Initial version. It doesn't look that pretty. I apologize. Next version
        I will do some more refactoring to hopefully prettify some of this and
        make it a bit more readable.

- v0.0: Does anyone actually read this? Probably yes now that it's been added to
        the Git commit log.
#>
param(
    # Whatif Switch
    [Parameter()]
    [switch]
    $WhatIf,

    # Path to the Settings.ini file - defaults to $PSScriptRoot\__OPCSSettings.ini
    [Parameter()]
    [string]
    $SettingsPath="$PSScriptRoot\__OPCSSettings.ini",

    # Path to the xml "Database" file - defaults to $PSScriptRoot\__OPCSData.xml
    [Parameter()]
    [string]
    $DataPath="$PSScriptRoot\__OPCSData.xml",

    # Path to the Boundary Collection file - defaults to $PSScriptRoot\_BoundaryCollectionNames.txt
    [Parameter()]
    [string]
    $CollectionFile="$PSScriptRoot\_BoundaryCollectionNames.txt",

    # Path to the Blacklisted Devices file - defaults to $PSScriptRoot\_BlacklistedDevices.txt
    [Parameter()]
    [string]
    $BlacklistFile="$PSScriptRoot\_BlacklistedDevices.txt",

    # Path to the Excluded Devices file - defaults to $PSScriptRoot\_ExcludePeerCacheSource.txt
    [Parameter()]
    [string]
    $ExcludeFile="$PSScriptRoot\_ExcludePeerCacheSource.txt"
    
)

####################
## INITIALIZAITON ##
####################
#region Initialization
# Configure Defaults
$OPCSLogFilePath = "$ENV:TEMP\Optimize-PeerCacheSources.log"
$OPCSPCCLimitingCollectionName = "All Systems"

# Chassis Types for Laptops
$ltChassis = @("8", "9", "10", "11", "12", "14", "18", "21")

# Load Settings
if(Test-Path "$SettingsPath")
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initialization" -Description "Loading Settings." -Level 4
    [array]$settingsArray = Get-Content "$SettingsPath" | Where-Object {($_ -ne "") -and (-not $_.StartsWith(';'))}
    foreach($s in $settingsArray)
    {
        $removeComments = $s.Split(';')
        $set = $removeComments[0].Split("=")
        if($set[1] -eq "true")
        {
            New-Variable -Name "OPCS$($set[0].Replace(' ',''))" -Value $true -Force
        }
        elseif($set[1] -eq "false")
        {
            New-Variable -Name "OPCS$($set[0].Replace(' ',''))" -Value $false -Force
        }
        else
        {
            New-Variable -Name "OPCS$($set[0].Replace(' ',''))" -Value $set[1] -Force
        }
    }
}
else
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initialization" -Description "Settings ini not found at $SettingsPath" -Level 3
    Throw "Settings ini file not found. Please check your parameters."
}

if($OPCSLogFileAppendDate)
{
    $date = Get-Date -Format "-yyyy-MM-dd"
    $OPCSLogFilePath = "$($OPCSLogFilePath.Substring(0,$OPCSLogFilePath.LastIndexOf(".")))$date$($OPCSLogFilePath.Substring($OPCSLogFilePath.LastIndexOf(".")))"
}

# Dependency Check
if(-not (Test-Path "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"))
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Dependency Check" -Description "The Configuration Manager PowerShell Module is not installed. Please install the ConfigMgr console on this device." -Level 3
    Throw "The Configuration Manager PowerShell Module must be installed (install the ConfigMgr Console)"
}
else
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initialization" -Description "Importing ConfigMgr module." -Level 4
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"
}

# Create Site Drive
if($null -eq (Get-PSDrive -Name $OPCSSiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initialization" -Description "Connecting to ConfigMgr site: $OPCSSiteServer - $OPCSSiteCode" -Level 4
    New-PSDrive -Name $OPCSSiteCode -PSProvider CMSite -Root $OPCSSiteServer
}

# Load or Create the Database
if((Test-Path "$DataPath") -and (-not $OPCSInitialRun))
{
    # Load the Database
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initialization" -Description "Loading the database at $DataPath" -Level 4
    [xml]$OPCSData = Get-Content "$DataPath"
}
else
{
    # Create and then load the database
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initialization" -Description "Database file not found - creating new one at: $DataPath" -Level 2
    [xml]$OPCSData = Get-Content (New-Item -Path "$DataPath" -ItemType "File" -Value "<?xml version=`"1.0`" ?>`r`n<PeerCacheSources>`r`n</PeerCacheSources>" -Force)
}

# Load the Boundary Collections Name File
[array]$OPCSCollections = @()
$OPCSCollectionsFile = $CollectionFile
if(Test-Path $OPCSCollectionsFile)
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initialization" -Description "Loading collections list from $OPCSCollectionsFile" -Level 4
    $OPCSCollections = Get-Content $OPCSCollectionsFile
}
else
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Dependency Check" -Description "Collection list file not found." -Level 3
    Throw "Collection list file not found."
}

# Load the Exclude Peer Cache Source File
[array]$OPCSExcludePCS = @()
$OPCSExcludePCSFile = $ExcludeFile
if(Test-Path $OPCSExcludePCSFile)
{
    $OPCSExcludePCS = Get-Content $OPCSExcludePCSFile
}
else
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Dependency Check" -Description "Exclusion file not found." -Level 2
}

# Load the Blacklist Source File
[array]$OPCSBlacklist = @()
$OPCSBlacklistFile = $BlacklistFile
if(Test-Path $OPCSBlacklistFile)
{
    $OPCSExcludePCS = Get-Content $OPCSBlacklistFile
}
else
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Dependency Check" -Description "Blacklist file not found." -Level 2
}
#endregion Initialization

##############################
## PUT THE FUN IN FUNCTIONS ##
##############################
#region Functions
######################
## LOGGING FUNCTION ##
######################
function Write-OPCSLogs 
{
    <#
    .SYNOPSIS
    Creates a log entry in all applicable logs (CMTrace compatible File and Verbose logging).
    #>
    [CmdletBinding()]
    Param
    (
        # Log File Enabled
        [Parameter()]
        [switch]
        $FileLogging,

        # Log File Path
        [Parameter()]
        [string]
        $LogFilePath,

        # Log Description
        [Parameter(mandatory=$true)]
        [string]
        $Description,

        # Log Source
        [Parameter(mandatory=$true)]
        [string]
        $Source,

        # Log Level
        [Parameter(mandatory=$false)]
        [ValidateRange(1,4)]
        [int]
        $Level,

        # Debugging Enabled
        [Parameter(mandatory=$false)]
        [switch]
        $Debugging
    )
    
    # Get Current Time (UTC)
    $dt = [DateTime]::UtcNow

    $lt = switch($Level)
    {
        1 { 'Informational' }
        2 { 'Warning' }
        3 { 'Error' }
        4 { 'Debug' }
    }

    if($FileLogging)
    {
        # Create Pretty CMTrace Log Entry
        if(($Level -lt 4) -or $Debugging)
        {
            if($Level -ne 1)
            {
                $cmtl  = "<![LOG[`($lt`) $Description]LOG]!>"
            }
            else
            {
                $cmtl  = "<![LOG[$Description]LOG]!>"
            }
            $cmtl += "<time=`"$($dt.ToString('HH:mm:ss.fff'))+000`" "
            $cmtl += "date=`"$($dt.ToString('M-d-yyyy'))`" "
            $cmtl += "component=`"$Source`" "
            $cmtl += "context=`"$($ENV:USERDOMAIN)\$($ENV:USERNAME)`" "
            $cmtl += "type=`"$Level`" "
            $cmtl += "thread=`"$($pid)`" "
            $cmtl += "file=`"`">"
    
            # Write a Pretty CMTrace Log Entry
            $cmtl | Out-File -Append -Encoding UTF8 -FilePath "$LogFilePath"
        }
    }

    if(($Level -lt 4) -or $Debugging)
    {
        if($VerbosePreference -ne 'SilentlyContinue')
        {
            Write-Verbose -Message "[$dt] ($lt) $Source`: $Description"
        }
    }
}

##############################
## VALIDATE DEVICE FUNCTION ##
##############################
function Confirm-OPCSDevice($deviceFQDN)
{
    <#
    .SYNOPSIS
    Returns an integer value based on the scan that is run.

    0 - Successful
    1 - Not Pingable / Not Active in ConfigMgr
    2 - Cannot resolve in DNS
    #>
    # PING TEST #
    if($OPCSDeviceScanType -eq "ping")
    {
        $scanResult = Test-NetConnection -ComputerName $deviceFQDN

        # Return Codes
        if($scanResult.NameResolutionSucceeded -eq $false){ return 2 }
        elseif($scanResult.PingSucceeded -eq $false){ return 1 }
        else{ return 0 }
    }

    # CONFIGMGR TEST #
    if($OPCSDeviceScanType -eq "configmgr")
    {
        
        $resourceID = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_COMPUTER_SYSTEM" -Filter "Name = '$($deviceFQDN.Substring(0,$deviceFQDN.IndexOf('.')))' and Domain = '$($deviceFQDN.Substring($deviceFQDN.IndexOf('.') + 1))'").ResourceID
        $onlineStatus = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_CN_ClientStatus" -Filter "ResourceID = '$($resourceID)'").OnlineStatus
        $dnsResolution = $true
        try{ $null = Resolve-DnsName -Name $deviceFQDN -DnsOnly -ErrorAction Stop } catch { $dnsResolution = $false }
        
        # Return Codes
        if($dnsResolution -eq $false){ return 2 }
        elseif($onlineStatus -eq 0){ return 1 }
        else{ return 0 }
    }
}

#####################################
## FIND VALID COLLECTIONS FUNCTION ##
#####################################
function Find-ValidCMCollections($phase, $collectionArray, [ref]$validCollections, [ref]$collectionsNotFound)
{
    # Store the current location, and switch to the ConfigMgr drive
    $initialLocation = (Get-Location).Path
    Set-Location "$($OPCSSiteCode):\"

    ##### Gather Collections List #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Gathering collections from provided list." -Level 1

    $pb = 0 # Progress Bar Counter
    foreach($collection in $OPCSCollections)
    {
        $pb++ # Increase progress bar counter
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Looking for Collection: $collection" -Level 4
        
        # Find Collection By Name
        $c = Get-CMDeviceCollection -Name $collection
        
        if($null -eq $c) #If null, warn in log and add to collections not found list
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Collection: $collection Not Found..." -Level 2
            $collectionsNotFound.Value += $collection
        }
        else # Found the collection - add it to the list
        {
            $validCollections.Value += $c
        }

        # Every three collections scanned - write progress bar to log file
        if($pb % 3 -eq 0)
        {
            $percentage = [math]::Round(($pb / $collectionArray.Count) * 100)
            $blocks = [math]::Round(($pb / $collectionArray.Count) * 25)
            $lines = 25 - $blocks
            $progbar = "|" + "#"*$blocks + "-"*$lines + "|"
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "$progbar Collection Gathering $percentage% complete." -Level 1
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description ("|" + "#"*25 + "| Collection Gathering 100% complete.") -Level 1

    # Reconnect to initial location
    Set-Location $initialLocation
}

###########################################
## GET MACHINES FROM COLLECTION FUNCTION ##
###########################################
function Find-CMDeviceByCollection($phase, $Collections, $hColToMachine)
{
    # Store the current location, and switch to the ConfigMgr drive
    $initialLocation = (Get-Location).Path
    Set-Location "$($OPCSSiteCode):\"

    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Gathering devices from found collections." -Level 1

    $pb = 0 # Progress bar counter
    foreach($c in $aCollections)
    {
        $pb++ # Increase progress bar counter
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Gathering devices from: $($c.Name)" -Level 4
        
        # Get devices belonging to the collection
        $cdevs = Get-CMDevice -CollectionId $($c.CollectionID)
        
        $nonExcludedComputers = @() # Array of computers to evaluate
        [array]$excludedComputers = $OPCSExcludePCS + $OPCSBlacklist # Computers excluded from being Peer Cache Sources (by FQDN)

        # Iterate through CMDevices and only add non-excluded computers
        foreach($cdev in $cdevs)
        {
            if($cdev.Name -notin $excludedComputers)
            {
                $nonExcludedComputers += $cdev
            }
        }

        # Add array of CMDevice objects to the hashtable with a key of the collection ID
        $hColToMachine.Add($c.CollectionID, $nonExcludedComputers)

        # Every three collections searched - write progress bar to log file
        if($pb % 3 -eq 0)
        {
            $percentage = [math]::Round(($pb / $aCollections.Count) * 100)
            $blocks = [math]::Round(($pb / $aCollections.Count) * 25)
            $lines = 25 - $blocks
            $progbar = "|" + "#"*$blocks + "-"*$lines + "|"
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "$progbar Collection Gathering $percentage% complete." -Level 1
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description ("|" + "#"*25 + "| Collection Gathering 100% complete.") -Level 1

    # Reconnect to initial location
    Set-Location $initialLocation
}

###############################
## EVALUATE DEVICES FUNCTION ##
###############################
function Find-ValidCMDevicesByCollection($phase, $DevicesForScanning, $cid, [ref]$EligibleDevices, [ref]$BlacklistedComputers)
{
    $pb = 0

    foreach($device in $DevicesForScanning)
    {
        $pb++ # increment progress bar
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Evaluating" -Description "Evaluating: $($device.Name)" -Level 4
        
        # Get the full domain (e.g. contoso.com) of the device for multi-domain support
        $dfulldomain = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_COMPUTER_SYSTEM" -Filter "ResourceID = '$($device.ResourceID)'").Domain
        
        # Gather the total physical memory
        $dmemory = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_X86_PC_MEMORY" -Filter "ResourceID = '$($device.ResourceID)'").TotalPhysicalMemory
        
        # Gather the space of the C drive.
        $dhdspace = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_LOGICAL_DISK" -Filter "ResourceID = '$($device.ResourceID)' and DeviceID = 'C:'").Size
        
        # Gather the free space of the C drive (logic will lean towards using the computer(s) with the most free space)
        $dhdfspace = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_LOGICAL_DISK" -Filter "ResourceID = '$($device.ResourceID)' and DeviceID = 'C:'").FreeSpace

        # Gather the chassis type to determine if it is a laptop or not
        $dchassis = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_SYSTEM_ENCLOSURE" -Filter "ResourceID = '$($device.ResourceID)'").ChassisTypes
        
        # Gather the drive captions to search for NVME/SSD
        $dLDTPA = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_LOGICAL_DISK_TO_PARTITION" -Filter "ResourceID = '$($device.ResourceID)' and Dependent like '%C:%'").Antecedent
        $dDDTDP = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_DISK_DRIVE_TO_DISK_PARTITION" -Filter "ResourceID = '$($device.ResourceID)'" | Where-Object {$_.Dependent -eq $dLDTPA}).Antecedent
        if($null -ne $dDDTDP)
        {
            $dPDID = $dDDTDP.Substring($dDDTDP.IndexOf("`"")).Replace("\\","\").Replace("`"","")
            $dPDName = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_DISK" -Filter "ResourceID = '$($device.ResourceID)'" | Where-Object {$_.DeviceID -eq $dPDID}).Caption
            if($dPDName -like "%NVME%" -or $dPDName -like "%SSD%")
            {
                $dSSD = $true
            }
            else
            {
                $dSSD = $false
            }
        }
        else
        {
            $dSSD = $false
        }

        # Determine if wireless disabled
        if((Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_SERVICE" -Filter "ResourceID = '$($device.ResourceID)' and Name = 'WlanSvc'").StartMode -eq "Manual" -or (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_SERVICE" -Filter "ResourceID = '$($device.ResourceID)' and Name = 'WlanSvc'").StartMode -eq "Disabled")
        {
            $dWirelessDisabled = $true
        }
        else{ $dWirelessDisabled = $false }

        # Determine if device is a VM
        $dvm = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_R_System" -Filter "ResourceID = '$($device.ResourceID)'").IsVirtualMachine
        
        # This is probably the most time consuming part - test the connection to the device to ensure that it is a worthy Peer Cache Source
        $dstatus = Confirm-OPCSDevice -deviceFQDN "$($device.Name).$dfulldomain"

        # If the network connection succeeds, then we can potentially use this device
        if($dstatus -eq 0)
        {
            # Here we want to make sure the device meets or exceeds Minimum Memory and Minimum Hard Drive requirements
            if($dmemory -ge ([int]$OPCSMinMemory * 1024) -and $dhdspace -ge ([int]$OPCSMinHardDrive * 1024))
            {
                # Finally we might want to exclude laptops... so check that as well
                # Also exclude VMs... because... yuck.
                if(((($dchassis -in $ltChassis) -and $OPCSIncludeLaptops) -or ($dchassis -notin $ltChassis)) -and ((-not $dvm) -or ($dvm -and $OPCSIncludeVMs)))
                {
                    # Create a custom PoSH object we'll use to build the evaluate and sort.
                    $do = New-Object -TypeName PSObject
                    $do | Add-Member -MemberType NoteProperty -Name 'Name' -Value "$($device.Name).$dfulldomain"
                    $do | Add-Member -MemberType NoteProperty -Name 'CollectionID' -Value $cid
                    $do | Add-Member -MemberType NoteProperty -Name 'ResourceID' -Value $device.ResourceID
                    $do | Add-Member -MemberType NoteProperty -Name 'Memory' -Value $dmemory
                    $do | Add-Member -MemberType NoteProperty -Name 'HDSpace' -Value $dhdspace
                    $do | Add-Member -MemberType NoteProperty -Name 'HDFreeSpace' -Value $dhdfspace
                    $do | Add-Member -MemberType NoteProperty -Name 'WirelessDisabled' -Value $dWirelessDisabled
                    $do | Add-Member -MemberType NoteProperty -Name 'SSD' -Value $dSSD

                    # Add the device to eligible devices
                    $eligibleDevices.Value += $do
                }
                else # Device was excluded because it's a laptop or vm
                {
                    if($dvm)
                    {
                        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Device $($device.Name) is not eligible. VMs are excluded via `"IncludeVMs`" setting in $SettingsPath" -Level 2
                    }
                    else
                    {
                        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Device $($device.Name) is not eligible. Laptops are excluded via `"IncludeLaptops`" setting in $SettingsPath" -Level 2
                    }
                }
            }
            else # Device didn't meet requirements
            {
                Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Device $($device.Name) is not eligible due to hard drive or memory." -Level 2
            }
        }
        elseif($dstatus -eq 2) # Device was not found in DNS... should be blacklisted
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Device $($device.Name) is not in DNS. Blacklisting." -Level 3
            Add-Content $OPCSBlacklistFile "`r$($device.Name).$dfulldomain" -Force -WhatIf:$WhatIf # Add to blacklist
            $BlacklistedComputers.Value += "$($device.Name).$dfulldomain" # Add to list of blacklisted devices for report
        }
        else # Device was unreachable... don't blacklist, but also let's not include it.
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Gathering" -Description "Device $($device.Name) is not reachable/online. Not including as eligible." -Level 2
        }

        # Every three devices, write progress bar to the log
        if($pb % 3 -eq 0)
        {
            $percentage = [math]::Round(($pb / $DevicesForScanning.Count) * 100)
            $blocks = [math]::Round(($pb /$DevicesForScanning.Count) * 25)
            $lines = 25 - $blocks
            $progbar = "|" + "#"*$blocks + "-"*$lines + "|"
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "$phase Run - Evaluating" -Description "$progbar Collection: $cid - $percentage% complete evaluating devices." -Level 1
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Evaluating" -Description ("|" + "#"*25 + "| Device evaluation for $cid 100% complete.") -Level 1
}

#endregion Functions

##################
## BEGIN SCRIPT ##
##################
#region Script
Set-Location "$($OPCSSiteCode):\"
if($OPCSInitialRun)
{
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "Beginning Initial Setup." -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
        
    # Validate collections and return valid objects to $aCollections and invalid collections to $CollectionsNotFound
    $aCollections = @() # Array of collections found in ConfigMgr
    $CollectionsNotFound = @() # Array of collections NOT found in ConfigMgr
    Find-ValidCMCollections -phase "Initial" -collectionArray $OPCSCollections -validCollections ([ref]$aCollections) -collectionsNotFound ([ref]$CollectionsNotFound)
        
    # Get devices for each collection and store in a hashtable
    $hColToMachine = @{} # Hashtable to store collection IDs and an associated array of CMDevice objects
    Find-CMDeviceByCollection -phase "Initial" -Collections $aCollections -hColToMachine $hColToMachine

    ##### Evaluate Eligible Devices #####
    ## WARNING THIS PROCESS WILL TAKE SOME TIME TO COMPLETE ##
    ## WARNING THIS PROCESS WILL TAKE SOME TIME TO COMPLETE ##
    ## WARNING THIS PROCESS WILL TAKE SOME TIME TO COMPLETE ##
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Evaluating" -Description "Evaluating eligible devices from found collections." -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Evaluating" -Description "++++++++++++++++++++++++++++++++++++" -Level 2
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Evaluating" -Description "THIS MAY TAKE SOME TIME TO COMPLETE - PATIENCE IS A VIRTUE" -Level 2
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Evaluating" -Description "++++++++++++++++++++++++++++++++++++" -Level 2
    
    $eligibleDevices = @() # Array of eligible devices
    $BlacklistedComputers = @() # Array of blacklisted devices (DNS resolution failed)
    $i = 0 # We're going to implement the progress on each collection rather than a total progress, so we're going to add a count of the number of collections (e.g. 1 of 42)
    foreach($cid in $hColToMachine.Keys)
    {
        $i++ # increment collection number
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Evaluating" -Description "Evaluating devices from: $cid ($i of $($hColToMachine.Count))" -Level 1
        
        # Iterate devices in collection
        Find-ValidCMDevicesByCollection -phase "Initial" -cid $cid -DevicesForScanning $hColToMachine[$cid] -EligibleDevices ([ref]$eligibleDevices) -BlacklistedComputers ([ref]$BlacklistedComputers)
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Evaluating" -Description "Eligible device evaluation complete." -Level 1

    ##### Build list of best devices #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Building" -Description "Building lists of best devices from found collections." -Level 1
    
    $PCSDevices = @()                   # Eligible Devices
    $EmptyCollections = @()             # Collections with no eligible devices
    $LessThanExpectedCollections = @()  # Collections with less than desired amount of eligible devices

    # Iterate through each found collection
    foreach($c in $aCollections)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Building" -Description "Building list of best devices for: $($c.Name)" -Level 1
        
        # Take the eligible devices, filter by collection, sort by free hard drive space and then memory
        # then select only the number of devices that we have configured in PeerCacheSourcesPerCollection
        [array]$devicesForCollection = $eligibleDevices | Where-Object {$_.CollectionID -eq $c.CollectionID} | Sort-Object -Property WirelessDisabled,SSD,HDFreeSpace,Memory -Descending | Select-Object -First $OPCSPeerCacheSourcesPerCollection
        
        if($devicesForCollection.Count -eq 0) # Collection has no eligible devices
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Building" -Description "Collection $($c.Name) contains no eligible devices." -Level 3
            $EmptyCollections += $c.Name
        }
        elseif($devicesForCollection.Count -lt $OPCSPeerCacheSourcesPerCollection) # Collection has less than desired amount of eligible devices
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Building" -Description "Collection $($c.Name) contains $($devicesForCollection.Count) eligible device(s) - less than the configured $OPCSPeerCacheSourcesPerCollection" -Level 2
            $LessThanExpectedCollections += $c.Name
        }
        foreach($d in $devicesForCollection) # Build the necessary data for the XML "database"
        {
            $pcsd = New-Object -TypeName PSObject
            $pcsd | Add-Member -MemberType NoteProperty -Name 'Name' -Value $d.Name
            $pcsd | Add-Member -MemberType NoteProperty -Name 'CN' -Value $c.Name
            $pcsd | Add-Member -MemberType NoteProperty -Name 'RI' -Value $d.ResourceID
            $pcsd | Add-Member -MemberType NoteProperty -Name 'NumWarnings' -Value 0

            # Add device to selected devices
            $PCSDevices += $pcsd
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Building" -Description "Completed building lists of best devices from found collections." -Level 1

    ##### Create "Database" File (XML) #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "Building `"database`" file." -Level 1
    
    # Iterate through selected devices
    foreach($d in $PCSDevices)
    {
        $child = $OPCSData.CreateElement("PeerCacheSource") # Create new PeerCacheSource element in XML
        $child.SetAttribute("CName",$d.Name) # Add Name attribute
        $child.SetAttribute("RI",$d.RI) # Add resource ID attribute (because you can't add to collection by name directly)
        $child.SetAttribute("CN",$d.CN) # Add the collection name for the device
        $child.SetAttribute("NumWarnings",$d.NumWarnings) # Create the number of warnings attribute - used for blacklisting devices that have been offline too many times
        $null = $OPCSData.DocumentElement.AppendChild($child) # Add the PeerCacheSource to the XML
    }
    if($WhatIf){ Write-Host -ForegroundColor Yellow "What If: Saving XML Database to $DataPath" }
    else{ $OPCSData.Save($DataPath) } # Save the XML file
    
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "`"Database`" built." -Level 1

    ##### Create Device Collection (if necessary) #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "Creating collection: `"$OPCSPCCName`" if necessary." -Level 1
    
    # Check to see if the collection exists
    $dcol = Get-CMDeviceCollection -Name $OPCSPCCName
    if(-not $dcol) # Collection doesn't exist - create it
    {
        # The collection specifically has no refresh because we'll expect the script to be run regularly and refresh when needed
        $null = New-CMDeviceCollection -Name $OPCSPCCName -RefreshType None -RefreshSchedule (New-CMSchedule -Start "1/1/1970 12:00:00 AM" -Nonrecurring) -LimitingCollectionName $OPCSPCCLimitingCollectionName -WhatIf:$WhatIf
    }

    # Add Devices To Collection
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "Adding devices to collection." -Level 1
    $pb = 0 # reset progress bar
    $pcsc = $PCSDevices.Count
    
    # Iterate selected devices
    foreach($d in $PCSDevices)
    {
        $pb++ # Increment progress bar
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "Adding `"$($d.Name)`" to collection." -Level 4
        
        # Add a direct relationship between device and collection - easier to update than a query and arguably less resource intensive
        Add-CMDeviceCollectionDirectMembershipRule -CollectionName $OPCSPCCName -ResourceId $d.RI -WhatIf:$WhatIf
        
        # Write progress bar to log every 3rd computer
        if($pb % 3 -eq 0)
        {
            $percentage = [math]::Round(($pb / $pcsc) * 100)
            $blocks = [math]::Round(($pb / $pcsc) * 25)
            $lines = 25 - $blocks
            $progbar = "|" + "#"*$blocks + "-"*$lines + "|"
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "$progbar Adding devices to collection $percentage% complete evaluating devices." -Level 1
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "Done adding devices to collection." -Level 1

    ##### Force Collection Refresh #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run - Create" -Description "Refreshing collection: `"$OPCSPCCName`"" -Level 1
    
    # Get the collection name to refresh
    $rc = Get-CMDeviceCollection -Name $OPCSPCCName 

    # Refresh the collection - null is used to keep data from being written back to console
    if(-not $WhatIf)
    {
        $null = Invoke-WmiMethod -Path "ROOT\SMS\Site_$($OPCSSiteCode):SMS_Collection.CollectionId='$($rc.CollectionId)'" -Name RequestRefresh -ComputerName $OPCSSiteServer -WhatIf:$WhatIf
    }

    ##### Completion Report #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "Completion Report" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    if($WhatIf) { Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "*** WHAT IF SWITCH USED - THIS IS AN EXAMPLE REPORT ***" -Level 1 }
    
    # General summary
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "Number of Expected Collections/Locations: $($OPCSCollections.Count)" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "Number of Found Collections/Locations: $($aCollections.Count)" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description " " -Level 1

    # Non found collections
    if($CollectionsNotFound.Count -gt 0){
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "The following collections were not found: " -Level 1
        foreach($c in $CollectionsNotFound)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "     $c" -Level 1
        }
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description " " -Level 1
    }

    # Less than optimal collections
    if($LessThanExpectedCollections.Count -gt 0)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "Collections with less than $OPCSPeerCacheSourcesPerCollection Peer Cache Sources: $($LessThanExpectedCollections.Count)" -Level 2

        foreach($c in $LessThanExpectedCollections)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "     $c" -Level 1
        }
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description " " -Level 1
    }

    # Empty collections
    if($EmptyCollections.Count -gt 0)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "Collections with NO Peer Cache Sources: $($EmptyCollections.Count)" -Level 3
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "The following collections have NO Peer Cache Sources: " -Level 1
        foreach($c in $EmptyCollections)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "     $c" -Level 1
        }
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description " " -Level 1
    }
    
    # Devices added to the blacklist
    if($BlacklistedComputers.Count -gt 0)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "The following computers were blacklisted:" -Level 2
        foreach($c in $BlacklistedComputers)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "     $c" -Level 1
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "Initial Setup Completed." -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Initial Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
}
else
{
    ##### Begin Delta Assessment #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Beginning Delta Assessment." -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    
    ##### Load "Database" File (XML) #####
    $peerCacheSources = $OPCSData.PeerCacheSources.ChildNodes

    ##### Evaluate User Exclusions and double check blacklist | Validate existing collection #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Evaluating Blacklist and User Exclusions" -Level 1
    $devicesRemoved = @()
    $removeFromXML = @()
    
    # Exclusions
    [array]$excludedComputers = $OPCSExcludePCS
    if($OPCSIgnoreBlacklist -ne $true){$excludedComputers += $OPCSBlacklist}

    foreach($pcs in $peerCacheSources)
    {
        if($pcs.CName -in $excludedComputers)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Removed `"$($pcs.CName)`" from Peer Cache Source List" -Level 2
            $devicesRemoved += $pcs.CName
            $removeFromXML += $pcs
            Remove-CMDeviceCollectionDirectMembershipRule -CollectionName "$OPCSPCCName" -ResourceId $pcs.RI -WhatIf:$WhatIf
        }
        else
        {
            if($null -eq (Get-CMDeviceCollectionDirectMembershipRule -CollectionName "$OPCSPCCName" -ResourceId $pcs.RI))
            {
                Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Device `"$($pcs.CName)`" missing from Peer Cache collection. Readding." -Level 2
                # Didn't see a direct relationship for this collection, re-adding device to collection. Maybe it was manually removed?
                Add-CMDeviceCollectionDirectMembershipRule -CollectionName "$OPCSPCCName" -ResourceId $pcs.RI -WhatIf:$WhatIf -ErrorAction SilentlyContinue
            }
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Completed evaluating Blacklist and User Exclusions" -Level 1
    
    ##### Cleanup XML File #####
    foreach($item in $removeFromXML)
    {
        $null = $OPCSData.PeerCacheSources.RemoveChild($item)
    }
    $removeFromXML = @()

    ##### Evaluate Device Connection State (Ping / DNS Tests)  #####
    $BlacklistedComputers = @()
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Evaluating Device Connection States..." -Level 1
    $pb = 0
    $pcsc = $peerCacheSources.Count
    foreach($pcs in $peerCacheSources)
    {
        $pb++
        $conTest = Confirm-OPCSDevice -deviceFQDN $pcs.CName
        if($conTest -eq 2)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Device `"$($pcs.CName)`" not resolvable. Adding to blacklist and removing from Peer Cache Sources." -Level 3
            $removeFromXML += $pcs
            Add-Content $OPCSBlacklistFile "$($pcs.CName)" -Force -WhatIf:$WhatIf # Add to blacklist
            $BlacklistedComputers += "$($pcs.CName)" # Add to list of blacklisted devices for report
            Remove-CMDeviceCollectionDirectMembershipRule -CollectionName "$OPCSPCCLimitingCollectionName" -ResourceId $pcs.RI -WhatIf:$WhatIf -ErrorAction SilentlyContinue
        }
        elseif($conTest -eq 1)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Device `"$($pcs.Name)`" unreachable. Incrementing counter." -Level 2
            [int]$numWarnings = $pcs.NumWarnings
            $numWarnings++
            $pcs.NumWarnings = $numWarnings.ToString()
            if($numWarnings -ge $OPCSMaxPeerCacheWarnings)
            {
                Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Device `"$($pcs.Name)`" exceeded warning threshold. Adding to blacklist and removing from Peer Cache Sources." -Level 3
                $removeFromXML += $pcs
                Add-Content $OPCSBlacklistFile "$($pcs.CName)" -Force -WhatIf:$WhatIf # Add to blacklist
                $BlacklistedComputers += "$($pcs.CName)" # Add to list of blacklisted devices for report
                Remove-CMDeviceCollectionDirectMembershipRule -CollectionName "$OPCSPCCLimitingCollectionName" -ResourceId $pcs.RI -WhatIf:$WhatIf -ErrorAction SilentlyContinue
            }
        }

        # Every three devices scanned - write progress bar to log file
        if($pb % 3 -eq 0)
        {
            $percentage = [math]::Round(($pb / $pcsc) * 100)
            $blocks = [math]::Round(($pb / $pcsc) * 25)
            $lines = 25 - $blocks
            $progbar = "|" + "#"*$blocks + "-"*$lines + "|"
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Gathering" -Description "$progbar Device Connection scanning $percentage% complete." -Level 1
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Completed evaluating device connection states." -Level 1
    
    ##### Cleanup XML File #####
    foreach($item in $removeFromXML)
    {
        $null = $OPCSData.PeerCacheSources.RemoveChild($item)
    }
    $removeFromXML = @()

    ##### Evaluate Collections for correct # of devices #####
    $aCollections = @() # Array of collections found in ConfigMgr
    $CollectionsNotFound = @() # Array of collections NOT found in ConfigMgr
    
    # Validate collections and return valid objects to $aCollections and invalid collections to $CollectionsNotFound
    Find-ValidCMCollections -phase "Delta" -collectionArray $OPCSCollections -validCollections ([ref]$aCollections) -collectionsNotFound ([ref]$CollectionsNotFound)

    $PCSDevices = @()
    $CollectionsBelowStandard = @()
    $EmptyCollections = @()
    $LessThanExpectedCollections = @()
    $eligibleDevices = @()
    $BlacklistedComputers = @()
    foreach($c in $aCollections)
    {
        # Count machines in for collections
        [array]$colDev = $OPCSData.PeerCacheSources.ChildNodes | Where-Object {$_.CN -eq $c.Name}
        
        # If count less than optimal then scan collection for new devices
        $pb = 0
        if($colDev.Count -lt $OPCSPeerCacheSourcesPerCollection)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Evaluating" -Description "Collection: $($c.Name) below expected Peer Cache Source count. Reevaluating." -Level 2
            $CollectionsBelowStandard += $c.Name
            # Number of devices needed to reach optimal
            $n = $OPCSPeerCacheSourcesPerCollection - $colDev.Count

            # Collect Devices
            # Get devices belonging to the collection
            $cdevs = Get-CMDevice -CollectionId $($c.CollectionID)
            
            $nonExcludedComputers = @() # Array of computers to evaluate
            [array]$excludedComputers = $OPCSExcludePCS + $colDev.CName # Computers excluded from being Peer Cache Sources (by FQDN) - also the devices already in the collection
            if($OPCSIgnoreBlacklist -ne $true){$excludedComputers += $OPCSBlacklist}

            # Iterate through CMDevices and only add non-excluded computers
            foreach($cdev in $cdevs)
            {
                $dfulldomain = (Get-WmiObject -ComputerName $OPCSSiteServer -Namespace "root\sms\site_$OPCSSiteCode" -Class "SMS_G_System_COMPUTER_SYSTEM" -Filter "ResourceID = '$($cdev.ResourceID)'").domain
                $fqdn = "$($cdev.Name).$dfulldomain"
                if($fqdn -notin $excludedComputers)
                {
                    $nonExcludedComputers += $cdev
                }
            }    
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Evaluating" -Description "Evaluating eligible devices from $($c.Name)." -Level 1
            Find-ValidCMDevicesByCollection -phase "Delta" -cid $c.CollectionId -DevicesForScanning $nonExcludedComputers -EligibleDevices ([ref]$eligibleDevices) -BlacklistedComputers ([ref]$BlacklistedComputers)
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Evaluating" -Description ("|" + "#"*25 + "| Device evaluation for $($c.Name) 100% complete.") -Level 1

            # Take the eligible devices, filter by collection, sort by wireless, ssd, free hard drive space, and then memory
            # then select only the number of devices that we have configured in PeerCacheSourcesPerCollection
            $devicesForCollection = $eligibleDevices | Sort-Object -Property WirelessDisabled,SSD,HDFreeSpace,Memory -Descending | Select-Object -First $n

            if($devicesForCollection.Count + $colDev.Count -eq 0) # Collection has no eligible devices
            {
                Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Building" -Description "Collection $($c.Name) contains NO eligible devices." -Level 3
                $EmptyCollections += $c.Name
            }
            elseif($devicesForCollection.Count + $colDev.Count -lt $OPCSPeerCacheSourcesPerCollection) # Collection has less than desired amount of eligible devices
            {
                Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Building" -Description "Collection $($c.Name) contains $(($devicesForCollection.Count) + $colDev.Count) eligible device(s) - less than the configured $OPCSPeerCacheSourcesPerCollection" -Level 2
                $LessThanExpectedCollections += $c.Name
            }
            foreach($d in $devicesForCollection) # Build the necessary data for the XML "database"
            {
                $pcsd = New-Object -TypeName PSObject
                $pcsd | Add-Member -MemberType NoteProperty -Name 'Name' -Value $d.Name
                $pcsd | Add-Member -MemberType NoteProperty -Name 'CN' -Value $c.Name
                $pcsd | Add-Member -MemberType NoteProperty -Name 'RI' -Value $d.ResourceID
                $pcsd | Add-Member -MemberType NoteProperty -Name 'NumWarnings' -Value 0

                # Add device to selected devices
                $PCSDevices += $pcsd
            }
        }
    }

    # Add Devices To Collection
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Create" -Description "Adding devices to collection." -Level 1
    $pb = 0 # reset progress bar
    $pcsc = $PCSDevices.Count
    # Iterate selected devices
    foreach($d in $PCSDevices)
    {
        $pb++ # Increment progress bar
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Create" -Description "Adding `"$($d.Name)`" to collection." -Level 4
        
        # Add a direct relationship between device and collection - easier to update than a query and arguably less resource intensive
        Add-CMDeviceCollectionDirectMembershipRule -CollectionName $OPCSPCCName -ResourceId $d.RI -WhatIf:$WhatIf

        # Add devices to database
        $child = $OPCSData.CreateElement("PeerCacheSource") # Create new PeerCacheSource element in XML
        $child.SetAttribute("CName",$d.Name) # Add Name attribute
        $child.SetAttribute("RI",$d.RI) # Add resource ID attribute (because you can't add to collection by name directly)
        $child.SetAttribute("CN",$d.CN) # Add the collection name for the device
        $child.SetAttribute("NumWarnings",$d.NumWarnings) # Create the number of warnings attribute - used for blacklisting devices that have been offline too many times
        $null = $OPCSData.DocumentElement.AppendChild($child) # Add the PeerCacheSource to the XML
        
        # Write progress bar to log every 3rd computer
        if($pb % 3 -eq 0)
        {
            $percentage = [math]::Round(($pb / $pcsc) * 100)
            $blocks = [math]::Round(($pb /$pcsc) * 25)
            $lines = 25 - $blocks
            $progbar = "|" + "#"*$blocks + "-"*$lines + "|"
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Create" -Description "$progbar Adding devices to collection $percentage% complete evaluating devices." -Level 1
        }
    }
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Create" -Description "Done adding devices to collection." -Level 1

    ##### Save the Database #####
    if($WhatIf){ Write-Host -ForegroundColor Yellow "What If: Saving XML Database to $DataPath" }
    else{ $OPCSData.Save($DataPath) } # Save the XML file

    ##### Force Collection Refresh #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run - Create" -Description "Refreshing collection: `"$OPCSPCCName`"" -Level 1
    
    # Get the collection name to refresh
    $rc = Get-CMDeviceCollection -Name $OPCSPCCName 

    # Refresh the collection - null is used to keep data from being written back to console
    $null = Invoke-WmiMethod -Path "ROOT\SMS\Site_$($OPCSSiteCode):SMS_Collection.CollectionId='$($rc.CollectionId)'" -Name RequestRefresh -ComputerName $OPCSSiteServer -WhatIf:$WhatIf

    #region DeltaReport
    ##### Completion Report #####
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Delta Completion Report" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    if($WhatIf) { Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "*** WHAT IF SWITCH USED - THIS IS AN EXAMPLE REPORT ***" -Level 1 }
    
    # General summary
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Number of Expected Collections/Locations: $($OPCSCollections.Count)" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Number of Found Collections/Locations: $($aCollections.Count)" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description " " -Level 1

    # Non found collections
    if($CollectionsNotFound.Count -gt 0){
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "The following collections were not found: " -Level 1
        foreach($c in $CollectionsNotFound)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "     $c" -Level 1
        }
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description " " -Level 1
    }

    # Less than optimal collections
    if($LessThanExpectedCollections.Count -gt 0)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Collections with less than $OPCSPeerCacheSourcesPerCollection Peer Cache Sources: $($LessThanExpectedCollections.Count)" -Level 2
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "The following collections have fewer than configured Peer Cache Sources: " -Level 1
        foreach($c in $LessThanExpectedCollections)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "     $c" -Level 1
        }
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description " " -Level 1
    }

    # Empty collections
    if($EmptyCollections.Count -gt 0)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Collections with NO Peer Cache Sources: $($EmptyCollections.Count)" -Level 3
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "The following collections have NO Peer Cache Sources: " -Level 1
        foreach($c in $EmptyCollections)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "     $c" -Level 1
        }
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description " " -Level 1
    }

    # Devices added to the blacklist
    if($BlacklistedComputers.Count -gt 0)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "The following computers were blacklisted:" -Level 2
        foreach($c in $BlacklistedComputers)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "     $c" -Level 1
        }
    }

    # Removed devices
    if($devicesRemoved.Count -gt 0)
    {
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "The following devices were previously Peer Cache Sources, but have been removed: " -Level 1
        foreach($c in $devicesRemoved)
        {
            Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "     $c" -Level 1
        }
        Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description " " -Level 1
    }

    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "Delta Assessment Completed." -Level 1
    Write-OPCSLogs -FileLogging:$OPCSLoggingEnabled -LogFilePath $OPCSLogFilePath -Debugging:$OPCSDebugging -Source "Delta Run" -Description "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -Level 1
    #endregion DeltaReport
}
#endregion Script