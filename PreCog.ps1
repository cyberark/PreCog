<#

############################################################################################
#                                                                                          #  
#   PreCog - Precognition of credentials theft through detection of HotSpots in networks   #
#                                                                                          #
############################################################################################

\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
----------------------------------------------------------------------
**********************************************************************
//////////////////////////////////////////////////////////////////////

Developed by: Asaf Hecht - @hechtov
              Cyberark Labs research team

\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
----------------------------------------------------------------------
**********************************************************************
//////////////////////////////////////////////////////////////////////

Authors of the HotSpots concept: Lavi Lazarovitz - @LaviLazarovitz
                                 Asaf Hecht - @Hechtov
                                 Cyberark Labs research team

\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
----------------------------------------------------------------------
**********************************************************************
//////////////////////////////////////////////////////////////////////

Optional usage of an external open source tool ACLight for discovering privileged accounts:
https://github.com/cyberark/ACLight (@Hechtov)
Using functions from the open source project PowerView created by: Will Schroeder (@harmj0y).
** ACLight is a different and external tool and there is no mutal dependencies\obligations what so over **

------------------------------------------------------------------------------------------------------

HOW TO RUN + EXPLANATION ON THE RESULTS FILES:
Check the PreCog's GitHub page:
https://github.com/cyberark/PreCog

Version Notes:
 
Version 1.0: 26.11.17
Version 1.1: 21.1.18
version 1.2: 1.2.18
version 1.3: 3.2.18
version 1.4: 5.2.18
version 1.5: 8.2.18
version 1.6: 26.2.18
version 1.7: 29.3.18 (Published through GitHub)

----------------------------------------------------------------------------------------------------#>

Param (
    # $days paramter defines how many days from the past the tool will analyze event logs
    [Double]
    $days = 0.005, # (0.005 days = 7.2mins)
    # if you want the tool to query a remote WEF server, $eventLogCollectorName is the name of the remote WEF computer
    [string]
    $eventLogCollectorName,
    # $sleepTime defines the sleeping time in seconds between each reading logs loop
    [int]
    $sleepTime = 1,
    # if you don't want the tool to save the raw output file of the analyzed logs - "LogsRawSavedData.csv"
    [switch]
    $noRawData,
    # if you want less messages to be printed in the tool window
    [switch]
    $quietMode,
    # the folder name of the forwarded logs in the WEF server, by defualt it's "ForwardedEvents"
    [string]
    $logFolderName = 'ForwardedEvents'
)

$version = "v1.7"

##Requires -Version 3.0 or above
#check the powershell version
if ($PSVersionTable.PSVersion.Major -lt 3){
    Write-Output "You are using an old PowerShell version, please upgrade to version 3 or above"
    end
}

$PreCog = @"
--------------------------------------------------------------------

______         _____             
| ___ \       /  __ \            
| |_/ / __ ___| /  \/ ___   __ _ 
|  __/ '__/ _ \ |    / _ \ / _`` |
| |  | | |  __/ \__/\ (_) | (_| |
\_|  |_|  \___|\____/\___/ \__, |
                            __/ |
                           |___/ 

"@

$Authors = @"
Authors: Lavi Lazarovitz - @LaviLazarovitz,   Asaf Hecht - @Hechtov
                      
                      Cyberark Labs research team

--------------------------------------------------------------------
"@

Write-Output $PreCog
Write-Output "***   Welcome to PreCog $version  ***`n"
Write-Output "The tool for detecting HotSpots - potential spots for credentials theft`n"
Write-Output $Authors

# Analyze previous ACLight results
function Get-ACLightResults {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Tier
    )

    $finalReport = $PSScriptRoot + "\Results\Privileged Accounts - Final Report.csv"
    $irregularReport = $PSScriptRoot + "\Results\Privileged Accounts - Irregular Accounts.csv"
    $layersAnalysis = $PSScriptRoot + "\Results\Privileged Accounts - Layers Analysis.txt"
    $ACLightResultFolder = $PSScriptRoot + "\Results\ACLight"
    if (Test-Path $ACLightResultFolder)
    {
        write-verbose "The ACLight results folder is already exists"
    }
    else
    {
        New-Item -ItemType directory -Path $ACLightResultFolder
    }
    try {
        Move-Item $finalReport $ACLightResultFolder -ErrorAction SilentlyContinue
        Move-Item $irregularReport $ACLightResultFolder -ErrorAction SilentlyContinue
        Move-Item $layersAnalysis $ACLightResultFolder -ErrorAction SilentlyContinue
    }
    catch { 
        write-verbose "The ACLight results may already been copied"
    }

    $finalReport = $ACLightResultFolder + "\Privileged Accounts - Final Report.csv"
    $tier0PrivilegedListPath = $PSScriptRoot + "\Accounts Lists\Tier 0 - most privileged accounts.csv"
    $tier1PrivilegedListPath = $PSScriptRoot + "\Accounts Lists\Tier 1 - privileged accounts.csv"
    $tier0PrivilegedAccountsList = @() 
    $tier1PrivilegedAccountsList = @() 

    if ($Tier -eq "tier0") {
        $tier0PrivilegedAccounts = Import-Csv $finalReport | select "AccountName", "Domain" -Unique 
        $tier0PrivilegedAccounts | Where-Object {$_} | ForEach-Object {
            $accountSID = Convert-NameToSid $_.AccountName
            $accountDetailLine = [PSCustomObject][ordered] @{
                AccountName = [string]$_.AccountName
                AccountSID = [string]$accountSID
                Domain = [string]$_.Domain
            }
            $tier0PrivilegedAccountsList += $accountDetailLine
        }
        $tier0PrivilegedAccountsList | sort Domain,AccountName | export-csv -NoTypeInformation $tier0PrivilegedListPath > $null
        Write-Output "Tier 0 accounts list (the most privileged accounts) was created`n"
    }
    else {
        try {
            $tier1PrivilegedAccounts = Import-Csv $finalReport | select "AccountName", "Domain" -Unique 
            $tier1PrivilegedAccounts | Where-Object {$_} | ForEach-Object {
                $accountSID = Convert-NameToSid $_.AccountName
                $accountDetailLine = [PSCustomObject][ordered] @{
                    AccountName = [string]$_.AccountName
                    AccountSID = [string]$accountSID
                    Domain = [string]$_.Domain
                }
                $tier1PrivilegedAccountsList += $accountDetailLine
            }
            $tier0PrivilegedAccounts = Import-Csv $tier0PrivilegedListPath
            $tier1PrivilegedAccounts = $tier1PrivilegedAccounts | Where {$tier0PrivilegedAccounts -NotContains $_}
            $tier1PrivilegedAccountsList | sort Domain,AccountName | export-csv -NoTypeInformation $tier1PrivilegedListPath > $null
            Write-Output "Tier 1 accounts list was created`n"
        }
        catch {
            write-verbose "Problem with the creation of Tier 1 accounts list"
        }
    }
}

# Analyze the log event and return a "log information object"
function Read-LogEventInfo {
    [CmdletBinding()]
            
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $LogObject
    )
    
    $eventDataObject = New-Object PSObject
    #Build object from Event XML Data
    try {
        $LogObject.Event.EventData.Data | foreach {
            $eventDataObject | Add-Member NoteProperty $_.Name $_."#text"           
        }
    
        # logon types who can lead to credential theft:
        # from the official Microsoft page: https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#T0E_BM
        $toAnalyzeLog = $true
        $riskyLogonTypes = @("2","4","5","7","8","9","10") 
        $LogonType = $eventDataObject.LogonType
        if ($LogonType) {
            if (-not $riskyLogonTypes.contains($LogonType)){
                $toAnalyzeLog = $false
                return
            }
        }
        # removing "DWM" event of "Window Manager"
        if (([string]$eventDataObject.SubjectDomainName -eq "Window Manager") -or ([string]$eventDataObject.TargetDomainName -eq "Window Manager")) {
            return
        }
        elseif (([string]$eventDataObject.SubjectDomainName -eq "NT AUTHORITY") -or ([string]$eventDataObject.TargetDomainName -eq "NT AUTHORITY")) { 
            return
        }

        if ($toAnalyzeLog) {
            $logEventTimeObject = [datetime]$LogObject.Event.System.TimeCreated.SystemTime
            $logSystemTimeZulu = ($logEventTimeObject -split " ")[1]
            $logSystemDateZulu = ($logEventTimeObject -split " ")[0]
            $logEventTime = (New-TimeSpan -Start $epochTime -End $logEventTimeObject).TotalSeconds

            if ($eventDataObject.PrivilegeList) {
                $privList = $eventDataObject.PrivilegeList
                $privList = $privList -replace '\t\t\t',''
                $privList = $privList -split "\n"
            }


            #optional to do: to add:
            <#
            Remaining logon information fields are new to Windows 10/2016

            Restricted Admin Mode:	Normally "-"."Yes" for incoming Remote Desktop Connections where the client specified /restrictedAdmin
            Virtual Account:	Normally "No". This will be Yes in the case of services configured to logon with a "Virtual Account".
            Elevated Token:	This has something to do with User Account Control but our research so far has not yielded consistent results.
            #>

            $logInfoObject = [PSCustomObject][ordered] @{
                # Event.System information:
                # event 4624:
                SystemTime        = [string]$logSystemTimeZulu 
                SystemDate        = [string]$logSystemDateZulu
                logEventTime      = [string]$logEventTime
                TaskCategory      = [string]$LogObject.Event.RenderingInfo.Task
                EventID           = [string]$LogObject.Event.System.EventID
                LogonType         = [string]$LogonType
                Computer          = [string]$LogObject.Event.System.Computer
                WorkstationName   = [string]$eventDataObject.WorkstationName 
                IpAddress         = [string]$eventDataObject.IpAddress
                SubjectUserSid    = [string]$eventDataObject.SubjectUserSid                                           
                SubjectUserName   = [string]$eventDataObject.SubjectUserName 
                SubjectDomainName = [string]$eventDataObject.SubjectDomainName 
                TargetUserSid     = [string]$eventDataObject.TargetUserSid                                  
                TargetUserName    = [string]$eventDataObject.TargetUserName                            
                TargetDomainName  = [string]$eventDataObject.TargetDomainName 
                LogonProcessName  = [string]$eventDataObject.LogonProcessName
                AuthenticationPackageName = [string]$eventDataObject.AuthenticationPackageName
                SubjectLogonId    = [string]$eventDataObject.SubjectLogonId                                   
                TargetLogonId     = [string]$eventDataObject.TargetLogonId                                   
                LogonGuid         = [string]$eventDataObject.LogonGuid
                # extra info
                Opcode            = [string]$LogObject.Event.System.Opcode
                Keywords          = [string]$LogObject.Event.System.Keywords
                Task              = [string]$LogObject.Event.System.Task
                Level             = [string]$LogObject.Event.System.Level
                Version           = [string]$LogObject.Event.System.Version
                ExecutionProcessID = [string]$LogObject.Event.System.Execution.ProcessID
                Channel           = [string]$LogObject.Event.System.Channel
                Correlation       = [string]$LogObject.Event.System.Correlation
                Security          = [string]$LogObject.Event.System.Security                                        
                TransmittedServices = [string]$eventDataObject.TransmittedServices                                           
                LmPackageName     = [string]$eventDataObject.LmPackageName                                                
                KeyLength         = [string]$eventDataObject.KeyLength                                                     
                ProcessId         = [string]$eventDataObject.ProcessId                                                  
                ProcessName       = [string]$eventDataObject.ProcessName                                      
                IpSourcePort      = [string]$eventDataObject.IpPort                              
                ImpersonationLevel = [string]$eventDataObject.ImpersonationLevel
                PrivilegeList     = [string]($privList -join ",")
                PrivilegeLength   = [string]$privList.count
                EventRecordID     = [string]$LogObject.Event.System.EventRecordID
            }
        }
    }
    catch {
        # the event log might be other than the regular logon events (like event logs number 4608, 6005, 6008)
        $logEventTimeObject = [datetime]$LogObject.Event.System.TimeCreated.SystemTime
        $logSystemTimeZulu = ($logEventTimeObject -split " ")[1]
        $logSystemDateZulu = ($logEventTimeObject -split " ")[0]
        $logEventTime = (New-TimeSpan -Start $epochTime -End $logEventTimeObject).TotalSeconds

        $logInfoObject = [PSCustomObject][ordered] @{
            # Event.System information:
            # event 4624:
            SystemTime        = [string]$logSystemTimeZulu 
            SystemDate        = [string]$logSystemDateZulu
            logEventTime      = [string]$logEventTime
            TaskCategory      = [string]$LogObject.Event.RenderingInfo.Task
            EventID           = [string]$LogObject.Event.System.EventID.'#text'
            LogonType         = [string]""
            Computer          = [string]$LogObject.Event.System.Computer
            WorkstationName   = [string]""
            IpAddress         = [string]""
            SubjectUserSid    = [string]""                                          
            SubjectUserName   = [string]""
            SubjectDomainName = [string]""
            TargetUserSid     = [string]""                                 
            TargetUserName    = [string]""                           
            TargetDomainName  = [string]""
            LogonProcessName  = [string]""
            AuthenticationPackageName = [string]""
            SubjectLogonId    = [string]""                                
            TargetLogonId     = [string]""                           
            LogonGuid         = [string]""
            # extra info
            Opcode            = [string]""
            Keywords          = [string]$LogObject.Event.System.Keywords
            Task              = [string]$LogObject.Event.System.Task
            Level             = [string]$LogObject.Event.System.Level
            Version           = [string]""
            ExecutionProcessID = [string]""
            Channel           = [string]$LogObject.Event.System.Channel
            Correlation       = [string]""
            Security          = [string]$LogObject.Event.System.Security                                        
            TransmittedServices = [string]""                                          
            LmPackageName     = [string]""                                      
            KeyLength         = [string]""                                                   
            ProcessId         = [string]""                                                 
            ProcessName       = [string]""                                      
            IpSourcePort      = [string]""                             
            ImpersonationLevel = [string]""
            PrivilegeList     = [string]""
            PrivilegeLength   = [string]""
            EventRecordID     = [string]$LogObject.Event.System.EventRecordID
        }
    }

    return $logInfoObject
}


# Check if the user is part of Tier 0 privileged accounts
function Check-UserTier0 {
    [CmdletBinding()]
            
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $userSID
    )
    if ($accountListTier0DB.ContainsKey($userSID)) {
        return "Yes"
    }
    else {
        return "No"
    }
} 


# Check if the user is part of Tier 1 privileged accounts
function Check-UserTier1 {
    [CmdletBinding()]
            
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $userSID
    )
    if ($accountListTier1DB.ContainsKey($userSID)) {
        return "Yes"
    }
    else {
        return "No"
    }
} 

# Get the status information
function Get-StatusInfo {
    [CmdletBinding()]
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $machineInfo,
        $logonUserInfo
    )
    $liveStatusLine = "" | select Computer,Color,TierLevel,PrivilegedAccountAtRisk,MightStolenBy,LogonID,StartTime,EndTime,Workstation,IP
    $liveStatusLine.Computer = $logonUserInfo.computer
    #if not start:
    $liveStatusLine.StartTime = $logonUserInfo.logOnStartTime
    #if clear:
    $liveStatusLine.privilegedAccountAtRisk = $tier0Unique
    $liveStatusLine.mightStolenBy = $localThiefAccount
    $liveStatusLine.LogonID = $logonUserInfo.logonID
    $liveStatusLine.workstation = $logonUserInfo.workstation
    $liveStatusLine.IP = $logonUserInfo.IP

    return $liveStatusLine
}

# Updating the status file
function Update-StatusFile  {
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $logonUserInfo,
        $liveStatusValues,
        $liveStatusLine,
        $updateType,
        $reset
    )

    if ($updateType -eq "NoTier0") {
        $HotSpotTier = "Tier0-HighestRisk"
        $ColdSpotTier = "Tier0-LoggedOn"    
    }
    elseif ($updateType -eq "NoTier1") {
        $HotSpotTier = "Tier1-HighestRisk"
        $ColdSpotTier = "Tier1-LoggedOn" 
    }
    elseif ($updateType -eq "NoHotSpotsTier0") {
        $HotSpotTier = "Tier0-HighestRisk"
        $ColdSpotTier = ""
    }
    elseif ($updateType -eq "NoHotSpotsTier1") {
        $HotSpotTier = "Tier1-HighestRisk"
        $ColdSpotTier = ""
    }

    if ($liveStatusDB.ContainsKey($logonUserInfo.Computer)) {
        $updatedStatusLines = @()
        foreach ($loggedLine in ($liveStatusDB[$logonUserInfo.Computer])){
            $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
            $startTime = $origin.AddSeconds($loggedLine.StartTime)
            if ($reset -or (($loggedLine.TierLevel -eq $HotSpotTier) -or ($loggedLine.TierLevel -eq $ColdSpotTier)) -or 
                (($updateType -eq "logoff") -and ($liveStatusLine.LogonID -eq $loggedLine.LogonID))) {
                if ($loggedLine.Computer -notlike "HISTORYspot-*") {
                    $totalSeconds = $logonUserInfo.logOnStartTime - $loggedLine.StartTime
                    $totalSeconds = [math]::Round($totalSeconds)
                    $loggedLine.EndTime = $logonUserInfo.logOnStartTime + "->From:" + $startTime + "->" + $totalSeconds + "seconds"
                    $loggedLine.Computer = "HISTORYspot->" + $logonUserInfo.Computer + "<-OLD"
                }
            }
            if ($loggedLine.EndTime -eq "-") {
                $updatedStatusLines += $loggedLine
            }
            else {
                if (-not ($loggedLine.EndTime).contains("0seconds")){
                    $updatedStatusLines += $loggedLine
                }
            }
        }
        $liveStatusDB[$logonUserInfo.Computer] = $updatedStatusLines
        Write-StatusFile -liveStatusValues $liveStatusDB.values
    }
}

# Write the status csv file to the disk
function Write-StatusFile {
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $liveStatusValues
    )
    $updatesStatus = @()
    foreach ($computer in $liveStatusValues){ $computer | foreach {$updatesStatus += $_}}
    $updatesStatus | export-csv -NoTypeInformation $liveStatusPath
}


# Check if there is a ColdSpot or a HotSpots
function Check-ColdHotSpot {
    [CmdletBinding()]
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $machineInfo,
        $logonUserInfo,
        $logoffEvent,
        $reset
    )

    $machineName = $machineInfo.computer | select -Unique
    $localPrivAccounts = $machineInfo | ? {($_.isLocalPrivilege -eq "Yes")}
    $localTier0 = $machineInfo | ? {($_.isTier0 -eq "Yes")}
    $localTier1 = $machineInfo | ? {($_.isTier1 -eq "Yes")}
    $liveStatusLine = Get-StatusInfo -machineInfo $machineInfo -logonUserInfo $logonUserInfo
    $updatedStatusLines = @()
    # if you want to delete previous event of cold and hot spots - in the Main-LiveStatus -> choose $true
    #$deleteHistory = $True
    $deleteHistory = $false
    
    if ($deleteHistory) {
        if ($logoffEvent) {
             $liveStatusDB[$logonUserInfo.Computer] = $liveStatusDB[$logonUserInfo.Computer] | ? {$_.LogonID -ne $liveStatusLine.LogonID}
        }
    }

    if ($reset) {
        Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "reset" -reset $true
        if (-not $quietMode) {
            if ($machineInfo) {
                Write-Host $logonUserInfo.Computer "information was cleared probably because of a restart of the target machine"
            }
        }
        return "Clear"
    }

    if ($logoffEvent) {
        Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "logoff" -liveStatusLine $liveStatusLine
    }

    # to do: fix the scenario of local admin logged on then domain admin logged on and the spot became HotSpots
    # after the sigout of the local admin the hotspot alert transformed to history spot but there is no new indication for the existing ColdSpot
    # it's not really a big issue because on any later on event the hotspot/coldspot will alert currectly also with the previous domain admin connection

    # if there are logons with Tier 0 accounts
    if ($localTier0){
        $tier0UniqueEx = ($localTier0.loggedOnUser).ToLower()  | select -Unique
        $tier0Unique = [string]$tier0UniqueEx
        $liveStatusLine.privilegedAccountAtRisk = $tier0Unique
        if ($localPrivAccounts) {
            $otherPrivAccount = $localPrivAccounts | ? {($_.isTier0 -eq "No")}
            if ($otherPrivAccount) {
                $localThiefAccount = ($otherPrivAccount.loggedOnUser).ToLower() | select -Unique
                if ($tier0UniqueEx.count -gt 1) {
                    Write-Host "Computer" $machineName "is a `"Hot Spot`"!`nTier0 privileged accounts" $tier0Unique "are in danger" -BackgroundColor Red
                }
                else {
                    Write-Host "Computer" $machineName "is a `"Hot Spot`"!`nTier0 privileged account" $tier0Unique "is in danger" -BackgroundColor Red
                }
                Write-Host "Its credentials might be stolen by: $localThiefAccount" -BackgroundColor Red
                # to do: check if mulitple local privileged are on the machine
                $liveStatusLine.Color = "HotSpot"
                $liveStatusLine.TierLevel = "Tier0-HighestRisk"
                $liveStatusLine.EndTime = "AtRisk"
                $liveStatusLine.mightStolenBy = [string]$localThiefAccount
                if (-not $liveStatusDB.ContainsKey($logonUserInfo.Computer)) {

                    $liveStatusDB.add($logonUserInfo.Computer, $liveStatusLine)
                }
                else {
                    $updatedStatusLines += $liveStatusDB[$logonUserInfo.Computer]
                    if ($logoffEvent) {                        
                        Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "logoff" -liveStatusLine $liveStatusLine
                    }
                    else {
                        $updatedStatusLines += $liveStatusLine
                    }
                    $liveStatusDB[$logonUserInfo.Computer] = $updatedStatusLines
                }
                Write-StatusFile -liveStatusValues $liveStatusDB.values

                return "HotSpotTier0"
            }
            else {
                Write-Host "Computer" $machineName "is a `"Cold Spot`" with the Tier0 privileged " $tier0Unique -BackgroundColor Blue
                $liveStatusLine.Color = "ColdSpot"
                $liveStatusLine.TierLevel = "Tier0-LoggedOn"
                $liveStatusLine.EndTime = "-"
                if (-not $liveStatusDB.ContainsKey($logonUserInfo.Computer)) {
                    $liveStatusDB.add($logonUserInfo.Computer, $liveStatusLine)
                }
                else {
                    $updatedStatusLines += $liveStatusDB[$logonUserInfo.Computer]
                    if ($logoffEvent) {
                        Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "logoff" -liveStatusLine $liveStatusLine
                    }
                    else {
                        $updatedStatusLines += $liveStatusLine
                    }
                    $liveStatusDB[$logonUserInfo.Computer] = $updatedStatusLines
                }
                Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "NoHotSpotsTier0"

                return "ColdSpotTier0"
            }
        }
        else {
            Write-Host "Computer" $machineName "is a `"Cold Spot`" with the Tier0 privileged " $tier0Unique -BackgroundColor Blue
            $liveStatusLine.Color = "ColdSpot"
            $liveStatusLine.TierLevel = "Tier0-LoggedOn"
            $liveStatusLine.EndTime = "-"
            if (-not $liveStatusDB.ContainsKey($logonUserInfo.Computer)) {
                $liveStatusDB.add($logonUserInfo.Computer, $liveStatusLine)
            }
            else {
                $updatedStatusLines += $liveStatusDB[$logonUserInfo.Computer]
                if ($logoffEvent) {
                    Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "logoff" -liveStatusLine $liveStatusLine
                }
                else {
                    $updatedStatusLines += $liveStatusLine
                }
                $liveStatusDB[$logonUserInfo.Computer] = $updatedStatusLines
            }
            Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "NoHotSpotsTier0"

            return "ColdSpotTier0"
        }
    }
    # if there are no log ons with Tier 0 accounts
    else {
        # if there are log ons with Tier 1 accounts
        if ($deleteHistory) {
            $liveStatusDB[$logonUserInfo.Computer] = $liveStatusDB[$logonUserInfo.Computer] | ? {$_.LogonID -ne $liveStatusLine.LogonID}
        }
        else {
            Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "NoTier0"
        }
        # if there are log ons of Tier 1 accounts
        if ($localTier1){
            $tier1UniqueEx = ($localTier1.loggedOnUser).ToLower()  | select -Unique
            $tier1Unique = [string]$tier1UniqueEx
            $liveStatusLine.privilegedAccountAtRisk = $tier1Unique
            if ($localPrivAccounts) {
                $otherPrivAccount = $localPrivAccounts | ? {($_.isTier1 -eq "No")}
                if ($otherPrivAccount) {
                    $localThiefAccount = ($otherPrivAccount.loggedOnUser).ToLower() | select -Unique
                    if ($tier1UniqueEx.count -gt 1) {
                        Write-Host "Computer" $machineName "is a `"Hot Spot`"!`nTier1 privileged accounts" $tier1Unique "are in danger" -BackgroundColor Red
                    }
                    else {
                        Write-Host "Computer" $machineName "is a `"Hot Spot`"!`nTier1 privileged account" $tier1Unique "is in danger" -BackgroundColor Red
                    }
                    Write-Host "Its credentials might be stolen by: $localThiefAccount" -BackgroundColor Red
                    # to do: check if mulitple local privileged are on the machine
                    $liveStatusLine.Color = "HotSpot"
                    $liveStatusLine.TierLevel = "Tier1-HighestRisk"
                    $liveStatusLine.EndTime = "AtRisk"
                    $liveStatusLine.mightStolenBy = $localThiefAccount
                    if (-not $liveStatusDB.ContainsKey($logonUserInfo.Computer)) {

                        $liveStatusDB.add($logonUserInfo.Computer, $liveStatusLine)
                    }
                    else {
                        $updatedStatusLines += $liveStatusDB[$logonUserInfo.Computer]
                        if ($logoffEvent) {
                            
                            Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "logoff" -liveStatusLine $liveStatusLine
                        }
                        else {
                            $updatedStatusLines += $liveStatusLine
                        }
                        $liveStatusDB[$logonUserInfo.Computer] = $updatedStatusLines
                    }
                    Write-StatusFile -liveStatusValues $liveStatusDB.values

                    return "HotSpotTier1"
                }
                else {
                    Write-Host "Computer" $machineName "is a `"Cold Spot`" with the Tier1 privileged " $tier0Unique -BackgroundColor Blue
                    $liveStatusLine.Color = "ColdSpot"
                    $liveStatusLine.TierLevel = "Tier1-LoggedOn"
                    $liveStatusLine.EndTime = "-"
                    if (-not $liveStatusDB.ContainsKey($logonUserInfo.Computer)) {
                        $liveStatusDB.add($logonUserInfo.Computer, $liveStatusLine)
                    }
                    else {
                        $updatedStatusLines += $liveStatusDB[$logonUserInfo.Computer]
                        if ($logoffEvent) {
                            Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "logoff" -liveStatusLine $liveStatusLine
                        }
                        else {
                            $updatedStatusLines += $liveStatusLine
                        }
                        $liveStatusDB[$logonUserInfo.Computer] = $updatedStatusLines
                    }
                    Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "NoHotSpotsTier1"

                    return "ColdSpotTier1"
                }
            }
            else {
                Write-Host "Computer" $machineName "is a `"Cold Spot`" with the Tier1 privileged " $tier0Unique -BackgroundColor Blue
                $liveStatusLine.Color = "ColdSpot"
                $liveStatusLine.TierLevel = "Tier1-LoggedOn"
                $liveStatusLine.EndTime = "-"
                if (-not $liveStatusDB.ContainsKey($logonUserInfo.Computer)) {
                    $liveStatusDB.add($logonUserInfo.Computer, $liveStatusLine)
                }
                else {
                    $updatedStatusLines += $liveStatusDB[$logonUserInfo.Computer]
                    if ($logoffEvent) {
                            Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "logoff" -liveStatusLine $liveStatusLine
                    }
                    else {
                        $updatedStatusLines += $liveStatusLine
                    }
                    $liveStatusDB[$logonUserInfo.Computer] = $updatedStatusLines
                }
                Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "NoHotSpotsTier1"
                return "ColdSpotTier1"
            }
        }
        # if there are no log ons with Tier 0 and no Tier 1
        else {
            Update-StatusFile -liveStatusValues $liveStatusDB.values -logonUserInfo $logonUserInfo -updateType "NoTier1"
            return "Clear"
        }
    }

    return "Clear"
}


# Get the logon information
function Get-LoggedOnInfoLine {
    [CmdletBinding()]
            
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $logInfoObject
    )
    $computerLiveConnectionInfo = "" | select computer,workstation,IP,
          loggedOnUser,loggedOnUserSID,userDomain,logonID,logOnStartTime,isLocalPrivilege,isTier0,isTier1,loggedOnRecordID
    $computerLiveConnectionInfo.computer = $logInfoObject.Computer
    $computerLiveConnectionInfo.workstation = $logInfoObject.workstation
    $computerLiveConnectionInfo.IP = $logInfoObject.IpAddress
    if ($logInfoObject.SubjectUserSid) {
        $computerLiveConnectionInfo.loggedOnUser = $logInfoObject.SubjectUserName
        $computerLiveConnectionInfo.loggedOnUserSID = $logInfoObject.SubjectUserSid
        $computerLiveConnectionInfo.userDomain = $logInfoObject.SubjectDomainName
    }
    else {
        $computerLiveConnectionInfo.loggedOnUser = $logInfoObject.TargetUserName
        $computerLiveConnectionInfo.loggedOnUserSID = $logInfoObject.TargetUserSid
        $computerLiveConnectionInfo.userDomain = $logInfoObject.TargetDomainName
    }
    if ($logInfoObject.SubjectLogonId) {
        $computerLiveConnectionInfo.logonID = $logInfoObject.SubjectLogonId
    }
    else {
        $computerLiveConnectionInfo.logonID = $logInfoObject.TargetLogonId
    }
    $computerLiveConnectionInfo.logOnStartTime = $logInfoObject.logEventTime
    $computerLiveConnectionInfo.isLocalPrivilege = "No"
    if ($logInfoObject.EventID -eq "4672") {
        $computerLiveConnectionInfo.isLocalPrivilege = "Yes"
    }
    # check the sensitivity level of the loggen on user
    $computerLiveConnectionInfo.isTier0 = Check-UserTier0 -userSID $computerLiveConnectionInfo.loggedOnUserSID
    $computerLiveConnectionInfo.isTier1 = Check-UserTier1 -userSID $computerLiveConnectionInfo.loggedOnUserSID
    $computerLiveConnectionInfo.loggedOnRecordID = $logInfoObject.EventRecordID
    
    return $computerLiveConnectionInfo
}

# Analyze the live connection on the monitored machines
function Analyze-liveConnections {
    [CmdletBinding()]
            
    param( 
        [Parameter(ValueFromPipeline=$true)]
        $logInfoObject
    )

    if ($logInfoObject.SubjectLogonId) {
        $logonId = $logInfoObject.SubjectLogonId 
    }
    else {
        $logonId = $logInfoObject.TargetLogonId
    }

    $liveConnectionCompPath = $PSScriptRoot + "\Results\" + $logInfoObject.Computer +"-liveConnections.csv"
    
    # check if the SubjectUserName is "LOCAL SERVICE" or SYSTEM and pass to the next event log
    if (($logInfoObject.SubjectUserName -eq "LOCAL SERVICE") -or ($logInfoObject.SubjectUserName -eq "SYSTEM")) {
        return $false
    }
    # check if there are events that might point out that the machine is probably after a restart, then we reset the machine's connections (it's for reducing FP rates)
    if (($logInfoObject.EventID -eq "4608") -or ($logInfoObject.EventID -eq "6005") -or ($logInfoObject.EventID -eq "6006") -or ($logInfoObject.EventID -eq "6009") -or ($logInfoObject.EventID -eq "6013")) {
        try {
            "" |  out-file $liveConnectionCompPath
            $computerLiveConnectionInfo = Get-LoggedOnInfoLine -logInfoObject $logInfoObject
            $machineColorSpot = Check-ColdHotSpot -machineInfo $liveConnectionsDB[$logInfoObject.Computer] -logonUserInfo $computerLiveConnectionInfo -reset $True
            # export the connection DB
            $liveConnectionsDB[$logInfoObject.Computer] = $liveConnectionsDB[$logInfoObject.Computer] | ? {$_.Computer -ne $logInfoObject.Computer}
            if ($liveConnectionsDB[$logInfoObject.Computer].count -eq 0) {
                $liveConnectionsDB.Remove($logInfoObject.Computer)
            }
            else {
                $liveConnectionsDB[$logInfoObject.Computer] | Export-Csv -NoTypeInformation $liveConnectionCompPath
            }
        }
        catch {
            Write-verbose "Could not reset the machine connections file"
        }
        return $false
    }

    # check if the loggedon user is a machine account then continue
    if ($logInfoObject.SubjectUserName) {
        if (($logInfoObject.SubjectUserName).Substring(($logInfoObject.SubjectUserName).Length - 1) -eq "$") {
            return $false
        }
    }
    elseif ($logInfoObject.TargetUserName) {
        if (($logInfoObject.TargetUserName).Substring(($logInfoObject.TargetUserName).Length - 1) -eq "$") {
            return $false
        }
    }

    if (-not $quietMode) {
        Write-host "--- new event log ---"
    }

    if ($liveConnectionsDB.ContainsKey($logInfoObject.Computer)) {
        # check if another user logged on to the same computer
        if ($logInfoObject.EventID -eq "4624" -or $logInfoObject.EventID -eq "4672") {    
            # check for duplicate log events
            if (
               ($liveConnectionsDB[$logInfoObject.Computer].logonID -contains $logInfoObject.SubjectLogonId) -or 
               ($liveConnectionsDB[$logInfoObject.Computer].logonID -contains $logInfoObject.TargetLogonId)){
                #Write-Host "existing logged on user"
                if ($logInfoObject.SubjectUserName) {
                    if (-not $quietMode) {
                        Write-host $logInfoObject.SubjectUserName "is already logged on in" $logInfoObject.Computer "[$logonId]"
                    }
                }
                else {
                    if (-not $quietMode) {
                        Write-host $logInfoObject.TargetUserName "is already logged on in" $logInfoObject.Computer "[$logonId]"
                    }
                }
            }
            else {
                $updatedComputerInfo = @()
                $computerLiveConnectionInfo = Get-LoggedOnInfoLine -logInfoObject $logInfoObject

                if ($logInfoObject.SubjectUserName) {
                    if (-not $quietMode) {
                        Write-host $logInfoObject.SubjectUserName "was logged on to " $logInfoObject.Computer "[$logonId]"
                    }
                }
                else {
                    if (-not $quietMode) {
                        Write-host $logInfoObject.TargetUserName "was logged on to " $logInfoObject.Computer "[$logonId]"
                    }
                }

                $updatedComputerInfo += $liveConnectionsDB[$logInfoObject.Computer] 
                $updatedComputerInfo +=  $computerLiveConnectionInfo
                $liveConnectionsDB[$logInfoObject.Computer] = $updatedComputerInfo
                $machineColorSpot = Check-ColdHotSpot -machineInfo $liveConnectionsDB[$logInfoObject.Computer] -logonUserInfo $computerLiveConnectionInfo
                # export the connection DB
                $liveConnectionsDB[$logInfoObject.Computer] | Export-Csv -NoTypeInformation $liveConnectionCompPath
            }
            
        }
        # check if the user logged off and remove it from the live connections DB 
        if ($logInfoObject.EventID -eq "4634" -or $logInfoObject.EventID -eq "4647") {
            if (($liveConnectionsDB[$logInfoObject.Computer].logonID -contains $logInfoObject.SubjectLogonId) -or 
               ($liveConnectionsDB[$logInfoObject.Computer].logonID -contains $logInfoObject.TargetLogonId)) {
                if ($logInfoObject.SubjectLogonId) {
                    $loggedOffId = $logInfoObject.SubjectLogonId
                }
                else {
                    $loggedOffId = $logInfoObject.TargetLogonId
                }
                # only remove the connection with the same LogonID
                $userLoggedoff = $liveConnectionsDB[$logInfoObject.Computer] | foreach {if($loggedOffId -eq $_.logonID){$_}}
                $liveConnectionsDB[$logInfoObject.Computer] = $liveConnectionsDB[$logInfoObject.Computer] | ? {$_.logonID -ne $loggedOffId}
                if (-not $quietMode) {
                    Write-host $logInfoObject.TargetUserName "was logged off from" $logInfoObject.Computer "[$logonId]" 
                }
                $computerLiveConnectionInfo = Get-LoggedOnInfoLine -logInfoObject $logInfoObject
                $machineColorSpot = Check-ColdHotSpot -machineInfo $liveConnectionsDB[$logInfoObject.Computer] -logonUserInfo $computerLiveConnectionInfo -logoffEvent $True
                # export the connection DB
                $liveConnectionsDB[$logInfoObject.Computer] | Export-Csv -NoTypeInformation $liveConnectionCompPath
                if ($liveConnectionsDB[$logInfoObject.Computer].count -eq 0) {
                    $liveConnectionsDB.Remove($logInfoObject.Computer)
                }
            #    }
            }
            else {
                if (-not $quietMode) {
                    Write-host $logInfoObject.TargetUserName "was logged off without previous log-on event from" $logInfoObject.Computer "[$logonId]"
                }
            }
        }
    }
    else {
        # build the new connection data info - when user as first and only one live logged on user
        if ($logInfoObject.EventID -eq "4624" -or $logInfoObject.EventID -eq "4672") {
            $computerLiveConnectionInfo = Get-LoggedOnInfoLine -logInfoObject $logInfoObject
            $updatedComputerInfo = @()
            $updatedComputerInfo +=  $computerLiveConnectionInfo
            $liveConnectionsDB.add($logInfoObject.Computer, $updatedComputerInfo)
            if ($logInfoObject.SubjectUserName) {
                if (-not $quietMode) {
                    Write-host $logInfoObject.SubjectUserName  "was the first to log on to"  $logInfoObject.Computer "[$logonId]"
                }
            }
            else {
                if (-not $quietMode) {
                    Write-host $logInfoObject.TargetUserName "was the first to log on to" $logInfoObject.Computer "[$logonId]" 
                }
            }
            $machineColorSpot = Check-ColdHotSpot -machineInfo $liveConnectionsDB[$logInfoObject.Computer] -logonUserInfo $computerLiveConnectionInfo
            # export the connection DB
            $liveConnectionsDB[$logInfoObject.Computer] | Export-Csv -NoTypeInformation $liveConnectionCompPath
        }
    }
    
    return $true
}

# The main funcation that start the detection process
function Start-DetectionProcess {
    $epochTime = [timezone]::CurrentTimeZone.ToLocalTime([datetime]'1/1/1970')
    $logsLiveDataPath = $resultsPath + "\LogsRawSavedData.csv"
    $eventLogHistory10mins = @{}
    $loopCounter = 0
    $logCounter = 0
    $logErrorCounter = 0
    $knownLogCounter = 0
    $logEventHistory = @{}
    # if you want the tool to analyze also logs from the history
    # if you choose $withHistory = $false it will start live analysis from from of the execution forward
    $withHistory = $true
    #$withHistory = $false

    do {
        $stop = $false
        $loopCounter += 1
        $startLoopTime = Get-Date
        # duration time parameter to query logs from the past loop (may be double log reading)
        if ($loopCounter -eq 1) {
            # here you can define the exact time the tool will analyze and read past history logs
            # 1 day = 1440 mins, 30 days = 43200 mins, 4 months = 175200 mins, 1 year = 525600 mins (analyzing more days will need more resources (time + memory))
            #$overlapTimeMinutes = 100
            try {
                $overlapTimeMinutes = [Double]$days*24*60
            }
            catch {
                $overlapTimeMinutes = 5
            }
            
        }
        else {
            $overlapTimeMinutes = 5
        }
        $lastRefreshTime = (Get-Date) - ($loopDuration + (New-TimeSpan -Minutes $overlapTimeMinutes))     

        # 4624: An account was successfully logged on
        # 4672: Special privileges assigned to new logon
        # 4634: An account was logged off
        # 4647: User initiated logoff
        # option to use "TimeCreated[timediff(@SystemTime) <= 10000]" to get events in the last 10 seconds.

        $eventLogs = Get-WinEvent -ComputerName $eventLogCollectorName -FilterHashtable @{logname=$logFolderName;id=4624,4672,4634,4647,6005,6006,6009,6013,4608; StartTime=$lastRefreshTime} -erroraction 'silentlycontinue' 
        if ($eventLogs) {
            [array]::Reverse($eventLogs)
            foreach ($eventObject in $eventLogs) {
                try {
                    $logXMLobject = [xml] $eventObject.ToXml()
                    # analyze each log event
                    $logInfoObject = Read-LogEventInfo -LogObject $logXMLobject
                    if ($logInfoObject) {
                        # update the exported logs data file
                        $EventRecordID = $logXMLobject.Event.System.EventRecordID
                        if ($logEventHistory.ContainsKey($EventRecordID)) {
                            $knownLogCounter += 1
                        }
                        else {
                            $logCounter += 1
                            # analyze the event log
                            $writelogInfo = Analyze-liveConnections -logInfoObject $logInfoObject
                            if ($writelogInfo) {
                                $logEventHistory.add($EventRecordID, $logCounter)
                                # check if the tool is configured to save the raw analyzed data of the logs - to the disk to "LogsRawSavedData.csv"
                                if (-not $noRawData) {
                                    $logInfoObject | Export-Csv $logsLiveDataPath -NoTypeInformation -Append
                                }
                            }
                        }  
                    }
                }
                catch {
                    $logErrorCounter += 1
                    $ErrorMessage = $_.Exception.Message
                    # in the future maybe to remove this alert
                    if (-not $quietMode) {
                        Write-Output "* Could not read log event number: $EventRecordID`nMessage:$ErrorMessage"
                    }
                }
                
            }
        }

        # the following parameter is setting the time interval that the tool will output an update of its loop counting number
        if (-not $quietMode) {
            $outputLoopStatusParameter = 100
        }
        else {
            $outputLoopStatusParameter = 10000
        }
        if ($loopCounter -eq 1){
            Write-Output "`n-----------------------------------------------------------------"
            Write-Output " Starting live monitoring of the logs..."
            Write-Output "-----------------------------------------------------------------"
        }
        if (($loopCounter % $outputLoopStatusParameter) -eq 0){
            Write-Output "Status: reading logs - loop number $loopCounter`n`t$logCounter log event analyzed successfully and $logErrorCounter specific errors"
        }

        # optional sleep parameter in seconds between each loop
        $sleepBetweenLoopsSeconds = $sleepTime
        Start-Sleep -s $sleepBetweenLoopsSeconds
        $loopDuration = (Get-Date) - $startLoopTime
    }
    until ($stop -eq $true)
}


# Create the results folder
$resultsPath = $PSScriptRoot + "\Results"
if (Test-Path $resultsPath)
{
    write-verbose "The results folder was already exists"
}
else
{
    New-Item -ItemType directory -Path $resultsPath
}

$ACLightPath = $PSScriptRoot + "\ACLight2.ps1"
$tier0PrivilegedListPath = $PSScriptRoot + "\Accounts Lists\Tier 0 - most privileged accounts.csv"
$tier1PrivilegedListPath = $PSScriptRoot + "\Accounts Lists\Tier 1 - privileged accounts.csv"
$liveConnectionsDBPath = $PSScriptRoot + "\Results\liveConnections.csv"
$liveStatusPath = $PSScriptRoot + "\Results\Main-LiveStatus.csv"


if (Test-Path $tier0PrivilegedListPath)
{
    write-verbose "The Tier 0 accounts list is already exists"
}
else {
    # the tool will scan the privileged account for only the current Domain
    $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    Import-Module $ACLightPath -force
    Start-ACLsAnalysis -Domain $currentDomain
    Get-ACLightResults -Tier "tier0"
}

# read the Tier0 account list - the most privileged account in the network
$accountListTier0 = Import-Csv $tier0PrivilegedListPath | select "AccountName", "AccountSID" -Unique 
$accountListTier0DB = @{}
$accountListTier0 | foreach {
    $accountListTier0DB.add($_.AccountSID, $_.AccountName)
}
Write-Output "`nTier 0 account list was loaded - the most privileged accounts are:"
Write-Output $accountListTier0DB.Values

# if you want the tool to create tier 1 automatically - $tier1EnableScan should be $true
$tier1EnableScan = $false
#$tier1EnableScan = $true
if ($tier1EnableScan) {
    if (Test-Path $tier1PrivilegedListPath)
    {
        write-verbose "The Tier 1 accounts list is already exists"
    }
    else {
        Import-Module $ACLightPath -force
        Start-ACLsAnalysis -Full $True -Domain $currentDomain
        Get-ACLightResults -Tier "tier1"
    }
}

$accountListTier1DB = @{}
if (Test-Path $tier1PrivilegedListPath)
{
    $accountListTier1 = Import-Csv $tier1PrivilegedListPath | select "AccountName", "AccountSID" -Unique 
    $accountListTier1 | foreach {
        $accountListTier1DB.add($_.AccountSID, $_.AccountName)
    }
    Write-Output "`nTier 1 account list was loaded - currently those privileged accounts are:"
    Write-Output $accountListTier1DB.Values,""
}

$loopDuration = New-TimeSpan -Minutes 0

# the structure of the live connections db "liveConnectionsDB":
$liveConnectionsDB = @{}
$liveStatusDB = @{}

Write-Output "-----------------------------------------------------------------"
Write-Output " Starting historical HotSpots detection for the last $days days..."
Write-Output "-----------------------------------------------------------------`n"

Start-DetectionProcess
