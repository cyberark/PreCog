# PreCog

Discover "HotSpots" - potential spots for credentials theft.

# The main goal
Discover and mitigate HotSpots machines in your network - those dangerous spots could be abused by attackers to steal privileged accounts credential.

Those risky spots are used by attackers for lateral movement and privilege escalation through the network until they achieved their desired “Domain Admin” credentials.

# More details could be found in CyberArk's Threat Research Blog

# Tool description
What is PreCog?  
PreCog is a PowerShell tool aimed to implement credentials theft precognition by detecting HotSpots in the network. The tool analyzes event logs from domain connected machines through WEF (Windows Event Forwarding) server and follows the privileged account activity on those machines.  
The analysis identifies machine HotSpots that have open logon sessions from both - Tier 0 privileged account (e.g. Domain Admin) and another account that has lower local admin rights on the detected machine spot. This last account might have been compromised by a potential attacker and so the credentials of the Tier 0 account might be at risk.  
Therefore, by discovering and eliminating those HotSpots, the risk can be mitigated and future possible credentials theft attempts are prevented.

# PreCog’s optional parameters:
*	$days:  
Sets how many days back the tool will analyze. By default it’s set to only analyze the past 7 mins.
*	$eventLogCollectorName:  
Set PreCog to query a remote WEF server, $eventLogCollectorName should be the name of the remote WEF server. The default is the current machine where the script is running.
*	$sleepTime:  
Sets the sleep duration time between each log reading check by the PreCog of the WEF’s logs storage. $sleepTime defines a sleeping time in seconds (by default it’s 1 second).
*	$noRawData:  
Switch parameter to cancel saving of the raw output file of the analyzed logs - the "LogsRawSavedData.csv" file.
*	$quietMode:  
Switch parameter used to reduce the number of messages to be printed out during the tool’s execution window. In the regular operation mode the tool will print out each event log that was processed with few more information like the account name, computer and logonID.

# Execution command examples:
```
*	. .\PreCog.ps1
```
Simple execution with default configuration.
```
*	. .\PreCog.ps1 -eventLogCollectorName RemoteWEF-Name -noRawData -quietMode
```
PreCog will be executed and fetch the event logs from the “RemoteWEF-Name” (it requires the permission to read those logs, and a network connectively to that WEF server). In this configuration example, PreCog will not save the raw information of the analyzed logs, and it will be running in a quiet mode - it will only print out to the screen if there are new Cold and Hot Spots that were detected.

# Full technical details
PreCog queries WEF and analyzes 4 important event logs:
*	4624 - An account was successfully logged on.
*	4672 - Special privileges assigned to new logon.
*	4647 - User initiated logoff.
*	4634 - An account was logged off.

Those event logs provide the PreCog the ability to follow the logon sessions on each of the monitored machines.  
The tool also process a few more event logs with the intention of detecting machines that were restarted and therefore their active logon sessions list should be reset. The event IDs that imply on a machine’s restart are: 4608 - “Windows is starting up”, 6005 - “Event Log service was started”, 6006 - “The Event log service was stopped” and 6008 - "There was unexpected shutdown”.

The tool includes two folders and two scripts in its home folder. 
A look of PreCog’s home folder:
<p align="center">
  <img width="600" height="145" src="https://github.com/Hechtov/Photos/blob/master/HotSpots/1.png">
</p>
The folder “Accounts lists” includes two csv files containing the lists of the privileged accounts in Tier 0 and Tier 1. Those accounts will be monitored by the PreCog tool.
The two csv lists are:
<p align="center">
  <img width="300" height="98" src="https://github.com/Hechtov/Photos/blob/master/HotSpots/2.png">
</p>
The structure of the privileged account lists:
<p align="center">
  <img width="600" height="276" src="https://github.com/Hechtov/Photos/blob/master/HotSpots/2-1.png">
</p>
PreCog correlates the AccountSID attribute from the csv lists with the SID attribute of the monitored event logs.

When you start the PreCog tool it will show the privilege accounts that were loaded and will be monitored.  
It will look like this:
<p align="center">
  <img width="600" height="485" src="https://github.com/Hechtov/Photos/blob/master/HotSpots/3.png">
</p>

Note - on first execution of PreCog - the list of “Tier 0 - most privileged accounts.csv” will be created automatically! It will be done by running the “ACLight2” tool script. ACLight is a special discovery tool that will discover the network’s most sensitive privileged accounts (more information on the ACLight tool could be seen in its official GitHub page:  
https://github.com/cyberark/ACLight  
And in the following blogpost:  
https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/.

PreCog’s first step is to check if it indeed has the Tier 0 list. If the file doesn’t exist ACLight2 will be executed. In addition - the two list of accounts - Tier 0 and Tier 1, could be modified manually, by adding the account’s details line with its name, domain and SID (the user’s Security Identifier). After PreCog loaded the accounts lists it progresses to the next step of analyzing the historic event logs. When past event logs analysis is completed, it will progress to perform live monitoring of the logs. 

Let’s move forward to describe the **Results folder**:
<p align="center">
  <img width="600" height="183" src="https://github.com/Hechtov/Photos/blob/master/HotSpots/4.png">
</p>
At first, the results folder should be empty. When the tool runs, the following csv files will be created, depends on the logs that the WEF server receives:
1.	Each of the monitored machines will have a separated csv file with the name format of: [ComputerName]-liveConnections.csv  
This csv file will follow the live logon sessions on each machine and will be updated automatically when those are created and terminated. The file will be first created on the first logon event that will be analyzed from that specific machine. When a sign out event log is processed, the corresponding user will be removed from the active session list in the machine’s liveConnection file.
An example for this file live connection csv file:
<p align="center">
  <img width="1000" height="79" src="https://github.com/Hechtov/Photos/blob/master/HotSpots/5.png">
</p>
You can see in the above example that “w10-research.research.com” machine host 3 active logon sessions (each has a unique logon ID). Two accounts are logged on, “win10_localAdmin” and “Administrator”.  
The liveConnection file contains more information on the monitored logged-on sessions, like: The account’s SID, domain name, time of the logged event the level of privileges associated with the account (local admin right, Tier 1 or Tier 0 privileges).
2.	Main-LiveStatus:  
This is the main analysis results file. There will be only one “main-liveStatus.csv” results file. 
<p align="center">
  <img width="1000" height="85" src="https://github.com/Hechtov/Photos/blob/master/HotSpots/6.png">
</p>
In the above example, we can see that there is an active Hot Spot!  
It’s the w10-research machine. The “Administrator” account, a Tier 0 privileged account, is logged-on while in the same time there is a non-Tier 0 account that is logged-on and it has local admin rights - it’s “win10_localAdmin” account.  
One can also notice that the machine ws-research-8.research.com is a “Cold Spot”. That is because PreCog detected that the “Administrator” account was logged-on to that computer.  
Another important thing to note is the historic spots! When a relevant sign out event log will be processed, the line of the Hot Spot will be changed to a historic spot - the term HISTORYspot will be added as a prefix to the computer name, as seen above. Moreover, the termination time of the HotSpot will be registered under the EndTime field.
3.	LogsRawSavedData  
This is a raw file with all the event logs that PreCog analyzed. The file isn’t needed for the standard operation tasks. 
4.	ACLight folder  
The folder will include the results of the ACLight2 if it was executed properly at the initial step of PreCog (to build the Tier 0 account list).
