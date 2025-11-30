# Threat-Hunting-Project-Port-of-Entry

## Executive Summary
INCIDENT BRIEF - Azuki Import/Export 
SITUATION:
Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

COMPANY:
Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia

COMPROMISED SYSTEMS:

AZUKI-SL (IT admin workstation)

EVIDENCE AVAILABLE:
Microsoft Defender for Endpoint logs


### 🕵️ **Flag 1: INITIAL ACCESS - Remote Access Source** 🔍 

Flag 1
Remote Desktop Protocol connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.
Hint 1:
Query logon events for interactive sessions from external sources during the incident timeframe.
Hint 2:
Use DeviceLogonEvents table and filter by ActionType or LogonType values indicating remote access.

Thought Process:
The flag description says this is about Remote Desktop Protocol and that we need to identify the source of unauthorized remote access.

Hint 1 tells me to look at interactive logon events from external sources during the incident window.

Hint 2 tells me to use the DeviceLogonEvents table and focus on fields that indicate remote access (such as ActionType and LogonType).

<img width="422" height="377" alt="1" src="https://github.com/user-attachments/assets/fa025d91-c350-4981-bf9e-f4cf69aa1a2b" />

**Answer**: 88.97.178.12

### 🕵️ **Flag 1: INITIAL ACCESS - Remote Access Source** 🔍 

Flag 1
Remote Desktop Protocol connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.
Hint 1:
Query logon events for interactive sessions from external sources during the incident timeframe.
Hint 2:
Use DeviceLogonEvents table and filter by ActionType or LogonType values indicating remote access.

Thought Process:
The flag description says this is about Remote Desktop Protocol and that we need to identify the source of unauthorized remote access.

Hint 1 tells me to look at interactive logon events from external sources during the incident window.

Hint 2 tells me to use the DeviceLogonEvents table and focus on fields that indicate remote access (such as ActionType and LogonType).

<img width="422" height="377" alt="1" src="https://github.com/user-attachments/assets/fa025d91-c350-4981-bf9e-f4cf69aa1a2b" />

**Answer**: 88.97.178.12

### 🕵️ **Flag 2: INITIAL ACCESS - Compromised User Account**

Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.
Hint 1:
Focus on the account that authenticated during the suspicious remote access session.
Hint 2:
Cross-reference the logon event timestamp with the external IP connection.


Thought Process:
Focus on the authenticated account with logonsuccess action type
<img width="728" height="317" alt="2" src="https://github.com/user-attachments/assets/80580ca9-2eb7-4c28-a87d-553d5de051c6" />


**Answer**: kenji.sato

### 🕵️ **Flag 3: DISCOVERY - Network Reconnaissance**

Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.
Hint 1:
Look for commands that reveal local network devices and their hardware addresses.
Hint 2:
Check DeviceProcessEvents for network enumeration utilities executed after initial access.

Thought Process:
Commands that look for network devices use ARP to reveal MAC addresses. If there is a scan most likely there will be ARP process.

<img width="560" height="236" alt="3" src="https://github.com/user-attachments/assets/fe1d9b7e-d5e8-4785-8fac-adfb358e73c7" />

**Answer**: "ARP.EXE" -a

### 🕵️ **Flag 4: DEFENCE EVASION - Malware Staging Directory** 🔍 

Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.
Hint 1:
Search for newly created directories in system folders that were subsequently hidden from normal view.
Hint 2:
Look for mkdir or New-Item commands followed by attrib commands that modify folder attributes.


Thought Process:
I checked Mitre framework for this and was able to check folder path that contains "zip"

<img width="573" height="451" alt="4" src="https://github.com/user-attachments/assets/ba57a28b-2349-47f4-9cfe-4dad29dd9e73" />


**Answer**: C:\ProgramData\WindowsCache

### 🕵️ **Flag 5: DEFENCE EVASION - File Extension Exclusions** 🔍 

Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.
Hint 1: Search DeviceRegistryEvents for registry modifications to Windows Defender's exclusion settings. Look for the RegistryValueName field containing file extensions.
Hint 2: Count the unique file extensions added to the "Exclusions\Extensions" registry key during the attack timeline.

Thought Process:
Checked Registry related logs where new values are set

<img width="695" height="552" alt="5" src="https://github.com/user-attachments/assets/c1a1cd25-479e-47ea-bc69-fc65a93e9499" />


**Answer**: 3

### 🕵️ **Flag 6: DEFENCE EVASION - Temporary Folder Exclusion** 🔍 

Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.
Hint 1: Search DeviceRegistryEvents for folder path exclusions added to Windows Defender configuration. Focus on the RegistryValueName field.
Hint 2: Look for temporary folder paths added to the exclusions list during the attack timeline. Copy the path exactly as it appears in the RegistryValueName field.
Hint 3: The registry key contains "Exclusions\Paths" under Windows Defender configuration.

Thought Process:
Searched registry value names with temp in the path.


<img width="732" height="557" alt="6" src="https://github.com/user-attachments/assets/11675b3e-def4-4cfa-ba32-fcfb9a431b28" />


**Answer**: C:\Users\KENJI~1.SAT\AppData\Local\Temp

### 🕵️ **Flag 7: DEFENCE EVASION - Download Utility Abuse** 🔍 

Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.
Hint 1: Look for built-in Windows tools with network download capabilities being used during the attack.
Hint 2: Search DeviceProcessEvents for processes with command lines containing URLs and output file paths.

Thought Process:
Checked command line processes that has http since there should be an outbound connection to a url


<img width="706" height="590" alt="7" src="https://github.com/user-attachments/assets/6b33cf6c-b119-4aae-95fc-d0b05f944da4" />


**Answer**: certutil.exe

### 🕵️ **Flag 8: PERSISTENCE - Scheduled Task Name** 🔍 

Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.
Hint 1: Search for scheduled task creation commands executed during the attack timeline.
Hint 2: Look for schtasks.exe with the /create parameter in DeviceProcessEvents.

Thought Process:
Looked for scheduled tasks exe command
<img width="693" height="491" alt="8" src="https://github.com/user-attachments/assets/5c71d27d-aa65-4a54-b369-7b46a6343710" />


**Answer**: Windows Update Check

### 🕵️ **Flag 9: PERSISTENCE - Scheduled Task Target** 🔍 

The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.
Hint 1: Extract the task action from the scheduled task creation command line.
Hint 2: Look for the /tr parameter value in the schtasks command.

Thought Process:
This was straight forward after finding the scheduled task exe, just had to check the location.

<img width="750" height="381" alt="9" src="https://github.com/user-attachments/assets/b31cea9b-9691-4839-9d42-6ed3a8e3d82f" />


**Answer**: C:\ProgramData\WindowsCache\svchost.exe 

### 🕵️ **Flag 10: COMMAND & CONTROL - C2 Server Address** 🔍 

Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.
Hint 1: Analyse network connections initiated by the suspicious executable shortly after it was downloaded.
Hint 2: Use DeviceNetworkEvents to find outbound connections from the malicious process to external IP addresses.

Thought Process:
Added exe into my search to catch execution event where action type had to be success since  and remote ip type public.
<img width="736" height="392" alt="10" src="https://github.com/user-attachments/assets/472e9bf4-1d84-4f56-91ff-1c0945b909b6" />

**Answer**: 78.141.196.6

### 🕵️ **Flag 11: COMMAND & CONTROL - C2 Communication Port** 🔍 

C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.
Hint 1: Examine the destination port for outbound connections from the malicious executable.
Hint 2: Check DeviceNetworkEvents for the RemotePort field associated with C2 traffic.

Thought Process:
Added remote port into the previous query.

<img width="727" height="472" alt="11" src="https://github.com/user-attachments/assets/69ff8f3c-8410-45d9-8a72-d3c1e3a3419f" />


**Answer**: 443

### 🕵️ **Flag 12: CREDENTIAL ACCESS - Credential Theft Tool** 🔍 

Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.
Hint 1: Look for executables downloaded to the staging directory with very short filenames.
Hint 2: Search for files created shortly before LSASS memory access events.

Thought Process:
Checked file names that includes exe and looked for a short name.

<img width="731" height="238" alt="12" src="https://github.com/user-attachments/assets/46f6516a-7257-40a5-90c7-1e760ce84d0f" />


**Answer**: mm.exe

### 🕵️ **Flag 13: CREDENTIAL ACCESS - Memory Extraction Module** 🔍 

Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.
Hint 1: Examine the command line arguments passed to the credential dumping tool.
Hint 2: Look for module::command syntax in the process command line or output redirection.

Thought Process:
Had to look for "::" keyword to find which command was executed.
<img width="531" height="245" alt="13" src="https://github.com/user-attachments/assets/b601e030-a87d-4786-aa2c-d903c54c925c" />


**Answer**: sekurlsa::logonpasswords

### 🕵️ **Flag 14: COLLECTION - Data Staging Archive** 🔍 
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.
Hint 1: Search for ZIP file creation in the staging directory during the collection phase.
Hint 2: Look for Compress-Archive commands or examine files created before exfiltration activity.

Thought Process:
Searched for zip and export keywords since it had to be compressed and exfiltrated


<img width="653" height="278" alt="14" src="https://github.com/user-attachments/assets/f140956c-2276-4ebf-8ff0-83c7b64d1fdf" />

**Answer**: export-data.zip

### 🕵️ **Flag 15: CREDENTIAL ACCESS - Memory Extraction Module** 🔍 

Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.
Hint 1: Analyse outbound HTTPS connections and file upload operations during the exfiltration phase.
Hint 2: Check DeviceNetworkEvents for connections to common file sharing or communication platforms.

Thought Process:
Looked for devicenetworkevents by using http in the query.

<img width="678" height="347" alt="15" src="https://github.com/user-attachments/assets/7d5da300-d72b-4da4-a057-8a4796c044e7" />


**Answer**: discort

### 🕵️ **Flag 16: ANTI-FORENSICS - Log Tampering** 🔍 

Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.
Hint 1: Search for event log clearing commands near the end of the attack timeline.
Hint 2: Look for wevtutil.exe executions and identify which log was cleared first.

Thought Process:
Looked for file name with wevtutil.exe

<img width="606" height="260" alt="16" src="https://github.com/user-attachments/assets/1b87efe7-be77-4d52-b70b-781889a1624f" />


**Answer**: Security

### 🕵️ **Flag 17: IMPACT - Persistence Account** 🔍 

Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.
Hint 1: Search for account creation commands executed during the impact phase.
Hint 2: Look for commands with the /add parameter followed by administrator group additions.

Thought Process:
Looked for account creation command that would have "/add" in the process command line

<img width="591" height="342" alt="17" src="https://github.com/user-attachments/assets/3dab7732-4930-498d-afc7-a83daa2e4f17" />


**Answer**: support


### 🕵️ **Flag 19: LATERAL MOVEMENT - Secondary Target** 🔍 
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.
Hint 1: Examine the target system specified in remote access commands during lateral movement.
Hint 2: Look for IP addresses used with cmdkey or mstsc commands near the end of the attack timeline.

Thought Process:
Searched for IP addresses used with cmdkey or mstsc commands.

<img width="623" height="296" alt="19" src="https://github.com/user-attachments/assets/6c05df71-62e9-4f7f-97e8-5f1a2f133f89" />


**Answer**: 10.1.0.188

### 🕵️ **Flag 20: LATERAL MOVEMENT - Remote Access Tool** 🔍 

Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.
Hint 1: Search for remote desktop connection utilities executed near the end of the attack timeline.
Hint 2: Look for processes launched with remote system names or IP addresses as arguments.


Thought Process:
Searched for remote port 3389 to look for remote connection

<img width="528" height="345" alt="20" src="https://github.com/user-attachments/assets/f531667b-5fa7-40ca-bdfc-6495260a6a68" />


**Answer**: mstsc.exe
