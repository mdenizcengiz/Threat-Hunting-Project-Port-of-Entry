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
