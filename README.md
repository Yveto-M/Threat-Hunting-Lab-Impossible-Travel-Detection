# Threat-Hunting-Lab-Impossible-Travel-Detection

# 🚨 Threat Hunting Lab: Impossible Travel Detection

## 📘 Overview
This lab simulates a common identity-related threat: **Impossible Travel** — when a user logs in from two or more geographic locations in a short period, raising the possibility of account compromise. Using **Microsoft Sentinel** and **KQL (Kusto Query Language)**, you'll configure detection logic, trigger an alert, and complete a full incident response cycle per **NIST 800-161** guidelines.

---

## 🧪 Scenario Summary
Some organizations enforce strict geo-access controls or VPN usage policies. This lab explores how to:
- Detect erratic login behavior using Sentinel analytics rules.
- Investigate impossible travel alerts via the SigninLogs table.
- Simulate Azure logins from different cities.
- Respond to incidents by applying cloud identity investigation techniques.

---

## 🧰 Tools Used
- Microsoft Sentinel
- Azure Log Analytics Workspace
- Azure Virtual Machine
- Entra ID (Azure Active Directory)
- KQL (Kusto Query Language)

---

## ⚙️ Part 1: Create Detection Rule
### 🔎 Scheduled Query Rule (KQL):
```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
![image](https://github.com/user-attachments/assets/feea9881-6ee5-434c-9306-aadf414671d4)

### 📌 Rule Settings:
- **Name**: Impossible Travel Detection
- **Description**: Detects users logging in from multiple locations in a short time window
- **Run Frequency**: Every 4 hours
- **Lookup Period**: Last 5 hours
- **Create Incident Automatically**: ✅
- **Stop Running After Trigger**: ✅
- **Group alerts into a single incident**: 1 per 24h
- **Entity Mapping**:
  - `UserId → AadUserId`
  - `UserPrincipalName → DisplayName`
![image](https://github.com/user-attachments/assets/133e815d-2d00-447d-a3a9-a208a8017672)

---

## 🚨 Part 2: Trigger the Alert
Login to [https://portal.azure.com](https://portal.azure.com) from a new VM in a different region (e.g., East US) to generate geographically distinct sign-in logs.

---

## 🕵️ Part 3: Investigate the Alert

### 🔬 Investigation KQL:
```kql
let TargetUserPrincipalName = "user@example.com";
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

### Example Case:
- **User**: a9d973...@lognpacific.com  
- **User ID**: 30688920-e870-49db-82f3-fc9e12135daa  
- **Sign-ins**:
  - Athina, Greece: 3:18 PM – 4:13 PM UTC  
  - Tokyo, Japan: 7:59 PM – 8:01 PM UTC  
- **Travel Time**: ~3 hours 46 minutes
- **Distance**: ~9,500 km
- **Conclusion**: ✅ **Impossible travel confirmed**

---
![image](https://github.com/user-attachments/assets/a8a41675-72d5-422b-8a75-0e7481a4e9e0)

## 🧭 MITRE ATT&CK Mapping
- **Tactic**: Credential Access → `T1078` – Valid Accounts
- **Tactic**: Defense Evasion → `T1078.004` – Valid Accounts: Cloud Accounts

---

## 🔒 Part 4: Incident Response Lifecycle (NIST 800-161)

### ✅ Preparation
- Tools: Microsoft Sentinel, KQL, Entra ID
- Roles: Analyst (you), Escalation team

### 🔎 Detection & Analysis
- Alert triggered by analytic rule
- Analysis confirms login from two distant regions within short time frame

### 🛡️ Containment, Eradication & Recovery
- **User Disabled in Entra ID**
- **Management Contacted**
- **AzureActivity Query**:
```kql
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "30688920-e870-49db-82f3-fc9e12135daa"
```
- VM operations (start, accept) and recovery service errors observed
![image](https://github.com/user-attachments/assets/1b866340-4bff-432c-8516-a4eacb78b56a)

### 🧾 Post-Incident Actions
- Recommend Conditional Access geo-fencing
- Enable Entra ID Identity Protection
- Integrate Sentinel with automated playbooks

### ✍️ Lessons Learned
- Impossible travel analytics are effective in early identity threat detection
- Combining SigninLogs + AzureActivity gives full context
- Multi-region logins without user explanation = 🚩

---

## ✅ Closure
- Incident status: **True Positive – Account Compromise**
- No further lateral movement detected
- Documented all findings in Sentinel
- Case closed
