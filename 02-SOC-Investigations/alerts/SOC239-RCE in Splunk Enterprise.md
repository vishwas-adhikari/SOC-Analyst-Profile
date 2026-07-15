
# SOC239 - Remote Code Execution Detected in Splunk Enterprise (CVE-2023-46214)

## 🚨 Raw Alert Details
```text
EventID : 201
Event Time : Nov, 21, 2023, 12:24 PM
Rule : SOC239 - Remote Code Execution Detected in Splunk Enterprise
Level : Security Analyst
Source IP Address : 180.101.88.240
Destination IP Address : 172.16.20.13
Hostname : Splunk Enterprise
Requested URL : http://18.219.80.54:8000/en-US/splunkd/__upload/indexing/preview?output_mode=json&props.NO_BINARY_CHECK=1&input.path=shell.xsl
Trigger File Path : /opt/splunk/var/run/splunk/dispatch/1700556926.3/shell.xsl
Alert Trigger Reason : Detected a malicious XSLT upload in Splunk Enterprise with the potential to trigger remote code execution.
Device Action : Allowed
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** WAF / Network IDS
- **Asset Affected:** Splunk Enterprise (172.16.20.13)
- **Threat Type:** Remote Code Execution (RCE) / Credential Stuffing
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding CVE-2023-46214
**CVE-2023-46214** is a critical Remote Code Execution vulnerability affecting Splunk Enterprise. It specifically targets the Extensible Stylesheet Language Transformations (XSLT) parsing functionality. 

**The Mechanics:** Splunk allows users to upload files for data parsing and previewing (`__upload/indexing/preview`). However, prior to specific patches, Splunk did not properly sanitize XSLT files uploaded by users. An attacker can craft a malicious `.xsl` file containing embedded system commands. When the attacker forces Splunk to parse this file, the underlying XML processor executes the embedded code under the security context of the `splunkd` daemon (often running as `root` or `splunk` user). 
*Note: This vulnerability requires authentication, meaning the attacker must first possess valid Splunk credentials.*

## Investigation Steps

### 1. Initial Access Verification (Authentication)
Because CVE-2023-46214 requires authentication, the initial phase of the investigation focused on determining how the external attacker (`180.101.88.240`) gained access to the Splunk instance.
- **Log Management:** A review of the raw proxy logs revealed a successful `POST` request to `/account/login`.
- **Finding:** The attacker successfully authenticated using the `admin` username and the password `SPLUNK-i-04673a41b8017af54`. 
- **Analysis:** This password format suggests the default, auto-generated AWS EC2 instance password was never rotated by the administrator, allowing the attacker to easily guess or pull it from a known default-credential list.

<img width="596" height="205" alt="image" src="https://github.com/user-attachments/assets/7e7bd3e8-e031-4f2c-a503-5832179a1515" />


### 2. Payload Delivery (The Exploit)
Immediately following the successful login, the attacker exploited the XSLT vulnerability.
- **Network Log:** `GET /en-US/splunkd/__upload/indexing/preview?output_mode=json&props.NO_BINARY_CHECK=1&input.path=shell.xsl`
- **Analysis:** The attacker utilized the `indexing/preview` API endpoint, explicitly bypassing binary checks to upload and execute a malicious stylesheet named `shell.xsl`.

<img width="595" height="185" alt="image" src="https://github.com/user-attachments/assets/4a703744-fa2b-4c05-be33-1e3cdfcab0cb" />


### 3. Execution Verification (Post-Exploitation)
To determine if the XSLT execution successfully spawned a shell, the network logs and Endpoint Terminal History were reviewed.
- **Network Action:** Following the `.xsl` upload, the firewall registered an outbound connection from the Splunk server to the attacker's IP on port `54321` via a process named `shell.sh`. This is the hallmark signature of a Reverse Shell.

<img width="572" height="241" alt="image" src="https://github.com/user-attachments/assets/15d9e58d-17d4-4770-9706-9dc9380ef52a" />


- **Terminal History:** EDR logs confirmed interactive command execution by the attacker. The attacker ran situational awareness commands (`whoami`, `groups`) followed immediately by persistence commands: `useradd -m analsyt` and `passwd analsyt`. 
- **Analysis:** The attacker successfully achieved RCE, mapped their privilege level, and created a new, persistent backdoor user account named `analsyt` (deliberately misspelled to blend in).

<img width="1177" height="416" alt="image" src="https://github.com/user-attachments/assets/a35da684-ca16-4e14-b185-3a3ed71a88eb" />


### 4. Threat Intelligence Enrichment
The source IP (`180.101.88.240`) was queried against VirusTotal.
- **Finding:** The IP originates from ChinaNet and is flagged as malicious by multiple vendors, indicating it is part of an active exploitation infrastructure.

<img width="1791" height="242" alt="image" src="https://github.com/user-attachments/assets/69bcbfc9-34bd-4966-a79c-19489ff15021" />


## Analysis and Findings
The incident is a confirmed **True Positive**. The threat actor successfully compromised the Splunk Enterprise server. The attack chain began with the exploitation of weak/default credentials (`SPLUNK-i-...`) to gain initial access to the web interface. Once authenticated, the attacker deployed an XSLT payload (CVE-2023-46214) to achieve Remote Code Execution. A reverse shell was established, and the attacker created a rogue local user account (`analsyt`) to maintain persistence. The server is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1078.001 | Valid Accounts: Default Accounts |
| **Execution** | T1190 | Exploit Public-Facing Application (CVE-2023-46214) |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| **Persistence** | T1136.001 | Create Account: Local Account |
| **Command and Control** | T1090 | Proxy (Reverse Shell to external IP) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 180.101.88.240 | Attacker Source IP |
| URL Path | `__upload/indexing/preview?` | Exploited Splunk API Endpoint |
| File Name | `shell.xsl` | Malicious XSLT Payload |
| User Account | `analsyt` | Rogue local persistence account created by attacker |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Default Credentials):** Alert when an authentication attempt is made where the `password` field begins with `SPLUNK-i-` (the default AWS format).
- **Detection 2 (XSLT Exploitation):** Alert when HTTP URI contains `indexing/preview` AND `input.path` contains `.xsl` or `.xslt`.
- **Detection 3 (Rogue Account Creation):** Alert when the Splunk service daemon account (e.g., `splunk` or `www-data`) spawns `useradd` or `usermod`.

## 🚀 Decision Tree for Application RCE Exploitation
1. **Analyze Initial Vector:** Did an external IP access a known vulnerable endpoint (e.g., XSLT upload)?
   - If Yes -> Check Authentication Logs.
2. **Verify Authentication:** Was the attacker logged in? (Required for this specific CVE).
   - *Confirmed successful login via default credentials.*
3. **Check for Reverse Shells:** Did the vulnerable application spawn an unexpected outbound connection to an unusual port?
   - *Confirmed `shell.sh` outbound to port 54321.*
4. **Analyze Terminal History:** Did the attacker execute post-exploitation commands?
   - *Confirmed `whoami` and `useradd`.*
5. **Verdict: True Positive - Successful Compromise (RCE & Persistence).**
6. **Action:** Immediately contain the host, disable compromised credentials, and initiate Incident Response.

## Response and Closure
- **Action Taken:** The compromised Splunk instance (`172.16.20.13`) was **Isolated** from the network to kill the active reverse shell. The attacker IP was blocked at the perimeter firewall.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Successful exploitation of CVE-2023-46214 resulting in RCE and persistent backdoor creation.

## Recommendations
1. **Immediate Patching:** Upgrade Splunk Enterprise to a patched version (e.g., 9.0.7, 9.1.2) that sanitizes user-supplied XSLT uploads.
2. **Credential Hygiene:** The root cause of this breach was a failure to change default cloud-provisioned passwords. Enforce a mandatory password rotation policy for all newly spun-up infrastructure.
3. **Forensic Rebuild:** Because the attacker successfully achieved interactive shell access and created local accounts, the integrity of the underlying Linux OS cannot be guaranteed. The server should be rebuilt from a clean backup image.

## 🛠️ Skills & Tools Used
- **Log Correlation:** Tying authentication logs to subsequent API exploitation attempts.
- **Vulnerability Triage:** Understanding XSLT injection mechanics (CVE-2023-46214).
- **Endpoint Forensics:** Identifying post-exploitation enumeration and persistence techniques (`useradd`).
- **Incident Containment & Eradication:** Host isolation and rogue account identification.
