
# SOC315 - Suspicious Certificate Management Activity Detected

## 🚨 Raw Alert Details
```text
EventID : 293
Event Time : 2024-08-23T09:29:04+03:00
Rule : SOC315 - Suspicious Certificate Management Activity Detected
Role : Incident Responder
Alert Type : C2 / Defense Evasion
Difficulty : Medium
MITRE ATT&CK : T1078, T1133, T1059.004, T1553.004
Hostname : Sharla
IP Address : 172.16.17.116
Command Line : sudo update-ca-certificates
Trigger Reason : Detects installation of new certificate on the system which attackers may use to avoid warnings when connecting to controlled web servers or C2s.
EDR Action : Allowed
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / Linux Audit Logs
- **Asset Affected:** Sharla (172.16.17.116)
- **Threat Type:** SSH Brute Force / Rogue Root CA Installation / C2 Preparation
- **Verdict:** True Positive (Compromised)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
Installing a rogue root certificate is a sophisticated **Defense Evasion** and **Credential Access** technique. 

**The Mechanics:** Modern operating systems and browsers rely on a Root Certificate Store to determine if an SSL/TLS certificate is trustworthy. If an attacker sets up a malicious proxy or C2 server using a self-signed certificate, victims will see prominent security warnings ("Your connection is not private"). To bypass this, attackers with root/sudo privileges will use `openssl` to generate their own Certificate Authority (`rootCA.key` and `rootCA.crt`), move it into the system's trusted certificate directory, and run `update-ca-certificates`. From that moment on, the operating system blindly trusts all network traffic signed by the attacker's private key, facilitating seamless Man-in-the-Middle (MitM) attacks or encrypted C2 communications.

## Investigation Steps

### 1. Initial Access Verification (SSH Brute Force)
The investigation began by reviewing authentication logs preceding the certificate installation to determine how the attacker gained entry.
- **Failed Logins:** Raw logs captured multiple `Failed password for invalid user` attempts originating from external IP `138.199.22.105` targeting port `17159` (SSH).
- **Successful Logon:** Shortly after the brute-force attempts, an `Accepted password for analyst` log was generated from the same IP on port `5621`.
- **Threat Intel:** Querying `138.199.22.105` on AbuseIPDB revealed it is hosted by Datacamp Limited in Tokyo, Japan, with an elevated abuse confidence score, confirming malicious access.

<img width="556" height="181" alt="image" src="https://github.com/user-attachments/assets/29ac0e31-99c8-46fe-b741-b7070e3b25cd" />

<img width="556" height="172" alt="image" src="https://github.com/user-attachments/assets/52445bce-6b33-4e21-8590-4557616de8f1" />

<img width="603" height="648" alt="image" src="https://github.com/user-attachments/assets/e043c954-34d8-46ba-8f91-723b8529f26b" />


### 2. Execution & Rogue CA Generation (Terminal History)
Once authenticated as the user `analyst` (and subsequently escalating to `sudo`), the attacker executed a sequence of commands to establish the rogue certificate.
- **Key Generation:** `openssl genrsa -out rootCA.key 4096` (Generating a 4096-bit private RSA key).
- **Certificate Generation:** `openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 -subj /C=US/ST=Denial/L=Springfield/O=Dis/CN=sketchanalyticsvault.com -out rootCA.crt` (Creating a self-signed root certificate for the domain `sketchanalyticsvault.com`).
- **Certificate Installation:** 
  - `mv rootCA.crt /usr/local/share/ca-certificates`
  - `sudo update-ca-certificates`
- **Analysis:** The attacker explicitly prepared the host to trust their infrastructure (`sketchanalyticsvault.com`) by embedding their custom certificate into the Linux trust store.

<img width="1194" height="618" alt="image" src="https://github.com/user-attachments/assets/6a1f84b8-9515-484b-b0fe-17c3ec286142" />

### 3. Threat Intelligence Enrichment
The newly discovered domain embedded in the certificate's Common Name (CN) was queried on VirusTotal.
- **Domain:** `sketchanalyticsvault.com`
- **Finding:** Flagged as Phishing/Malicious by multiple security vendors, confirming it as attacker-controlled infrastructure.

<img width="1796" height="519" alt="image" src="https://github.com/user-attachments/assets/d8eb5c27-70bd-4852-9ce8-813f411378e4" />


## Analysis & Findings
The incident is a confirmed **True Positive**. An external threat actor (`138.199.22.105`) brute-forced the SSH service on host `Sharla` (172.16.17.116) and successfully authenticated using the `analyst` account. Following initial access, the attacker leveraged `sudo` privileges to generate a self-signed root certificate (`rootCA.crt`) tied to the malicious domain `sketchanalyticsvault.com` and injected it into the system's trusted certificate store. This action prepares the host for encrypted C2 communications or SSL/TLS interception without triggering OS certificate warnings. The endpoint is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services (SSH) |
| **Credential Access** | T1110 | Brute Force |
| **Defense Evasion** | T1553.004 | Subvert Trust Controls: Install Root Certificate |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 138.199.22.105 | Attacker SSH Brute-Force / Access IP |
| Domain | `sketchanalyticsvault.com` | Attacker C2 / Infrastructure Domain |
| File Name | `rootCA.key` | Rogue Private RSA Key |
| File Name | `rootCA.crt` | Rogue Self-Signed Root Certificate |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of rogue root certificate installations on Linux, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: Rogue Root Certificate Installation via OpenSSL on Linux
id: c81f0594-8912-4a5e-994d-70580c5e9f03
status: experimental
description: Detects the generation of a self-signed root CA using OpenSSL and its subsequent installation into system trust stores.
author: SOC Analyst Portfolio
logsource:
  product: linux
  service: auditd
detection:
  selection_openssl:
    CommandLine|contains:
      - 'openssl req'
      - '-x509'
      - '-new'
  selection_update:
    CommandLine|contains:
      - 'update-ca-certificates'
      - 'update-ca-trust'
  condition: selection_openssl or selection_update
falsepositives:
  - Legitimate internal PKI testing or local developer self-signed cert generation
level: high
tags:
  - attack.t1553.004
  - attack.t1059.004
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for certificate management activity (`update-ca-certificates`)?
   - If Yes -> Check audit/terminal history for `openssl` commands.
2. **Evaluate Certificate Subject (CN):** What domain or organization name is tied to the generated certificate?
   - *Found `CN=sketchanalyticsvault.com`.*
3. **Check Initial Access:** Did the user or account execute this intentionally as part of authorized administrative tasks? Check SSH logs for external access.
   - *Confirmed SSH brute-force login from an external Japanese IP (`138.199.22.105`).*
4. **Action:** **Verdict: True Positive - Compromised.** Immediately isolate the host and purge the rogue certificate from the trust store.

## 📝 Playbook Questions & Answers
- **Is the alert a True Positive or False Positive?**
  - *Answer:* True Positive.
  - *Reasoning:* Terminal history and Linux audit logs confirmed an unauthorized actor used `openssl` to generate a self-signed root CA for `sketchanalyticsvault.com` and installed it via `update-ca-certificates` following an SSH breach.
- **Has the certificate been installed?**
  - *Answer:* Yes.
  - *Reasoning:* The commands `mv rootCA.crt /usr/local/share/ca-certificates` and `sudo update-ca-certificates` successfully updated the system trust store.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The host suffered an external SSH compromise and the attacker successfully tampered with core system trust controls to facilitate secure C2 communication.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised endpoint (`Sharla / 172.16.17.116`) was immediately **Isolated** from the network via EDR to prevent lateral movement and C2 traffic stabilization.
- **Perimeter Blocking:** The attacker's IP (`138.199.22.105`) and domain (`sketchanalyticsvault.com`) were added to the perimeter blocklist.
- **Why:** Isolating the host prevents the attacker from leveraging their newly established trusted certificate channel to exfiltrate data or deploy secondary payloads.

## Recommendations
1. **Remove Rogue Certificate:** Purge `rootCA.crt` from `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates --fresh` to rebuild the clean certificate store.
2. **SSH Hardening:** Disable password authentication for SSH globally across all Linux servers. Mandate SSH Key-Based Authentication and restrict SSH access to internal management subnets or a corporate VPN.
3. **Audit User Accounts:** Review `/etc/passwd` and sudoers configurations on host `Sharla` to ensure the attacker did not create additional user accounts or persistence mechanisms while operating with `sudo` privileges.

## 🛠️ Skills & Tools Used
- Linux Audit Log & Terminal History Analysis (`auditd`, `bash_history`)
- Cryptographic Analysis (`openssl` CA generation and trust store manipulation)
- Threat Intelligence Correlation (AbuseIPDB, VirusTotal)
- Incident Containment (Host Isolation)
