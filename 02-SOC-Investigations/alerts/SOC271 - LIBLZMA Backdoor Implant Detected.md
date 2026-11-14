
# SOC271 - LIBLZMA Backdoor Implant Detected (CVE-2024-3094)

## 🚨 Raw Alert Details
```text
EventID : 247
Event Time : 2024-04-04T04:52:00+03:00
Rule : SOC271 - XZ/LIBLZMA Backdoor Implant Detected CVE-2024-3094
Role : Incident Responder
Alert Type : Malware
Difficulty : Hard
MITRE ATT&CK : T1195.002, T1078, T1546
Hostname : SSHDevServer01
IP Address : 172.16.17.121
File Name : liblzma.so.5.6.1
File Path : /usr/local/lib/
File Hash : 9b368d0ad8b3bda5eabfdf8a40944f4dd270955bab868da9a51beedcfde38699
Device Action : Allowed
Trigger Reason : Suspicious Hash detected for the file liblzma.so.5.6.1
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / File Integrity Monitoring
- **Asset Affected:** SSHDevServer01 (172.16.17.121 - Linux)
- **Threat Type:** Supply Chain Compromise / Backdoor Implant (CVE-2024-3094)
- **Verdict:** True Positive (Compromised / Vulnerable)
- **Containment Status:** Contained (Isolated)

## 🧠 Attack Context / Technical Background
**CVE-2024-3094** is a catastrophic, CVSS 10.0 supply chain backdoor discovered in **XZ Utils** (versions 5.6.0 and 5.6.1). 

**The Mechanics:** This vulnerability is a masterclass in sophisticated supply chain compromise. An attacker spent years contributing to the open-source XZ Utils project to gain maintainer trust before injecting a heavily obfuscated backdoor into the release tarballs. 

When the backdoored `liblzma` shared library (`liblzma.so.5.6.1`) is compiled into software that links against it—most notably **OpenSSH (`sshd`)**—the backdoor hooks into the application's runtime memory. Specifically, during public key authentication (`RSA_public_decrypt`), the backdoor intercepts the routine, allowing an unauthenticated attacker to inject arbitrary code and achieve remote code execution (RCE) before authentication is even verified, completely bypassing SSH security controls.

## Investigation Steps

### 1. Initial Triage & Threat Intelligence Enrichment
The investigation began with an L1 analyst escalation regarding a publicly exposed development server (`SSHDevServer01`) flagging on a suspicious file hash in `/usr/local/lib/`.
- **File Hash:** `9b368d0ad8b3bda5eabfdf8a40944f4dd270955bab868da9a51beedcfde38699`
- **OSINT Verification:** Querying the file hash on VirusTotal returned 37/63 malicious detections, explicitly categorizing the binary as a Trojan and labeling the family as `xzbackdoor` associated with CVE-2024-3094.
<img width="1790" height="239" alt="image" src="https://github.com/user-attachments/assets/f53c588f-374a-4b0d-aaf3-b0db6683829f" />


### 2. Live Host Verification (Terminal Triage)
To verify the alert, an interactive terminal session was established on `SSHDevServer01` to inspect the file system and verify version details.
- **File Verification:** Confirmed the presence of the malicious file at `/usr/local/lib/liblzma.so.5.6.1`.
- **Hash Validation:** Ran `sha256sum /usr/local/lib/liblzma.so.5.6.1`, which matched the alert hash precisely.
- **Version Check:** Executed `xz --version`, confirming the installed version was **5.6.1**, placing the server directly in the vulnerable window.

<img width="805" height="339" alt="image" src="https://github.com/user-attachments/assets/68888bae-7038-45b4-9bba-004b136373cb" />


### 3. Impact Assessment & Execution Check
While the backdoored library was present on the system, log management and network traffic analysis were reviewed for active exploitation.
- **Network Traffic:** No suspicious outbound connections or anomalous C2 traffic originating from `sshd` were observed during the alert window.
- **Analysis:** This indicates that while the host was **infected** via a supply chain compromise, the backdoor had **not yet been actively triggered or exploited** by an external attacker. 

## Analysis & Findings
The incident is a confirmed **True Positive**. The internet-facing development server `SSHDevServer01` was provisioned with a backdoored release of XZ Utils (version 5.6.1), containing the malicious `liblzma.so.5.6.1` shared library (CVE-2024-3094). VirusTotal verification and local hash checks confirmed the presence of the supply chain implant. Although no active exploitation or malicious network traffic was observed, the presence of the unauthenticated RCE backdoor on an internet-exposed SSH server represents an immediate, critical risk.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1195.002 | Supply Chain Compromise: Compromise Software Dependencies |
| **Execution** | T1203 | Exploitation for Client Execution |
| **Defense Evasion** | T1574.006 | Hijack Execution Flow: LD_PRELOAD / Library Interception |
| **Credential Access** | T1588.006 | Obtain Capabilities: Vulnerabilities |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| File Path | `/usr/local/lib/liblzma.so.5.6.1` | Location of backdoored shared library |
| File Hash (SHA256) | `9b368d0ad8b3bda5eabfdf8a40944f4dd270955bab868da9a51beedcfde38699` | Malicious `liblzma` Backdoor Implant |
| Affected Version | XZ Utils 5.6.0 & 5.6.1 | Vulnerable Software Release |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of XZ backdoors on Linux systems, the following Sigma rule has been engineered for deployment in the SIEM:

```yaml
title: XZ Utils Backdoor Library Presence (CVE-2024-3094)
id: f23a0598-7890-4a5e-994d-70580c5e9f13
status: experimental
description: Detects the presence of known backdoored liblzma.so file hashes associated with CVE-2024-3094.
author: SOC Analyst Portfolio
logsource:
  product: linux
  service: auditd
detection:
  selection:
    FileHash.SHA256:
      - '9b368d0ad8b3bda5eabfdf8a40944f4dd270955bab868da9a51beedcfde38699'
  condition: selection
falsepositives:
  - None
level: critical
tags:
  - attack.t1195.002
```

## 🚀 Decision Tree 
1. **Analyze Trigger Reason:** Did an alert fire for a suspicious hash in system library paths (`/usr/local/lib/`)?
   - If Yes -> Extract the file hash and check VirusTotal.
2. **Verify Threat Intel:** Is the hash associated with a supply chain CVE (e.g., CVE-2024-3094 / XZ backdoor)?
   - *Confirmed 37/63 detections matching `liblzma.so.5.6.1`.*
3. **Check Local Installation:** Connect to the host and run version checks (`xz --version`) and hash validation (`sha256sum`).
   - *Confirmed vulnerable version 5.6.1 is actively present.*
4. **Action:** **Verdict: True Positive - Compromised (Vulnerable Implant).** Immediately isolate the host from the network.

## 📝 Playbook Questions & Answers
- **Is the alert a True Positive or False Positive?**
  - *Answer:* True Positive.
  - *Reasoning:* VirusTotal and local sha256sum verification confirmed the presence of the backdoored `liblzma.so.5.6.1` binary tied to CVE-2024-3094.
- **Is the host vulnerable?**
  - *Answer:* Yes.
  - *Reasoning:* Running `xz --version` confirmed version 5.6.1, and the OpenSSH daemon (`sshd`) dynamically links against the compromised `liblzma` library.
- **Does the device need to be isolated?**
  - *Answer:* Yes.
  - *Reasoning:* The server is exposed to the internet and contains an unauthenticated RCE backdoor. Immediate isolation is required to prevent external exploitation.

## Response & Containment Actions Taken
- **Host Isolation:** The compromised development server (`SSHDevServer01 / 172.16.17.121`) was immediately **Isolated** from the network via EDR.
- **External SSH Restriction:** Temporarily blocked external internet-facing SSH access to the development server pending remediation.
- **Why:** Isolating the server neutralizes the unauthenticated RCE threat, ensuring external actors cannot exploit the SSH daemon while mitigation is underway.

## Recommendations
1. **Downgrade XZ Utils:** Immediately downgrade XZ Utils from version 5.6.1 to a secure, unaffected version (such as 5.4.6 Stable) or apply vendor patches to remove the malicious code.
2. **Enterprise Software Audit:** Run an enterprise-wide asset scan for file hashes matching CVE-2024-3094 to ensure no other Linux servers or containers ingested the compromised release tarballs.
3. **Revoke Exposed Credentials:** Because this server was exposed to the internet and ran a backdoored SSH daemon, assume all SSH keys and credentials stored or entered on this server have been compromised. Rotate all credentials immediately.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Supply Chain vs. Runtime Malware):** When investigating this alert, initial network logs showed no suspicious outbound traffic or C2 activity. A junior analyst might mistakenly close this as a False Positive or low-risk anomaly due to the lack of active traffic.
- **The Lesson (Infection vs. Exploitation):** Supply chain compromises operate differently than traditional malware. The attacker does not need to drop a malicious `.exe` or beacon out to a C2 server immediately; the backdoor is silently baked into foundational libraries waiting for an incoming connection. **Presence of a supply chain implant equals a compromise**, regardless of whether network traffic is currently active.

## 🛠️ Skills & Tools Used
- Linux Terminal Forensics (`xz --version`, `sha256sum`, `ldd`)
- Supply Chain Vulnerability Triage (CVE-2024-3094 / XZ Backdoor)
- Threat Intelligence Correlation (VirusTotal)
- Incident Containment (Host Isolation)
