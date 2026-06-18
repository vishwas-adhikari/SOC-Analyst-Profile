

# Malicious VBA Macro Analysis — Case #VBA-409

## Alert Overview
- Severity: High
- Detection Source: Email Security Gateway / User Submission
- Asset Affected: Corporate Workstation
- Threat Type: Malicious Document (MalDoc) / VBA Downloader
- Status: True Positive

## Strategy and Technical Context
This incident involves a Malicious Document (MalDoc) delivered via phishing (Invoice lure). The strategic objective of this document is to act as a "Stager." Its sole purpose is to bypass email security gateways by hiding its true intent (using Hex obfuscation), reach the user's endpoint, download a secondary binary payload from the internet, and execute it stealthily using Windows Management Instrumentation (WMI) to evade process-tree detection.

## Brief about the Concept
Visual Basic for Applications (VBA) macros are scripts embedded in Microsoft Office documents. Threat actors abuse them to interact with the Windows operating system. Because standard antivirus easily catches plain-text malicious commands (like `powershell.exe` or `http://malicious.com`), attackers write custom decoding functions. The script stores its commands as raw Hexadecimal strings, decodes them in memory upon execution, and utilizes native Windows COM objects (like `MSXML2.ServerXMLHTTP` and `ADODB.Stream`) to perform network and file I/O operations without dropping traditional command-line artifacts.

## Investigation Steps

### 1. Macro Extraction and Triage
The suspicious file (`invoice.docm`) was isolated. I extracted the embedded VBA macros using static analysis tools to safely view the code without detonating the payload. Four main modules were identified: `inf.docm`, `cuabumrbh.bas`, `cwzbjoiuq.bas`, and `lkxosgcqm.bas`.

### 2. Execution Flow Analysis
Reviewing the `inf.docm` module revealed an `AutoOpen()` subroutine, meaning the malicious code executes immediately when the user enables macros.

### 3. Deobfuscation (Hex Decoding)
The script utilized a custom function (`hgmneqolwgxg`) that processed strings by evaluating them two characters at a time and converting the hexadecimal values to ASCII characters. I replicated this logic using CyberChef to decode the primary indicators:
- **Payload URL:** `68747470733a2f2f74696e7975726c2e636f6d2f67327a3267683666` -> `https://tinyurl.com/g2z2gh6f`
- **Payload Name:** `64726f707065642e657865` -> `dropped.exe`
- **Network Object:** `MSXML2.ServerXMLHTTP.6.0`
- **User-Agent:** `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)`

### 4. Payload Staging and I/O Analysis
The decoded strings show the macro initiates an HTTP GET request to the TinyURL link. It checks for a `200 OK` HTTP status. If successful, it utilizes the `ADODB.Stream` object to write the HTTP response body directly to the disk at `%TEMP%\dropped.exe`.

### 5. Stealth Execution (WMI & Fallback)
The macro passes the dropped executable to a secondary module for execution. It attempts to launch the payload using WMI (`winmgmts:\\.\root\cimv2:Win32_Process`). It specifically configures `Win32_ProcessStartup` with `ShowWindow = 0` to execute the malware invisibly. By using WMI, the malware breaks the parent-child process relationship (it spawns under `WmiPrvSE.exe` instead of `WINWORD.exe`), evading basic EDR behavior rules. If WMI fails, a fallback module uses `WScript.Shell` to execute the file.

## Analysis & Findings
The investigation confirms the document is a True Positive malicious downloader. The VBA code is highly structured, utilizing hex-obfuscation to hide its network C2 and evasion techniques to hide its execution. If a user clicked "Enable Content," the script successfully downloaded and executed `dropped.exe` in the background without any visible indicators to the user.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1204.002 | User Execution: Malicious File |
| **Execution** | T1059.005 | Command and Scripting Interpreter: Visual Basic |
| **Execution** | T1047 | Windows Management Instrumentation |
| **Defense Evasion** | T1027 | Obfuscated Files or Information |
| **Command and Control** | T1105 | Ingress Tool Transfer |

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|------|--------|
| URL | `https://tinyurl.com/g2z2gh6f` | Primary staging URL |
| File Name | `dropped.exe` | Second-stage payload dropped to disk |
| File Path | `%TEMP%\dropped.exe` | Expected location of the payload |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)` | Spoofed legacy IE User-Agent |

## Blind Spots
1. **Dynamic URL:** The attacker used a TinyURL redirect. Without executing the link in a sandbox or checking DNS/Proxy logs, the true destination IP and hosting server of the final payload remain unknown.
2. **Payload Capabilities:** The analysis covers the downloader mechanism. The actual capabilities of `dropped.exe` (e.g., ransomware, infostealer, RAT) cannot be determined without analyzing the binary itself.

## False Positives: Legitimate Activity Comparison
1. **Financial/Accounting Macros:** Many legitimate finance departments use complex VBA macros to pull live data from web servers into Excel. However, legitimate macros rarely use WMI to spawn hidden `.exe` files from the `%TEMP%` directory.

## Decision Tree for Malicious Documents
1. **Identify Macros:** Does the document contain VBA macros?
   - If Yes -> Check for `AutoOpen` or `Document_Open`.
2. **Analyze Strings:** Are the strings obfuscated (Hex, Base64, Chr arrays)?
   - If Yes -> High probability of malicious intent. Decode strings.
3. **Check Capabilities:** Does the decoded code contain network objects (`XMLHTTP`) and file execution objects (`WScript.Shell`, `WMI`)?
   - If Yes -> Verdict: True Positive - Malicious Downloader.
4. **Endpoint Correlation:** Search EDR for `WmiPrvSE.exe` spawning `dropped.exe` or network connections to the identified URL.

## Response & Closure
- Action Taken: Extracted and safely deobfuscated the VBA macro. Identified the staging URL and the file creation path. Checked corporate proxy logs for connections to the TinyURL link. 
- Containment Required: Yes. If proxy logs show a successful connection, the affected host must be isolated for memory and disk forensics to capture `dropped.exe`.
- Closure Reason: True Positive. Confirmed Malicious VBA Downloader.

## Recommendations
1. **Macro Security Policy:** Implement Group Policy Objects (GPO) to "Block macros from running in Office files from the Internet" (Mark of the Web enforcement).
2. **Proxy Filtering:** Consider blocking link-shortening services (like TinyURL, bit.ly) on corporate networks, as they are heavily abused to obscure malicious destinations.
3. **EDR Hardening:** Implement behavioral rules to alert when `WINWORD.exe` or `EXCEL.exe` drop executable files (`.exe`, `.dll`, `.bat`) into the `%TEMP%` directory.

## Evidence / Screenshots
- **Hex Encoded VBA Source**  
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/667f315a-004c-42c7-b0dc-0387dd498a96" />


- **CyberChef Decoding**

  <img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/7cc93221-e889-4a9a-a4c0-2fc569dca7aa" />


## Skills & Tools Used
Static Malware Analysis, VBA Code Review, De-obfuscation (Hex Decoding), CyberChef, WMI Execution Analysis, Incident Triage.
