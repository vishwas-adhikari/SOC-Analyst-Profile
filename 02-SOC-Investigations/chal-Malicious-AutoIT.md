
# Malicious AutoIT Analysis — Case #202-MAL


## Alert Overview
- **Severity:** High
- **Detection Source:** Endpoint Detection and Response (EDR) / SOC Alert
- **Asset Affected:** Internal Workstation
- **Threat Type:** Malicious Compiled Script (AutoIT)
- **Status:** True Positive

## Brief about the Concept
AutoIT is a legitimate freeware automation language for Microsoft Windows. However, threat actors frequently abuse it to create "compiled" malware. Because the actual malicious logic is stored as an embedded script within a legitimate AutoIT interpreter executable, it often evades traditional signature-based detection. Analysis typically requires extracting the original script from the compiled PE (Portable Executable) file to understand the attacker's intent.

## Investigation Steps

### 1. Initial Static Analysis
The investigation began with a static analysis of the suspicious binary `sample.exe` using the **Detect It Easy (DIE)** tool.
- **Hash Extraction:** Collected the MD5 hash for threat intelligence cross-referencing.
- **Entropy Calculation:** Analyzed the file's entropy to determine if it was packed or encrypted. A value of **6.58565** was returned, which DIE flagged as "packed," indicating high randomness consistent with obfuscated code.
- **PE Header Review:** Inspected the section headers to identify the memory layout. The `.text` section (where executable code resides) was found at a Virtual Address of **0x1000**.
- **Entry Point:** The entry point of the executable was identified as **0x42800a**.

### 2. Decompilation and Unpacking
Given the "packed" nature of the AutoIT binary, standard strings analysis was insufficient. I utilized **AutoIt-Ripper**, a specialized Python-based extraction tool, to retrieve the embedded script.
- **Command:** `python autoit-ripper.exe sample.exe [output_dir]`
- **Result:** Successfully extracted `script.au3`, the source code for the malicious logic.

### 3. Code Analysis
The extracted script was reviewed using **Notepad++**. The script contained several obfuscated functions designed to download secondary payloads and interact with the Windows API.
- **Network Activity:** Two calls to `InetRead` were identified, targeting the domain `office-cleaner-commander.com`.
- **String Obfuscation:** The script utilized hexadecimal encoding for file paths to evade basic string detection.
- **API Interaction:** The script made a call to `user32.dll` using the `CallWindowProcW` function, a common technique for executing shellcode or redirected code in memory.

## Analysis and Findings
The analysis confirms that `sample.exe` is a malicious downloader. The script is programmed to reach out to a remote command-and-control (C2) domain to retrieve two files: `Pay.txt` and `Run.txt`. 

A critical finding was the use of a hex-encoded string: `0x3A5C57696E646F77735C53797374656D33325C`. Upon decoding, this revealed the target installation path: **:\Windows\System32\**. The script attempts to place its payloads directly into a sensitive system directory. Furthermore, the use of `user32.dll` via `CallWindowProcW` suggests that the "text" files being downloaded likely contain malicious shellcode meant to be executed directly in memory, bypassing disk-based scanners.

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|------|--------|
| Hash | 5e53b40cf972f4eb08990999ce17c5c8 | MD5 Hash of the malicious AutoIT sample. |
| Domain | office-cleaner-commander.com | Command and Control (C2) / Payload delivery domain. |
| URL | `http://office-cleaner-commander.com/Pay.txt` | Primary payload download link. |
| URL | `http://office-cleaner-commander.com/Run.txt` | Secondary payload download link. |
| Path | `C:\Windows\System32\` | Targeted directory for malicious activity. |

## Decision Tree for Suspicious Compiled Scripts
1. **Identify File Type:** Is it a PE file compiled via AutoIT/PyInstaller?
   - If Yes -> Proceed to Entropy Check.
2. **Entropy Check:** Is Entropy > 6.0?
   - If Yes -> Likely packed/obfuscated. Proceed to Unpacking.
3. **Extraction:** Use specialized tools (AutoIT-Ripper, PyInstxtractor).
   - If Successful -> Analyze extracted script for IOCs (URLs, IPs, Paths).
4. **Identify Persistence/API Calls:** Does it use `user32.dll`, `kernel32.dll`, or registry keys?
   - If Yes -> High confidence for malicious intent.
5. **Verdict:** True Positive / Malicious.

## Response and Closure
- **Action Taken:** Binary analyzed, script unpacked, and C2 infrastructure identified.
- **Containment Required:** Yes. Block the identified domain at the proxy/firewall level.
- **Closure Reason:** True Positive. Analysis complete.

## Recommendations
- **Domain Blocking:** Block `office-cleaner-commander.com` across all perimeter security controls.
- **EDR Hardening:** Implement rules to alert on any non-system processes (like AutoIT) attempting to write to `C:\Windows\System32\`.
- **API Monitoring:** Monitor for suspicious calls to `CallWindowProcW` or `CreateRemoteThread` originating from user-space interpreted languages.
- **Binary Restriction:** Consider implementing Application Whitelisting (AppLocker) to prevent the execution of unassigned AutoIT interpreters in the user environment.

## Evidence / Screenshots

- **MD5 Hash Extraction in DIE**  
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/bb52a8ac-6bee-4657-89db-ddb2afe16f5d" />


- **Entropy and Packing Analysis**  
<img width="600" height="427" alt="image" src="https://github.com/user-attachments/assets/01d83b16-9fcf-465d-ad24-bdbdfc8ef9f6" />


- **PE Section Virtual Address**  
<img width="600" height="433" alt="image" src="https://github.com/user-attachments/assets/2bd11290-89d9-466f-a61f-148b44d10044" />


- **Malicious Script Analysis (`script.au3`)**  
<img width="600" height="550" alt="image" src="https://github.com/user-attachments/assets/9b2cef9d-eb3f-4893-849c-16a4c99b1425" />
