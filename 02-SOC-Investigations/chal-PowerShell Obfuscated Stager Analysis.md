
# PowerShell Obfuscated Stager Analysis — Case #PS-772

## Alert Overview
- **Severity:** High
- **Detection Source:** Endpoint Logging / EDR
- **Asset Affected:** Corporate Workstation
- **Threat Type:** Living off the Land (LotL) / Obfuscated PowerShell
- **Status:** True Positive

## Strategy and Technical Context
The primary strategy in this attack is "Living off the Land" (LotL). By utilizing `powershell.exe`, a legitimate Windows system tool, the attacker bypasses many application whitelisting controls. The use of the `-EncodedCommand` flag is a standard evasion technique used to hide script logic from casual observation and simple keyword-based detection. 

Technically, the script is designed to operate as a "stager." It establishes a connection to a remote Command and Control (C2) server, downloads a second-stage payload, and executes it directly in memory using the `IEX` (Invoke-Expression) command. This "fileless" approach ensures that the malicious logic never touches the physical disk, complicating traditional forensic recovery.

## Brief about the Concept
PowerShell scripts are frequently used in the initial access and execution phases of an attack. Obfuscation techniques—such as Base64 encoding and XOR bitwise operations—are used to bypass Network Intrusion Detection Systems (NIDS) and Antimalware Scan Interface (AMSI). In this specific case, the script sets up a persistent web client, configures it to navigate through enterprise proxies, and uses a symmetric XOR key to decrypt its incoming instructions.

## Investigation Steps

### 1. Command Line Deconstruction
The investigation began with the analysis of the initial execution string:
`powershell.exe -NoP -sta -NonI -W Hidden -Enc [Base64 Data]`

The flags were decoded as follows:
- **-NoP (NoProfile):** Prevents PowerShell from loading the user’s profile script, ensuring a predictable environment and speeding up execution.
- **-sta (Single-Threaded Apartment):** Sets the threading model, often required for specific COM objects used in exploitation.
- **-NonI (Non-Interactive):** Prevents the script from presenting an interactive prompt to the user, ensuring the process doesn't hang or get closed by a user.
- **-W Hidden (WindowStyle Hidden):** Ensures no terminal window appears on the victim's screen.
- **-Enc (EncodedCommand):** Signals that the subsequent string is a Base64 encoded script.

### 2. Base64 Deobfuscation
Using **CyberChef**, the Base64 string was decoded from UTF-16LE (the standard for PowerShell encoding). The resulting cleartext script revealed the functional malicious logic.

### 3. Script Logic Analysis
The script performs the following sequential actions:
1. **Environment Setup:** Creates a `System.Net.WebClient` object (`$WC`) to handle network communication.
2. **User-Agent Spoofing:** Sets the User-Agent to an older Internet Explorer string (Trident/7.0) to blend in with legitimate legacy web traffic.
3. **Proxy Bypassing:** Configures the script to use the system's default web proxy and injects the current user’s network credentials to bypass enterprise web filters.
4. **XOR Key Definition:** Defines a key `$K` (`IM-S&fA9Xu{[)|wdWJhC+!N~vq_12Lty`).
5. **Payload Retrieval:** Downloads a string from `http://98.103.103.170:7443/index.asp`.
6. **Decryption & Execution:** Iterates through the downloaded data, performing a **BXOR** (Bitwise XOR) operation against the key `$K`. The final result is then piped to **IEX** for immediate in-memory execution.

## Analysis and Findings
The incident is a confirmed **True Positive**. The script is a highly functional downloader for a second-stage payload. The most critical discovery is the XOR logic; even if a firewall intercepted the traffic from `98.103.103.170`, the payload would appear as gibberish. Only the XOR operation on the endpoint transforms it into an executable script. This indicates a sophisticated level of preparedness by the threat actor to evade network-level inspection.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Defense Evasion** | T1027 | Obfuscated Files or Information |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files or Information (XOR) |
| **Command and Control** | T1105 | Ingress Tool Transfer |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP/URL | `http://98.103.103.170:7443/index.asp` | C2 Payload Delivery URL |
| XOR Key | `IM-S&fA9Xu{[)|wdWJhC+!N~vq_12Lty` | Symmetric key for payload decryption |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko` | Spoofed User-Agent string |

## Blind Spots
1. **In-Memory Payload:** Because the script uses `IEX`, the decrypted payload never exists as a file on the disk. Without advanced memory forensics or AMSI logging enabled, the contents of the final payload remain unknown.
2. **Short-Lived C2:** IP-based C2 infrastructure (like `98.103.103.170`) is often rotated or taken offline shortly after the attack, making retrospective analysis difficult.

## False Positives: Legitimate Activity Comparison
1. **System Administration Scripts:** IT departments often use obfuscated or encoded PowerShell commands in deployment tools like SCCM or PDQ Deploy to simplify command-line length, though they rarely use `-W Hidden`.
2. **Third-Party Updaters:** Some legacy software updaters use `WebClient` and proxy credential passing to download patches from the vendor's site.

## Decision Tree for PowerShell Analysis
1. **Identify EncodedCommand:** Is `-Enc` or `-EncodedCommand` present?
   - If Yes -> Decode via CyberChef.
2. **Analyze Flags:** Are stealth flags (`-W Hidden`, `-NonI`) present?
   - If Yes -> High probability of malicious intent.
3. **Examine Network Logic:** Does the script use `WebClient` or `Invoke-WebRequest`?
   - If Yes -> Identify the target URL/IP.
4. **Identify Execution:** Is `IEX` or `Invoke-Expression` used?
   - If Yes -> Verdict: **True Positive - Malicious Downloader.**

## Response and Closure
- **Action Taken:** The C2 IP address has been blocklisted on the perimeter firewall. PowerShell logging (Script Block Logging) has been enabled on the affected endpoint to capture the decrypted payload if execution is attempted again.
- **Containment Required:** Yes (Endpoint isolation for memory dump).
- **Closure Reason:** True Positive. Analysis of the stager confirmed intent to download and execute an obfuscated second-stage payload.

## Recommendations
1. **Enable Script Block Logging:** Ensure PowerShell Event ID 4104 is captured. This logs the *decrypted* contents of the script after the XOR operation, providing visibility into the final payload.
2. **Constrained Language Mode:** Enforce PowerShell Constrained Language Mode to prevent the use of `Net.WebClient` and other advanced .NET objects by non-admin users.
3. **Execution Policy:** Set PowerShell Execution Policy to `AllSigned` via Group Policy.
4. **Proxy Monitoring:** Monitor for unusual User-Agents (like the legacy IE string used here) originating from non-browser processes.

## Evidence / Screenshots
- **Original Encoded Command**  
<img width="1219" height="347" alt="image" src="https://github.com/user-attachments/assets/ec6dcc8a-508e-47ba-9ad5-a6286807609d" />

- **Decoding Output**  
<img width="1193" height="240" alt="image" src="https://github.com/user-attachments/assets/2449d7ee-fa6b-4225-a519-445558f34176" />

## Skills & Tools Used
CyberChef (Base64/UTF-16LE Decoding), PowerShell Script Analysis, De-obfuscation, Threat Intelligence, Traffic Analysis, MITRE ATT&CK Mapping.

## Mistakes and Lessons Learned
- **Initial Confusion:** Initially, the XOR key `$K` seemed like random data. 
- **Learning:** Realized that `$K` is used as a symmetric key for the `-BXor` operation. This taught me that any time a script defines a random-looking string and then uses the `%` (modulo) and `-BXor` operators, it is performing a decryption loop on a downloaded payload. scrutinizing the mathematical operators in the script is key to identifying the decryption method.
