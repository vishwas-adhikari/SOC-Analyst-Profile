

# PowerShell Keylogger & RAT Analysis — Case #PS-804

## 📄 Alert Summary
- **Severity:** Critical
- **Detection Source:** EDR / Script Block Logging (Event ID 4104)
- **Asset Affected:** Corporate Workstation
- **Threat Type:** Remote Access Trojan (RAT) / Keylogger / C2 via Tor
- **Status:** True Positive

## 🛡️ Strategy and Technical Context
This script represents a sophisticated, modular Remote Access Trojan (RAT) written in PowerShell. Its primary strategy is to maintain a persistent, interactive connection with an attacker while operating entirely from memory (Fileless execution). 

To evade network detection and hide the true location of the Command and Control (C2) server, the malware routes all its traffic through a public SOCKS5 proxy to a hidden `.onion` (Tor) service. Functionally, it relies on **P/Invoke**—a feature that allows managed .NET code (PowerShell) to call unmanaged Windows API functions (like `user32.dll`)—to achieve deep system surveillance, such as intercepting hardware keystrokes, without dropping a compiled `.exe` keylogger.

## 📘 Brief about the Concept
Modern attackers prefer "Living off the Land" (LotL). Instead of bringing custom malware binaries that easily trigger Antivirus, they write scripts that use the operating system's native tools against itself. This PowerShell script builds a custom SOCKS5 network client from scratch, captures the screen using native `.NET` drawing libraries, and interacts with the Windows keyboard buffer directly. Because it executes via `Invoke-Expression` and loads APIs dynamically, it acts as a fully featured backdoor operating under the trusted context of `powershell.exe`.

## 🕵️ Investigation Steps

### 1. Network Configuration & C2 Infrastructure Analysis
The script initializes with hardcoded parameters for its C2 infrastructure. It routes TCP traffic through a SOCKS proxy to reach a Dark Web `.onion` service, heavily anonymizing the attacker's location.

### 2. System Reconnaissance (Get-SystemInfo)
Upon establishing a connection, the script immediately profiles the victim machine. It gathers the OS version, Hostname, Username, and true local IPv4 address, filtering out local loopback interfaces.

### 3. Keylogger Mechanism (Start-Keylogger)
The script uses C# `Add-Type` to import unmanaged APIs from `user32.dll` to check the hardware state of individual keys and translate raw key presses into readable characters. It spawns a background job (`Start-Job`) that polls the keyboard state every 40 milliseconds.

### 4. C2 Command Loop Analysis (Establish-Connection)
The core of the RAT is an infinite `while ($true)` loop that reads commands from the attacker and executes them. Identified capabilities include screen capturing (`screenshot`), executing arbitrary code (`powershell:` / `shell:`), file transfers (`upload:` / `download:`), and keylogger management.

---

## 🎯 Targeted Code Extraction (Key Findings)
During the static analysis of the script, specific variables, logic blocks, and imported libraries were identified to map out the exact capabilities of the malware:

**1. Proxy Configuration (Port)**
The script hardcodes the proxy details at the very beginning to route traffic through the Tor network. The proxy port is defined as **9050**, which is the default listening port for the Tor service.
```powershell
[string]$proxyAddress = "37.143.129.165",
[int]$proxyPort = 9050
```

**2. Keylogger Initialization**
The malware establishes the keylogging function as a background job to prevent blocking the main C2 loop. The function responsible for initiating this is **`Start-Keylogger`**.
```powershell
function Start-Keylogger {
    $global:keylogger_active = $true
    $global:captured_keys = ""
# ... [Imports APIs and starts background job] ...
```

**3. Keylogger Output File**
As the user types, the script intercepts the keystrokes and appends them to a hidden, temporary text file named **`keylog.txt`** located in the user's `%TEMP%` directory.
```powershell
if ($success) {
    [System.IO.File]::AppendAllText("$env:temp\keylog.txt", $mychar, [System.Text.Encoding]::Unicode)
}
```

**4. Windows API Interaction (DLL Import)**
To intercept keystrokes at the hardware level from within PowerShell, the attacker utilizes P/Invoke to import unmanaged functions directly from the core Windows User API library, **`user32.dll`**.
```powershell
$signature = @"
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);
"@
```

**5. IP Address Filtering (Regex)**
During the `Get-SystemInfo` phase, the script captures the victim's IP address. It uses the regex **`^(127\.|169\.254\.)`** to explicitly ignore localhost (127.0.0.x) and APIPA (169.254.x.x) addresses, ensuring only the valid internal network IP is sent to the attacker.
```powershell
"ip" = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.IPAddress -notmatch "^(127\.|169\.254\.)" } | Select-Object -First 1).IPAddress
```

**6. C2 Directives (Upload & Persist)**
By analyzing the `if/elseif` command loop within the `Establish-Connection` function, specific attacker directives were identified. The attacker uses the string **`upload:`** to drop files onto the victim, and **`persist`** to trigger (or eventually manage) a persistence mechanism.
```powershell
elseif ($command.StartsWith("upload:")) {
    $parts = $command.Split(":")
# ...
elseif ($command -eq "persist") {
    $writer.WriteLine("Persistence mechanism is managed separately")
} 
```

**7. Connection Resiliency (Wait Time)**
If the connection to the C2 server is interrupted or dropped, the malware catches the error, stops the keylogger, and waits for **30 seconds** before attempting to re-establish the SOCKS5 connection.
```powershell
catch {
    Write-Error "Connection error: $_"
    if ($keylogger_job) {
        Stop-Keylogger $keylogger_job
    }
    Start-Sleep -Seconds 30  # Attendre avant de tenter une reconnexion
}
```
---

## 🧪 Analysis and Findings
The incident is a confirmed **True Positive**. The analyzed sample is a highly capable PowerShell RAT. It grants the attacker full interactive control over the victim's machine, including data exfiltration, surveillance (screenshots and keylogging), and remote code execution. The use of a SOCKS5 proxy to route traffic to the Tor network indicates a mature threat actor attempting to bypass standard corporate firewall egress filtering and domain reputation checks.

## 🚩 MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell |
| **Collection** | T1056.001 | Input Capture: Keylogging |
| **Collection** | T1113 | Screen Capture |
| **Command and Control** | T1090.003 | Proxy: Multi-hop Proxy (Tor/SOCKS5) |
| **Defense Evasion** | T1127 | Trusted Developer Utilities Proxy Execution (P/Invoke) |
| **Discovery** | T1082 | System Information Discovery |

## 📉 Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Domain | `opioem3zmp3bgx3qjqkh6vimkdoerrwh3uhawklm5ndv5e7k3t4edbqd.onion` | Dark Web C2 Server |
| IP Address | 37.143.129.165 | SOCKS5 Proxy IP |
| Port | 9050 | SOCKS5 Proxy Port |
| File Path | `%TEMP%\keylog.txt` | Keylogger output file |

## 🌫️ Blind Spots
- **Network Visibility:** Because the C2 traffic is tunneled through a SOCKS5 proxy to the Tor network, packet inspection tools (IDS/IPS) at the perimeter will only see a TCP connection to `37.143.129.165`, not the underlying commands or the `.onion` destination.
- **In-Memory Execution:** Commands sent via the `powershell:` directive are executed in memory via `Invoke-Expression`. Without Script Block Logging (Event ID 4104), the exact commands executed by the attacker during the session cannot be recovered.

## 🚫 False Positives
- **Legitimate Admin Tools:** Some RMM (Remote Monitoring and Management) tools utilize `System.Drawing` for remote desktop viewing, but the combination of SOCKS5 routing, `user32.dll` API hooking, and hidden background jobs strictly points to malicious intent.

## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection:** When analyzing a large script, it is easy to get bogged down in the complex C# SOCKS5 proxy network creation code at the beginning. 
- **The Lesson:** The most critical phase of RAT analysis is identifying the `if/elseif` command loop. By skipping to the `Establish-Connection` function, I rapidly mapped out every capability the attacker had implemented, allowing for a faster and more accurate impact assessment.

## 🛠️ Response and Closure
- **Action Taken:** The SOCKS5 proxy IP (`37.143.129.165`) and Port (`9050`) were immediately blocked at the perimeter firewall. The affected workstation was isolated from the network to sever the C2 connection. 
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Host compromised by a PowerShell Remote Access Trojan.

## 📘 Recommendations
- **Tor Traffic Blocking:** Implement strict egress filtering on the corporate firewall to block connections to known Tor exit nodes and proxies. Port 9050 should be blocked outbound unless explicitly required.
- **Script Block Logging:** Ensure PowerShell Script Block Logging (Event ID 4104) is enabled and forwarded to the SIEM to capture dynamically executed payloads.
- **File System Monitoring:** Create EDR behavioral rules to alert on non-standard processes rapidly writing text to hidden or temporary files (e.g., catching the `keylog.txt` behavior).

## 🛠️ Skills & Tools Used
Static Code Analysis, PowerShell Forensics, Malware Capability Mapping, Windows API Analysis (P/Invoke), Incident Triage, MITRE ATT&CK Mapping.
