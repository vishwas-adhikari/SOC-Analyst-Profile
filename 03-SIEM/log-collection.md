
# 📘 SOC Analyst Handbook: SIEM Log Collection & Architecture (IBM QRadar Focus)

**Category:** SIEM Engineering / Infrastructure
**Severity:** N/A (Core Architecture)
**Skill Level:** Intermediate / Advanced

---

### 1. The Concept

**The Analogy (ELI5)**
Imagine the SOC is a Central Post Office. 
*   **The Endpoints (Servers/PCs):** Citizens writing letters (generating logs).
*   **Log Collection:** The mail trucks and letter carriers bringing the mail to the Post Office.
*   *The Problem:* If a mail truck breaks down (Agent crash), or the highway is closed (Firewall blocking port 514), the Post Office stops receiving mail from that neighborhood. The SOC goes blind.

**The Technical Definition**
Log Collection is the systematic gathering of event data from diverse network endpoints, security appliances, and cloud platforms into a centralized SIEM (Security Information and Event Management) system. The SIEM normalizes this raw data into a unified format for correlation, alerting, and retention.

---

### 2. The 4 Pillars of Log Ingestion (How Data Moves)

To get data into a SIEM, you must choose a transport method. Each has trade-offs.

#### **A. Agent-Based Collection (The Heavy Lifter)**
*   **How it works:** A small piece of software (e.g., Splunk Universal Forwarder, Filebeat, IBM WinCollect) is installed directly on the target server.
*   **Pros:** Highly reliable. Can compress and encrypt (TLS) logs. Can filter noise *before* sending over the network (saving bandwidth). Caches logs locally if the network goes down.
*   **Cons:** Management overhead. You have to install, update, and monitor CPU/RAM usage on 10,000+ endpoints.

#### **B. Agentless Collection (The Lightweight)**
*   **How it works:** The SIEM reaches out over the network to pull logs using native OS protocols (e.g., Windows MSRPC / WMI) without installing third-party software.
*   **Pros:** Zero deployment friction. Great for legacy or fragile servers where you can't install new software.
*   **Cons:** Heavy reliance on network stability. Harder to traverse firewalls. Often unencrypted.

#### **C. Syslog (The Universal Translator)**
*   **How it works:** The industry standard for network/Linux devices (Firewalls, Routers, IDS). Devices push logs directly to the SIEM via UDP Port 514 or TCP Port 6514.
*   **Pros:** Universally supported. Instant setup.
*   **Cons:** Standard UDP Syslog is **cleartext** (can be sniffed) and **lossy** (if the network drops a packet, it's gone forever—no resend). *Pro-Tip: Always use Syslog over TCP/TLS for critical logs.*

#### **D. API-Based Collection (The Modern Cloud)**
*   **How it works:** The SIEM uses HTTP/HTTPS (REST APIs) to "pull" logs in JSON/XML format from Cloud SaaS providers (e.g., AWS CloudTrail, Office 365, CrowdStrike).
*   **Pros:** Perfect for Cloud-native infrastructure. Highly secure (HTTPS).
*   **Cons:** APIs have **Rate Limits**. If you pull logs too fast, the cloud provider blocks you (HTTP 429 Too Many Requests). API calls can also incur high cloud computing costs.

---

### ⚙️ 3. IBM QRadar Architecture Deep Dive

If you use IBM QRadar, you must understand its specific ingestion vocabulary. 


| Collection Method | Technical Protocol | Best Use Case |
| :--- | :--- | :--- |
| **Syslog** | UDP 514 / TCP 1468 | **Universal.** Used for Linux, Firewalls, Routers, and generic security appliances. |
| **WinCollect** | Managed/Standalone Agent | **Windows native.** High-fidelity collection of Windows Security, System, and Application event logs. |
| **MSRPC** | RPC over Port 445/135 | **Agentless Windows.** Used when you aren't allowed to install software on the Windows server. |
| **API Based** | REST (JSON/XML) | **Cloud & SaaS.** Collecting from O365, AWS CloudTrail, Azure, or CrowdStrike. |
| **QFlow** | Deep Packet Inspection | **Network Traffic.** Collects raw packet data and metadata to see *what* happened inside the traffic (L7). |
| **JDBC / Database** | SQL Query | **Database Auditing.** Reaches into Oracle, SQL Server, or MySQL to pull audit trail tables. |
| **SNMP Traps** | UDP 161/162 | **Network Health.** Receiving real-time alerts from switches and routers regarding hardware status. |
| **OPSEC / LEA** | Proprietary | **Check Point.** A specific encrypted tunnel for pulling Check Point Firewall and VPN logs. |
| **Directory / File** | SCP / SFTP / NFS | **Flat Files.** QRadar logs into a server and "reads" a text file directly from the hard drive. |
| **LSE / Custom DSM** | Regex / Mapping | **Unknown Devices.** Used when you have a tool QRadar doesn't support. You write custom regex to "teach" QRadar how to read it. |

---


### 🌳 4. Decision Tree (SIEM Engineering)

*   **Device is Linux/Network?** -> Use **Syslog**.
*   **Device is Windows & high-security?** -> Use **WinCollect** (Encrypted/Reliable).
*   **Device is Windows & "No-Touch" policy?** -> Use **MSRPC** (Agentless).
*   **Device is a Cloud App (e.g., Salesforce)?** -> Use **API**.
*   **Device is a Database?** -> Use **JDBC**.

---

### ⚠️ 5. SOC Reality: EPS & The Cost of Logging

**Events Per Second (EPS)** is the heartbeat of the SIEM. 
*   SIEM licenses (QRadar/Splunk) cost millions of dollars based on how much data you ingest (EPS or GB/Day).
*   **The SOC Rule:** You cannot log *everything*.
*   *Action:* If you turn on "Windows Firewall Filtering - All Connections," a single server can generate 5,000 EPS and crash your SIEM license. You must **Filter at the Source** (e.g., tell the Agent to drop all `Event ID 5156` before sending it to the SIEM).

---

### 🕵️ 6. Troubleshooting Workflow (Log Source Failure)

When an alert fires for **"Log Source Stopped Reporting,"** the SOC Analyst/Engineer uses this playbook:

**Step 1: Check the Network (The Pipes)**
*   Is the Firewall blocking the traffic?
*   *Test:* From the SIEM, use `ping` or `telnet target_ip 514` to see if the port is open.

**Step 2: Check the Endpoint Service (The Engine)**
*   Did the service crash?
*   *Test:* Log into the Windows Server. Is the `WinCollect` or `SplunkForwarder` service running? Restart it.

**Step 3: Check the API Rate Limits (The Cloud)**
*   If Office 365 logs stop arriving, check the SIEM internal error logs. Look for `HTTP 429 (Rate Limited)` or `HTTP 401 (Unauthorized)`. The API key may have expired!

**Step 4: Check the Parser (The Translator)**
*   Logs are arriving, but they are useless. In QRadar, they show up as `Stored` instead of categorized. 
*   *Fix:* The vendor updated their log format, breaking your Regex. Update the DSM/Parser.

---

### 🚨 7. Attack Detection: Log Tampering

Adversaries know you are watching. Their first step is often to blind the SIEM.

**Pattern 1: The "Agent Kill"**
*   **Anomaly:** EDR/WinCollect service stops unexpectedly, but the server is still pingable.
*   **Meaning:** The attacker ran `net stop wincollect` or `taskkill /IM splunkd.exe`. 
*   **Detection:** Set a SIEM rule: `If Log Source = Offline AND System Ping = Alive -> Trigger Critical Alert`.

**Pattern 2: The "Log Clear"**
*   **Anomaly:** Windows Event ID `1102` (The audit log was cleared).
*   **Meaning:** The attacker wiped the local Windows logs to hide their tracks.
*   **Defense:** Because you have an Agent instantly forwarding logs to the SIEM, the SIEM already has a copy of the attacker's actions *before* they cleared the local log!

---

### 7. TL;DR for Interviews / Quick Recall

*   **Agent vs Agentless:** Agents are software installed on the host (secure, fast, filtering capable). Agentless uses network protocols (easy setup, high network load).
*   **Syslog:** Standard protocol (UDP 514 / TCP 6514). UDP is lossy; always advocate for TCP/TLS for critical infrastructure logs.
*   **APIs:** Used for Cloud/SaaS. Beware of API Key expiration and Rate Limiting.
*   **IBM QRadar Specifics:** **DSM** (Parses logs), **WinCollect** (Windows Agent), **QFlow** (Network packet inspection).
*   **EPS (Events Per Second):** The metric of SIEM cost and performance. Filtering noise at the source is critical for SOC efficiency.

### 🎯 8. MITRE ATT&CK Mapping
*   **T1562.001:** Impair Defenses: Disable or Modify Tools (Attacker kills the logging agent).
*   **T1070:** Indicator Removal on Host (Attacker clears Event Logs - Event ID 1102).
*   **DS0009:** Windows Registry / System Logs (The Data Source).





