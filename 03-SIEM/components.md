
# 📔 Module 2: SIEM Architecture & Components

## 1. Data Collection (The Ingestion Layer)
Data is the fuel for the SIEM. If the data is bad, the detections are useless (**Garbage In = Garbage Out**).

### Collection Methods:
*   **Agent-Based:** A small software (e.g., Splunk Universal Forwarder, Winlogbeat) is installed on the host.
    *   *Pro:* Can encrypt data, compress it, and "buffer" it if the network goes down.
    *   *Example:* Collecting local Windows Event Logs (Security, System, Application).
*   **Agentless (Push/Pull):**
    *   **Syslog (Push):** Devices like Firewalls and Switches "push" logs to a central collector on Port 514 (UDP/TCP).
    *   **WMI/WinRM (Pull):** The SIEM reaches out to the server and "pulls" the logs.
*   **API-Based:** Used for Cloud (SaaS) environments.
    *   *Example:* Pulling logs from Microsoft 365, AWS CloudTrail, or Okta.

**Senior Tip:** In an internship, you'll likely be asked to troubleshoot a "silent" log source. Always check: 1. Is the agent running? 2. Is the Firewall blocking the port? 3. Is the source generating logs at all?

---

## 2. Log Normalization & Parsing (The Translation Layer)
Raw logs are messy. Normalization is the process of making them readable and uniform.

*   **The Problem:** 
    *   Linux log: `user=root`
    *   Windows log: `Account Name: Administrator`
    *   Firewall log: `usr: admin`
*   **The Solution:** The SIEM parses these and maps them to a **Common Schema** (like ECS or CIM). Now, they all appear as the field: `user_name`.

**Example Pattern:**
> `Raw: 2023-10-12 10:00:01 IP=1.1.1.1 action=REJECT`
> 
> `Parsed: { "timestamp": "2023-10-12T10:00:01", "src_ip": "1.1.1.1", "status": "blocked" }`

---

## 3. Log Correlation (The Intelligence Layer)
Correlation turns **Events** into **Incidents**. It connects the dots between different data sources.

*   **Logic Example (The "Classic" Correlation):**
    1.  *Event A:* Firewall detects a port scan from IP `x.x.x.x`.
    2.  *Event B:* Web Server detects a failed login from IP `x.x.x.x`.
    3.  *Event C:* Database detects a successful login from IP `x.x.x.x`.
    *   **SIEM Correlation:** "Alert! Potential compromise. Brute force successful from a known scanning IP."

---

## 4. Storage & Retention (The Data Management Layer)
Logs are heavy and expensive to store. You must manage them in tiers:

1.  **Hot Storage (Searchable):** Fast SSDs. Data from the last 7–30 days. Used for active investigations.
2.  **Warm Storage:** Slower drives. Data from 30–90 days.
3.  **Cold/Frozen Storage (Archive):** Compressed data for compliance (PCI, HIPAA). Might take hours to "thaw" and search.

---

## 5. UEBA (User and Entity Behavior Analytics)
Traditional SIEM uses **Rules** (If X, then Y). UEBA uses **Baselines** (If X is unusual for this person, then Alert).

*   **The "Impossible Travel" Example:**
    *   User logs into VPN from **New York** at 08:00 AM.
    *   Same user logs into VPN from **Germany** at 08:05 AM.
    *   *UEBA Verdict:* Anomaly detected. No human can travel that fast. Trigger alert.

---

## 6. Forensic Analysis & Incident Response
The SIEM acts as the "Black Box" of a flight. After a crash (breach), we go to the SIEM to see:
*   **Timeline:** When did the attacker first enter?
*   **Scope:** How many servers did they touch?
*   **Persistence:** Did they create a "Backdoor" user account while they were here?

---

## 7. Reporting & Compliance
This is for the Managers and Auditors.
*   **Operational Report:** "How many logs did we ingest today? Are any collectors down?"
*   **Executive Report:** "What were the top 10 blocked threats this month?"
*   **Compliance Report:** "Prove that we have kept all Firewall logs for 365 days for the PCI auditor."

---

### 🛠 Junior Engineer vs. Senior Analyst Perspective

| Component | Junior (What you do) | Senior (How I think) |
| :--- | :--- | :--- |
| **Data Collection** | "I'll install the agent on this server." | "Is this log source high-volume? Do we have enough bandwidth/license?" |
| **Alerting** | "I'll create an alert for every failed login." | "That will create too much noise. Let's set a threshold of 10 failures in 1 minute." |
| **Parsing** | "I'll write a regex to find the IP address." | "Let's ensure this field maps to the 'src_ip' standard so our global dashboards work." |

---

### 💡 Career Portfolio Tip:
In your notes, create a small section called **"My Lab Logic."** Write down a scenario: 
*"I want to detect when a new user is added to a local Administrators group."* 
1. **Source:** Windows Security Logs.
2. **Event ID:** 4732.
3. **Correlation:** If `Member Name` != `Built-in Admin`, then send `High` alert. 



