
# 📘 SOC Analyst Handbook: IDS/IPS Log Analysis

**Category:** Network Defense / Threat Detection
**Severity:** Core Skill (High Alert Volume)
**Skill Level:** Intermediate

---

### 1. The Concept

**The Analogy (ELI5)**
*   **Firewall:** Blocks "Red Cars" but allows "Blue Cars."
*   **IDS/IPS:** Stops the "Blue Car," opens the trunk, and checks if there is a bomb inside.
    *   **IDS (Passive):** Sees the bomb, screams "BOMB!", but lets the car drive through.
    *   **IPS (Active):** Sees the bomb, screams "BOMB!", and shoots the tires out to stop the car.

**The Technical Definition**
IDS/IPS systems inspect the **Payload** (Layer 7 content) of network packets against a database of **Signatures** (Rules) to detect exploits, malware, and command-and-control traffic.
*   **IDS (Intrusion Detection System):** Generates an alert (`action=detected`) but does not stop traffic.
*   **IPS (Intrusion Prevention System):** Generates an alert and drops the packet (`action=dropped`).

---

### 2. Log Anatomy (The Vocabulary)

You need to understand Fortinet/Suricata/Snort fields to triage effectively.

#### **📝 Common Log Fields**

| Field | Definition | Why it matters for SOC |
| :--- | :--- | :--- |
| **attack / signature** | The specific threat name | Tells you *what* they tried (e.g., `Log4j`, `SQL Injection`, `Buffer Overflow`). |
| **severity / level** | `Info`, `Low`, `Medium`, `High`, `Critical` | Helps prioritize. `Critical` usually means a successful exploit or malware C2. |
| **action** | `Detected` vs `Dropped` | **Detected** = The attack reached the target. **Dropped** = The attack failed. |
| **direction** | `Incoming` vs `Outgoing` | `Incoming` = Attack attempt. `Outgoing` = Infected host calling home (C2). |
| **ref / cve** | Reference URL / CVE ID | Link to the vulnerability details (Google this immediately). |
| **category** | Rule Category | `Exploit`, `Policy`, `Info`, `Malware`. (See "Reliability" below). |

---

### 3. Example Log (The Evidence)

**Raw Fortinet IPS Log:**
```text
date=2022-05-21 time=14:06:38 devname="FG500" type="utm" subtype="ips" severity="high" srcip=12.11.2.4 dstip=19.66.201.16 srcport=57673 dstport=53 action="detected" attack="DNS.Server.Label.Buffer.Overflow" ref="http://www.fortinet.com/ids/VID37088" msg="misc: DNS.Server.Label.Buffer.Overflow"
```

**Breakdown & Analysis:**
1.  **Who:** `12.11.2.4` (External Attacker).
2.  **Target:** `19.66.201.16` (Internal DNS Server).
3.  **What:** `DNS.Server.Label.Buffer.Overflow` (Buffer Overflow Exploit).
4.  **Verdict:** `detected` (**BAD**). The IPS saw it but did **not** block it.
5.  **Context Check:** The log says the exploit targets "Tftpd32 DNS Server."
    *   *Question:* Is my server (`19.66.201.16`) actually running Tftpd32?
    *   *If Yes:* **Critical Incident.**
    *   *If No:* **False Positive** (Failed Attempt).

---

### 🔍 4. Signature Reliability Note (Rule Quality)

Not all alerts are created equal. You must judge the "Fidelity" of the signature.

| Signature Prefix/Type | Reliability | Meaning |
| :--- | :--- | :--- |
| **ET EXPLOIT / CURRENT_EVENTS** | **High** | Usually a specific exploit or active malware campaign. Treat as Real. |
| **ET SCAN / INFO** | **Low** | Informational noise (e.g., "Executable Download"). Often benign. |
| **ET POLICY** | **Variable** | Violation of rules, not necessarily a hack (e.g., "Dropbox usage", "Tor Client", "BitTorrent"). |
| **GPL (General Public License)** | **Medium** | Older, generic rules. Prone to false positives on modern traffic. |

**Pro Tip:** If you see a generic signature like `HTTP Generic SQL Injection`, check the packet payload. It triggers on *any* SQL keyword (even in a blog post). If you see `Log4j Malicious LDAP Request`, it is highly specific and likely real.

---

### ⚠️ 5. Signal vs. Noise (Critical Thinking)

**The "Contextual Awareness" Check:**
Before panicking, check if the attack is even possible.

| Signature Name | Context Check | Verdict |
| :--- | :--- | :--- |
| **IIS Buffer Overflow** | Is the target running Windows/IIS? | If Target = Linux/Apache, it's a **False Positive**. |
| **SQL Injection** | Is the target a Database or Web Server? | If Target = Printer, it's a **False Positive**. |
| **SSH Brute Force** | Is Port 22 Open? | If Firewall blocks Port 22, the IPS alert is just noise. |

---

### 6. Investigation Steps (The Playbook)

**Step 1: Check the Action**
*   **Blocked/Dropped:** The system defended itself. Monitor for persistence.
*   **Detected/Pass:** The attack went through. **High Urgency.**

**Step 2: Check the Direction**
*   **Inbound:** Someone attacking us.
*   **Outbound:** Someone *inside* attacking out (or C2). **Critical Urgency.**

**Step 3: Research the Signature (CVE)**
*   Google the `attack` name or CVE.
*   *Example:* "Log4j RCE". Does my server have Java installed?

**Step 4: Check Response Traffic**
*   Did the server reply?
*   Check **Flow Logs**. If `Bytes Sent` > 0, the server responded. If `Bytes Sent` = 0, the exploit likely failed or crashed the service.

---

### 🌳 7. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Blocked Scan)**
    *   `Action: Dropped` + `Direction: Inbound` + `Scanner IP`
    *   *Action:* Ignore. The perimeter held.

*   **🟡 Medium Priority (False Positive)**
    *   `Action: Detected` + `Signature: IIS Exploit` + `Target: Linux Server`
    *   *Action:* Close ticket. "Vulnerability not applicable to host."

*   **🔴 High Priority (Successful Exploit)**
    *   `Action: Detected` + `Target: Vulnerable Server` + `Bytes Sent > 0`
    *   *Action:* **Isolate Host.** Check for webshells or new processes.

*   **🟣 Critical Priority (Active C2)**
    *   `Action: Detected` + `Direction: Outbound` + `Signature: Trojan/Botnet`
    *   *Action:* **Full Incident Response.** The network is compromised.

---

### 🛠️ 8. False Positive Tuning (Remediation)

SOC Analysts don't just close tickets; they fix the system. If an alert is "Noise," apply one of these fixes:

1.  **Whitelisting (Pass Rule):**
    *   *Scenario:* Your internal Vulnerability Scanner (Nessus) triggers 10,000 "Exploit" alerts every Friday.
    *   *Fix:* Rule: `Pass all traffic FROM IP 192.168.1.5 (Nessus)`.

2.  **Thresholding (Rate Limiting):**
    *   *Scenario:* "SSH Login Attempt" fires every time an admin logs in once.
    *   *Fix:* Rule: `Only alert if count > 5 within 60 seconds`.

3.  **Disabling the Rule:**
    *   *Scenario:* A rule detects "Ping" packets as "ICMP Attack," but your network relies on Ping for monitoring.
    *   *Fix:* Disable that specific Signature ID (SID).

---

### 📊 9. Impact Assessment

**1. Integrity Risk**
*   If an exploit succeeds (e.g., File Upload), the attacker has changed the system state.

**2. Confidentiality Risk**
*   Did the signature indicate "Information Disclosure" (e.g., Heartbleed)?

**3. Availability Risk**
*   Did the attack crash the service (DoS)? Check `Server-RST` in firewall logs.

---

### 🎯 10. MITRE ATT&CK Mapping

*   **T1190:** Exploit Public-Facing Application.
*   **T1210:** Exploitation of Remote Services.
*   **T1071:** Application Layer Protocol (C2 traffic).

---

### 11. Interview Summary (TL;DR)
*   **IDS vs IPS:** IDS = Camera (Alerts); IPS = Bouncer (Blocks).
*   **Signature:** A unique pattern (fingerprint) of a known attack.
*   **Action Types:** `Detected` (Attack succeeded/passed) vs `Dropped` (Attack failed).
*   **Context is King:** Always check if the target is actually vulnerable to the alert (e.g., Don't panic about Windows exploits hitting Linux servers).
*   **Tuning:** Know when to Whitelist (Scanners) vs Disable (Bad Rules).