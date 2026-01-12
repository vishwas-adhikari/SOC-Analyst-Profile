
# 📘 SOC Analyst Handbook: Intrusion Detection Systems (IDS)

**Category:** Network Defense & Monitoring
**Severity:** Variable (Info to Critical)
**Skill Level:** Core / Fundamental

---

### 1. The Concept

**The Analogy (ELI5)**
Imagine a security camera system in a bank.
*   **IDS (Intrusion *Detection* System):** The camera sees a robber, records it, and buzzes the manager's office. It **does not** stop the robber; it only warns you.
*   **IPS (Intrusion *Prevention* System):** The camera sees the robber and automatically locks the doors and releases tear gas. It takes action to **stop** the threat.
*   **NIDS vs. HIDS:**
    *   *NIDS (Network):* Cameras in the lobby watching everyone (Network Traffic).
    *   *HIDS (Host):* A sensor inside the vault (Individual Server/PC) checking if files are being touched.

**The Technical Definition**
An **IDS** is a device or software application that monitors a network or system for malicious activity or policy violations. It analyzes traffic packets against a database of **Signatures** (known attack patterns) or **Anomalies** (deviations from normal behavior) and generates alerts for the SIEM/SOC.

---

### 2. The Mechanism (How it detects)

#### **1. Signature-Based Detection**
The IDS compares packets against a database of known "fingerprints."
*   *Example:* "If you see a packet containing the hex bytes `0x909090` (NOP Sled) followed by `/bin/sh`, alert immediately."
*   *Pros:* Very low false positives for known attacks.
*   *Cons:* Blind to "Zero-Day" attacks (new attacks with no signature yet).

#### **2. Anomaly-Based (Behavioral) Detection**
The IDS learns what "Normal" looks like (the baseline).
*   *Example:* "This server usually sends 10MB of data a day. Today it sent 5GB. Alert!"
*   *Pros:* Can catch new/unknown attacks.
*   *Cons:* High false positives (legitimate large file transfers can trigger it).

---

### 3. The Detective's Lens (The Rules)

To understand an alert, you must understand the **Rule** that triggered it. Most IDS (Snort, Suricata) use a specific syntax.

#### **Anatomy of a Snort/Suricata Rule**
```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Possible SQL Injection"; content:"UNION SELECT"; sid:100001; rev:1;)
```

*   **Header:**
    *   `alert`: Action to take (alert, log, pass, drop).
    *   `tcp`: Protocol (tcp, udp, icmp).
    *   `$EXTERNAL_NET any`: Source IP and Source Port.
    *   `->`: Direction of traffic (one way).
    *   `$HOME_NET 80`: Destination IP and Destination Port.
*   **Options (The parenthesis part):**
    *   `msg`: The text that appears in your alert log.
    *   `content`: The specific pattern/keyword to look for inside the packet payload.
    *   `sid`: Signature ID (Unique number for the rule).
    *   `rev`: Revision number (version of the rule).

---

### 4. The Log (What you see on screen)

When a rule matches, it generates an alert. You will see this in your SIEM (Splunk, Wazuh, ELK).

#### **Example Log Snippet (Suricata "fast.log" format)**
```text
10/25/2023-14:30:05.123456  [**] [1:100001:1] Possible SQL Injection Detected [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.55:44332 -> 10.0.0.5:80
```
*   **Analysis:**
    *   **Timestamp:** `10/25/2023...`
    *   **Signature ID:** `[1:100001:1]` (GID:SID:Rev). Identifying rule #100001 triggered.
    *   **Message:** `Possible SQL Injection Detected`.
    *   **Source:** `192.168.1.55` (Port 44332).
    *   **Destination:** `10.0.0.5` (Port 80).
    *   **Protocol:** `{TCP}`.

---

### 🌳 5. Mini Decision Tree (Triage Logic)

When an IDS alert pops up, use this quick logic to determine urgency:

*   **🟢 Low Priority (Noise)**
    *   `Inbound` + `Blocked/Dropped by FW` + `Known Scanner IP`
    *   *Action:* Ignore or bulk close. The defenses worked.

*   **🟡 Medium Priority (Investigation Needed)**
    *   `Inbound` + `Allowed` + `404/403 Response`
    *   *Action:* The attack passed the firewall but failed to exploit the server. Check if they found anything else.

*   **🔴 High Priority (Incident)**
    *   `Inbound` + `Allowed` + `200 OK` + `Large Response Size`
    *   *Action:* The attack worked and the server replied with data. Start Incident Response.

*   **🟣 Critical Priority (Compromise)**
    *   `Outbound` + `Rare Destination IP` + `Repeating Pattern (Beaconing)`
    *   *Action:* **Isolate Host Immediately.** This is C2 (Command & Control) traffic.

---

### 6. Investigation Steps (The Playbook)

**Step 1: Understand the Direction**
*   **Inbound (External -> Internal):** An attacker is trying to hit you.
*   **Outbound (Internal -> External):** A device inside is talking to a bad guy. **CRITICAL.**

**Step 2: Check the Payload (The "Packet Capture")**
*   An IDS alert is just a pointer. You need to see the *actual data*.
*   *Action:* Look at the HTTP Request body.
    *   *Real:* `id=1 UNION SELECT password...`
    *   *False Positive:* `blog_post=How to write a UNION SELECT query...` (User reading a blog).

**Step 3: Check Reputation**
*   Is the Source IP a known scanner? (GreyNoise, VirusTotal).
*   If it's a known scanner hitting your firewall, it's usually "Background Noise" (Low priority).

**Step 4: Correlation**
*   Did this alert happen in isolation?
*   Or did you see: `Port Scan` -> `SQL Injection Alert` -> `Outbound connection to Rare IP`? (This is a Kill Chain).

---

### 💻 7. Code Lab: The Rule vs. The Traffic

Let's look at how we detect the **Directory Traversal** attack we learned in Entry #07.

**The Traffic (What the attacker sends):**
```http
GET /download.php?file=../../../../etc/passwd HTTP/1.1
Host: website.com
```

**The Snort/Suricata Rule (How we catch it):**
```text
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"WEB-ATTACK Directory Traversal attempt"; flow:established,to_server; content:"../"; http_uri; content:"etc/passwd"; http_uri; classtype:web-application-attack; sid:1000005; rev:1;)
```

**Breakdown of the Rule Logic:**
1.  `flow:established,to_server`: Only look at established connections (ignore random packet fragments) going toward our server.
2.  `content:"../"; http_uri;`: Look for the text `../` specifically inside the **URI** (URL path).
3.  `content:"etc/passwd"; http_uri;`: Look for `etc/passwd` inside the URI.
4.  If **BOTH** contents are found in the same packet -> **TRIGGER ALERT**.

---

### 8. Remediation & Defense

**Immediate Actions (SOC)**
1.  **IP Block:** If the alert is a True Positive, block the Source IP at the Firewall.
2.  **Isolate:** If the alert was "Outbound C2 Traffic," isolate the internal host immediately.

**Long-term Fixes (Engineering)**
1.  **Rule Tuning:** If a rule fires on legitimate traffic (False Positive), tune it.
    *   *Example:* A rule detects `cmd.exe`. But your System Admins use `cmd.exe` remotely for maintenance.
    *   *Fix:* Edit the rule to `pass` (ignore) traffic from the Admin Subnet.
2.  **Encryption Handling:** IDS cannot read encrypted traffic (HTTPS). Ensure you have **SSL/TLS Decryption** set up, or place the IDS *behind* the Load Balancer.

---

### 🛑 SOC Pro-Tips (Beyond the Basics)

1.  **The "HOME_NET" Variable:**
    *   IDS relies on knowing what is "Home" (Internal) and what is "External".
    *   If this is misconfigured in the `snort.conf`, you might miss alerts because the IDS thinks the attack is coming from "inside."

2.  **The Encryption Blind Spot:**
    *   90% of web traffic is HTTPS. If your IDS is looking at raw internet traffic, it sees garbage: `Encrypted Packet...`.
    *   **Solution:** Place IDS sensors behind the WAF or Load Balancer (Decrypted Zone).

3.  **Alert Fatigue:**
    *   You will see thousands of "Port Scan" alerts.
    *   **Pro Tip:** Don't investigate every single scan. Focus on **Successful Responses**.
    *   *Ignorable:* Attacker sends Exploit -> Server responds `404 Not Found` or `RST`.
    *   *Critical:* Attacker sends Exploit -> Server responds `200 OK` and sends 5MB of data back.

---

### TL;DR for Interviews / Quick Recall
*   **What:** IDS monitors traffic for malicious patterns (Signatures) or anomalies.
*   **Difference:** IDS **alerts** (Passive); IPS **blocks** (Active).
*   **Rule Structure:** `Header (Action Protocol IPs)` + `Options (Content to match)`.
*   **Common Tools:** Snort, Suricata, Zeek (Bro), Wazuh (HIDS).
*   **Key Challenge:** Distinguishing **False Positives** (Legitimate traffic looking like attacks) from **True Positives**.
*   **Blind Spot:** Encrypted traffic (HTTPS) unless decryption is enabled.

### 🎯 MITRE ATT&CK Mapping
*   **DS0015:** Network Traffic (The Data Source).
*   **M1031:** Network Intrusion Prevention (The Mitigation).
*   **T1031:** Modify Existing Service (Attackers might try to kill the IDS process).