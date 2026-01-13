
# 📘 SOC Analyst Handbook: Intrusion Prevention Systems (IPS)

**Category:** Network Defense & Enforcement
**Severity:** N/A (Defensive Tool)
**Skill Level:** Core / Fundamental

---

### 1. The Concept

**The Analogy (ELI5)**
*   **IDS (The Camera):** Watches the door. If a thief enters, it records the crime and sends an email to security. The thief still gets inside.
*   **IPS (The Bouncer):** Stands *in* the doorway. If a thief tries to enter, the bouncer physically stops them, pushes them back, and locks the door. The thief never gets inside.

**The Technical Definition**
An **Intrusion Prevention System (IPS)** is a network security appliance (or software) that sits **Inline** (directly in the flow of network traffic). Unlike an IDS, which only *monitors* traffic, an IPS has the capability to **inspect, block, and drop** malicious packets in real-time before they reach the target server.

---

### 2. The Mechanism (Types & Modes)

#### **Placement is Everything**
*   **Inline Mode:** The IPS sits between the Firewall and the Switch. Traffic *must* pass through the IPS to get to the network. This allows it to block attacks.
*   **Fail-Open vs. Fail-Closed:** Since the IPS is a bottleneck:
    *   *Fail-Open:* If the IPS crashes/loses power, traffic keeps flowing (Security Risk, but Business Continuity).
    *   *Fail-Closed:* If IPS crashes, it cuts the wire. No internet (High Security, but Business Outage).

#### **Types of IPS**
1.  **NIPS (Network-based):** Protects the entire subnet. Sits at the network edge.
2.  **HIPS (Host-based):** Installed on a specific server (e.g., an Agent on a Windows Server). Protects only that device but can see encrypted traffic if decrypted locally.
3.  **WIPS (Wireless):** Monitors Wi-Fi frequencies for rogue Access Points or de-authentication attacks.
4.  **NBA (Network Behavior Analysis):** Detects DDoS or massive data transfers based on flow, not signatures.

---

### 3. The Detective's Lens (Logs & Actions)

The biggest difference in logs between IDS and IPS is the **"Action"** field.

#### **Key Actions**
*   **Alert:** Saw it, logged it, let it pass (IDS mode).
*   **Drop:** Silently destroyed the packet. The attacker waits for a response that never comes.
*   **Reject/Reset:** Destroyed the packet and sent a TCP RST (Reset) flag to the attacker, telling them "Connection Closed."
*   **Block:** Added the IP to a temporary blacklist (e.g., "Block for 5 minutes").

#### **Example Log Snippet (Suricata IPS)**
```text
10/26/2023-09:15:22.45001  [Drop] [1:200005:2] ET EXPLOIT HiSilicon DVR - Default Telnet Credentials [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 14.1.2.3:55442 -> 192.168.1.10:23
```
*   **Analysis:**
    *   **Action:** `[Drop]` (The attack was successfuly stopped).
    *   **Signature:** Telnet Default Creds.
    *   **Outcome:** The internal server `192.168.1.10` never received this packet.

---

### 🌳 4. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Success)**
    *   `Inbound` + `Action: Dropped/Blocked` + `Known Malicious IP`
    *   *Action:* No immediate response needed. The system did its job.

*   **🟡 Medium Priority (Tuning Needed)**
    *   `Outbound` + `Action: Dropped` + `Legitimate Business App`
    *   *Action:* **False Positive.** The IPS broke a valid application. Investigate and whitelist.

*   **🔴 High Priority (Evaded)**
    *   `Inbound` + `Action: Alert/Passed` + `Payload: Malicious`
    *   *Action:* The IPS saw it but was configured only to "Alert." The attack reached the server. **Start Incident Response.**

*   **🟣 Critical Priority (DDoS/Flood)**
    *   `Inbound` + `Action: Drop` + `100,000 events/sec`
    *   *Action:* The IPS might crash due to load. Check upstream filtering or ISP mitigation.

---

### 5. Investigation Steps (The Playbook)

**Step 1: Verify the Action**
*   Did the IPS actually stop it?
*   *Log check:* Look for `Drop`, `Block`, or `Deny`. If it says `Permit` or `Alert`, the threat is still active.

**Step 2: Check for False Positives (The #1 IPS Issue)**
*   IPS rules are strict.
*   *Scenario:* A developer runs a script that looks like SQLi. The IPS drops the connection.
*   *Action:* Verify the Source IP. Is it an employee? If so, tune the rule.

**Step 3: Check "Context" (The Victim)**
*   The IPS dropped an exploit targeting "Apache Struts."
*   *Check:* Is the destination server actually running Apache Struts?
    *   *Yes:* Good catch. Patch the server.
    *   *No:* It's just background noise (Port Scanning).

---

### 💻 6. Configuration Lab: IDS vs. IPS Rules

The difference often comes down to a single word in the configuration.

**IDS Rule (Passive - Snort/Suricata syntax):**
```bash
# This just tells the analyst. The packet continues.
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Possible SQL Injection"; content:"UNION SELECT"; sid:1001;)
```

**IPS Rule (Active - Snort/Suricata syntax):**
```bash
# This KILLS the packet.
drop tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Possible SQL Injection"; content:"UNION SELECT"; sid:1001;)
```

**What happens if this is a False Positive?**
*   **IDS:** The analyst gets a spam email. The website keeps working.
*   **IPS:** The customer tries to checkout, the website hangs or crashes. The company loses money. **This is why tuning is critical.**

---

### 7. Remediation & Defense

**Immediate Actions (SOC)**
1.  **Unblock (False Positive):** If the IPS blocked the CEO, verify the traffic, then add an "Exception" or "Pass Rule" for that IP/Signature.
2.  **Shun/Blacklist:** If the IPS is dropping packets but the attacker keeps trying, add a block at the **Firewall** level to save IPS resources.

**Long-term Fixes (Engineering)**
1.  **SSL Decryption:** Like IDS, an IPS cannot stop what it cannot read. It needs to be placed where traffic is decrypted.
2.  **Regular Updates:** Attack signatures change daily. Ensure the IPS feed is auto-updating.

---

### 🛑 SOC Pro-Tips (Beyond the Basics)

1.  **Latency Matters:**
    *   Because IPS sits *inline*, it inspects every packet. This adds milliseconds of delay. High-Frequency Trading firms often refuse to use IPS for this reason.

2.  **The "Learning Mode":**
    *   Never deploy a new IPS in "Block" mode immediately.
    *   Run it in **"Monitor/Alert Only"** mode for 2 weeks. See what *would* have been blocked. Tune the False Positives. *Then* switch to Block mode.

3.  **WAF vs. IPS:**
    *   **IPS:** Great at network exploits (Buffer overflows, SMB attacks, OS exploits). Good at generic SQLi.
    *   **WAF (Web App Firewall):** Specialized for Web (SQLi, XSS, Logic flaws).
    *   *Verdict:* You need both. IPS catches the network hacks; WAF catches the application logic hacks.

---

### TL;DR for Interviews / Quick Recall
*   **What:** Hardware/Software that sits inline and actively blocks malicious traffic.
*   **Difference:** IDS = Detects (Camera); IPS = Prevents (Bouncer).
*   **Modes:** **Inline** (Blocking) vs. **Promiscuous** (Monitoring/IDS mode).
*   **Key Actions:** `Drop`, `Reject`, `Block`.
*   **Risk:** **False Positives** in an IPS cause service outages (blocking legitimate users).
*   **Placement:** Must be behind the firewall but before the internal network (usually).

### 🎯 MITRE ATT&CK Mapping
*   **M1031:** Network Intrusion Prevention.
*   **DS0015:** Network Traffic.
*   **T1031:** Modify Existing Service (Attackers trying to disable the IPS).