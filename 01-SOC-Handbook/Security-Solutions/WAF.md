Here is **Entry #15**.

This is crucial because while standard Firewalls (Entry #12) handle **Who** connects (IPs/Ports), WAFs handle **What** they say (HTTP Payload). In a SOC, WAF alerts are your primary indicator of web-based attacks like SQLi and XSS.

***

# 📘 SOC Analyst Handbook: Web Application Firewall (WAF)

**Category:** Application Security / Defensive Tool
**Severity:** N/A (Defensive Tool)
**Skill Level:** Core / Intermediate

---

### 1. The Concept

**The Analogy (ELI5)**
Imagine a VIP club.
*   **Network Firewall:** The bouncer at the street. He checks your ID. If you are on the list (Allowed IP), you get into the building. He doesn't listen to what you say.
*   **WAF (Web App Firewall):** The bodyguard standing right next to you inside the club. He listens to every word you speak. Even if your ID is valid, if you whisper *"I'm going to steal the cash register"* (SQL Injection) or pull out a megaphone to scream at guests (XSS), he throws you out immediately.

**The Technical Definition**
A **Web Application Firewall (WAF)** is a security solution that operates at **Layer 7 (Application Layer)** of the OSI model. It sits in front of web servers (as a Reverse Proxy) to decrypt, inspect, and filter HTTP/HTTPS traffic. Unlike standard firewalls, it understands web logic and is specifically designed to block **OWASP Top 10** attacks (SQLi, XSS, RCE, etc.).

---

### 2. The Mechanism (How it works)

#### **1. Inspection Models**
*   **Negative Security Model (Blacklist):** "Allow everything *except* known attacks."
    *   *Pros:* Easy to set up.
    *   *Cons:* Misses Zero-Days.
*   **Positive Security Model (Allowlist):** "Block everything *except* known good traffic."
    *   *Example:* "Only allow numeric input for `id=` parameter."
    *   *Pros:* Extremely secure.
    *   *Cons:* High maintenance (High False Positives).

#### **2. Virtual Patching**
This is a WAF superpower.
*   *Scenario:* A new vulnerability is found in WordPress. The patch won't be ready for 3 days.
*   *Action:* You write a WAF rule to block the specific exploit payload immediately.
*   *Result:* The vulnerability exists on the server, but the WAF stops the attack before it touches the server.

---

### 💥 3. Impact Analysis (Why we need it)

1.  **Prevents Data Breaches:** Stops attackers from dumping databases via SQLi.
2.  **Stops Defacement:** Prevents Stored XSS attacks that change website content.
3.  **Bot Mitigation:** Detects and blocks scrapers, crawlers, or credential stuffers attacking login pages.
4.  **Compliance:** PCI-DSS (Credit Card security) strictly requires a WAF or regular code reviews.

---

### 4. The Detective's Lens (Logs & Patterns)

WAF logs give you the specific payload the attacker tried to use.

#### **Key Log Fields**
*   **Client IP:** Who sent it.
*   **URI / Path:** Which page they attacked.
*   **Match / Rule ID:** What signature triggered? (e.g., `sqli-signature-5`).
*   **Payload / Data:** The actual malicious string (e.g., `' OR 1=1`).
*   **Action:** `Block` (403 Forbidden) vs. `Log` (200 OK - Monitoring Mode).


#### **Example Log Snippet (ModSecurity / AWS WAF style)**
```json
{
  "timestamp": "2023-11-10T14:22:01Z",
  "client_ip": "45.33.2.10",
  "uri": "/search.php",
  "http_method": "GET",
  "args": "q=<script>alert(1)</script>",
  "action": "BLOCK",
  "response_code": 403,
  "rule_name": "XSS_SCRIPT_TAG",
  "rule_id": "941100"
}
```
*   **Analysis:**
    *   **Attacker:** `45.33.2.10`
    *   **Vector:** `q=` parameter in `/search.php`.
    *   **Payload:** `<script>alert(1)</script>` (Classic XSS).
    *   **Result:** **Blocked (403).** The attack failed.

---

### 🌳 5. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Scanner Noise)**
    *   `Action: Blocked` + `Scanner UA (e.g., Nessus/Nikto)` + `Many Rules Triggered`
    *   *Action:* Ignore. Automated scanners hit WAFs all day.

*   **🟡 Medium Priority (Targeted Attempt)**
    *   `Action: Blocked` + `Complex Payload` + `Specific Endpoint`
    *   *Action:* An attacker is manually trying to break a specific page. Monitor source IP.

*   **🔴 High Priority (False Negative / Breach)**
    *   `Action: Allowed` + `Malicious Payload` + `200 OK Response`
    *   *Action:* **Incident.** The WAF saw the attack but didn't stop it (or was in "Log Only" mode). Check backend logs immediately.

*   **⚪ White Flag (False Positive)**
    *   `Action: Blocked` + `Legitimate User` + `Safe Payload`
    *   *Action:* A user tried to upload code (e.g., a developer posting on a forum) and got blocked. Tune the rule.

---

### 6. Investigation Steps (The Playbook)

**Step 1: Check the "Action"**
*   **Blocked (403):** Good. The WAF worked.
*   **Detected/Count (200):** Bad. The WAF just watched it happen. You need to verify if the server executed the command.

**Step 2: Decode the Payload**
*   WAF logs usually show URL-encoded strings.
*   *Raw:* `UNION%20SELECT%201%2C2%2C3`
*   *Decoded:* `UNION SELECT 1,2,3` -> Confirmed SQLi.

**Step 3: Check Source Reputation**
*   Is it a known scanner? Or a residential IP?
*   If a residential IP is sending SQLi, it might be a compromised PC (Botnet) or a determined hacker.

**Step 4: Check Response Size**
*   If the WAF missed it (Status 200), did the server send back a huge file (Database Dump)?

---

### 💻 7. Code Lab: The WAF Rule

Understanding **Regular Expressions (Regex)** is key to understanding WAFs.

**The Attack:**
`http://site.com/?id=1 AND 1=1`

**The WAF Rule (ModSecurity Syntax):**
```text
SecRule ARGS "AND [0-9]+=[0-9]+" \
    "id:1001, \
    phase:2, \
    deny, \
    status:403, \
    msg:'SQL Injection Detected'"
```
*   **Logic:**
    *   `SecRule ARGS`: Look in Arguments (URL parameters).
    *   `"AND [0-9]+=[0-9]+"`: Look for the word "AND" followed by "Number = Number".
    *   `deny, status:403`: If found, stop request and send 403 Forbidden.

**The Bypass (What attackers do):**
*   Attacker changes payload to: `1 && 2==2`
*   If the Regex isn't smart enough, it misses the `&&` symbols. This is the "Cat and Mouse" game of WAF tuning.

---

### 8. Remediation & Defense

**Immediate Actions (SOC)**
1.  **IP Block:** If an IP is aggressively attacking, block it at the Network Firewall (Layer 3) to save WAF resources.
2.  **Emergency Rule:** If a Zero-Day hits (like Log4j), deploy a specific WAF signature immediately.

**Long-term Fixes (Engineering)**
1.  **Tuning:** Review False Positives weekly. If the "SQLi" rule keeps blocking the "Search Inventory" page because product IDs look weird, whitelist that specific parameter.
2.  **Bot Protection:** Enable CAPTCHA challenges for IPs that trigger too many 404s or login failures.

---

### 🛑 SOC Pro-Tips (Beyond the Basics)

1.  **WAF Bypass via IP Rotation:**
    *   Attackers use "Rotating Proxies" to send 1 attack per IP. Blocking IPs is useless here.
    *   **Defense:** Rate limit by *Session ID* or *User Fingerprint*, not just IP.

2.  **Learning Mode:**
    *   Never turn a WAF on in "Block Mode" day one. It will break the website.
    *   Run in "Learning/Monitoring" mode for 2-4 weeks to understand normal traffic.

3.  **Layer 7 DDoS:**
    *   Network Firewalls stop "Volumetric" DDoS (lots of data).
    *   WAFs stop "App Layer" DDoS (e.g., refreshing `search.php` 100 times a second). This kills the CPU/Database without using much bandwidth.

---

### TL;DR for Interviews / Quick Recall
*   **What:** Layer 7 Firewall that inspects HTTP/HTTPS traffic.
*   **Protects Against:** OWASP Top 10 (SQLi, XSS, RCE).
*   **Placement:** Reverse Proxy (sits in front of the web server).
*   **Key Concept:** **Virtual Patching** (Blocking an exploit at the WAF level before the code is fixed).
*   **Logs:** Look for `403 Forbidden` (Block) vs `200 OK` (Allow/Monitor).
*   **Challenge:** High False Positives (blocking legit users).

### 🎯 MITRE ATT&CK Mapping
*   **T1190:** Exploit Public-Facing Application.
*   **M1031:** Network Intrusion Prevention (WAF is a specialized IPS).
*   **T1088:** Bypass User Account Control (WAF blocks credential stuffing).