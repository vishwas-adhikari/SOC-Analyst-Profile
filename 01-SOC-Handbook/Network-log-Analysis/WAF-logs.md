
# 📘 SOC Analyst Handbook: WAF Log Analysis (Practical)

**Category:** Web Application Security / Log Analysis
**Severity:** Core Skill (High Volume)
**Skill Level:** Advanced

---

### 1. The Concept

**The Analogy (ELI5)**
*   **Network Firewall:** The Customs Officer at the border. He checks your passport (IP) and checks if you are on a ban list. He keeps the gate closed if you aren't allowed.
*   **WAF (Web App Firewall):** The Security Screener who opens your luggage. Even if your passport is valid, she opens your bag (SSL Offload), reads your diary (HTTP Payload), and checks if you are carrying instructions on how to build a bomb (SQL Injection/XSS).

**The Technical Definition**
WAF Log Analysis involves examining **Layer 7** HTTP/HTTPS traffic. Unlike standard firewalls that see opaque encrypted packets, WAFs perform **SSL Offloading** (Decryption) to inspect the actual data parameters (`?id=1 OR 1=1`). WAFs are the primary defense against OWASP Top 10 attacks.

---

### 2. Log Anatomy (The Vocabulary)

You must understand the specific fields to interpret the attack.

#### **📝 WAF Log Fields Reference**

| Field | Definition | SOC Analysis Tip |
| :--- | :--- | :--- |
| **date / time** | Event Timestamp | Critical for correlation with Backend Server logs. |
| **type / main_type** | Log Category | E.g., `Attack`, `Traffic`, `Event`. Focus on `Attack`. |
| **sub_type / attack_type** | Attack Category | E.g., `SQL Injection`, `XSS`, `RCE`. Tells you the *intent*. |
| **severity_level** | Incident Severity | `High`/`Critical` usually implies a known exploit signature match. |
| **action** | Action Taken | **CRITICAL:** `Alert` (Traffic passed), `Block` (Traffic stopped). |
| **policy** | Rule Name | E.g., `Alert_Policy`. Tells you if the WAF is in Monitor Mode. |
| **src / dst** | Source/Dest IP | Who is attacking (`src`) vs. Who is the victim (`dst`). |
| **http_method** | Request Method | `GET` (Read), `POST` (Write), `PUT` (Upload). |
| **http_url** | The Target Path | The specific page and malicious parameters (e.g., `?id=1' OR 1=1`). |
| **http_agent** | User-Agent | Browser fingerprint. Look for scanners like `sqlmap` or `nikto`. |
| **status_code** | HTTP Response | **The Verdict.** Did the web server accept the request? |

---

### 3. HTTP Primer (Codes & Methods)

To know if an attack succeeded, you must read the HTTP context.

#### **🚦 HTTP Response Codes (The Verdict)**

| Code | Meaning | SOC Interpretation |
| :--- | :--- | :--- |
| **200 (OK)** | Request Processed | **DANGER:** If the payload was malicious, the server accepted it. Potential Breach. |
| **301 (Redirect)** | Moved Permanently | **Check Dest:** Did it redirect to an Admin Panel (Success) or Login Page (Fail)? |
| **403 (Forbidden)** | Access Denied | **Safe:** The WAF or Web Server blocked the request. |
| **404 (Not Found)** | Content Missing | **Safe:** Attacker is scanning for non-existent files (Reconnaissance). |
| **500 / 503** | Server Error | **Investigate:** The exploit crashed the application (DoS) or triggered a DB error. |

#### **request_method (The Action)**

| Method | Usage | Malicious Use Case |
| :--- | :--- | :--- |
| **GET** | Retrieve data | SQLi via URL parameters (`?id=1`). |
| **POST** | Send data (Forms) | Credential Stuffing, File Uploads, SQLi in Login forms. |
| **PUT** | Update/Create file | Uploading Webshells (`shell.php`) to the server. |
| **DELETE** | Delete resource | Deleting logs or critical website files (DoS). |

---

### 4. Example Logs (The Evidence)

**Log A: The "Passive" Detection (High Risk)**
```text
date=2022-01-26 time=19:47:26 type=attack sub_type="SQL Injection" severity_level=High action=Alert src=19.6.150.138 dst=172.16.10.10 http_method=get http_url="?v=(SELECT (CHR(113)...))" msg="Parameter(Password) triggered signature ID 030000136" policy="Monitor_Only" status_code=200
```
*   **Analysis:**
    *   **Attack:** SQL Injection (High Complexity).
    *   **Action:** `Alert` (Monitor Mode). The WAF saw it but let it pass.
    *   **Status:** `200 OK`.
    *   **Verdict:** **CRITICAL INCIDENT.** The attack was allowed, and the server responded successfully. Investigate immediately.

**Log B: The "Scanner" Noise (Low Risk)**
```text
date=2022-01-26 time=20:00:01 type=attack sub_type="Cross Site Scripting" severity=Medium action=Block src=45.33.2.1 dst=172.16.10.10 http_url="/search=<script>alert(1)</script>" http_agent="Nessus" status_code=403
```
*   **Analysis:**
    *   **Attack:** XSS.
    *   **Action:** `Block`.
    *   **Agent:** `Nessus` (Vulnerability Scanner).
    *   **Verdict:** **Benign Noise.** Authorized scanning or script kiddie blocked by WAF.

---

### 5. Detection Tricks & Patterns

**1. The "200 OK" Disaster**
*   **Pattern:** `Action: Alert` + `Attack: SQL Injection` + `Response Code: 200`.
*   **Meaning:** The WAF didn't block it, and the server accepted it successfully. **Data breach likely.**

**2. Method Abuse (Web Shells)**
*   **Pattern:** `http_method=PUT` or `DELETE` on a public endpoint (e.g., `/images/logo.php`).
*   **Meaning:** Attackers trying to upload webshells or delete files. Public sites should usually only allow GET/POST.

**3. The "Scanner" Pattern**
*   **Pattern:** One IP triggering `XSS`, `SQLi`, `Path Traversal`, and `RCE` signatures all within 10 seconds.
*   **Meaning:** Automated Vulnerability Scanner. If `Action=Block`, ignore. If `Action=Alert`, check for 200 OKs.

**4. Credential Stuffing**
*   **Pattern:** High volume of `POST` requests to `/login` from one IP, but no attack signature triggered.
*   **Meaning:** The payload isn't malicious (it's just passwords), so WAF signatures miss it. You must detect via **Rate Limiting**.

---

### 🌳 6. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Blocked Scan)**
    *   `Action: Blocked` + `Source: Known Scanner` + `Status: 403`
    *   *Action:* Ignore. WAF doing its job.

*   **🟡 Medium Priority (False Positive)**
    *   `Action: Blocked` + `Payload: Valid SQL in a Forum Post`
    *   *Action:* A user tried to post code snippets on a dev forum. Whitelist the rule for that URL.

*   **🔴 High Priority (Successful Attack)**
    *   `Action: Alert` + `Payload: ' OR 1=1` + `Response: 200 OK` + `Bytes: High`
    *   *Action:* **Incident.** The attack passed the WAF and retrieved data.

*   **🟣 Critical Priority (Web Shell)**
    *   `Method: PUT` + `File: shell.php` + `Response: 201 Created`
    *   *Action:* **Isolate Host.** Attacker successfully uploaded a backdoor.

---

### 🛡️ 7. Containment Actions (SOC Reality)

If a WAF detection is confirmed as a true positive:

1.  **Block the IP (Layer 3):** Don't let the WAF waste CPU processing their requests. Block them at the Network Firewall.
2.  **Emergency WAF Rule:** If the attacker found a bypass (e.g., specific encoding), create a custom regex rule to block that specific string immediately.
3.  **Disable the Account:** If the logs show successful login attempts (Credential Stuffing), lock the victim accounts.
4.  **Backend Cleanup:** If a file was uploaded (`shell.php`), delete it from the web server and patch the vulnerability.

---

### 🧬 8. Advanced WAF Concepts

#### **A. Virtual Patching**
*   **Concept:** A vulnerability exists (e.g., Log4j), and developers need 3 days to fix it. The SOC applies a **WAF Rule** immediately to block the exploit string.
*   **Result:** The server is still vulnerable, but the WAF shields it.

#### **B. Attack Confirmation (Verification Workflow)**
**Never trust the WAF alone.** If you see `Alert` + `200 OK`:
1.  **Pivot to App Logs:** Check IIS/Apache logs.
2.  **Check Response Size:** Did the server send back 50MB (Database Dump) or 2KB (Login Page)?
3.  **Check DB Logs:** Did the database execute the query or throw a syntax error?

#### **C. API Abuse Detection**
*   **BOLA (Broken Object Level Authorization):** User A requests `/api/order/100`. Then requests `/api/order/101` (User B's order). If WAF sees sequential ID access, it should flag "Enumeration."

---

### 🛠️ 9. False Positive Tuning Workflow

1.  **Analyze Payload:** Decode the string. Does `SELECT * FROM` appear in a legitimate forum post?
2.  **Check Source:** Is the IP a developer or internal scanner?
3.  **Action:**
    *   *Safe:* Whitelist the specific **Parameter** (e.g., allow HTML tags in `body_text` but not `username`).
    *   *Unsafe:* Never disable the rule globally.

---

### 📊 10. Impact Assessment

*   **Data at Risk:** SQLi = Database contents. XSS = User Cookies.
*   **Blast Radius:** Is this the public brochure site (Low) or the Customer Portal (High)?

### 🎯 11. MITRE ATT&CK Mapping
*   **T1190:** Exploit Public-Facing Application.
*   **T1595:** Active Scanning.
*   **T1059:** Command and Scripting Interpreter (RCE).

---

### 12. Interview Summary (TL;DR)
*   **WAF vs Firewall:** WAF inspects Layer 7 (Content/Payload); Firewall inspects Layer 3/4 (IP/Port).
*   **SSL Offload:** WAFs must decrypt traffic to see attacks inside HTTPS.
*   **Alert vs Block:** Always check the `Action`. `Alert` means the traffic passed through.
*   **Confirmation:** `200 OK` on a malicious request is the biggest red flag. Verify with backend server logs.
*   **Virtual Patching:** Using WAF rules to stop exploits while waiting for code fixes.