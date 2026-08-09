
# SOC127 - SQL Injection Detected — Case #235

## Alert Overview
- **Severity:** High
- **Detection Source:** SIEM / WAF
- **Asset Affected:** WebServer1000 (172.16.20.12)
- **Threat Type:** SQL Injection (SQLi) / Automated Vulnerability Scanning
- **Status:** True Positive (Unsuccessful)

## Strategy and Technical Context
The strategy observed in this incident relies on "Spray and Pray" automated vulnerability scanning. Rather than carefully mapping the target application, the threat actor utilized an automated tool (likely SQLMap or a custom script) to fire heavily nested, multi-vector payloads at the web server. 

The payload attempts to test for multiple vulnerabilities simultaneously in a single HTTP GET request. It combines a `UNION SELECT` statement for database enumeration, a Cross-Site Scripting (XSS) payload for reflection testing, and OS Command Injection via `xp_cmdshell` attempting to read Linux system files. The technical objective is to trigger an error or a successful execution that the automated scanner can record for later, targeted exploitation.

## Brief about the Concept
SQL Injection (SQLi) occurs when user-supplied input is improperly sanitized, allowing an attacker to interfere with the queries the application makes to its database. 
- **UNION-Based SQLi:** Used to extract data from other tables by appending results to the original query.
- **Error-Based SQLi:** Forces the database to generate an error containing the requested data (e.g., using Oracle's `XMLType` function).
- **xp_cmdshell:** A specific extended stored procedure in Microsoft SQL Server that spawns a Windows command shell, allowing attackers to pivot from SQLi to Remote Code Execution (RCE).

## Investigation Steps

### 1. Alert Triage and Directionality
The alert identified a malicious GET request originating from `118.194.247.28` directed at the internal asset `WebServer1000` (172.16.20.12). 
- **Directionality:** Internet to Company Network.
- **Device Action:** Allowed.
<img width="776" height="202" alt="image" src="https://github.com/user-attachments/assets/44e367c6-2a41-4cd0-a14e-cc9360bba48a" />

### 2. Threat Intelligence Enrichment
The source IP (`118.194.247.28`) was queried against threat intelligence databases. 
- **Finding:** The IP resolves to a public pool allocated to China Unicom. Threat intelligence vendors flagged the IP with a high malicious confidence score (10/91), noting it as a source of active, automated web exploitation scanning.

### 3. Payload Deobfuscation and Analysis
Using CyberChef (URL Decode), multiple payload variations from this source IP were analyzed:
- **Payload 1 (Primary Alert):** Attempted to use a `UNION ALL SELECT` to pull `table_name` from `information_schema.tables`, combined with an XSS script `<script>alert("XSS")</script>`, and concluded with an execution command: `EXEC xp_cmdshell('cat ../../../etc/passwd')#`.
- **Payload 2 (Log Review):** `(SELECT (CASE WHEN (4611=4629) THEN 1 ELSE (SELECT 4629 UNION SELECT 6288) END))` — A classic Boolean/Time-based Blind SQLi syntax.
- **Payload 3 (Log Review):** `(SELECT UPPER(XMLType(CHR...)) FROM DUAL)` — An Oracle-specific Error-Based SQLi syntax.

<img width="700" height="377" alt="image" src="https://github.com/user-attachments/assets/f4c7bdb8-ffa8-4d76-92ef-01c32c28a9d1" />

<img width="700" height="386" alt="image" src="https://github.com/user-attachments/assets/b15aefd0-73d5-4370-a7d8-f7d6263f3521" />


### 4. Impact Assessment & Outcome Verification
To determine if the attack was successful, the HTTP response was evaluated.
- **HTTP Status:** 200 OK
- **Response Size:** 865 bytes
- **Architecture Mismatch:** The primary payload attempts to use `xp_cmdshell`, which is an exclusive feature of Microsoft SQL Server running on Windows. However, the command it tries to execute is `cat /etc/passwd`, which is a Linux command. This fundamental mismatch guarantees a backend syntax execution failure. Furthermore, an 865-byte response is too small to contain a successful dump of `information_schema.tables`.

## Targeted Code Extraction (Key Findings)
**1. The "Kitchen Sink" Payload**
```sql
UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/*;*/ EXEC xp_cmdshell('cat ../../../etc/passwd')#
```
*Analyst Note:* This string proves the attack is automated. A human attacker would test for XSS, Database Enumeration, and OS Command Execution separately. The tool is simply throwing every known exploit string into the parameter to see what sticks.

**2. Oracle Database Probing**
```sql
(SELECT UPPER(XMLType(CHR(60)||CHR(58)...)) FROM DUAL)
```
*Analyst Note:* The presence of `FROM DUAL` and `XMLType` indicates the automated scanner is cycling through different database management system (DBMS) profiles. Since it is testing both MSSQL (`xp_cmdshell`) and Oracle (`DUAL`), the attacker clearly has no prior knowledge of our backend architecture.

## Analysis and Findings
The incident is a confirmed **True Positive**. The external IP `118.194.247.28` launched an automated SQL Injection attack against WebServer1000. Despite the web server returning a `200 OK` status, the attack is classified as **Unsuccessful**. The response size (865 bytes) indicates the server merely returned the default landing page or a generic error message, rather than a massive database dump. The use of conflicting OS and Database syntaxes further confirms that the payload failed to execute on the backend. 

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application |
| **Execution** | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| **Defense Evasion** | T1027 | Obfuscated Files or Information (URL Encoding) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 118.194.247.28 | External Malicious Scanner IP |
| URL Path | `/?douj=3034` | Targeted query parameter |
| Payload | `EXEC xp_cmdshell` | RCE execution signature |

## Blind Spots
1. **WAF Truncation:** Web Application Firewalls (WAF) or SIEM loggers will occasionally truncate exceedingly long HTTP GET requests. If the payload exceeded the maximum logged character limit, secondary execution commands might be hidden.
2. **Encrypted Payloads:** If the traffic was over HTTPS and SSL decryption was not applied at the edge, the exact SQLi string would not be visible in network-layer packet captures.

## False Positives: Legitimate Activity Comparison
1. **Security Scanners:** Authorized internal DAST (Dynamic Application Security Testing) tools like Nessus, Qualys, or Acunetix will generate identical traffic. Analysts must verify if the source IP belongs to an authorized internal scanner or an approved third-party pentest vendor.
2. **Data Analytics:** Highly complex URL queries used by internal analytics or reporting tools can occasionally trigger generic SQLi alerts if they contain words like "SELECT" or "UNION" in a benign context.

## Mistakes and Lessons Learned
- **The Error (Status Code Misinterpretation):** Initially, I classified this attack as "Successful" because the HTTP status code was `200 OK`. 
- **The Lesson:** In web attacks, a `200 OK` only means the web server (like Apache or IIS) successfully processed the HTTP connection; it does not mean the *database* successfully processed the SQL injection. By analyzing the **Response Size** (865 bytes) and identifying the logical mismatch in the payload (Windows SQL trying to run a Linux command), I correctly re-classified the attack as **Not Successful**.
- **The Error (Playbook Escalation):** I initially recommended Tier 2 Escalation.
- **The Lesson:** Standard SOC playbook rules dictate that Tier 2 escalation is reserved for *successful* breaches or internal-to-internal lateral movement. Since this was an external inbound attack that failed to compromise the asset, Tier 2 escalation is explicitly not required, saving critical analyst resources.

## Decision Tree for SQL Injection Alerts
1. **Payload Verification:** Does the URL/Body contain SQL syntax (`UNION`, `SELECT`, `' OR 1=1`)?
   - If Yes -> Malicious Intent confirmed.
2. **Check Response Status:** Is the status `500 Internal Server Error`?
   - If Yes -> Attack failed (Syntax broke the database).
3. **Check Response Status:** Is the status `200 OK`?
   - If Yes -> **Check Response Size.** 
4. **Evaluate Size & Content:** Is the response size unusually large compared to baseline? 
   - If Yes -> Verdict: True Positive - Successful (Escalate to Tier 2).
   - If No (Low bytes) -> Verdict: **True Positive - Unsuccessful.**

## Response and Closure
- **Action Taken:** The malicious IP (`118.194.247.28`) was added to the perimeter firewall blocklist to halt further automated scanning.
- **Containment Required:** No. The host was not compromised.
- **Closure Reason:** True Positive. Unsuccessful automated vulnerability scan.

## Recommendations
1. **WAF Enforcement:** Ensure the Web Application Firewall (WAF) is set to "Blocking" mode for known SQLi signatures. The fact that this payload bypassed the firewall (Device Action: Allowed) indicates the WAF is either misconfigured or in "Monitoring" mode.
2. **Parameterized Queries:** Verify with the development team that the `douj` parameter on the web application utilizes strict parameterized queries (prepared statements) to prevent future injection attempts.
3. **Database Hardening:** Even though the OS mismatch saved the system here, ensure that `xp_cmdshell` is explicitly disabled in the database configuration, as it is a critical pivot point for attackers.

## Skills & Tools Used
CyberChef (URL Decoding), SQL Syntax Analysis, HTTP Log Correlation (Response Size Analysis), Threat Intelligence (VirusTotal), Incident Triage, MITRE ATT&CK Mapping.






