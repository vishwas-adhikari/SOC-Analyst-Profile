
---

## Alert Summary
- **Type:** Web Attack (SQL Injection)
- **Severity:** High
- **Source:** SIEM / IDS Alert
- **Status:** True Positive

##  Investigation and Analysis
On February 25, 2022, at 11:34 a.m., a high-severity alert was triggered indicating a potential SQL Injection (SQLi) attempt against **WebServer1001** (172.16.17.18). The attack originated from the external IP address **167.99.169.17**.

![[Pasted image 20260125024255.png]]


### 1. Reputation Analysis
I began the investigation by performing a reputation check on the source IP (**167.99.169.17**) using **VirusTotal**, **Cisco Talos**, and **AbuseIPDB**. 
- **VirusTotal:** 11/94 security vendors flagged the IP as malicious.
- **Geographic Data:** The IP was identified as a known source of malicious activity targeting web applications.

 ![[Pasted image 20260125024040.png]]

### 2. Payload Deobfuscation
The alert captured a suspicious GET request to the `/search/` directory. The query parameter `q` contained URL-encoded characters. I utilized **CyberChef** to decode the string:

- **Raw URL:** `https://172.16.17.18/search/?q=%22%20OR%201%20=%201%20--%20`
- **Decoded Payload:** `" OR 1 = 1 -- `

This is a classic "tautology-based" SQL injection payload. The attacker attempted to manipulate the back-end SQL query to return a 'true' result for all rows, which is commonly used to bypass authentication or extract unauthorized data from a database.

![[Pasted image 20260125024323.png]]

### 3. Log Correlation & Impact Assessment
I pivoted to the SIEM **Log Management** section to analyze the server's response to this request.
- **HTTP Response Status:** 500 (Internal Server Error)
- **Response Size:** 948 bytes
- **Device Action:** Allowed (The request reached the application)

The **HTTP 500** status code suggests that the malicious input caused a server-side crash or a syntax error in the database engine, rather than successfully executing and returning data (which would typically result in a 200 OK status). To ensure no further compromise occurred, I inspected the endpoint's command history and process logs; no unauthorized lateral movement or secondary payloads were detected.

## 🧪 Indicators of Compromise (IOCs)
| Type | Value | Description |
| :--- | :--- | :--- |
| **IP** | 167.99.169.17 | Malicious Source IP (Attacker) |
| **URL** | `https://172.16.17.18/search/?q=%22%20OR%201%20=%201%20--%20` | SQL Injection Attack Vector |
| **Hostname** | WebServer1001 | Targeted Internal Asset |

##  Skills & Tools Used
- **SIEM:** Log Analysis & Correlation
- **OSINT:** VirusTotal, AbuseIPDB, Cisco Talos (Threat Intelligence)
- **Decoding:** CyberChef (URL Decoding)
- **Endpoint Security:** Command History & Log Review
- **Incident Response:** Playbook Execution

##  Playbook Solutions
1. **Initial Assessment:** Identified the alert as a potential SQLi via URL parameters.
2. **Reputation Check:** Confirmed the source IP has a history of malicious activity.
3. **Payload Analysis:** Decoded the URL to confirm the SQLi attempt.
4. **Impact Analysis:** Verified the HTTP 500 response, indicating an unsuccessful exploit.
5. **Sanity Check:** Confirmed via email exchange that no authorized penetration testing was scheduled.
6. **Artifact Collection:** Documented IP, URL, and server logs.

##  Conclusion & Recommendations
The incident was a **True Positive** SQL Injection attempt. The attacker (167.99.169.17) targeted the search functionality of WebServer1001. Based on the HTTP 500 error code and the absence of suspicious post-exploitation activity on the host, the attack is classified as **Unsuccessful**. 

However, the fact that the request reached the application indicates a lack of robust edge filtering. If successful, an attack of this nature could lead to a full database breach, unauthorized data exfiltration, or administrative bypass.

### **Recommendations:**
1. **Implement Parameterized Queries:** Ensure the development team uses prepared statements (parameterized queries) for all database interactions to prevent malicious input from being interpreted as code.
2. **Web Application Firewall (WAF) Hardening:** Configure WAF rules to automatically block requests containing common SQL keywords (e.g., `UNION`, `SELECT`, `OR 1=1`) at the edge.
3. **Input Sanitization:** Implement strict "Allow-list" validation on the `/search/` parameter to ensure only alphanumeric characters are processed.
4. **IP Blocking:** Add the malicious IP (**167.99.169.17**) to the organizational blocklist at the firewall level.
5. **Error Message Masking:** Configure the web server to return generic error pages instead of "500 Internal Server Error" to prevent attackers from using verbose errors for database fingerprinting.

---
**Status:** Closed - True Positive / No Impact
**Analyst:** Vishwas Adhikari

![](Pasted%20image%2020260125162853.png)

