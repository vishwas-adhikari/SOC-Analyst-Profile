

# SOC169 - Possible IDOR Attack Detected — Case #169

## Alert Overview
- **Severity:** High
- **Detection Source:** WAF / SIEM
- **Asset Affected:** WebServer1005 (172.16.17.15)
- **Threat Type:** Insecure Direct Object Reference (IDOR) / Data Scraping
- **Status:** True Positive (Successful)

## Strategy and Technical Context
This incident involves the exploitation of an Insecure Direct Object Reference (IDOR) vulnerability. IDOR occurs when an application provides direct access to objects based on user-supplied input without proper authorization checks. The strategy of the threat actor is to identify an API endpoint or web page that retrieves data based on an integer (like a User ID) and then systematically enumerate that integer (e.g., 1, 2, 3, 4) to scrape unauthorized data belonging to other users. 

## Brief about the Concept
While authentication verifies *who* the user is, authorization verifies *what* they are allowed to see. An IDOR vulnerability indicates a failure in authorization. The application blindly trusts the user-supplied parameter (`user_id=X`) and queries the database without checking if the active session token actually belongs to that specific user ID. 

## Investigation Steps

### 1. Alert Triage and Log Correlation
The SIEM triggered an alert due to an excessive number of consecutive requests to the same web page from a single external IP.
- **Source IP:** 134.209.118.137
- **Target Asset:** WebServer1005 (172.16.17.15)
- **Target Endpoint:** `https://172.16.17.15/get_user_info/`
- **Directionality:** Internet to Corporate Network.

### 2. Threat Intelligence Enrichment
The source IP (`134.209.118.137`) was queried against Cisco Talos and AlienVault OTX.
- **Ownership:** DigitalOcean, LLC.
- **Reputation:** Talos categorized the IP with a "Poor" reputation and a Critical Spam Level, noting its presence on the Spamhaus blocklist. AlienVault linked the IP to 25 tags associated with historical Intrusion Detection System (IDS) alerts and malicious scanning.

### 3. Traffic Analysis & Parameter Enumeration
A deep dive into the firewall logs for the timeframe surrounding the alert (22:45 to 22:48) revealed a clear automated enumeration pattern.
- The attacker made 5 consecutive HTTP requests to the `/get_user_info/` endpoint.
- Each request modified the HTTP parameter sequentially: `?user_id=1`, `?user_id=2`, `?user_id=3`, `?user_id=4`, and `?user_id=5`.

### 4. Impact Assessment (Success Verification)
To determine if the IDOR exploit successfully extracted data, the HTTP Response Status and Response Sizes were analyzed for the 5 requests.
- **HTTP Status:** All 5 requests returned a `200 OK` status.
- **Response Size Variance:** The response sizes were 158, 204, 351, etc. 
- **Analyst Note:** The variance in response size is the definitive proof of a successful IDOR attack. If the server had blocked the requests (e.g., returning a standard "Access Denied" page), the response sizes would be identical. Because the byte counts varied, it confirms the backend database successfully retrieved and returned different user profiles for each queried ID.

### 5. Scheduled Test Verification
A search of the Email Security system and internal change-management logs for "WebServer1005" and "172.16.17.15" yielded no results. This confirmed the traffic was a hostile attack, not an authorized penetration test.

## Analysis and Findings
The incident is a confirmed **True Positive (Successful)**. An external threat actor utilized an automated script to exploit an IDOR vulnerability on WebServer1005. By sequentially manipulating the `user_id` parameter, the attacker successfully scraped the private account information of at least 5 different users. Because unauthorized data exfiltration occurred, the incident requires immediate containment and escalation.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application |
| **Discovery** | T1087 | Account Discovery |
| **Collection** | T1119 | Automated Collection |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 134.209.118.137 | Malicious Source IP (DigitalOcean) |
| URL Path | `/get_user_info/` | Vulnerable API Endpoint |
| Parameter | `user_id=` | Exploited parameter for IDOR enumeration |

## Blind Spots
- **Total Exfiltration Scope:** If the firewall logs rolled over or if the WAF only alerted after a certain threshold, the attacker may have successfully scraped hundreds of user IDs prior to the 5 logged attempts. Database query logs are required to determine the exact number of compromised records.

## False Positives: Legitimate Activity Comparison
- **Admin Dashboards:** Legitimate administrators loading a dashboard that populates user data might generate sequential `user_id` queries. However, this traffic would originate from an internal IP or VPN subnet, not a DigitalOcean droplet with a poor reputation.

## Decision Tree for IDOR Alerts
1. **Identify Pattern:** Are there multiple requests to the same endpoint with iterating parameters (e.g., ID=1, 2, 3)?
   - If Yes -> Proceed to Impact Analysis.
2. **Check Response Status:** Is it `200 OK`?
   - If Yes -> Check Response Size.
3. **Compare Response Sizes:** Are the response sizes identical?
   - If Yes -> Verdict: Unsuccessful (Server likely returned the same error page for all requests).
   - If No (Sizes vary) -> Verdict: **True Positive - Successful Data Exfiltration.**
4. **Action:** Isolate Host and escalate to Tier 2 for code remediation.

## Response and Closure
- **Action Taken:** The compromised web server (`172.16.17.15`) was **Contained** via the Endpoint Security console to halt further data scraping. The attacker IP was added to the firewall blocklist.
- **Containment Required:** Yes.
- **Tier 2 Escalation:** Yes.
- **Closure Reason:** True Positive. Successful data scraping via IDOR vulnerability.

## Recommendations
1. **Remediate Code Logic (Authorization):** The development team must implement Object-Level Access Control. The backend code must verify that the `user_id` being requested mathematically matches the Session ID/Token of the user making the HTTP request.
2. **Implement UUIDs:** Replace sequential integers (1, 2, 3) with Universally Unique Identifiers (UUIDs) for database records. While this does not fix the underlying authorization flaw, it makes automated enumeration and scraping mathematically impossible.
3. **WAF Rate Limiting:** Implement strict rate-limiting on the `/get_user_info/` endpoint to block IPs that request an anomalous number of unique user IDs within a short timeframe.

## Evidence / Screenshots

<img width="995" height="256" alt="image" src="https://github.com/user-attachments/assets/63ea0ec1-6001-4992-8c02-8ac916d46495" />

<img width="728" height="310" alt="image" src="https://github.com/user-attachments/assets/8fa12f51-6dce-403c-97f4-15bf4c33f09a" />


## Skills & Tools Used
SIEM Log Correlation, HTTP Protocol Analysis (Response Size Variance), Threat Intelligence (AlienVault OTX, Cisco Talos), IDOR / Web Application Security Triage, Host Containment, MITRE ATT&CK Mapping.
