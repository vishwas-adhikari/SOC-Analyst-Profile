

# SOC257 - VPN Connection Detected from Unauthorized Country

## Alert Overview
- **Severity:** Low
- **Detection Source:** SIEM / VPN Gateway
- **Asset Affected:** VPN Gateway / Host: Monica
- **Threat Type:** Initial Access / Brute Force / Unauthorized Geographic Login
- **Status:** True Positive (Unsuccessful / Blocked by MFA)

## Strategy and Technical Context
The strategy observed in this incident is a straightforward credential-stuffing or brute-force attack directed at the corporate Virtual Private Network (VPN). Threat actors frequently utilize automated scripts and botnets to test compromised credentials against public-facing infrastructure. 

The detection rule triggered because the authentication attempt originated from a geographically unauthorized location (Vietnam), violating conditional access policies. The critical pivot point for the analyst in this scenario is determining whether the attacker successfully bypassed the primary authentication layer and, more importantly, whether they successfully fulfilled the Multi-Factor Authentication (MFA) challenge.

## Brief about the Concept
VPN gateways typically listen on TCP port 443 (HTTPS) to allow remote workers to connect securely to the corporate network. Because these portals are public-facing, they are under constant attack. A robust security posture relies on **Defense in Depth**: Even if an attacker correctly guesses a user's password (Primary Authentication), conditional access policies (Geo-blocking) and MFA (Secondary Authentication) should halt the intrusion.

## Investigation Steps

### 1. Alert Triage and Directionality
The alert was triggered by an incoming VPN connection attempt.
- **Source IP:** 113.161.158.12
- **Destination Port:** 443 (HTTPS)
- **Target Asset:** User: Monica
- **Directionality:** External (Internet) to Internal (Corporate VPN Gateway).

### 2. Threat Intelligence Enrichment
The source IP (`113.161.158.12`) was queried against IP geolocation and Threat Intelligence databases.
- **Geolocation:** Vietnam.
- **Reputation:** VirusTotal identified the IP as malicious, confirming it is not a legitimate remote worker traveling abroad, but rather a known hostile actor.

### 3. Log Correlation & Impact Assessment (The Critical Step)
To determine if the attack was successful, the raw VPN authentication logs were reviewed in the SIEM.
- **Finding:** Multiple authentication attempts were logged originating from `113.161.158.12`.
- **Authentication Flow:** The logs indicate the attacker repeatedly attempted to obtain a One-Time Password (OTP).
- **Impact Assessment:** The continuous requests for an OTP confirm that while the attacker may have possessed valid primary credentials (username/password), they were unable to satisfy the secondary authentication requirement. The MFA control successfully blocked access to the VPN.

### 4. Endpoint Execution Verification (EDR)
Out of an abundance of caution, the EDR logs for the host `Monica` were reviewed.
- **Finding:** No suspicious running processes, anomalous network connections, or indicators of compromise were observed. This correlates with the network logs, proving the attacker never gained access to the internal network or the endpoint.

## Analysis and Findings
The incident is a confirmed **True Positive**. An external threat actor (113.161.158.12) launched a brute-force attack against the corporate VPN portal, targeting the user "Monica." The alert correctly identified an unauthorized geographic login attempt. However, the attack was **Unsuccessful**. The organization's Multi-Factor Authentication (MFA) requirement effectively neutralized the threat, preventing the attacker from establishing a VPN session. 

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1078 | Valid Accounts |
| **Initial Access** | T1133 | External Remote Services |
| **Credential Access** | T1110 | Brute Force |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 113.161.158.12 | Malicious Source IP (Vietnam) |
| Target Account | Monica | Targeted user for brute force |
| Protocol | TCP / 443 | Exploited Service (VPN / HTTPS) |

## Blind Spots
- **Credential Source:** It is unknown how the attacker obtained the initial credentials for the user "Monica" (e.g., whether they were guessed via brute-force, phished previously, or obtained from a third-party data breach).

## False Positives: Legitimate Activity Comparison
- **Traveling Employees:** A legitimate employee traveling to an unauthorized country and attempting to log in would trigger this alert. However, a legitimate user would successfully enter their MFA token, resulting in a successful login log rather than repeated OTP failures, and the IP would not possess a malicious reputation on VirusTotal.

## Decision Tree for VPN Alerts
1. **Verify Location & Reputation:** Is the source IP from an unexpected country or flagged as malicious?
   - If Yes -> Proceed to Authentication Logs.
2. **Check Authentication Status:** Did the VPN log indicate a "Successful Login" or "Session Established"?
   - If Yes -> **Verdict: Successful Compromise.** Immediate containment required.
3. **Evaluate Failure Reason:** Do the logs indicate "Invalid Credentials" or "OTP/MFA Failed"?
   - If Yes -> **Verdict: True Positive - Unsuccessful.**
4. **Action:** Reset compromised credentials and block the source IP.

## Response and Closure
- **Action Taken:** The malicious IP (`113.161.158.12`) was added to the perimeter blocklist. 
- **Containment Required:** No. The host and network were not breached.
- **Closure Reason:** True Positive. Unauthorized access attempt successfully blocked by MFA.

## Recommendations
1. **Mandatory Password Reset:** Although the attacker failed the MFA challenge, the fact that they reached the OTP prompt suggests they possessed the correct password for the user "Monica." A mandatory password reset must be enforced for this account immediately.
2. **Geo-Blocking Enforcement:** Ensure the VPN gateway is configured to automatically drop connections from unauthorized countries at the firewall level, preventing the attacker from even reaching the authentication portal.
3. **MFA Fatigue Monitoring:** Monitor the account for "MFA Fatigue" attacks, where an attacker continuously spams the user with push notifications hoping they accidentally approve the request.

## Evidence / Screenshots
<img width="581" height="268" alt="image" src="https://github.com/user-attachments/assets/9e5e9f97-cee1-4242-8c74-f6fa0ffebc80" />
<img width="295" height="299" alt="image" src="https://github.com/user-attachments/assets/19886c13-9889-4d11-9c31-11796e5d49cb" />
<img width="577" height="188" alt="image" src="https://github.com/user-attachments/assets/3356c067-1fda-440a-a537-2acd174f6b85" />




## Skills & Tools Used
SIEM Log Correlation (Authentication Logs), Identity and Access Management (IAM / MFA Triage), Threat Intelligence (VirusTotal/IP Geolocation), Incident Triage, MITRE ATT&CK Mapping.
