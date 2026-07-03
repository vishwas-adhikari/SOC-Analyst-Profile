
# SOC325 - Unauthorized Cloud Region Access Attempt Detected 

## Alert Overview
- Severity: Medium
- Detection Source: SIEM / Cloud Access Security Broker (CASB)
- Asset Affected: AWS_Services (52.15.206.21)
- Threat Type: Credential Stuffing / Cloud Region Evasion
- Status: True Positive (Unsuccessful / Blocked by Geo-Fencing)

## Strategy and Technical Context
This incident highlights a credential stuffing attack thwarted by robust cloud architecture. The threat actor acquired valid credentials from a third-party data breach and attempted to authenticate to the corporate AWS frontend (`/accounts/login`). 

The defense strategy relies on **Conditional Access and Geo-Fencing**. The organization had previously configured the cloud environment to block inbound authentication attempts from unused geographic zones (specifically, the Asia Pacific region `ap-south-1`). Because the attacker utilized a Virtual Private Server (VPS) located in India, the cloud proxy intercepted and denied the request with an HTTP 403 Forbidden error before the authentication logic could even process the stolen password.

## Investigation Steps

### 1. Alert Triage and Log Analysis
The investigation was triggered by an alert regarding forced authentication attempts targeting the URI `/accounts/login`.
- **Source IP:** 134.209.145.73
- **Destination:** AWS_Services (52.15.206.21)
- **Target Account:** `test@letsdefend.io`
- **Proxy Logs:** Reviewed the raw proxy logs, which revealed the following error message: `Suspicious request from unused cloud region (134.209.145.73)`. The associated HTTP response code was `403 Forbidden`.

### 2. Threat Intelligence Enrichment
The source IP was queried against external OSINT databases.
- **Provider:** DigitalOcean, LLC (AS 14061)
- **Location:** India
- **Reputation:** Flagged as malicious by multiple vendors for SSH brute-forcing, phishing, and web attacks. The use of a DigitalOcean droplet is a common tactic for threat actors attempting to mask their true origin.

### 3. Cyber Threat Intelligence (CTI) Correlation
To understand the initial access vector, internal CTI and Email Security records were cross-referenced with the targeted user account (`test@letsdefend.io`).
- **Finding:** A previous internal CTI alert email was discovered, titled "Compromised Account Alert from CTI."
- **Analysis:** The email confirmed that the password for `test@letsdefend.io` had been leaked in a recent breach. This proves the attacker was not blindly brute-forcing, but actively attempting to use known-compromised credentials.

## Analysis & Findings
The incident is a confirmed True Positive. An external threat actor attempted to access the corporate AWS environment using a stolen credential pair. However, the attack was strictly Unsuccessful. The organization's cloud proxy was properly configured to deny traffic originating from unsupported geographic regions. As a result, the attacker received a 403 Forbidden response, and the system remained secure.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|------|------|--------|
| Initial Access | T1078 | Valid Accounts |
| Initial Access | T1133 | External Remote Services |
| Defense Evasion | T1562 | Impair Defenses (Unused/Unsupported Cloud Regions) |
| Defense Evasion | T1090 | Proxy (Use of external VPS/DigitalOcean) |

## Indicators of Compromise
| Type | Value | Context |
|------|------|--------|
| IP Address | 134.209.145.73 | Malicious VPS Source IP (India) |
| Account | `test@letsdefend.io` | Compromised user account |
| URI | `/accounts/login` | Targeted authentication endpoint |

## Decision Tree for Geo-Blocked Authentication Alerts
1. **Analyze Request:** Is the source IP targeting an authentication endpoint (`/login`)?
   - If Yes -> Proceed to location verification.
2. **Check Source Location:** Is the IP originating from an unauthorized or unused cloud region?
   - If Yes -> Proceed to Impact Analysis.
3. **Verify Proxy/Firewall Action:** Did the server return an HTTP 200 OK or a 403 Forbidden?
   - If 200 OK -> Alert: Security controls bypassed. Host compromise likely.
   - If 403 Forbidden -> Alert: Attack blocked.
4. **Correlate CTI:** Is the targeted username associated with a recent credential leak?
   - If Yes -> Verdict: **True Positive - Unsuccessful (Credential Stuffing Blocked)**.

## Response & Closure
- Action Taken: Verified the failed authentication status via proxy logs. Validated the source IP geolocation against known cloud restrictions. Confirmed the credential leak via CTI reports.
- Containment Required: No. The cloud perimeter successfully blocked the attack.
- Closure Reason: True Positive. Unauthorized access attempt blocked by Geo-Fencing.

## Mistakes and Lessons Learned
- **Analyst Reflection (Containment):** Initially, the host was isolated out of an abundance of caution upon seeing the malicious IP and the compromised account.
- **The Lesson:** Over-containment can cause unnecessary business disruption. By carefully verifying the HTTP `403 Forbidden` status code and the explicit "Connection Blocked" firewall message, the analyst can confidently prove the attack failed at the perimeter, rendering host isolation unnecessary.
- **Analyst Reflection (Root Cause Analysis):** The initial assessment identified the attack as a standard brute-force attempt, missing the broader context of the CTI data leak.
- **The Lesson:** Network logs only tell half the story. Cyber Threat Intelligence (CTI) and email logs tell the "Why." Cross-referencing targeted accounts against identity protection systems or leaked credential databases is a mandatory step to distinguish between a noisy, automated scan and a highly targeted credential-stuffing attack.

## Recommendations
1. **Identity & Access Management (IAM):** Immediately disable the `test@letsdefend.io` account. Default, generic, or test accounts should never be left enabled on public-facing remote services.
2. **Password Reset:** If the test account is actively utilized, initiate a mandatory password reset.
3. **MFA Enforcement:** Ensure Multi-Factor Authentication (MFA) is strictly enforced for all public-facing authentication portals. Had the attacker used a VPN originating from an approved country (e.g., the US), the Geo-fence would have failed, and MFA would have been the final line of defense against the compromised password.

## Evidence

<img width="400" height="300" alt="image" src="https://github.com/user-attachments/assets/a7860d09-759c-4bab-8195-4c107f1b232b" />
<img width="700" height="200" alt="image" src="https://github.com/user-attachments/assets/02b816ea-b1d8-4cd8-a388-15078e654d5b" />
<img width="400" height="350" alt="image" src="https://github.com/user-attachments/assets/bb28000a-7231-4578-9bf9-dad629ae61ed" />




## Skills & Tools Used
SIEM Log Correlation (Proxy/Firewall Logs), HTTP Protocol Analysis (403 Status Codes), Threat Intelligence (AbuseIPDB/VirusTotal), Cyber Threat Intelligence (CTI) Correlation, Identity and Access Management (IAM), Cloud Security Posture Management (CSPM), MITRE ATT&CK Mapping.
