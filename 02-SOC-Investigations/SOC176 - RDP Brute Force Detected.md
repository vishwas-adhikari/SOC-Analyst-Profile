
# SOC176 - RDP Brute Force Detected — Case #234

## 📄 Alert Summary
- **Severity:** Medium (Escalated to Critical post-triage)
- **Detection Source:** SIEM / Firewall
- **Asset Affected:** Matthew (172.16.17.148)
- **Threat Type:** Initial Access / Brute Force (RDP)
- **Status:** True Positive (Successful Compromise)

## 🛡️ Strategy and Technical Context
The Remote Desktop Protocol (RDP), running on TCP port 3389, is frequently targeted by automated scanners and botnets. The strategy of a brute force attack is to systematically guess credentials (often using lists of common usernames like `admin`, `administrator`, `test`, or known compromised passwords) until authentication is achieved. 

The SIEM triggered this alert based on a behavioral threshold: multiple login failures from a single external IP address attempting non-existent accounts in a short time frame. The critical pivot point in this investigation is determining if the attacker eventually guessed the correct credentials, transitioning the incident from a simple network probe to a confirmed system breach.

## 🕵️ Investigation Steps

### 1. Alert Triage and Directionality
The alert identified multiple RDP connection attempts directed at the internal host `Matthew` (172.16.17.148). The source IP address was identified as `218.92.0.56`. 
- **Directionality:** External (Internet) to Internal (Corporate Network).
- **Firewall Action:** Allowed. (The perimeter firewall permits RDP traffic to this host, allowing the brute force attempts to reach the endpoint).

### 2. Threat Intelligence Enrichment
A reputation check was performed on the external source IP (`218.92.0.56`).
- **VirusTotal:** 7/91 security vendors flagged the IP as malicious.
- **AbuseIPDB & LetsDefend Threat Intel:** The IP is associated with ChinaNet (AS 4134) and has a 100% abuse confidence score, with hundreds of thousands of reports specifically for SSH/RDP brute-forcing and unauthorized scanning.

### 3. Log Correlation & Attack Scope
A query was run in the Log Management system filtering for traffic from `218.92.0.56` on Port `3389`.
- **Finding:** A high volume of rapid connection attempts was observed utilizing randomized source ports, confirming automated brute-forcing behavior.
- **Scope Analysis:** A broader search across the SIEM confirmed the attacker only targeted the host `Matthew` (172.16.17.148). No lateral scanning against other internal subnets was observed from this external IP.

### 4. Impact Assessment (Authentication Verification)
To determine if the attack was successful, Windows Security Event logs for the targeted host were reviewed, specifically looking for Logon events associated with the external IP.
- **Finding:** Amidst the high volume of failed login attempts (Event ID 4625), a successful logon (Event ID 4624 - Logon Type 3/10) was recorded originating from `218.92.0.56`. 
- **Conclusion:** The attacker successfully guessed a valid username and password combination and established an unauthorized remote session.

## 🧪 Analysis and Findings
The incident is a confirmed **True Positive**. While the initial alert severity was "Medium" (indicating a brute-force attempt), the investigation upgraded the status to a critical breach. The attacker (`218.92.0.56`) leveraged automated tools to brute-force RDP and successfully authenticated to the host `Matthew`. Because the firewall was configured to allow inbound port 3389, the endpoint was directly exposed to the internet, leading to the compromise.

## 🚩 MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services |
| **Credential Access** | T1110.001 | Brute Force: Password Guessing |
| **Discovery** | T1046 | Network Service Discovery |

## 📉 Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 218.92.0.56 | Attacker Source IP |
| Hostname | Matthew (172.16.17.148) | Compromised Internal Endpoint |
| Protocol | TCP / 3389 | Exploited Service (RDP) |

## 🌫️ Blind Spots
- **Post-Exploitation Visibility:** While the successful login was confirmed, further forensic analysis on the host (EDR process logs, registry modifications) is required to determine if the attacker dropped ransomware, created persistence (e.g., new user accounts), or moved laterally.

## 🚫 False Positives
- **Legitimate Remote Access:** Authorized administrators or remote workers typing their passwords incorrectly multiple times can trigger brute-force alerts. However, the external Chinese IP and 100% abuse rating rule out a legitimate user in this scenario.

## 🛠️ Response and Closure
- **Action Taken:** The targeted endpoint (`Matthew / 172.16.17.148`) was immediately **Isolated/Contained** via the EDR console to terminate the attacker's active RDP session and prevent lateral movement.
- **Containment Required:** Yes (Due to successful Event ID 4624).
- **Closure Reason:** True Positive. Initial Access achieved via RDP Brute Force.

## 📘 Recommendations & Lessons Learned
1. **RDP Exposure (Root Cause):** RDP (Port 3389) should *never* be exposed directly to the public internet. All remote desktop access must be placed behind a Virtual Private Network (VPN) or an RD Gateway requiring Multi-Factor Authentication (MFA).
2. **Account Lockout Policies:** Implement stricter Active Directory account lockout policies (e.g., lock out after 5 failed attempts for 15 minutes) to severely hinder automated guessing tools.
3. **Password Hygiene:** The successful brute force implies the user "Matthew" had a weak or easily guessable password. Enforce strong password complexity rules and initiate a mandatory password reset for the compromised account.
4. **Geo-Blocking:** Implement geo-IP blocking at the perimeter firewall to drop traffic from countries where the organization has no legitimate business operations.

## 🖼️ Evidence

<img width="700" height="300" alt="image" src="https://github.com/user-attachments/assets/189f85b6-5910-41ad-a108-42c4319d7686" />
<img width="700" height="300" alt="image" src="https://github.com/user-attachments/assets/d79f3eb7-9d1a-4118-a936-19d692465d4f" />
<img width="700" height="300" alt="image" src="https://github.com/user-attachments/assets/d80ef893-1954-4c0e-a9c4-e3682ffe27fe" />



## 🛠️ Skills & Tools Used
SIEM Log Correlation, Windows Event Log Analysis (Event IDs 4624/4625), Threat Intelligence (AbuseIPDB/VirusTotal), Network Protocol Analysis (RDP), Host Containment & Incident Response.
