

# SOC210 - Possible Brute Force Detected on VPN 

## 🚨 Raw Alert Details
```text
EventID : 162
Event Time : Jun, 21, 2023, 01:51 PM
Rule : SOC210 - Possible Brute Force Detected on VPN
Level : Security Analyst
Source Address : 37.19.221.229
Destination Address : 33.33.33.33
Destination Hostname : Mane
Username : mane@letsdefend.io
Alert Trigger Reason : A successful VPN login was detected shortly after failed login attempts from the same source IP address.
```

## Alert Overview
- **Severity:** High
- **Detection Source:** SIEM / VPN Gateway Logs
- **Asset Affected:** Corporate VPN Gateway (`vpn-letsdefend.io`) / User Account: `mane@letsdefend.io`
- **Threat Type:** Brute Force / User Enumeration / Initial Access
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: User Enumeration vs. Credential Stuffing
This incident highlights a two-phase authentication attack against a perimeter VPN gateway. 
1. **Phase 1 (User Enumeration):** The attacker first guesses or fuzzes usernames (e.g., `sane@letsdefend.io`). The VPN gateway responds with `user name does not exist`. The attacker uses this verbose error handling to build a list of valid corporate email addresses.
2. **Phase 2 (Brute Force / Stuffing):** Once a valid user is identified (`mane@letsdefend.io`), the gateway responds with `user name is correct but the password is wrong`. The attacker then focuses all brute-force efforts on this specific account until authentication succeeds. 

Verbose error messages on public-facing login portals drastically reduce the time an attacker needs to compromise an environment, as they do not waste time guessing passwords for non-existent users.

## Investigation Steps

### 1. Alert Triage and Directionality
The alert was triggered by a behavioral anomaly: a successful VPN authentication immediately following a barrage of failed attempts from the same external IP address.
- **Source IP:** 37.19.221.229
- **Destination:** `vpn-letsdefend.io`
- **Directionality:** External (Internet) to Internal (Corporate VPN Gateway).

### 2. Log Correlation (Phase 1: User Enumeration)
To understand the scope of the attack, the VPN authentication logs were queried for the malicious source IP (`37.19.221.229`).
- **Timestamp:** 01:43 PM
- **User Attempt:** `sane@letsdefend.io`
- **Action:** `user name does not exist`
- **Analysis:** This confirms the attacker was actively guessing email prefixes to map the organization's Active Directory structure. 

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/467c6fe4-8584-4b4e-8773-58d38d37e71c" />


### 3. Log Correlation (Phase 2: Targeted Brute Force)
The logs showed the attacker transitioning tactics once a valid account was discovered.
- **Timestamp:** 01:47 PM
- **User Attempt:** `mane@letsdefend.io`
- **Action:** `user name is correct but the password is wrong`
- **Analysis:** The attacker identified `mane@letsdefend.io` as a valid target and began systematically guessing passwords against this specific account.

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/2ac77034-c40a-466e-bc1d-3b7c79998ee4" />


### 4. Impact Assessment (Compromise Verification)
The critical pivot point in this investigation is determining if the brute-force attempt eventually succeeded.
- **Timestamp:** 01:51 PM
- **User Attempt:** `mane@letsdefend.io`
- **Action:** `Login Successful`
- **Analysis:** After four minutes of targeted password guessing, the attacker successfully authenticated to the VPN. The attacker now has authenticated access to the internal corporate network under the security context of the user "Mane."

<img width="600" height="300" alt="image" src="https://github.com/user-attachments/assets/405edfff-5696-4b22-9c11-764aa8f885c4" />


## Analysis and Findings
The incident is a confirmed **True Positive (Successful)**. An external threat actor successfully compromised the corporate VPN by chaining user enumeration with a targeted brute-force attack. The attacker gained unauthorized access to the internal network via the `mane@letsdefend.io` account. Because the VPN grants internal routing privileges, this incident requires immediate escalation to Tier-2 Incident Response for lateral movement hunting.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1133 | External Remote Services (VPN) |
| **Initial Access** | T1078.002 | Valid Accounts: Domain Accounts |
| **Credential Access** | T1110.001 | Brute Force: Password Guessing |
| **Discovery** | T1087.004 | Account Discovery: Cloud/Remote Account (Enumeration) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 37.19.221.229 | Attacker Source IP |
| Account | `mane@letsdefend.io` | Compromised VPN/Domain Account |
| Domain | `vpn-letsdefend.io` | Targeted VPN Gateway |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (User Enumeration):** Alert when a single external IP generates >5 "User name does not exist" errors across multiple unique usernames within a 5-minute window.
- **Detection 2 (Brute Force Success Pivot):** Alert when a single external IP generates >10 "Bad Password" errors, followed by a "Login Successful" event for the same user account within a 15-minute window.

## 🚀 Decision Tree for VPN Authentication Alerts
1. **Analyze Authentication Logs:** Are there multiple failed login attempts from a single IP?
   - If Yes -> Proceed to evaluate the failure reason.
2. **Evaluate Error Messages:** Is the attacker generating "User not found" errors or "Bad password" errors?
   - *Found both. Attack transitioned from Enumeration to Brute Force.*
3. **Verify Success:** Did the barrage of failed logins culminate in a "Login Successful" or "Session Established" log from the same IP?
   - If Yes -> **Verdict: True Positive - Successful Compromise.**
4. **Action:** Immediately terminate the active VPN session, reset the compromised user's password, and block the attacker's IP.

## Response and Closure
- **Action Taken:** The active VPN session for `mane@letsdefend.io` originating from `37.19.221.229` was forcefully terminated. The attacker's IP address was added to the perimeter firewall blocklist. 
- **Containment Required:** Yes (Network-level session termination and account suspension).
- **Closure Reason:** True Positive. Successful VPN compromise via brute force.

## Recommendations
1. **Generic Error Handling:** The VPN portal must be reconfigured to return generic error messages for all failed logins (e.g., "Invalid Username or Password"). Providing distinct errors for "User does not exist" vs. "Password is wrong" allows attackers to silently enumerate valid internal directories.
2. **Account Lockout Policy:** Implement a strict account lockout policy (e.g., 5 failed attempts locks the account for 15 minutes) to mathematically defeat automated brute-force attacks.
3. **MFA Enforcement:** Ensure Multi-Factor Authentication (MFA) is strictly mandated for all VPN connections. A compromised password should not result in a network breach without a secondary physical token.
4. **Mandatory Credential Reset:** Force an immediate password reset for `mane@letsdefend.io`, as the password is now known to the threat actor.

## 🛠️ Skills & Tools Used
- **SIEM Log Correlation:** Tracking authentication attempts across a chronological timeline to map attacker progression.
- **Authentication Triage:** Differentiating between User Enumeration and Password Spraying/Brute Forcing tactics.
- **Vulnerability Identification:** Identifying verbose error handling as an architectural security flaw.
- **Incident Response:** VPN session termination and account remediation.
