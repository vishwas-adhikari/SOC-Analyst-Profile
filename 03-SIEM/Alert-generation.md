
# 📘 SOC Analyst Handbook: SIEM Alert Generation & Alarming

**Category:** SIEM Operations / Threat Detection
**Severity:** N/A (Core Logic)
**Skill Level:** Intermediate / Advanced

---

### 1. The Concept (What & Why)

**The Analogy (ELI5)**
Imagine a grocery store security system.
*   **Simple Event:** A customer picks up a bottle of wine. (Normal)
*   **Correlation Rule:** IF (Customer picks up wine) AND (Customer puts wine in bag) AND (Customer walks past register WITHOUT paying) WITHIN (2 minutes) -> **TRIGGER ALARM.**
*   The SIEM looks for a *sequence* of events that are individually normal but collectively dangerous.

**The Technical Definition**
**Correlation Rules** are logical expressions used by a SIEM to identify relationships between diverse security events. By analyzing data from firewalls, endpoints, and applications against defined **Conditions** and **Match Conditions**, the SIEM can detect complex attack chains (e.g., Recon -> Exploit -> Exfiltration) that individual tools would miss.

---

### 2. The 4 Pillars of a Correlation Rule

| Component | Definition |
| :--- | :--- |
| **Events & Source Data** | The raw logs (Network, System, App, Threat Intel) that serve as the foundation. |
| **Fundamental Principle** | The logic defining *why* a rule should fire based on meaningful relationships. |
| **Conditions & Match** | The specific filters (IPs, Ports, File names) and binding operators (AND/OR). |
| **Triggering Mechanism** | The actual detection of the state which initiates an appropriate response. |

---

### ⚙️ 3. Creating Rules & Alarms (IBM QRadar Workflow)

In QRadar, the rule logic and the alarm response are created together using the **Rule Wizard**. 
**Path:** `QRadar -> Offenses -> Rules -> Actions -> New Event Rule`

#### **Step 1: Define Trigger Criteria (Tests)**
Using the wizard, you select the filters that must be met:
*   **Search Filter:** `when the event matches this search filter` (e.g., Destination Port is 3389).
*   **IP Filter:** `when the source IP is one of the following IP addresses`.
*   **Sequence/Frequency Filter:** `when these rules match at least X times in Y minutes`.
*   **Category/QID Filter:** `when the event QID is one of the following`.
*   **Severity Filter:** `when the event severity is greater than 5`.

#### **Step 2: Rule Action & Alarming (The Response)**
Once the conditions match, you define the response in the **Rule Response** section:

1.  **Rule Action:** Determine the Severity, Credibility, and Bias of the alert.
2.  **Dispatch New Event:** Create a "Synthetic Event" that summarizes the attack and ensures it becomes part of an **Offense**.
3.  **Response Limiter:** Configure how often the rule can fire to prevent "Alert Fatigue" (e.g., don't fire again for 30 minutes).
4.  **Alarm/Notification Methods:**
    *   **Email:** Select the Email option and enter the address for immediate notification.
    *   **Send to Forwarding Destinations:** Forward the alert via Syslog to a different target (e.g., Ticketing system).
    *   **Notify:** Generates a real-time notification/pop-up in the QRadar interface.
    *   **Add to Reference Set:** Automatically adds the malicious IP or Username to a list to be used by other rules for future detection.
    *   **Execute Custom Action:** Trigger a self-written script (Python/Bash) to perform automated containment (e.g., block IP).

---

### 📚 4. The Master Library of SOC Rules

#### **A. Common & Identity Rules**
*   **Failed Login Attempts:** Consecutive failed logins in security logs.
*   **Off-Hours Login:** Successful logins to critical systems outside of business hours.
*   **Account Management:** Trigger on **New User Created** or **Account Deleted**.

#### **B. Network & Perimeter (Firewall / IPS / IDS)**
*   **Illegal Port Scans:** Multiple prohibited port access attempts from one IP.
*   **Illegal Country Resources:** Traffic from unauthorized/unknown geographic locations.
*   **Permissive Policy Change:** Adding an "Any-Any-Allow" rule to a firewall.
*   **Harmful Downloads:** Malware signatures detected in transit by IPS.

#### **C. Web Application (WAF)**
*   **Injection Trials:** SQLi, XSS, or CSRF attempts detected in web parameters.
*   **Bot Traffic:** Automatic detection of high-volume automated traffic.

#### **D. Host Security (Windows & Linux)**
*   **Log Tampering:** Trigger if Windows Security or System logs are deleted (Event ID 1102).
*   **Privilege Escalation:** User added to `Domain Admins` or `Enterprise Admins`.
*   **Linux Root Access:** Direct login activity using the `root` account.
*   **Critical File Change:** Unauthorized changes to `/etc/passwd` or `/etc/shadow`.

#### **E. Infrastructure (VPN / VM / Vuln)**
*   **VPN Anomaly:** "Impossible Travel" (logins from two locations in a short time).
*   **Virtualization:** Deletion of a VM or high-access privilege changes on the hypervisor.
*   **Scan Failure:** Trigger if a scheduled vulnerability scan is blocked or fails.

---

### 🔔 5. Global Alarm Mechanisms

SIEMs use multiple channels to ensure the SOC reacts quickly:
1.  **Email/SMS:** Standard for high-priority or out-of-hours alerts.
2.  **Web-Based/Console:** Visual alerts appearing on the analyst's dashboard.
3.  **Mobile App:** Push notifications for analysts on the move.
4.  **Webhooks & API:** Integration with **Slack**, **Microsoft Teams**, or **SOAR** platforms.
5.  **Dashboard Notifications:** Real-time visual monitoring of alarm status.

---

### 🌳 6. Decision Tree (Triage Logic)

*   **Is it a single failed event?** -> Monitor (Low Priority).
*   **Is it an 'Allow' on a critical server?** -> **ACT IMMEDIATELY.**
*   **Is the source an authorized scanner?** -> Close as False Positive (Tune Rule).
*   **Is there a successful login after 100 failures?** -> **ACCOUNT COMPROMISE.**

---

### 📊 7. Impact Assessment

*   **Alert Fatigue:** Too many noise-filled rules cause analysts to miss real threats.
*   **Detection Gaps:** If a log source (like Linux) isn't included, the rules can't fire.
*   **Performance:** Complex rules with inefficient logic can crash SIEM performance.

---

### 🎯 8. MITRE ATT&CK Mapping
*   **T1078:** Valid Accounts (Identity rules).
*   **T1110:** Brute Force (Authentication rules).
*   **T1562:** Impair Defenses (Log Deletion rules).
*   **T1046:** Network Service Scanning (Firewall rules).

---

### 9. Interview Summary (TL;DR)
*   **Correlation Rule:** Logic that connects logs from multiple sources to find a pattern.
*   **AND vs OR:** AND (Strict - all must match); OR (Flexible - any can match).
*   **Response Limiter:** Critical for suppressing duplicate alerts during a single incident.
*   **QRadar Rule Responses:** Email, Forwarding, Notify, Reference Sets, and Custom Actions.
*   **Tuning:** The ongoing process of refining rules to reduce False Positives.
