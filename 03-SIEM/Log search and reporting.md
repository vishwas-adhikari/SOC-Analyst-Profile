
# 📘 SOC Analyst Handbook: Log Search, Analysis & Reporting

**Category:** SIEM Operations / Data Analytics
**Severity:** N/A (Core Analytical Skill)
**Skill Level:** Intermediate

---

### 1. Concept (What & Why)
**Log Search** is the process of querying and analyzing security events from disparate sources (servers, network devices, apps). It transforms raw logs into meaningful information.
**Log Analysis** extracts value from that data to:
1.  **Identify Abnormal Activity:** Establish a "normal" baseline to spot outliers.
2.  **Threat Detection:** Identify malware, unauthorized access, and vulnerabilities.
3.  **Compliance Monitoring:** Prepare for audits (PCI DSS, GDPR, HIPAA).

**Reporting** summarizes these activities into documents that monitor security status, track threat trends, and prove compliance to management.

---

### 2. Log Search with SIEM: Purposes & Steps

#### **Purposes of Log Search**
*   **Monitoring Events:** Tracking daily activity to identify threats early.
*   **Reviewing Events:** Specific analysis of event types within set timeframes.
*   **Answering Questions:** Investigating specific activity (e.g., "Show all logins from IP X").
*   **Specifying Time Frames:** Determining the exact start and end of a breach.
*   **Data Filtering:** Eliminating noise using Source/Dest IP, Event Type, or Time.

#### **The 5 Steps of a Log Search**
1.  **Identify Goals:** Clarify what you want to track (e.g., "Detect SQLi attempts").
2.  **Create Queries:** Build specific queries (Time + Source + Target + Event Type).
3.  **Examine Data:** Review results to identify anomalies.
4.  **Analysis & Alerts:** Create automatic alerts for discovered threats.
5.  **Reporting:** Present findings to senior admin or auditors.

---

### 3. IBM QRadar: Log Activity Interface

In QRadar, the **Log Activity** tab is the primary workspace.

#### **📝 QRadar Search Methods Table**

| Method | Functionality |
| :--- | :--- |
| **Search** | Options for "New Search" or "Edit Search" to refine criteria. |
| **Quick Search** | Ready-made filters (Firewall Deny/Permit, Offenses, Top Log Sources). |
| **Add Filter** | Search by Parameter, Operator (Equals/Not Equals), and Value. |
| **Quick Filter** | Direct typing of plain text or custom phrases to search raw logs. |
| **Advanced Search** | Uses **Ariel Query Language (AQL)** for complex forensics. |
| **Right-Click Tip** | Right-click any result to "Filter In" or "Filter Out" values instantly. |

---

### 💻 4. Deep Dive: Ariel Query Language (AQL)

AQL is the most powerful way to search in QRadar. It allows you to:
*   Build complex **WHERE** clauses with nested **AND/OR** logic.
*   Lookup and include data from **Reference Sets**, tables, and maps.
*   Pull info from the **Asset Database** (User, Property, Location).
*   Produce **customized column headings** and **concatenate** fields.
*   Use **string expressions** and calculate **mathematical expressions**.
*   Complete custom **time and date formatting**.

#### **AQL Examples**
*   **Filter by IP:** `SELECT * FROM events WHERE source_IP='192.168.1.10'`
*   **Date Range + Source:** `SELECT * FROM events WHERE startswith(logsourceid, 'Linux') AND starttime >= 'Start_Date' AND endtime <= 'End_Date'`
*   **Specific Attack Type:** `SELECT * FROM events WHERE QIDNAME='Potential SQL Injection'`
*   **Specific User Login:** `SELECT * FROM events WHERE username='Admin' AND eventname='Successful Logon'`

---

### 🕵️ 5. The SIEM Log Analysis Lifecycle (6 Steps)
1.  **Data Collection:** Gathering logs from security devices, servers, and apps.
2.  **Data Normalization:** Converting diverse logs into a standardized, comparable format.
3.  **Automatic Analysis:** SIEM engines scan for conditions to trigger alerts/offenses.
4.  **Manual Analysis:** Analysts perform deep-dives to verify automated alerts.
5.  **Incident Response:** Isolating incidents, identifying origins, and blocking attacks.
6.  **Documentation:** Generating reports on threats and the response taken.

---

### 📊 6. SIEM Reporting & QRadar Workflow

#### **Types of SIEM Reports**
*   **Security Incident:** Summarizes attacks (failed logins, malware detections).
*   **Compliance:** Evaluates compliance with regulations (PCI DSS, GDPR).
*   **Performance:** SIEM health (Network traffic, resource usage, EPS rates).
*   **User Activity:** Tracks logins, file access, and unauthorized attempts.

#### **Steps to Create a Report in QRadar**
1.  **Selection:** Choose `Reports -> Action -> Create Report`.
2.  **Scheduling:** Determine if it is **Manual** or **Scheduled** (e.g., daily/weekly).
3.  **Layout:** Define the visual structure and sections.
4.  **Content Detail:** Select specific data (e.g., "Offense Details") for each section.
5.  **Format:** Choose output format (PDF, XML, CSV, etc.).
6.  **Distribution:** Select "Download from Console" or "Send via E-mail."
7.  **Finalize:** Name the report, assign to a group, and click **Finish**.

---

### 🌳 7. Mini Decision Tree (Analysis Triage)

*   **Is it a known signature match?** → Check if host is vulnerable (Manual Analysis).
*   **Is it a high volume of 404s/Denies?** → Likely automated scanning (Monitor).
*   **Is it a Successful Login (200/Success) at 3 AM?** → **INVESTIGATE IMMEDIATELY.**
*   **Is the report for an auditor?** → Run a **Compliance Report** with "User Activity."

---

### 📊 8. Impact Assessment
*   **Threat Visibility:** Effective search reduces the "dwell time" of an attacker.
*   **Compliance Risk:** Poor reporting leads to audit failures and legal penalties.
*   **Operational Efficiency:** Automation (Normalized logs + Scheduled reports) allows humans to focus on complex threats.

---

### 🎯 9. MITRE ATT&CK Mapping
*   **T1070:** Indicator Removal on Host (Detected by identifying gaps during search).
*   **T1530:** Data from Cloud Storage (Detected via User Activity Reporting).
*   **T1078:** Valid Accounts (Detected via Logon Activity Analysis).

---

### 10. Interview Summary (TL;DR)
*   **Log Search vs Analysis:** Search is "finding the data"; Analysis is "understanding the threat."
*   **Normalization:** Crucial for comparing logs from different vendors (e.g., Cisco and Fortinet).
*   **AQL:** The SQL-like language for QRadar; used for complex, high-speed queries.
*   **Reporting Steps:** Collection -> Normalization -> Analysis -> Generation -> Distribution.
*   **QRadar Quick Filters:** Use these for fast, plain-text searches across the raw payload.
