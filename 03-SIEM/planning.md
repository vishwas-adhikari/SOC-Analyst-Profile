
# 📔 Module 4: The SIEM Engineering & Planning Phase

## 1. The Engineer's "Discovery" Questions
When you sit down with the IT Director or the Network Team, you need to ask "Hard" questions. These will determine if your SIEM succeeds or crashes.

### A. Data Volume & Velocity
*   **Question:** *"What is our peak EPS (Events Per Second) and average daily ingestion (GB/day)?"*
*   **Why?** Licensing. If you buy a 100GB/day license but your firewalls generate 150GB, you will lose data or your SIEM will stop searching.
*   **Pro-Tip:** Ask for the **"Peak"** during a crisis. Logs spike during a DDOS attack or a malware outbreak—that's when you need the SIEM most!

### B. Network Topology & Bandwidth
*   **Question:** *"Do we have remote sites? How is the bandwidth between the Branch Office and the Data Center?"*
*   **Why?** If you send 50Mbps of logs over a 100Mbps VPN, you will crash the branch office's internet.
*   **Solution:** You might need **"Heavy Forwarders"** or **"Collectors"** at each site to compress the data before sending it.

### C. Data Sovereignty & Compliance
*   **Question:** *"Are there laws (like GDPR) that prevent us from storing German logs in a US-based Cloud SIEM?"*
*   **Why?** This determines if you can use **Cloud (Sentinel/Splunk Cloud)** or if you MUST use **On-Prem (QRadar/ArcSight)**.

---

## 2. Scenario Analysis: Which Architecture is Best?

As an engineer, you must recommend the right "Build." Here is the decision matrix:

| Situation | Best Architecture | Why? |
| :--- | :--- | :--- |
| **Small Startup** (All Cloud, no IT staff) | **Cloud-Native** (Sentinel) | Zero hardware to manage. Scalable. Pay only for what you use. |
| **Global Bank** (Air-gapped, high security) | **On-Premise** (QRadar / ArcSight) | Total control over data. No data leaves the physical building. |
| **Large Enterprise** (Mixing old and new) | **Hybrid** (Splunk + Heavy Forwarders) | Keep heavy logs local; send "Security Essentials" to the cloud. |
| **MSSP** (Managing 10 different companies) | **Multi-Tenant** (LogRhythm / Splunk) | Need to keep Company A's logs strictly separated from Company B's. |

---

## 3. The "Blind Spot" Analysis
Before installing, you must identify what you are **missing**. I call this the "Visibility Gap."

**Scenario:** The company has 1,000 Windows Laptops.
*   **Engineer Question:** *"Are these laptops always on the VPN?"*
*   **The Risk:** If they aren't on the VPN, the logs won't reach the SIEM.
*   **The Solution:** You need a **Cloud Ingestor** or an agent that can send logs over HTTPS directly to the SIEM.

---

## 4. Resource & Math (The "Sizing" Example)
A major part of planning is **Sizing**. You will be asked: *"How much disk space do we need?"*

**The Senior Math Formula:**
> **Daily Ingestion (GB)**  ×  **Retention Days**  ×  **Compression Factor (0.5)**  =  **Total Storage Required**

*   *Example:*
    *   100 GB/day ingestion.
    *   Needs to be searchable for 90 days.
    *   Splunk/QRadar usually compresses data by ~50%.
    *   **Math:** `100 * 90 * 0.5 = 4,500 GB (4.5 TB)` of High-Speed SSD storage needed.

---

## 5. Integration Checklist (The "Log Source" Plan)
Don't just say "Logs." Categorize them by **Priority**:

1.  **Priority 1 (Identity):** Active Directory, Azure AD, Okta. (If the identity is compromised, the whole network is gone).
2.  **Priority 2 (Network):** Firewall (Traffic/VPN), DNS, Proxy. (Shows where the attacker went).
3.  **Priority 3 (Endpoint):** EDR (Crowdstrike/SentinelOne), Antivirus. (Shows what the attacker did on the machine).
4.  **Priority 4 (Applications):** Database logs, Web Server logs (IIS/Apache).


## 1. The Engineer's "Discovery" Questions
When you sit down with the IT Director or the Network Team, you need to ask "Hard" questions. These will determine if your SIEM succeeds or crashes.

### A. Data Volume & Velocity
*   **Question:** *"What is our peak EPS (Events Per Second) and average daily ingestion (GB/day)?"*
*   **Why?** Licensing. If you buy a 100GB/day license but your firewalls generate 150GB, you will lose data or your SIEM will stop searching.
*   **Pro-Tip:** Ask for the **"Peak"** during a crisis. Logs spike during a DDOS attack or a malware outbreak—that's when you need the SIEM most!

### B. Network Topology & Bandwidth
*   **Question:** *"Do we have remote sites? How is the bandwidth between the Branch Office and the Data Center?"*
*   **Why?** If you send 50Mbps of logs over a 100Mbps VPN, you will crash the branch office's internet.
*   **Solution:** You might need **"Heavy Forwarders"** or **"Collectors"** at each site to compress the data before sending it.

### C. Data Sovereignty & Compliance
*   **Question:** *"Are there laws (like GDPR) that prevent us from storing German logs in a US-based Cloud SIEM?"*
*   **Why?** This determines if you can use **Cloud (Sentinel/Splunk Cloud)** or if you MUST use **On-Prem (QRadar/ArcSight)**.

---

## 2. Scenario Analysis: Which Architecture is Best?

As an engineer, you must recommend the right "Build." Here is the decision matrix:

| Situation | Best Architecture | Why? |
| :--- | :--- | :--- |
| **Small Startup** (All Cloud, no IT staff) | **Cloud-Native** (Sentinel) | Zero hardware to manage. Scalable. Pay only for what you use. |
| **Global Bank** (Air-gapped, high security) | **On-Premise** (QRadar / ArcSight) | Total control over data. No data leaves the physical building. |
| **Large Enterprise** (Mixing old and new) | **Hybrid** (Splunk + Heavy Forwarders) | Keep heavy logs local; send "Security Essentials" to the cloud. |
| **MSSP** (Managing 10 different companies) | **Multi-Tenant** (LogRhythm / Splunk) | Need to keep Company A's logs strictly separated from Company B's. |

---

## 3. The "Blind Spot" Analysis
Before installing, you must identify what you are **missing**. I call this the "Visibility Gap."

**Scenario:** The company has 1,000 Windows Laptops.
*   **Engineer Question:** *"Are these laptops always on the VPN?"*
*   **The Risk:** If they aren't on the VPN, the logs won't reach the SIEM.
*   **The Solution:** You need a **Cloud Ingestor** or an agent that can send logs over HTTPS directly to the SIEM.

---

## 4. Resource & Math (The "Sizing" Example)
A major part of planning is **Sizing**. You will be asked: *"How much disk space do we need?"*

**The Senior Math Formula:**
> **Daily Ingestion (GB)**  ×  **Retention Days**  ×  **Compression Factor (0.5)**  =  **Total Storage Required**

*   *Example:*
    *   100 GB/day ingestion.
    *   Needs to be searchable for 90 days.
    *   Splunk/QRadar usually compresses data by ~50%.
    *   **Math:** `100 * 90 * 0.5 = 4,500 GB (4.5 TB)` of High-Speed SSD storage needed.

---

## 5. Integration Checklist (The "Log Source" Plan)
Don't just say "Logs." Categorize them by **Priority**:

1.  **Priority 1 (Identity):** Active Directory, Azure AD, Okta. (If the identity is compromised, the whole network is gone).
2.  **Priority 2 (Network):** Firewall (Traffic/VPN), DNS, Proxy. (Shows where the attacker went).
3.  **Priority 3 (Endpoint):** EDR (Crowdstrike/SentinelOne), Antivirus. (Shows what the attacker did on the machine).
4.  **Priority 4 (Applications):** Database logs, Web Server logs (IIS/Apache).

---

## 🛠 Senior SIEM Engineer "Pro-Tips" :

1.  **The "Proof of Concept" (POC):** Never install the whole thing at once. Plan a POC with 2 Domain Controllers and 1 Firewall. Prove it works, then scale.
2.  **EPS vs. GB:** Some vendors charge by **EPS** (Volume of events), some charge by **GB** (Size of data).
    *   *Note:* If your logs are very "fat" (lots of text in one log), **EPS licensing** is cheaper.
    *   *Note:* If your logs are "thin" (small syslog entries), **GB licensing** might be cheaper.
3.  **NTP (Network Time Protocol):** This is the **most common failure** in SIEM planning. If your servers have the wrong time, your SIEM correlation will fail. **Ensure all log sources use the exact same NTP server.**

---

### 🎓 Interview Question Preparation:
*   **Interviewer:** *"How would you plan a SIEM installation for a company with 5 worldwide branches?"*
*   **Your Answer:** *"I would first perform a **Needs Analysis** to determine the total **EPS**. Then, I would evaluate the **bandwidth** at each branch. I'd likely place **Collectors/Forwarders** at each branch to compress data and handle network outages before sending the logs to the central **Indexer**."* (This answer proves you are an Engineer, not just a user).

