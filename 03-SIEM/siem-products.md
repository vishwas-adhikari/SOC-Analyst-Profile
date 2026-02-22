

# 📔 Module 3 (Expanded): The SIEM Engineer's Deep Dive

## 1. Splunk: The "Formula 1" of SIEM
Splunk is often called a "data engine" first and a SIEM second. 

*   **Architecture (The Engineer's View):**
    *   **Universal Forwarder (UF):** Lightweight agent. Only collects and sends data. No parsing happens here.
    *   **Indexer (IX):** The "Muscle." It compresses data and writes it to disk. 
    *   **Search Head (SH):** The "Brain." This is where you write your **SPL** (Search Processing Language).
*   **The "Schema-on-Read" Advantage:** 
    *   Unlike other SIEMs, Splunk stores data as raw text. You define what an "IP Address" or "User" is *at the moment you search*. 
    *   *Why this matters:* If a log format changes next month, you don't have to re-ingest the data. You just update your regex.
*   **Unique Feature: Risk-Based Alerting (RBA):** 
    *   Instead of alerting on a single event, Splunk assigns "Risk Scores" to users. 
    *   *Example:* If a user downloads 1GB from Dropbox (+10 points) and then clears their browser history (+20 points), no alert fires. But if they then log in from an unusual IP (+50 points), their score hits 80, and the SIEM fires a **"High Risk User"** alert.
*   **Troubleshooting Tip:** If searches are slow, check the **"Skip Ratio."** This means the Search Head is overwhelmed and skipping scheduled security rules. You may need more Indexers.

---

## 2. IBM QRadar: The "Context" Machine
QRadar is built for stability and reducing noise. It doesn't want you to look at logs; it wants you to look at **Offenses**.

*   **Key Logic: The "Offense" Model:** 
    *   QRadar uses the **Magistrate** component to "chain" events. 
    *   *Example:* 100 failed logins + 1 successful login from the same IP = **1 Offense**. In Splunk, this might look like 101 separate events you have to dig through.
*   **Unique Component: Network Flows (QFlow):**
    *   QRadar doesn't just look at *what* the log says; it looks at the *actual packet headers* (Layer 4). It can see if a server is talking to a malicious IP even if the server logs were deleted.
*   **Data Enrichment: Reference Sets:**
    *   Think of these as "live memory" lists.
    *   *Example:* You create a Reference Set called `Executive_Users`. You then write a rule: `If (Logon) AND (User is NOT in Executive_Users) AND (Destination is CEO_Laptop) -> ALERT.`
*   **Troubleshooting Tip:** Watch for **"Dropped Events."** QRadar has a hard limit on EPS (Events Per Second) based on your license. If you hit that limit, the system literally throws logs away to save itself.

---

## 3. Microsoft Sentinel: The "AI-Native" SIEM
Sentinel is the fastest-growing SIEM because it removes the "Infrastructure Headache."

*   **Architecture:** Zero hardware. It lives in a **Log Analytics Workspace (LAW)**. You pay for what you ingest (Pay-As-You-Go).
*   **The "Copilot" Factor:** 
    *   Sentinel uses **Generative AI** to summarize incidents. Instead of an analyst looking at raw hex code, Sentinel says: *"This incident involves User 'Bob' being phished by an IP in Russia; it used PowerShell to steal tokens."*
*   **Advanced Logic: KQL (Kusto Query Language):**
    *   KQL is extremely readable. It’s designed like a set of stairs.
    *   **KQL Example:**
      ```kql
      SecurityEvent
      | where EventID == 4624
      | summarize count() by Account, IpAddress
      | where count_ > 50
      ```
*   **Why use it?** If you are a "Microsoft Shop" (Office 365, Azure, Defender), you get a massive discount and out-of-the-box integration.
*   **Troubleshooting Tip:** Check for **"Ingestion Latency."** Because it's cloud-based, logs can sometimes take 5-10 minutes to travel from your server to the Azure cloud. This creates a "blind spot" in real-time.

---

## 4. ArcSight: The "Legacy King"
ArcSight is built for the world's largest, most complex networks (Banks, Governments).

*   **Unique Feature: SmartConnectors:**
    *   These are the most powerful log collectors in the world. They don't just send logs; they **categorize** them before they leave the source.
    *   *Example:* A SmartConnector sees a Windows Logon and a Linux SSH Login. It sends both to the SIEM as the exact same category: `/Authentication/Logon/Failure`.
*   **The CEF Standard:** 
    *   ArcSight invented **CEF (Common Event Format)**. Almost every security vendor in the world (Cisco, Palo Alto, etc.) now supports CEF because of ArcSight.
*   **Example Raw Log (CEF):**
    `CEF:0|Vendor|Product|Version|ID|Name|Severity|[Extension Pairs]`

---

## 🛡️ Senior Analyst Engineering Table: Comparison of Logic

| Concept | Splunk (Data Centric) | QRadar (Security Centric) | Sentinel (Cloud Centric) |
| :--- | :--- | :--- | :--- |
| **Parsing** | **Late Binding** (On-Search) | **Early Binding** (On-Ingest) | **Hybrid** |
| **Logic Unit** | Correlation Search | Offense / Magistrate | Analytics Rule |
| **Enrichment** | Lookup Tables (.csv) | Reference Sets (In-Memory) | Watchlists |
| **Automation** | Splunk SOAR (Phantom) | Resilient | Logic Apps (Playbooks) |

---

### 🎓 Pro-Level Note: "The SIEM Engineer's Daily Check"
In your internship, if you want to look like a senior, do these three things every morning:
1.  **Check Ingestion Health:** Are any log sources flat-lining (0 logs in 1 hour)?
2.  **Monitor Search Concurrency:** Are too many people running heavy searches at once? (Slows down the alerts).
3.  **Review False Positives:** Pick the most frequent alert. Can we "tune" it by adding a "Whitelisted IP" or a "Service Account" to an enrichment list?

