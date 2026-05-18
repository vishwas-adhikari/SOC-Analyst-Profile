

# 📘 SOC Notes: Wazuh Platform Overview & Architecture Deep Dive

## PART 1: Introduction & Capabilities

### 🎯 Concept (TL;DR)
**Wazuh** is an open-source, full-stack cybersecurity platform combining **SIEM** (Security Information and Event Management) and **XDR** (eXtended Detection and Response) capabilities. Originally a fork of OSSEC-HIDS (2015), it monitors endpoints, cloud environments, and containers in real-time to collect logs, detect anomalies, alert the SOC, and automatically respond to threats.

---

### 🛡️ Core Capabilities (What Blue Teamers use it for)
Wazuh isn't just for reading logs; it actively assesses the endpoint and infrastructure. 

*   **Security Analytics & Log Data Analysis:** Ingests standard logs (Windows Event Logs, Syslog, Firewalls), parses them, and correlates them against rule sets in real-time to detect attacks (e.g., detecting port scans from firewall logs).
*   **Intrusion Detection (HIDS):** Monitors for hidden processes, rootkits, malicious files, and unexpected listening ports using signatures, regex, and Indicators of Compromise (IoCs).
*   **File Integrity Monitoring (FIM):** Tracks changes, deletions, and permission modifications to critical files and directories (mandatory for PCI-DSS).
*   **Vulnerability Detection:** Scans the endpoint's installed application inventory and cross-references it with the periodically updated global CVE database.
*   **Configuration Assessment (SCA):** Audits endpoints to see if they pass or fail standard security configurations (e.g., CIS benchmarks).
*   **Incident Response (Active Response):** Automatically executes customized scripts (Bash, PowerShell, Python) on endpoints to stop attacks in progress.
*   **Regulatory Compliance:** Automatically maps alerts to compliance frameworks like MITRE ATT&CK, PCI-DSS, GDPR, NIST, and HIPAA.
*   **Cloud & Container Security:** Native modules to pull logs from AWS (e.g., S3 bucket changes), Azure, GCP, Office365, as well as monitoring Docker images, volumes, and running containers.

### 💡 Practical Examples (What it looks like in action)
*   **FIM Alert:** Wazuh detects and alerts that the `/etc/hosts` file on a Linux web server was modified by the root user.
*   **Intrusion Detection Alert:** Wazuh detects a newly opened listening port (e.g., port 4444) indicative of an attacker setting up a bind-shell.
*   **Active Response Event:** After detecting repeated failed login attempts (Brute Force) via Active Directory, Wazuh executes a script to temporarily disable the targeted user account.
*   **SCA / Vulnerability Alert:** Wazuh flags a Windows endpoint because it has an outdated instance of MSSQL 2014 vulnerable to CVE-2017-8516.


***


## PART 2: Distributed Architecture (Enterprise Deployment)


<img width="900" height="600" alt="image" src="https://github.com/user-attachments/assets/8c4b3940-67b2-4264-8bb0-fa6eac350d8b" />


### 🧩 Wazuh Mechanics: Breaking Down the Components
For enterprise environments (typically >100 endpoints), Wazuh is split into a **Distributed Architecture** cluster. This ensures high availability, prevents log dropping during massive attacks, and allows the SOC to scale up. 

Here is how the architecture functions from Endpoints to the SOC Analyst:

#### 1. Endpoints (The Data Sources)
*   **Assets:** Servers, Desktops, Laptops, Cloud Instances, and Virtual Machines. 
*   **Function:** Each device runs a **Wazuh Agent**. The agent reads local logs, monitors file integrity, detects malware, and securely ships this data out. 

#### 2. Network Load Balancer (The Traffic Cop)
*   **Function:** Sits between the Endpoints and the Wazuh Central Components. If you have 5,000 agents sending logs at once, one server would crash. The load balancer evenly distributes incoming agent traffic across multiple Worker Nodes.

#### 3. Wazuh Server Cluster (The Analysis Brain)
*This is where the SIEM/HIDS analysis happens. It uses a Master-Worker architecture:*
*   **Worker Nodes (1...n):** They do the heavy lifting. They receive logs from the load balancer, pass them through the **Analysis Engine** (applying decoders to parse data, and rules to spot threats). If a log matches a rule, they use **Filebeat** to securely forward that alert to the Indexer.
*   **Master Node:** It has the same Analysis/Filebeat capabilities as a worker, but handles two critical administrative tasks:
    1.  **Nodes Communication:** Synchronizes rules, decoders, and configurations across all worker nodes so they all look for the same threats.
    2.  **API Server:** Hosts the Wazuh API, allowing the Dashboard to talk to the server cluster.

#### 4. Wazuh Indexer (The Storage Vault)
*   **Function:** A highly scalable full-text search engine (similar to Elasticsearch) consisting of one or more **Indexer Nodes**. It receives structured alerts from the servers and stores them. When you search for an IP address or Event ID, the Indexer is the database processing that search.

#### 5. Wazuh Dashboard (The SOC Interface)
*   **Function:** The web UI used by the Blue Team. 
    *   It connects **down to the W. Indexer** to query and visualize logs (Dashboards, Threat Hunting).
    *   It connects **across to the Master Node API** to allow analysts to manage agent settings or edit rules directly from the web interface.

---

### 🛠️ The Data Flow Playbook (Life of a Log)
As an analyst, you must memorize this flow to troubleshoot missing alerts:
1.  Attacker fails a login on a **Cloud Instance**.
2.  The **Wazuh Agent** grabs the OS log and sends it to the **Load Balancer**.
3.  The Load balancer forwards the raw log to an available **Worker Node**.
4.  The Worker's **Analysis Engine** parses the log, matches it to a "Brute Force" rule, and creates an alert.
5.  The Worker's **Filebeat** service ships the structured alert to the **Wazuh Indexer**.
6.  The **Indexer** stores it.
7.  A **Wazuh User** refreshes the **Wazuh Dashboard** and sees the alert on their screen.

---

### ⚠️ Blue Team Pro-Tips & Troubleshooting
*   **Agent Disconnections:** If *all* agents go offline simultaneously but the dashboard is up, your **Network Load Balancer** might be down or a firewall is blocking port `1514` (Agent-to-Server log forwarding port).
*   **Missing Logs but Agents are "Active":** Check the connection between the **Worker Nodes (Filebeat)** and the **Indexer**. The server might be analyzing logs properly, but failing to send them to storage.
*   **Dashboard API Errors:** If you can see logs but get an "API Error" when trying to edit a rule or restart an agent, the connection between the **Dashboard** and the **Master Node API** is broken (usually port `55000`).
*   **Architecture Best Practice:** In massive enterprise environments, the Master node should *only* handle API requests and worker syncing. Configure the Load Balancer to only send endpoint logs to the Worker Nodes to keep the Master from becoming a bottleneck.
