

# 📘 SOC Notes: Wazuh Installation & Agent Deployment Playbook

### 🎯 Concept (TL;DR)
To monitor infrastructure, you first need a **Wazuh Server** (Manager + Filebeat + Indexer + Dashboard). Once the server is up, you deploy **Wazuh Agents** to endpoints (Windows/Linux). By default, agents collect standard OS logs, but as a SOC Analyst, you must manually configure them to ingest high-value logs like **Sysmon** (Windows) or **Nginx/Apache** (Linux).

---

## 🖥️ PART 1: Wazuh Server Installation
*There are two main ways to deploy the server. Use Method A for your Blue Team lab, and Method B for Enterprise production.*

### Method A: The "Quick Lab" Deployment (Recommended for Training)
The fastest way to get a single-node Wazuh instance running is via the automated bash script or OVA.

**Option 1: Automated Script (Run on a fresh Ubuntu/CentOS machine)**
1. Run the all-in-one script: 
   `curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`
2. Once complete, the terminal will output your Dashboard URL, Username (`admin`), and Password. Save these!

**Option 2: OVA Virtual Machine**
1. Download the Wazuh OVA from the official site.
2. Import it into VMware / VirtualBox.
3. Login via console (User: `wazuh-user` / Pass: `wazuh`).
4. Type `ip a` to find the IP address, then type that IP into your browser to access the Dashboard.

### Method B: Enterprise Package Installation (The Hard Way)
In production, you install components manually (Manager ➡️ Filebeat ➡️ Indexer ➡️ Dashboard) via `apt` or `yum`. 
*   **Crucial Enterprise Step:** Once installed, you must configure a **Master-Worker cluster** by editing `/var/ossec/etc/ossec.conf` on the master node and setting `<node_type>master</node_type>`, generating a 32-character cluster key, and applying that key to all worker nodes.

---

## 🪟 PART 2: Windows Agent & Sysmon Integration
*Wazuh requires the Manager IP to link the agent. Run these commands as Administrator.*

### 1. Install Windows Agent
1. Open **PowerShell as Administrator**.
2. Run the silent installer (Replace `10.0.0.2` with your Wazuh Server IP):
   ```powershell
   .\wazuh-agent-4.14.5-1.msi /q WAZUH_MANAGER="10.0.0.2"
   ```
3. Start the Wazuh service:
   ```powershell
   Start-Service wazuhsvc
   ```

### 2. Configure Sysmon Log Collection (High-Value Telemetry)
*By default, Wazuh does not read Sysmon logs. You must tell it to.*
1. Install Sysmon on the Windows machine (if not already installed).
2. Open the Agent GUI: `Start -> OSSEC -> Manage Agent -> Run as Administrator`.
3. Click **View -> View Config**.
4. Paste this block anywhere inside the `<ossec_config>` section:
   ```xml
   <localfile>    
     <location>Microsoft-Windows-Sysmon/Operational</location>    
     <log_format>eventchannel</log_format>
   </localfile>
   ```
5. Save the file and go to **Manage -> Restart** in the agent GUI.

### 3. Verify in Dashboard (Test the Rule)
1. On the Windows machine, open PowerShell and type: `svchost.exe` then `lsass.exe` (this looks like suspicious activity to Wazuh).
2. Go to your Wazuh Dashboard ➡️ Security Events.
3. Add Filter: `rule.groups` `is` `sysmon`. You should see the alerts!

---

## 🐧 PART 3: Linux Agent & Web Server (Nginx) Integration
*Run these commands as `root` or with `sudo`.*

### 1. Install Linux Agent (Debian/Ubuntu Example)
1. Add the Wazuh GPG Key and Repository:
   ```bash
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
   echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
   apt-get update
   ```
2. Install the agent and point it to your Manager IP:
   ```bash
   WAZUH_MANAGER="10.0.0.2" apt-get install wazuh-agent
   ```
3. Start and enable the service:
   ```bash
   systemctl daemon-reload && systemctl enable wazuh-agent && systemctl start wazuh-agent
   ```

### 2. Configure Nginx Log Collection
*Wazuh needs to know the exact file path of custom application logs.*
1. Open the configuration file: `nano /var/ossec/etc/ossec.conf`
2. Scroll to the bottom and add this block inside `<ossec_config>`:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/nginx/access.log</location>
   </localfile>
   ```
3. Save and restart the agent: `systemctl restart wazuh-agent`

### 3. Verify in Dashboard (Test the Rule)
1. On the Linux machine, simulate a web attack: 
   ```bash
   curl http://localhost/cmd.exe
   ```
2. Go to your Wazuh Dashboard ➡️ Security Events.
3. Add Filter: `rule.groups` `is` `web` (or `web filter`). You will see a "Web server 400 error code" or "SQLi/LFI" alert triggered.

---

### ⚠️ Blue Team Pro-Tips & Best Practices
*   **Disable Agent Updates:** After installing a Linux Agent, run `sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list`. **Why?** The Wazuh Manager version *must* be greater than or equal to the Agent version. If a cronjob auto-updates the Linux agent to v4.15 but your manager is still v4.14, the agent will break and stop communicating!
*   **The Golden Rule of Log Collection:** If an application writes logs to a text file (like Apache, Nginx, or an antivirus), you can collect it in Wazuh by adding a `<localfile>` block to `ossec.conf`. 
*   **Troubleshooting Agents:** If an agent shows as "Disconnected", check the agent log file locally on the endpoint: 
    *   Linux: `tail -f /var/ossec/logs/ossec.log` 
    *   Windows: `C:\Program Files (x86)\ossec-agent\ossec.log`
    *   *Look for errors like "Connection refused" (port 1514 blocked) or "Invalid agent key".*
