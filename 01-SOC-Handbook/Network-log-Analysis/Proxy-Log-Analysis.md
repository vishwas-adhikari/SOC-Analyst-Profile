
# 📘 SOC Analyst Handbook: Proxy Log Analysis

**Category:** Network Forensics / Web Security
**Severity:** Core Skill
**Skill Level:** Intermediate

---

### 1. The Concept

**The Analogy (ELI5)**
*   **Firewall:** The Bouncer. He checks your ID (IP Address) and decides if you can enter. He doesn't look in your bag.
*   **Proxy:** The Airport Security Scanner. You put your bag on the belt. The proxy opens your bag (Packet), looks at the book you are reading (URL), reads the pages (Content Inspection), and checks if the author is on a terrorist watch list (Category Filtering).

**The Technical Definition**
Proxy Log Analysis involves examining HTTP/HTTPS transactions between internal clients and the Internet. Unlike firewalls (which see IPs/Ports), Proxies see **URLs, User-Agents, and Categories**.
*   **Transparent Proxy:** The user doesn't know it's there. The destination sees the user's real IP.
*   **Anonymous Proxy:** The proxy hides the user's IP from the destination.

---

### 2. Log Anatomy (The Vocabulary)

Proxy logs are verbose. Vendors (Fortinet, BlueCoat, Zscaler, Forcepoint) use different names for the same things. Here is the translation table.

#### **📝 Common Proxy Log Fields**

| Field | Definition | Why it matters for SOC |
| :--- | :--- | :--- |
| **srcip / source** | Source IP | The internal device making the request. |
| **dstip / dest** | Destination IP | The server they are trying to reach. |
| **url / hostname** | Requested Domain | The exact website (e.g., `evil.com/payload.exe`). **Critical for C2 detection.** |
| **category / cat** | Web Category | The vendor's classification (e.g., `Gambling`, `Malware`, `Uncategorized`). |
| **action / act** | `Block`, `Pass`, `Allow` | Did the user get to the site? |
| **method / requestMethod** | `GET`, `POST`, `CONNECT` | `GET` = Download. `POST` = Upload (Exfiltration). `CONNECT` = HTTPS Tunnel. |
| **user_agent** | Browser Signature | Is it `Chrome`? Or is it `Python-urllib` (Script)? |
| **sentbyte / rcvdbyte** | Data Volume | High `sentbyte` = Data Theft. High `rcvdbyte` = Malware Download. |
| **status_code** | HTTP Code | `200` (OK), `403` (Blocked), `302` (Redirect). |
| **profile / user** | Identity | The Active Directory user associated with the traffic. |

---

### 3. Example Logs (The Evidence)

#### **Log A: The "Policy Block" (Fortinet Style)**
```text
date=2022-05-21 time=16:15:44 type="utm" subtype="webfilter" srcip=192.168.209.142 user="guest" dstip=54.20.21.189 hostname="android.prod.cloud.netflix.com" action="blocked" url="https://android.prod.cloud.netflix.com/" profile="Wifi-Guest" msg="URL was blocked because it is in the URL filter list"
```
*   **Analysis:**
    *   **Who:** Guest User (`192.168.209.142`).
    *   **What:** Netflix (`android.prod.cloud.netflix.com`).
    *   **Action:** `Blocked`.
    *   **Why:** The "Wifi-Guest" profile does not allow streaming sites to save bandwidth.
    *   **Verdict:** **Benign.** Policy violation, not a security threat.

#### **Log B: The "Suspicious Beacon" (Forcepoint Style)**
```text
Jun 17 10:47:00 10.10.18.11 CEF:0|Forcepoint|Security|act=blocked app=https dst=104.26.11.18 dhost=sentry-proxy.cargox.cc requestMethod=POST suser=Test_User cs1=Block_Risk_Category_Policy(Servers) cat=194
```
*   **Analysis:**
    *   **Who:** `Test_User` (Server IP `10.80.18.50`).
    *   **What:** `sentry-proxy.cargox.cc` (A proxy/tunneling site).
    *   **Method:** `POST` (Sending data *out*).
    *   **Category:** `194` (Extended Protection Suspicious Content).
    *   **Verdict:** **High Risk.** A server is trying to `POST` data to a "Suspicious" external proxy. This looks like malware trying to hide its C2 traffic.

---

### 4. Detection Tricks & Patterns

**1. The "Uncategorized" Trap**
*   **Pattern:** High volume of traffic to a domain categorized as `Uncategorized` or `Newly Registered Domain (NRD)`.
*   **Meaning:** Security vendors haven't scanned this site yet. 90% of Phishing/C2 domains fall into this category for the first 24 hours. **Treat "Uncategorized" as "Malicious" until proven otherwise.**

**2. The "CONNECT" Method (Tunneling)**
*   **Pattern:** `Method=CONNECT` + `Port=443` + `Duration=4 hours` + `Bytes=500MB`.
*   **Meaning:** Someone created an encrypted tunnel through your proxy. They might be running SSH or RDP over port 443 to bypass firewalls.

**3. User-Agent Anomalies**
*   **Pattern:** A request where the User-Agent is empty, or just `-`, or `curl/7.64`.
*   **Meaning:** Normal users use Browsers (Mozilla/Chrome). Scripts and Malware use command-line agents.

**4. DGA (Domain Generation Algorithm)**
*   **Pattern:** Requests to `xkqz-banking.com`, `ab12-update.net`.
*   **Meaning:** Malware generating random domains to find a Command Server.

---

### ⚠️ 5. Signal vs. Noise (Critical Thinking)

| Observation | ✅ Benign (False Positive) | ❌ Malicious (True Positive) |
| :--- | :--- | :--- |
| **Blocked "Malware"** | Advertising networks (Ads often get flagged as malicious). | Request to a known C2 IP or "Raw IP" access (no domain). |
| **High Upload (POST)** | User uploading a large PDF to SharePoint/Google Drive. | User uploading `password.zip` to `anonfiles.com` or `pastebin`. |
| **Category: Hacking** | IT Admin visiting GitHub or StackOverflow security threads. | HR Employee visiting "Kali Linux Tools" or "ExploitDB". |
| **Multiple Blocks** | A webpage with 50 broken ad trackers loading in the background. | A single host trying to connect to 50 *different* malware domains in 1 minute (Worm behavior). |

---

### 6. Investigation Steps (The Playbook)

**Step 1: Verify the Category Code**
*   Vendors use numbers (e.g., Forcepoint `194`). Always lookup the vendor documentation.
*   *Action:* Is it "Spam" (Low risk) or "Botnet" (Critical)?

**Step 2: Check the "Referer" Header**
*   **Scenario:** A user visited a malicious site.
*   **Check:** Look at the `Referer` field.
    *   If Referer is `google.com` -> They clicked a search result.
    *   If Referer is `mail.google.com` -> They clicked a **Phishing Link**.
    *   If Referer is Empty -> It was likely an automated script/malware.

**Step 3: Analyze the Payload (Bytes)**
*   **Blocked:** Check if they tried again. Did they succeed 5 minutes later?
*   **Allowed:** Check `sentbyte`. Did data leave the building?

**Step 4: Pivot to Endpoint**
*   If you see a `POST` to a suspicious Proxy/Tunnel site (like the Forcepoint example), check the **Process List** on that server. What process initiated that connection?

---

### 🌳 7. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Policy)**
    *   `Action: Blocked` + `Cat: Streaming/Gambling`
    *   *Action:* User wasting time. Ignore.

*   **🟡 Medium Priority (Adware)**
    *   `Action: Blocked` + `Cat: Advertising/Spyware` + `Frequency: High`
    *   *Action:* User likely has a browser toolbar/extension installed. Schedule a cleanup.

*   **🔴 High Priority (C2 Beacon)**
    *   `Action: Allowed` + `Cat: Uncategorized` + `Method: POST` + `Frequency: Regular Interval`
    *   *Action:* **Isolate Host.** Active malware infection.

*   **🟣 Critical Priority (Exfiltration)**
    *   `Action: Allowed` + `Bytes Sent: >50MB` + `Site: Personal Cloud (Dropbox/Mega)`
    *   *Action:* **Data Breach.** Stop the session. Interview user.

---

### 📊 8. Impact Assessment

**1. Data at Risk**
*   Proxy logs are the best source for quantifying data loss.
*   *Formula:* `Sum(sentbyte)` to the malicious domain = Total Data Stolen.

**2. Blast Radius**
*   Are multiple users connecting to this domain? (Phishing Campaign).
*   Is it just one machine? (Targeted Malware).

---

### 🎯 9. MITRE ATT&CK Mapping

*   **T1071.001:** Web Protocols (C2 over HTTP/S).
*   **T1567:** Exfiltration Over Web Service.
*   **T1090:** Proxy (Using external proxies to hide).

---

### 10. Interview Summary (TL;DR)
*   **Difference from Firewall:** Proxies see **URLs** and **Content**, Firewalls see IPs/Ports.
*   **Key Fields:** `Method` (GET/POST/CONNECT), `Category` (The reputation), `User-Agent`.
*   **Top Detection:** Looking for **"Uncategorized"** domains and **POST** requests to unknown sites.
*   **The "CONNECT" Trick:** Attackers use `CONNECT` to tunnel non-web traffic (like SSH) through a web proxy.
*   **Response:** If you see a successful connection to a "Malware" category -> **Isolate the host.** The download already happened.