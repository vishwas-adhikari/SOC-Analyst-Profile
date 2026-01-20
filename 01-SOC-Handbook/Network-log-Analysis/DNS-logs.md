
# 📘 SOC Analyst Handbook: DNS Log Analysis

**Category:** Network Forensics / Threat Hunting
**Severity:** Critical (Early Warning System)
**Skill Level:** Advanced

---

### 1. The Concept

**The Analogy (ELI5)**
*   **The Address Book:** You want to visit "Evil-Hacker-Base," but the internet only understands coordinates (IP Addresses).
*   **The DNS Server:** You ask, "Where is Evil-Hacker-Base?" The DNS server replies, "192.168.1.66."
*   **The SOC Value:** Even if the firewall blocks the connection to the base, the **DNS Log** proves the user *tried* to go there. It is the "Intent" log.

**The Technical Definition**
DNS (Domain Name System) resolves hostnames (`google.com`) to IP addresses (`8.8.8.8`). For a SOC, analyzing **DNS Queries** allows us to detect malware "phoning home" (C2), data exfiltration via tunneling, and Domain Generation Algorithms (DGA) before the payload even executes.

---

### 2. Log Anatomy (The Vocabulary)

You will likely see logs from **Zeek (Bro)**, **Bind**, or **Windows DNS (Debug)**.

#### **📝 Common DNS Log Fields**

| Field | Definition | SOC Interpretation |
| :--- | :--- | :--- |
| **query** | The Domain Requested | The target (`malware.com`). Look for entropy (randomness). |
| **qtype** | Record Type | `A` (IPv4), `AAAA` (IPv6), `TXT` (Text), `MX` (Mail), `PTR` (Reverse). |
| **rcode** | Response Code | `NOERROR` (Found it), `NXDOMAIN` (Domain doesn't exist - Suspicious if high volume). |
| **client_ip** | Source IP | The infected machine asking the question. |
| **answers** | The Result | The IP returned. If it's a known "Sinkhole" IP, the threat is contained. |
| **proto** | Protocol | Usually `UDP/53`. If `TCP/53`, check connection duration (Zone Transfer or Tunneling). |

---

### 3. Example Logs (The Evidence)

#### **Log A: The "DGA" Beacon (Zeek Style)**
```json
{
  "ts": 1591367999.306,
  "id.orig_h": "192.168.10.12",
  "query": "xkqz-84ba-19ca.bad-domain.ru",
  "qtype_name": "A",
  "rcode_name": "NXDOMAIN"
}
```
*   **Analysis:**
    *   **Query:** Random characters (`xkqz...`). This is **DGA** (Domain Generation Algorithm).
    *   **Response:** `NXDOMAIN`. The domain doesn't exist *yet*. Malware generates 1,000 domains daily; the attacker registers only one. The malware is hunting for its master.

#### **Log B: Contextual Suspicion (The "Oracle" Scenario)**
```text
Feb 5 09:12:11 ns1 named[80090]: client 192.168.10.3#3261: query: login.microsoftonline.com IN A
Feb 5 09:13:11 ns1 named[80090]: client 192.168.10.3#4536: query: onedrive.live.com IN A
```
*   **Analysis:**
    *   **Source:** `192.168.10.3` (Identified as **Oracle Database Server**).
    *   **Query:** `onedrive.live.com` (Personal Cloud Storage).
    *   **Verdict:** **High Risk.** Why is a backend Database Server accessing Personal Cloud Storage? This indicates **Data Exfiltration** or a compromised admin. Servers should not browse the web.

#### **Log C: DNS Tunneling (Data Theft)**
```text
Query: user=admin.pass=123.confidential-data.attacker.com | Type: TXT
```
*   **Analysis:** The attacker isn't looking for an IP. They are encoding stolen data (`user=admin...`) into the *subdomain* itself. The attacker's DNS server logs the query, effectively receiving the stolen data.

---

### 4. Detection Patterns & Tricks

**1. High Entropy Domains (DGA)**
*   **Pattern:** `aj7s8d7f6s.com`, `98734kjh.net`.
*   **Technique:** Use "Shannon Entropy" scripts. If a domain looks like a cat walked on the keyboard, it's malware.

**2. The "NXDOMAIN" Spike**
*   **Pattern:** A single host generates 500 `NXDOMAIN` responses in 1 minute.
*   **Meaning:** The host is infected with malware using DGA. It's trying to find a C2 server that is currently offline or blocked.

**3. DNS Tunneling (Size Analysis)**
*   **Pattern:** Queries with unusually long subdomains (60+ characters) or large `TXT` record responses.
*   **Meaning:** Encoded Command & Control traffic bypassing the firewall.

**4. Fast Flux (Botnets)**
*   **Pattern:** You query `bad-site.com` five times in 5 minutes. You get 5 *different* IP addresses every time.
*   **Meaning:** The attacker is rapidly changing IPs to evade blacklists.

---

### ⏳ 5. Time-Based Behavioral Detection (Beaconing)

DNS isn't just about *what* strings are queried, but *when*.

**1. The Heartbeat (Regular Intervals)**
*   **Concept:** Automated malware is programmed to check for commands on a schedule (e.g., `sleep 60`).
*   **Detection:** Look for queries to the same domain occurring at precise intervals.
    *   *Example:* 12:00:00, 12:01:00, 12:02:00.
*   **Analysis:** Humans are random. Machines are rhythmic.

**2. Jitter Detection (Advanced)**
*   **Concept:** Smart malware adds "Jitter" (Randomness) to hide the heartbeat (e.g., `sleep 60 +/- 10%`).
*   **Detection:** Look for "near-matches" in timing.
    *   *Example:* 12:00:00, 12:01:05, 12:02:02, 12:03:07.
    *   *Tooling:* Use SIEM aggregation to spot these "fuzzy" patterns.

---

### 🔒 6. Encrypted DNS Strategy (DoH / DoT)

Attackers use **DNS over HTTPS (DoH)** to hide their queries from your SOC.

**The Blind Spot:**
If a user uses `https://8.8.8.8/dns-query`, your DNS logs are empty. Your Firewall sees "HTTPS traffic to Google," which looks benign.

**Detection & Mitigation Strategy:**
1.  **Block Known DoH Resolvers:** Create a Firewall/Proxy Group containing the IPs of all public DoH providers (Cloudflare, Google, Quad9) and **BLOCK** access to port 443 for these specific IPs.
    *   *Result:* This forces the browser/malware to "fail open" and fall back to standard (visible) UDP/53 DNS.
2.  **Monitor Port 853 (DoT):** DNS over TLS runs on a specific port (853). Block or alert on *any* traffic to this port.
3.  **EDR Insight:** Since the network is blind, use EDR to see the browser process command line arguments (e.g., `--doh-url`).

---

### ⚠️ 7. Signal vs. Noise (Critical Thinking)

| Observation | ✅ Benign (False Positive) | ❌ Malicious (True Positive) |
| :--- | :--- | :--- |
| **High Entropy** | `d34z7...cloudfront.net` (CDN) or `av-update-v8.com`. | `xy87z.ru` (Random DGA domain). |
| **NXDOMAIN Spike** | Chrome Browser "Startup Check" (generates 3 random domains to check DNS hijacking). | 100+ requests to `[random].net` in rapid succession. |
| **Cloud Storage** | HR Employee accessing OneDrive. | **Database Server** accessing OneDrive. (Context is King). |
| **TXT Records** | SPF/DKIM records (Email security). | Encoded Base64 strings in TXT records (C2 Instructions). |

---

### 🌳 8. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Adware/Tracking)**
    *   `Query: ads.tracker.com` + `Source: User Laptop`
    *   *Action:* Ignore. Browser noise.

*   **🟡 Medium Priority (Shadow IT)**
    *   `Query: dropbox.com` + `Source: Server VLAN`
    *   *Action:* Investigate why a server needs DropBox. Policy violation?

*   **🔴 High Priority (DGA/C2)**
    *   `Query: High Entropy` + `Rcode: NXDOMAIN (High Vol)` + `Source: User PC`
    *   *Action:* **Isolate Host.** It is infected and trying to phone home.

*   **🟣 Critical Priority (Exfiltration)**
    *   `Query: [sensitive-data].attacker.com` + `Type: TXT/A`
    *   *Action:* **Major Incident.** Data is leaving the network via DNS queries.

---

### 🛡️ 9. Containment Actions (SOC Reality)

1.  **Sinkholing:** Configure your internal DNS server to resolve the malicious domain to a "Sinkhole IP" (a server you control).
    *   *Benefit:* The malware connects to you instead of the attacker. You can analyze the traffic.
2.  **Block Domain:** Add to the Firewall/Proxy Blocklist.
3.  **Flush DNS Cache:** On the infected host (`ipconfig /flushdns`) to force it to query again (hitting your sinkhole/block).

---

### 📊 10. Impact Assessment

*   **Confidentiality:** DNS Tunneling = Data Leak.
*   **Integrity:** Did the DNS response direct the user to a Phishing site? (DNS Poisoning).
*   **Availability:** Is this a DNS Amplification attack (DDoS)?

### 🎯 11. MITRE ATT&CK Mapping
*   **T1071.004:** Application Layer Protocol: DNS (C2).
*   **T1568.002:** Dynamic Resolution: Domain Generation Algorithms (DGA).
*   **T1048:** Exfiltration Over Alternative Protocol.
*   **T1572:** Protocol Tunneling.

---

### 12. Interview Summary (TL;DR)
*   **Why DNS?** It's the "Phonebook." Malware *must* use it to find the C2 server.
*   **Top 3 Detects:**
    1.  **DGA:** Random domain names + High `NXDOMAIN` volume.
    2.  **Tunneling:** Long subdomains + High `TXT` volume.
    3.  **Beaconing:** Queries occurring at exact regular intervals (Time-based analysis).
*   **Blind Spot:** **DoH (DNS over HTTPS).** If used, you must rely on Endpoint logs or Firewall blocks against known DoH resolvers.
*   **Passive DNS:** A historical record of "Which IP did this domain resolve to yesterday?" Critical for tracking Fast Flux networks.