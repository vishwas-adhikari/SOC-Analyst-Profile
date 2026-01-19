
# 📘 SOC Analyst Handbook: NetFlow Analysis (Generic Network Logs)

**Category:** Network Defense / Traffic Analysis
**Severity:** Core Skill (The "Vitals" of the Network)
**Skill Level:** Intermediate

---

### 1. The Concept

**The Analogy (ELI5)**
Imagine a telephone bill.
*   **Full Packet Capture (PCAP):** A recording of the actual conversation. You hear every word said. Expensive to store.
*   **NetFlow:** The itemized bill. It shows *Who* called, *When* they called, *How long* they talked, and *Where* they called from. It does **not** record what was said.

**The Technical Definition**
**NetFlow** (and variants like sFlow/IPFIX) is a network protocol that collects **Metadata** about IP traffic flowing through a router, switch, or firewall. It records "Flows"—a sequence of packets sharing the same 5-tuple attributes (Src IP, Dst IP, Src Port, Dst Port, Protocol). It operates at **Layer 3 and 4**.

**⚠️ Crucial Limitation:** NetFlow **cannot** see Layer 7 data (URLs, User-Agents, X-Forwarded-For headers, or File Contents). It is blind to the payload.

---

### 2. Log Source / Tool

| Source | Primary Use Case | Key Fields |
| :--- | :--- | :--- |
| **Routers/Switches** | Visibility into East-West (internal) traffic or WAN traffic. | `Src/Dst IP`, `Src/Dst Port`, `Protocol` (6=TCP, 17=UDP), `Interface`. |
| **Firewalls** | Correlation with Allow/Block actions. | `Action`, `Rule Name`, `Bytes Sent`, `Bytes Received`. |
| **VPC Flow Logs** | Cloud (AWS/Azure) visibility. | `Account-ID`, `Interface-ID`, `Accept/Reject`. |

---

### 3. Example Logs

#### **A. The "DDoS" Scenario (UDP Flood)**
*As seen in your quiz material.*
```text
Date: 2023-11-20 14:00:01 | Src: 45.1.1.1   | Dst: 10.0.0.5 | Proto: UDP | Port: 53 | Packets: 50 | Bytes: 3000
Date: 2023-11-20 14:00:01 | Src: 89.2.2.2   | Dst: 10.0.0.5 | Proto: UDP | Port: 53 | Packets: 50 | Bytes: 3000
Date: 2023-11-20 14:00:01 | Src: 101.3.3.3  | Dst: 10.0.0.5 | Proto: UDP | Port: 53 | Packets: 50 | Bytes: 3000
... (Repeats 10,000 times) ...
```

#### **B. The "Data Exfiltration" Scenario**
```text
Date: 2023-11-20 03:00:00 | Src: 192.168.1.50 | Dst: 104.21.55.1 | Proto: TCP | Port: 443 
Flags: PSH,ACK | Packets: 500,000 | Bytes_Sent: 4,500,000,000 (4.5GB) | Bytes_Rcvd: 500
Duration: 3600s
```

#### **C. The "Scanning" Scenario**
```text
Date: 2023-11-20 09:00:00 | Src: 192.168.1.50 | Dst: 192.168.1.51 | Port: 22 | Bytes: 60 | Flags: SYN
Date: 2023-11-20 09:00:00 | Src: 192.168.1.50 | Dst: 192.168.1.51 | Port: 23 | Bytes: 60 | Flags: SYN
Date: 2023-11-20 09:00:00 | Src: 192.168.1.50 | Dst: 192.168.1.51 | Port: 80 | Bytes: 60 | Flags: SYN
```

---

### 4. What It Means

*   **Log A (UDP Flood):** 10,000 different external IPs are hitting one internal IP (`10.0.0.5`) on the same port (`UDP/53` DNS) at the same time. This is a volumetric **DDoS Attack**.
*   **Log B (Exfil):** An internal host sent 4.5GB of data to an external IP. The session lasted an hour. This is likely **Data Exfiltration** (or a backup).
*   **Log C (Scanning):** One internal host is trying multiple ports on another host rapidly. The low byte count (60 bytes) and `SYN` flags indicate it's just checking if the door is open (Port Scanning).

---

### 5. How To Investigate (The Pivot)

**Step 1: Baseline the Volume**
*   Is 4GB upload normal for this user?
*   *Action:* Check historical NetFlow for this IP. If they usually upload 50MB/day, this is an anomaly.

**Step 2: Calculate "Bytes Per Packet"**
*   *Formula:* `Total Bytes / Total Packets`.
*   *Why?*
    *   High Bytes/Packet (e.g., 1400 bytes) = Large file transfer.
    *   Low Bytes/Packet (e.g., 60 bytes) = Control traffic (Keyboard strokes in SSH, or Scanning).

**Step 3: Protocol Mismatch Check**
*   NetFlow sees the port (e.g., 443) and protocol (TCP).
*   *Scenario:* You see traffic on Port 53 (DNS) but it's TCP, and the session is 2 hours long.
*   *Verdict:* DNS is usually UDP and fast. Long TCP connections on Port 53 usually mean **DNS Tunneling** (Malware hiding traffic).

---

### ⚠️ 6. Signal vs. Noise (Critical Thinking)

| Observation | ✅ Benign (False Positive) | ❌ Malicious (True Positive) |
| :--- | :--- | :--- |
| **High Outbound Bytes** | Nightly Cloud Backup, Dropbox Sync, Video Call. | Exfiltration to unknown IP / Pastebin / Mega.nz. |
| **High Inbound Traffic** | Windows Update, Game Download, ISO Download. | DDoS Attack (UDP Flood), Amplification Attack. |
| **Port Scanning** | IT Asset Management Software (Lansweeper/Nessus). | Compromised host looking for lateral movement targets. |
| **Traffic on High Ports** | WebRTC (Zoom/Teams) often uses dynamic UDP ports. | C2 Beaconing using random high ports to bypass filters. |

---

### 7. SOC Decision Logic

*   **🟢 Low Priority (Noise)**
    *   `Port Scan` + `Source: Nessus Scanner IP`
    *   *Action:* Ignore authorized scanning.

*   **🟡 Medium Priority (Policy Violation)**
    *   `Protocol: BitTorrent` + `Source: Employee PC`
    *   *Action:* P2P traffic detected. Likely not a hack, but a policy violation.

*   **🔴 High Priority (Exfiltration)**
    *   `Bytes Sent > 1GB` + `Dst IP: Unknown/Uncategorized` + `Time: 3 AM`
    *   *Action:* **Isolate Host.** Check what files were accessed on the endpoint.

*   **🟣 Critical Priority (DDoS)**
    *   `Flows > 10,000/sec` + `Many Src IPs` + `One Dst IP`
    *   *Action:* **Engage ISP mitigation.** Your firewall state table might fill up and crash.

---

### 📊 8. Impact Assessment

**1. Data at Risk**
*   *High Bytes Sent:* Confidentiality Loss. Intellectual property or PII might be gone.
*   *High Bytes Received:* Integrity Risk. Did they download a massive malware toolkit?

**2. Blast Radius**
*   *Internal Scanning:* If NetFlow shows `192.168.1.5` talking to `192.168.1.0/24` (the whole subnet), the infection is trying to spread (Worm behavior).

**3. Business Impact**
*   *DDoS:* Availability Loss. Customers cannot access the website.

---

### 🎯 9. MITRE ATT&CK Mapping

*   **T1048:** Exfiltration Over Alternative Protocol (Detected via NetFlow volume).
*   **T1046:** Network Service Scanning (Detected via Flow patterns).
*   **T1498:** Network Denial of Service (Detected via Flow volume).
*   **T1571:** Non-Standard Port (Detected via Port/Protocol mismatch).

---

### 10. Interview Summary (TL;DR)
*   **NetFlow = Metadata:** Who, When, Where, How Much. **No Content.**
*   **Key Fields:** 5-Tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol).
*   **Use Case:** Best for detecting **Data Exfiltration** (High Bytes) and **DDoS** (High Flows).
*   **Blind Spot:** Cannot see inside the packet (No URLs, No Files, No XFF).
*   **Analysis:** Look for "Long Duration" connections (Tunneling) or "High Outbound Bytes" (Theft).