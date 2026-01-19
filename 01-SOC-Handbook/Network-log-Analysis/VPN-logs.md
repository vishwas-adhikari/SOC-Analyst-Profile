
# 📘 SOC Analyst Handbook: VPN Log Analysis

**Category:** Authentication / Perimeter Defense
**Severity:** Critical (Access Control)
**Skill Level:** Intermediate

---

### 1. The Concept

**The Analogy (ELI5)**
*   **Office Building:** To get in, you need a badge.
*   **VPN (Virtual Private Network):** It’s a magical door installed in your employee's house. When they swipe their badge at home, a long secure tunnel opens up that connects their living room directly to their office desk.
*   **The Risk:** If a thief steals the badge (credentials), the building security thinks the thief is the employee.

**The Technical Definition**
VPN technology encrypts traffic between a remote client and the corporate network. For a SOC Analyst, VPN logs serve two distinct purposes:
1.  **Authentication:** Validating *who* is connecting (User + Password + MFA).
2.  **Attribution:** Mapping an external public IP (`remip`) to an internal virtual IP (`tunnelip`), allowing you to track what the remote user did inside the network.

---

### 2. Log Anatomy (The Vocabulary)

VPN logs bridge the gap between "The Internet" and "The Internal Network."

#### **📝 Common Log Fields (Fortinet/Cisco)**

| Field | Definition | Why it matters for SOC |
| :--- | :--- | :--- |
| **user** | Authenticated Username | Who is claiming to be logging in? |
| **remip** (Remote IP) | Source Public IP | **Where** are they physically? (Geo-Location). |
| **tunnelip** | Assigned Internal IP | **Virtual Identity.** The IP the firewall sees *inside* the network. |
| **action** | `tunnel-up`, `tunnel-down` | Did the connection succeed (`up`) or fail? |
| **os_name / host** | **Device Fingerprint** | Windows 10? Mac? Kali Linux? (Crucial for anomaly detection). |
| **tunneltype** | `ssl-web`, `ipsec` | How are they connecting? (Browser vs Client). |
| **duration** | Session Length | How long were they inside? |

---

### 3. Example Logs (The Evidence)

**Log 1: The Connection Event (VPN Log)**
```text
date=2022-05-21 time=14:06:38 devname="FG500" type="event" subtype="vpn" user="letsdefend-user" remip=13.29.5.4 action="tunnel-up" tunnelip=10.10.10.5 os_name="Windows 10" reason="login successfully"
```
*   **Analysis:** User `letsdefend-user` successfully logged in from `13.29.5.4` using a Windows 10 device.

**Log 2: The Activity Event (Firewall Traffic Log)**
```text
date=2022-05-21 time=14:08:00 devname="FG500" srcip=10.10.10.5 dstip=192.168.1.50 dstport=3389 action="accept"
```
*   **Correlation:** We link `10.10.10.5` back to the user to confirm they accessed the server via RDP.

---

### 4. Detection Tricks & Patterns (Advanced)

**1. Concurrent Session Detection (Critical)**
*   **Pattern:** User `jdoe` has an active session from **London** (Office IP) AND a new session starts from **Russia** (Attacker IP) at the same time.
*   **Meaning:** Two people are holding the same badge. 100% Account Compromise.
*   *Note:* Legitimate users rarely have two active VPN tunnels simultaneously.

**2. Device Fingerprint Anomalies**
*   **Pattern:** User `asmith` has logged in 500 times using `Windows 10`. Suddenly, a login occurs using `Linux` or `Android`.
*   **Meaning:** The credentials might have been stolen and used on the attacker's machine.

**3. Impossible Travel (Geo-Velocity)**
*   **Pattern:** Login from New York at 10:00 AM. Login from China at 10:30 AM.
*   **Meaning:** Physics violation. Credentials are being shared or stolen.

**4. Session Abuse Behavior**
*   **Pattern:** A valid VPN user starts performing **Port Scans** or accessing **Admin Subnets** (HR User -> Server VLAN).
*   **Meaning:** The user is authenticated, but the *behavior* is malicious. This is either an **Insider Threat** or an attacker who has already bypassed the perimeter.

---

### ⚠️ 5. Signal vs. Noise (Critical Thinking)

| Observation | ✅ Benign (False Positive) | ❌ Malicious (True Positive) |
| :--- | :--- | :--- |
| **Failed Login** | User caps-lock error or expired password. | Hundreds of failures from one IP (Brute Force). |
| **Concurrent Session** | User phone (Mobile VPN) + Laptop (WiFi VPN) on at same time. | User Laptop (Office) + Attacker Laptop (Foreign IP). |
| **New Country** | Employee traveling for business (Check HR logs). | No travel record + Login from High Risk country. |
| **MFA Fail** | User typed the code wrong. | **MFA Fatigue:** User denying multiple push requests (Attacker has the password). |

---

### 6. Investigation Steps (The Playbook)

**Step 1: Validate the Source (`remip`)**
*   Is the IP a residential line (Comcast/Verizon) or a Hosting Provider (DigitalOcean/AWS)? *Employees don't live in data centers.*

**Step 2: Check Device Fingerprints**
*   Compare `os_name` or `client_version` with historical logs.
*   *Red Flag:* A generic User-Agent or a version mismatch (e.g., Old VPN Client).

**Step 3: Track the `tunnelip` (The Pivot)**
*   Take the internal IP (`10.10.10.5`) and search it in your **Firewall** and **NetFlow** logs.
*   *Question:* What did they do *after* they connected? Did they access the File Server? Did they run a port scan?

---

### 🛡️ 7. Containment Actions (SOC Reality)

If you confirm a VPN compromise, you must act in this **specific order**:

1.  **Disable Active Directory Account:** Stops *new* logins.
    *   *Warning:* **This does NOT kill the active VPN session.** If the attacker is already connected, disabling the AD account usually does nothing to the existing tunnel.
2.  **Kill the Active Session:** Log into the Firewall/VPN Concentrator and force-disconnect the user (Terminate Session).
3.  **Block Source IP:** Add the attacker's Public IP to the firewall blocklist.
4.  **Reset Password & MFA:** Only after the session is killed.

---

### 📊 8. Impact Assessment

**1. Blast Radius**
*   VPN access grants a foothold *inside* the firewall. The attacker effectively bypassed the perimeter.
*   Check if the user has **Domain Admin** privileges.

**2. Data at Risk**
*   Check `Bytes Sent` in the traffic logs associated with the VPN session. Large transfers indicate data theft.

---

### 🎯 9. MITRE ATT&CK Mapping

*   **T1078:** Valid Accounts (Attacker logging in with stolen creds).
*   **T1133:** External Remote Services (VPN).
*   **T1078.002:** Valid Accounts: Domain Accounts (Concurrent sessions).

---

### 10. Interview Summary (TL;DR)
*   **Key Fields:** `remip` (Source), `tunnelip` (Internal), `user`, `os_name`.
*   **Correlation:** Link VPN log (Auth) to Firewall log (Activity) via `tunnelip`.
*   **Top Detection:** **Impossible Travel** and **Concurrent Sessions** (Two IPs, one user).
*   **Containment Reality:** Disabling the AD user is not enough; you must **Kill the active VPN session** on the firewall to kick the attacker out.