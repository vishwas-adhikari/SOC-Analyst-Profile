

# SOC287 - Arbitrary File Read on Checkpoint Security Gateway [CVE-2024-24919] — Case #263

##  Alert Summary
- **Type:** Public-Facing Exploit / Arbitrary File Read (AFR)
- **Severity:** Critical
- **Source:** IPS / SIEM
- **Status:** True Positive (Successful)

##  Brief about the Concept
**Arbitrary File Read (AFR)** is a vulnerability class where an application improperly sanitizes user input, allowing an attacker to navigate the server's file system and read sensitive files. **CVE-2024-24919** specifically targets Check Point Security Gateways. By utilizing a Path Traversal attack (`../`), unauthenticated attackers can access system files like `/etc/passwd` (user list) and `/etc/shadow` (password hashes) on the underlying Gaia OS.

##  Strategy and Technical Context
The technical strategy for detecting this exploit involves identifying the `aCSHELL` signature in POST requests to the `/clients/MyCRL` endpoint. Because this is an **Information Disclosure** vulnerability, it does not typically spawn new processes or shells on the host. Therefore, the primary detection strategy must pivot from Endpoint Detection (EDR) to **Network Log Correlation**, specifically comparing the HTTP response size of the malicious request against a known baseline request to confirm data exfiltration.

##   Investigation Steps
1. **Signature Match:** Identified the malicious string `aCSHELL/../../../../../../etc/passwd` in the SIEM raw logs.
2. **Threat Intel:** Confirmed the source IP `203.160.68.12` is a known malicious actor currently exploiting this specific CVE.
3. **Host Review (EDR):** Checked the **Terminal History** and **Process List** for `CP-Spark-Gateway-01`. No suspicious bash commands or unauthorized processes were found.
4. **Log File Triage:** Analyzed the `access.log` to determine the outcome of the request.
5. **Response Correlation:** Compared the baseline request size (**452 bytes**) with the exploit request size (**1256 bytes**). 

##  Analysis and Findings
The incident is a **True Positive (Successful)**. The attacker successfully exfiltrated the `/etc/passwd` file. While the attempt to read `/etc/shadow` resulted in a **403 Forbidden**, the initial successful read (indicated by the **200 OK** and the **804-byte increase** in response size) confirms that the attacker obtained the full list of system users. This information can be used for targeted brute-force attacks or further exploitation.

##   MITRE ATT&CK Mapping
- **Initial Access:** T1190 - Exploit Public-Facing Application
- **Discovery:** T1083 - File and Directory Discovery
- **Exfiltration:** T1041 - Exfiltration Over C2 Channel

##   Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| **IP** | 203.160.68.12 | Attacker Source IP |
| **URL** | `172.16.20.146/clients/MyCRL` | Vulnerable Target Endpoint |
| **File** | `/etc/passwd` | Exfiltrated Sensitive File |

##   Blind Spots
- **EDR Limitations:** EDR tools on network appliances often lack the granularity to monitor internal file-read operations performed by the web server process itself.
- **Encrypted Payloads:** Without SSL/TLS inspection, the `aCSHELL` payload remains invisible to network-level monitoring tools.

##  False Positives
- **Authorized Vulnerability Scanners:** Internal security tools may use these payloads to verify patch compliance. 

##  Mistakes and Lessons Learned
- **The Error:** The initial analysis incorrectly concluded the attack was **Unsuccessful** because no malicious activity was found in the EDR **Terminal History** or **Process Logs**.
- **Root Cause (Confirmation Bias):** I relied too heavily on the "No Shell = No Success" mindset. I expected the attacker to spawn a bash shell or run commands, which is common in RCE but **not** in Arbitrary File Read attacks.
- **The Missed Clue:** I initially failed to scrutinize the `access.log` file's **Response Size**. By ignoring the jump from 452 bytes to 1256 bytes, I missed the evidence of data exfiltration.
- **Lesson Learned:** In web attacks, the **HTTP Response Size** is just as important as the **Status Code**. A "200 OK" doesn't just mean "the page loaded"; it can mean "the data was stolen." Always establish a baseline for "normal" response sizes for an endpoint.

##   Decision Tree for Path Traversal
1. **Identify Pattern:** Does the request contain `../` or `aCSHELL`?
   - If Yes -> Proceed to Impact Analysis.
2. **Check Response Status:** Is it `200 OK`?
   - If Yes -> **Check Response Size.**
3. **Compare Size to Baseline:** Is the size significantly larger than a normal request?
   - If Yes -> **Verdict: Successful Attack.**
4. **Check Host Logs:** Are there new processes?
   - If Yes -> **Verdict: Compromised (RCE).**

##   Response and Closure
- **Action Taken:** Isolated the Check Point Gateway; escalated to Tier 2 for credential audit.
- **Containment Required:** Yes.
- **Closure Reason:** True Positive. Confirmed exfiltration of system user list.

##  Recommendations
- **Patching:** Apply the Check Point Jumbo Hotfix Accumulator immediately.
- **Credential Rotation:** Rotate all local system passwords on the Gaia OS.
- **IPS Enforcement:** Set CVE-2024-24919 signatures to "Prevent" mode.

##  Evidence

<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/d8ff4229-be11-40ec-a7a7-f6897e4f0689" />
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/abf3548c-be1a-4b30-9a51-ef74f81f8490" />
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/19b3d4c1-4e96-4e59-876d-cb0e8cb7cdbf" />




## 🛠️ Skills & Tools Used
SIEM, Log Analysis (Response Size Delta), CVE Research (CVE-2024-24919), Check Point Gaia OS Analysis, Incident Triage, MITRE ATT&CK Mapping.
