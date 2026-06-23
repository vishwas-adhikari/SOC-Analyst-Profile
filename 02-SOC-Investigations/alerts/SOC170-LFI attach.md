
# SOC170 - Passwd Found in Requested URL (Possible LFI Attack) — Case #120

## Alert Overview
- **Severity:** High
- **Detection Source:** SIEM / WAF
- **Asset Affected:** WebServer1006 (172.16.17.13)
- **Threat Type:** Local File Inclusion (LFI) / Directory Traversal
- **Status:** True Positive (Unsuccessful)

## Strategy and Technical Context
This incident involves a Local File Inclusion (LFI) attempt. LFI vulnerabilities occur when a web application improperly sanitizes user input passed to file-inclusion mechanisms (such as the `?file=` parameter in PHP applications). By injecting directory traversal characters (`../`), the threat actor attempts to escape the web root directory and navigate the underlying server's file system. The strategic objective is to read sensitive configuration files, such as `/etc/passwd` on Linux systems, to map valid user accounts for subsequent brute-force attacks or privilege escalation.

## Brief about the Concept
Automated vulnerability scanners constantly probe public-facing infrastructure. They utilize predefined payloads, such as `../../../../etc/passwd`, to test if input validation is missing. If the server is vulnerable, it will process the traversal and return the contents of the password file in the HTTP response. Defenders must analyze the server's response code and payload size to determine if the exfiltration was successful.

## Investigation Steps

### 1. Alert Triage and Directionality
The alert was triggered by an incoming HTTP GET request.
- **Source IP:** 106.55.45.162 (External)
- **Destination:** WebServer1006 / 172.16.17.13 (Internal)
- **Device Action:** Permitted (The traffic successfully reached the web server).
- **Directionality:** Internet to Company Network.

### 2. Threat Intelligence & Artifact Enrichment
The source IP (`106.55.45.162`) was queried against Threat Intelligence platforms, including **VirusTotal** and **Cisco Talos**.
- **Finding:** The IP is geographically located in China and flagged as a known malicious scanner by multiple security vendors. 
- **User-Agent Analysis:** The attacker utilized the User-Agent string: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)`. This corresponds to Internet Explorer 6 running on Windows XP—a 20-year-old environment. This highly anomalous User-Agent is a definitive signature of an automated exploit script or botnet, rather than a legitimate human user.

### 3. Payload Deconstruction
The requested URL contained the payload: `https://172.16.17.13/?file=../../../../etc/passwd`
- **Methodology:** The attacker used four sequential `../` commands to move up four directories from the current web root, attempting to reach the root `/` directory, followed by accessing the `etc/passwd` file.

### 4. Impact Assessment (Log Correlation)
To determine if the attack successfully extracted the file, the raw web server logs were analyzed for the specific transaction.
- **HTTP Response Status:** 500 (Internal Server Error)
- **HTTP Response Size:** 0 bytes
- **Observation:** The server crashed or encountered a fatal processing error when handling the malformed input. Because the response size was exactly 0 bytes, it is mathematically impossible for the contents of the `/etc/passwd` file to have been returned to the attacker.

## Analysis and Findings
The incident is a confirmed **True Positive**. An external threat actor utilized an automated scanning tool to test WebServer1006 for a Local File Inclusion (LFI) vulnerability. While the initial request bypassed perimeter blocking (Action: Permitted), the attack was ultimately **Unsuccessful**. The backend application failed to process the directory traversal, returning an HTTP 500 error and a 0-byte payload. The web server remains uncompromised, and no data was exfiltrated. 

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application |
| **Discovery** | T1083 | File and Directory Discovery |
| **Credential Access** | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 106.55.45.162 | Malicious Scanner Source IP |
| URL Path | `/?file=../../../../etc/passwd` | LFI Directory Traversal Payload |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)` | Suspicious/Spoofed User-Agent |

## Blind Spots
- **Application Logic Flaws:** While the attack failed, the HTTP 500 error indicates the application does not handle unexpected input gracefully. Without reviewing the application's source code, it is unclear if the failure was due to the OS lacking the file, permissions blocking the read, or a generic code crash.

## False Positives: Legitimate Activity Comparison
- **Internal Vulnerability Scanning:** Authorized DAST (Dynamic Application Security Testing) tools run by internal security teams will generate identical traffic. Analysts must verify the source IP against authorized scanner lists before classifying it as a threat.

## Mistakes and Lessons Learned
- **Analyst Reflection:** In web-based alerts, it is easy to assume that "Device Action: Allowed" equates to a successful compromise. 
- **The Lesson:** This case perfectly demonstrates why endpoint and server log correlation is mandatory. By verifying the **HTTP Response Size (0)** and **Status Code (500)**, I was able to definitively prove the attack failed. This prevented an unnecessary Tier 2 escalation and avoided needlessly taking a production web server offline for containment.

## Response and Closure
- **Action Taken:** The malicious source IP (`106.55.45.162`) was added to the perimeter firewall's blocklist to halt further reconnaissance from this threat actor. 
- **Containment Required:** No. The attack was unsuccessful.
- **Tier 2 Escalation:** No. The attack originated externally and failed.
- **Closure Reason:** True Positive. Unsuccessful automated LFI exploit attempt.

## Recommendations
1. **Input Validation:** The development team must implement strict input sanitization on the `?file=` parameter. The application should use an "allow-list" approach, only permitting specific, expected filenames, and explicitly dropping requests containing `../` or `%2e%2e%2f` (URL-encoded traversal).
2. **WAF Tuning:** Update the Web Application Firewall (WAF) to drop traffic matching known LFI signatures (e.g., `etc/passwd`, `boot.ini`) at the edge, so the requests never reach the web server application layer.
3. **Error Handling:** Configure the web server to return generic, custom HTTP 400 (Bad Request) or 403 (Forbidden) error pages instead of HTTP 500 crashes, which can reveal backend processing flaws to attackers.

## Evidence / Screenshots

<img width="606" height="467" alt="image" src="https://github.com/user-attachments/assets/9d82f5f9-4031-4dd5-9d2f-03454ad818a9" />

## Skills & Tools Used
SIEM Log Correlation, HTTP Protocol Analysis (Status Codes & Response Size), Threat Intelligence (VirusTotal, Cisco Talos), LFI/Directory Traversal Triage, User-Agent Profiling, MITRE ATT&CK Mapping.
