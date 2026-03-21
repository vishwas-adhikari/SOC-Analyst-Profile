# PCAP Analysis: Unauthorized File Upload — Case #P13-01

## Alert Overview
- Severity: High
- Detection Source: Network Traffic Capture (PCAP)
- Asset Affected: Internal Web Server (192.168.1.7)
- Threat Type: Suspicious File Upload / Data Exfiltration
- Status: True Positive

## Investigation Steps
1. Initial indicator identified by filtering network traffic for the string "P13" to isolate activity related to the specific user workstation.
2. Isolated HTTP protocol traffic to identify web-based interactions between the host and internal infrastructure.
3. Conducted deep packet inspection (DPI) on an HTTP POST request directed at a PHP administrative panel.
4. Followed the TCP stream (Stream EQ 24) to analyze the multipart form-data and the server's subsequent response.
5. Utilized Wireshark Conversation Statistics to calculate the exact duration and throughput of the data transfer.

## Analysis & Findings
The investigation focused on the network activity of workstation 192.168.235.137 (User: P13). Analysis of the traffic revealed an HTTP POST request directed at an internal web server (192.168.1.7) targeting the endpoint `/panel.php`. 

Detailed inspection of the packet headers and payload confirmed that a file named "file" was uploaded using `multipart/form-data`. The payload content exhibited high entropy, suggesting the file was either encrypted or a binary executable. The server, running Apache/2.4.54 (Win64) and PHP/8.0.25, accepted the transmission and returned an HTTP 200 OK status. The response body explicitly confirmed the success of the operation, stating the file was stored at the location `uploads/file`. 

Statistical analysis of the conversation between the host and the server showed the entire transfer was completed in 0.0073 seconds. Given that `panel.php` appears to be an administrative or developer-level upload utility, this activity is classified as a True Positive. The presence of encrypted or binary data being uploaded to a web-accessible directory without clear authorization poses a significant risk of Remote Code Execution (RCE) or data exfiltration.

## Evidence
- Alert Log / Traffic Evidence  
![Insert Screenshot: Wireshark packet list showing the POST request to 192.168.1.7/panel.php]

- Threat Intelligence Verification  
![Insert Screenshot: TCP Stream showing the 'file uploaded' message and server headers]

- Conversation Statistics
![Insert Screenshot: Statistics window showing the 0.0073 second duration for the transfer]

## Indicators of Compromise

| Type | Value | Context |
|------|------|--------|
| IP | 192.168.235.137 | Source IP (User P13) |
| IP | 192.168.1.7 | Destination Web Server |
| URL | http://192.168.1.7/panel.php | Target upload endpoint |
| Directory | /uploads/file | Destination path for the uploaded payload |

## Response & Closure
- Action Taken: Traffic analyzed to identify source and destination; payload inspected for malicious indicators; server response validated to confirm successful upload.
- Containment Required: Yes (The uploaded file should be removed and the source host isolated for forensic review).
- Closure Reason: True Positive — Successful unauthorized file upload to a production web server.

## Skills & Tools Used
SIEM, Log Analysis, Wireshark, PCAP Analysis, Network Forensics, HTTP Protocol Analysis, Traffic Statistics, Incident Triage.

## Conclusion & Recommendations
The analysis confirms that user P13 (192.168.235.137) successfully uploaded a file of unknown type to a web-accessible directory on 192.168.1.7 via an administrative panel. The speed of the transfer and the nature of the target directory suggest an automated or scripted action. If the uploaded file is a web shell, the attacker would have immediate command execution capabilities under the context of the Apache service.

**Remediation Steps:**

1. **Immediate File Removal:** Delete the file located at `uploads/file` on the web server immediately to prevent execution.
2. **Access Control Hardening:** Restrict access to `/panel.php` to specific authorized internal IP addresses or implement Multi-Factor Authentication (MFA) for the administrative panel.
3. **Disable Execution in Uploads Directory:** Configure the Apache server to disable the execution of scripts (e.g., .php, .exe, .sh) within the `/uploads/` directory using an `.htaccess` file or server configuration.
4. **Input Validation:** Implement strict file-type validation (MIME-type checking) to ensure only authorized file formats (e.g., .jpg, .pdf) can be uploaded.
5. **Endpoint Investigation:** Perform a full forensic scan on P13's workstation to determine if the upload was intentional or if the host has been compromised by a remote actor.


  <img width="600" height="500" alt="1" src="https://github.com/user-attachments/assets/42995440-0295-4c40-8043-92e970fd7546" />
  
  <img width="600" height="499" alt="2" src="https://github.com/user-attachments/assets/c9543653-9b43-442c-9c1c-d76a1612e88c" />
  
  <img width="600" height="500" alt="3" src="https://github.com/user-attachments/assets/d7059ca3-2cbd-490f-827c-191f0a656612" />
  
  <img width="600" height="500" alt="4" src="https://github.com/user-attachments/assets/554deab8-36d3-4705-a120-28f050d8dcd5" />
  
  <img width="600" height="500" alt="5" src="https://github.com/user-attachments/assets/c9396916-49e8-46ec-89b1-bd5af95c9643" />






