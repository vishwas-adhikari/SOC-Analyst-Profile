# HTTP Basic Auth Credential Exposure — Case #PCAP-102

## Alert Overview
- Severity: Medium
- Detection Source: Network Traffic Capture (PCAP)
- Asset Affected: Web Server (192.168.63.100)
- Threat Type: Cleartext Credential Exposure
- Status: True Positive

## Brief about the Concept
HTTP Basic Authentication is a simple challenge-response mechanism that allows a client to provide credentials to a server. However, it does not provide confidentiality. Credentials are transmitted as a Base64-encoded string in the HTTP header. Because Base64 is an encoding scheme and not encryption, any adversary capable of intercepting network traffic (sniffing) can easily decode the string to retrieve the username and password in cleartext. This highlights the critical necessity of wrapping such protocols in TLS (HTTPS).

## Investigation Steps

### 1. Traffic Volume and Protocol Identification
The investigation began by opening the `webserver.em0.pcap` file in Wireshark to assess the volume of HTTP activity.
- **Action:** Applied a filter to isolate GET requests.
- **Filter:** `http.request.method == "GET"`
- **Finding:** A total of 5 HTTP GET requests were identified within the capture.

### 2. Server Fingerprinting and Environment Analysis
By inspecting the HTTP response headers (specifically the "Server" field) in any successful communication (HTTP 200 OK), the server environment was mapped.
- **Web Server Software:** Apache/2.2.15
- **Operating System:** FreeBSD
- **Support Library:** OpenSSL/0.9.8n
- **Finding:** The server is running legacy versions of Apache and OpenSSL, which may contain known vulnerabilities.

### 3. Client Profiling
The User-Agent string was analyzed to identify the source of the requests.
- **User-Agent:** `Lynx/2.8.7rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8n`
- **Finding:** The client is using Lynx, a text-based web browser, which is frequently used by administrators or in automated scripts, but can also be used by attackers for reconnaissance.

### 4. Credential Extraction and Decoding
Following the TCP stream (Stream 4), an "Authorization" header was discovered in the request to the server.
- **Header:** `Authorization: Basic d2ViYWRtaW46VzNiNERtMW4=`
- **Action:** Extracted the Base64 string `d2ViYWRtaW46VzNiNERtMW4=` and utilized CyberChef to decode it.
- **Decoding Result:** `webadmin:W3b4Dm1n`
- **Finding:** The username is **webadmin** and the password is **W3b4Dm1n**. The server responded with a "200 OK" and the content "It works!", confirming a successful login with these credentials.

## Analysis & Findings
The analysis of the network traffic confirms that a user successfully authenticated to the web server (192.168.63.100) using HTTP Basic Authentication. Because the session was conducted over an unencrypted HTTP connection, the credentials for the **webadmin** account were transmitted in a reversible format. 

The successful response from the server indicates that these credentials are valid. This represents a complete compromise of the `webadmin` account for this web service. Furthermore, the server is running significantly outdated software (Apache 2.2.15 and OpenSSL 0.9.8n), which increases the overall risk profile of the asset due to unpatched vulnerabilities.

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|------|--------|
| IP | 192.168.63.100 | Target web server. |
| Account | webadmin | Compromised administrative account. |
| Password | W3b4Dm1n | Exposed cleartext password. |
| User-Agent | Lynx/2.8.7rel.1 | Client browser used during the session. |

## Decision Tree for HTTP Authentication Scenarios
1. **Is HTTP traffic present?**
   - If Yes -> Check for `Authorization: Basic` or `Authorization: Bearer` headers.
2. **Is the traffic over Port 80 (HTTP)?**
   - If Yes -> Any credentials found are considered exposed/compromised.
3. **Can the string be decoded?**
   - If it begins with `Basic`, it is Base64. Decode to retrieve `User:Pass`.
4. **Was the login successful?**
   - Check for `HTTP 200 OK` or `HTTP 302 Redirect`.
   - If Yes -> Verdict: True Positive - Credential Compromise.

## Response & Closure
- **Action Taken:** Extracted and decoded cleartext credentials from network traffic; identified vulnerable server software versions.
- **Containment Required:** Yes. The `webadmin` account password must be changed immediately across all systems where it may be reused.
- **Closure Reason:** True Positive. Credential exposure via unencrypted management protocol.

## Recommendations
1. **Enforce HTTPS:** Disable all HTTP (Port 80) listeners and migrate the service to HTTPS (Port 443) using modern TLS certificates to ensure credentials are encrypted in transit.
2. **Password Rotation:** Rotate the password for the `webadmin` account immediately. 
3. **Software Lifecycle Management:** Update Apache and OpenSSL to current, supported versions. Apache 2.2.15 and OpenSSL 0.9.8n are end-of-life and subject to numerous vulnerabilities (e.g., Heartbleed, POODLE, etc.).
4. **Disable Basic Auth:** Where possible, replace Basic Authentication with more secure methods such as OAuth2 or certificate-based authentication.
5. **Credential Policy:** Ensure administrative passwords like `W3b4Dm1n` meet complexity requirements and are not easily guessable.

## Evidence / Screenshots

<img width="650" height="500" alt="image" src="https://github.com/user-attachments/assets/c3ae177a-89a9-4754-81ba-b8d353a31ba9" />


## Skills & Tools Used
Wireshark, Network Traffic Analysis, Packet Inspection, CyberChef, Base64 Decoding, HTTP Fingerprinting, Incident Triage.
