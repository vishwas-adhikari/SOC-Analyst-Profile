

# Section 3: Common SOC Patterns

### 1. IPv4 Address (Simple)
> *Use this for general extraction where log data is expected to be cleanly formatted.*

**Pattern:**   `\b\d{1,3}(?:\.\d{1,3}){3}\b`
**Breakdown:** 
*   `\b` = Word boundary (prevents matching numbers inside longer strings)
*   `\d{1,3}` = One to three digits
*   `(?:\.\d{1,3}){3}` = A non-capturing group containing a literal dot `\.` and 1-3 digits, repeated exactly `{3}` times
**Matches:**   `192.168.1.1`, `10.0.0.5`, `999.999.999.999` *(Valid format, invalid IP)*
**SOC Log:**   `Accepted password for root from 10.10.10.50 port 22 ssh2`
**Engine:**    Both (Splunk / Wazuh)

---

### 2. IPv4 Address (Strict 0–255)
> *Use this to strictly validate IPs and avoid false positives in noisy, unstructured text.*

**Pattern:**   `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`
**Breakdown:** 
*   `25[0-5]` = Matches 250–255
*   `2[0-4][0-9]` = Matches 200–249
*   `[01]?[0-9][0-9]?` = Matches 0–199
*   `\.` = Literal dot
*   `{3}` = Repeats the entire octet logic three times before evaluating the final octet
**Matches:**   `192.168.1.1`, `255.255.255.0`, `8.8.8.8` *(Fails on `256.100.50.1`)*
**SOC Log:**   `src_ip=203.0.113.10 dest_port=443 action=allowed`
**Engine:**    PCRE (Splunk / Wazuh PCRE2)

---

### 3. Email Addresses
> *Use this to extract sender/recipient addresses from mail gateways or phishing alerts.*

**Pattern:**   `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`
**Breakdown:** 
*   `[a-zA-Z0-9._%+-]+` = One or more valid mailbox characters
*   `@` = Literal at-symbol
*   `[a-zA-Z0-9.-]+` = One or more valid domain characters
*   `\.[a-zA-Z]{2,}` = Literal dot followed by a TLD of 2 or more letters
**Matches:**   `admin@company.com`, `user.name+tag@sub.domain.org`, `alert-123@sec.net`
**SOC Log:**   `RCPT TO:<phisher@malicious-domain.xyz> Relay access denied`
**Engine:**    Both

---

### 4. URLs and Domains
> *Use this to pull full web links from proxy logs, DNS requests, or email bodies.*

**Pattern:**   `\bhttps?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)`
**Breakdown:** 
*   `https?:\/\/` = Matches "http://" or "https://"
*   `(?:www\.)?` = Optionally matches "www."
*   `[-a-zA-Z0-9@:%._\+~#=]{1,256}` = Matches domain name characters
*   `\.[a-zA-Z0-9()]{1,6}` = Matches the TLD (e.g., .com, .org)
*   `(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)` = Optionally matches the URI path and query strings
**Matches:**   `http://evil.com/payload.exe`, `https://www.google.com/?q=regex`
**SOC Log:**   `CONNECT evil.com:443 HTTP/1.1 User-Agent: Mozilla/5.0 Request: https://evil.com/login`
**Engine:**    PCRE (Splunk / Wazuh PCRE2)

---

### 5. Suspicious File Extensions
> *Use this to detect potentially dangerous file types being executed or downloaded.*

**Pattern:**   `(?i)\.(exe|ps1|bat|vbs|js|dll|scr|hta)(?:\s|"|'|$)`
**Breakdown:** 
*   `(?i)` = Inline flag for Case-Insensitive matching
*   `\.` = Literal dot
*   `(exe|ps1|bat...)` = Target extensions
*   `(?:\s|"|'|$)` = Must end with a space, quote, or end-of-line. *(Prevents false positive matching on files like `script.exe.txt`)*
**Matches:**   `.ps1`, `.EXE"`, `.vbs `
**SOC Log:**   `Process Create: CommandLine: cmd.exe /c "C:\Temp\dropper.bat"`
**Engine:**    PCRE (Splunk / Wazuh PCRE2)

---

### 6. File Hashes (MD5, SHA1, SHA256)
> *Use this to extract hash values from Sysmon (Event ID 1) or EDR telemetry.*

**Pattern:**   `\b[a-fA-F0-9]{32}\b`
**Breakdown:** 
*   `\b` = Word boundary
*   `[a-fA-F0-9]` = Hexadecimal characters (A-F, 0-9)
*   `{32}` = Exactly 32 characters long for **MD5**. *(Change to `{40}` for SHA1, or `{64}` for SHA256)*
**Matches:**   `d41d8cd98f00b204e9800998ecf8427e`, `D41D8CD98F00B204E9800998ECF8427E`
**SOC Log:**   `Image loaded: C:\Windows\System32\ntdll.dll Hashes: MD5=F75B2CAAF3...`
**Engine:**    Both

---

### 7. Base64 Encoded Strings
> *Use this to detect long, obfuscated command-line arguments or payloads.*

**Pattern:**   `\b(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b`
**Breakdown:** 
*   `(?:[A-Za-z0-9+/]{4})` = Groups of 4 valid base64 characters
*   `{10,}` = Requires at least 10 groups (40+ characters) to reduce false positives on random text
*   `(?:...)?` = Handles optional `==` or `=` padding at the end of the string
**Matches:**   `cGF5bG9hZF9leGFtcGxlX3N0cmluZw==`, `SGVsbG8gV29ybGQhSGVsbG8gV29ybGQh`
**SOC Log:**   `powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBl...`
**Engine:**    PCRE (Splunk / Wazuh PCRE2)

---

### 8. Windows Registry Paths
> *Use this to identify persistence mechanisms or registry modifications in EDR logs.*

**Pattern:**   `(?i)^(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\\s-]+`
**Breakdown:** 
*   `(?i)` = Case-insensitive
*   `^` = Start of string
*   `(?:HKLM|HKCU...)` = Common registry root keys
*   `\\` = Literal backslash
*   `[a-zA-Z0-9_\\\s-]+` = One or more alphanumeric, underscore, backslash, space, or dash characters
**Matches:**   `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKEY_CURRENT_USER\Software\Policies`
**SOC Log:**   `Registry value set: HKLM\System\CurrentControlSet\Services\MaliciousService\ImagePath`
**Engine:**    PCRE (Splunk / Wazuh PCRE2)

---

### 9. Unix File Paths
> *Use this to extract Linux/Unix file paths from auditd or syslog.*

**Pattern:**   `^\/(?:[a-zA-Z0-9_.-]+\/)*[a-zA-Z0-9_.-]+$`
**Breakdown:** 
*   `^\/` = Start of string, followed by the root directory slash `/`
*   `(?:[a-zA-Z0-9_.-]+\/)*` = Optional repeating directory paths ending in a slash
*   `[a-zA-Z0-9_.-]+$` = The final filename or directory name, anchored to the end of the string
**Matches:**   `/etc/passwd`, `/var/log/auth.log`, `/tmp/script.sh`
**SOC Log:**   `type=PATH msg=audit(1612345678.123:45): item=0 name="/etc/shadow" inode=12345`
**Engine:**    Both

***


### 10. IPv6 Address
> *IPv6 is increasingly common in modern infrastructure logs and firewall telemetry. Note: This handles full-form IPv6. Compressed IPv6 (with `::`) requires significantly more complex regex and is rarely needed for basic SOC field extraction.*

**Pattern:**   `\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b`
**Breakdown:** 
*   `\b` = Word boundary
*   `(?:[A-Fa-f0-9]{1,4}:)` = 1 to 4 hexadecimal characters followed by a colon
*   `{7}` = Repeats the previous group exactly 7 times
*   `[A-Fa-f0-9]{1,4}` = The final 1 to 4 hexadecimal characters
**Matches:**   `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
**SOC Log:**   `Connection from 2001:0db8:85a3:0000:0000:8a2e:0370:7334 port 443`
**Engine:**    Both

---

### 11. MAC Address
> *Shows up constantly in DHCP logs, wireless logs, and Network Access Control (NAC) alerts. Handles both Linux/Cisco and Windows formats.*

**Pattern:**   `\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`
**Breakdown:** 
*   `[0-9A-Fa-f]{2}` = Exactly two hexadecimal characters
*   `[:-]` = Matches either a colon (Linux format) or a hyphen (Windows format)
*   `{5}` = Repeats the octet and separator 5 times
*   `[0-9A-Fa-f]{2}` = Matches the final two characters
**Matches:**   `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`
**SOC Log:**   `DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff via eth0`
**Engine:**    Both

---

### 12. Windows Event ID
> *Extracts Event IDs cleanly from unstructured Event Log entries. Critical IDs to know: 4624 (logon), 4625 (failed logon), 4688 (process creation), 4720 (account created).*

**Pattern:**   `(?i)EventID[=:\s]+(\d{3,5})`
**Breakdown:** 
*   `(?i)EventID` = Matches "EventID" (case-insensitive)
*   `[=:\s]+` = Matches one or more equals signs, colons, or spaces
*   `(\d{3,5})` = Captures the 3 to 5 digit Event ID into a group
**Matches:**   `EventID=4625`, `EventID: 4624`, `eventid 4688`
**SOC Log:**   `Message=An account failed to log on. EventID=4625`
**Engine:**    Both

---

### 13. User-Agent String
> *Malware, scanners, and automated tools often have unusual or generic User-Agent strings. Extracting them from proxy or web logs is a core SOC hunting task.*

**Pattern:**   `User-Agent:\s+([^\r\n]+)`
**Breakdown:** 
*   `User-Agent:\s+` = Literal string followed by one or more spaces
*   `([^\r\n]+)` = Captures one or more characters that are NOT a carriage return or newline. This grabs the entire User-Agent value without spilling into the next log field.
**Matches:**   `User-Agent: curl/7.68.0`, `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
**SOC Log:**   `GET /malware.sh HTTP/1.1 User-Agent: curl/7.68.0 Host: 10.10.10.5`
**Engine:**    PCRE (Splunk / Wazuh PCRE2)

---

### 14. HTTP Request Method
> *Useful for detecting unusual HTTP methods in web logs. PUT, DELETE, PATCH, and OPTIONS requests to sensitive paths can indicate exploitation. CONNECT indicates proxy tunneling (C2).*

**Pattern:**   `\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b`
**Breakdown:** 
*   `\b` = Word boundaries to prevent matching "FOR**GET**"
*   `(GET|POST...)` = Alternation group containing all standard HTTP methods
**Matches:**   `GET`, `POST`, `CONNECT`
**SOC Log:**   `192.168.1.10 - - "CONNECT evil.com:443 HTTP/1.1" 200`
**Engine:**    Both

---

### 15. Port Number (Field-Based)
> *Extracts the destination port from structured or semi-structured firewall/proxy logs.*

**Pattern:**   `(?i)(?:dport|dst_port|port)[=:\s]+(\d{1,5})`
**Breakdown:** 
*   `(?i)` = Case-insensitive
*   `(?:dport|dst_port|port)` = Non-capturing group matching common port field names
*   `[=:\s]+` = Delimiters (equals, colon, space)
*   `(\d{1,5})` = Captures 1 to 5 digits
**Matches:**   `dport=443`, `dst_port: 22`, `Port 8080`
**SOC Log:**   `Action=Deny src=10.0.0.5 dst=8.8.8.8 dport=53 proto=UDP`
**Engine:**    Both

---

### 16. Process Command Line (Suspicious Flags)
> *Catches obfuscation and LOLBin (Living off the Land Binaries) abuse. One of the most common detection use cases in a modern SOC.*

**Pattern:**   `(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32).*?(-enc|-nop|-w\s+hidden|-exec\s+bypass|\/c\s+|\/e\s+)`
**Breakdown:** 
*   `(powershell|cmd...)` = Captures the suspicious binary name
*   `.*?` = Lazy match for any characters between the binary and the flag
*   `(-enc|-nop...)` = Captures the suspicious flag (e.g., encoded command, hidden window, execution policy bypass)
**Matches:**   `powershell -ExecutionPolicy Bypass -File`, `cmd.exe /c calc.exe`
**SOC Log:**   `Process Create: powershell.exe -nop -w hidden -enc JABzAD...`
**Engine:**    PCRE (Splunk / Wazuh PCRE2)

---

### 17. CVE Identifier
> *Extracts vulnerabilities from threat intel feeds, vulnerability scanner outputs, or IDS/IPS alerts.*

**Pattern:**   `\bCVE-\d{4}-\d{4,7}\b`
**Breakdown:** 
*   `CVE-` = Literal string
*   `\d{4}` = The 4-digit year
*   `\d{4,7}` = The 4 to 7 digit sequence number
**Matches:**   `CVE-2021-44228`, `CVE-2023-23397`
**SOC Log:**   `[Priority: 1] ET EXPLOIT Apache Log4j Core JNDI Exploit Attempt (CVE-2021-44228)`
**Engine:**    Both

---

### 18. Timestamps (Syslog & ISO 8601)
> *Parsing timestamps lets you correlate events across different log sources.*

**Pattern (Syslog):**    `\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b`
**Pattern (ISO 8601):**  `\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b`
**Breakdown (ISO):**
*   `\d{4}-\d{2}-\d{2}T` = YYYY-MM-DDT
*   `\d{2}:\d{2}:\d{2}` = HH:MM:SS
*   `(?:\.\d+)?` = Optional milliseconds
*   `(?:Z|[+-]\d{2}:\d{2})?` = Optional timezone offset (Z or +/-HH:MM)
**Matches:**   `Oct 14 10:00:00`, `2023-10-14T10:00:00.123Z`
**SOC Log:**   `2023-10-14T10:00:00Z web-server-01 nginx: [error] access denied`
**Engine:**    Both

---

### 19. MIME Type
> *Helps detect content-type mismatches — a common indicator of file type masquerading (e.g., an executable served as text/html).*

**Pattern:**   `Content-Type:\s+([\w]+\/[\w\-\+\.]+)`
**Breakdown:** 
*   `Content-Type:\s+` = Literal string and spacing
*   `([\w]+` = Captures the primary type (e.g., application, text, image)
*   `\/` = Literal forward slash separator
*   `[\w\-\+\.]+)` = Captures the subtype (e.g., octet-stream, html, x-msdownload)
**Matches:**   `Content-Type: application/octet-stream`, `Content-Type: application/x-msdownload`
**SOC Log:**   `HTTP/1.1 200 OK Content-Type: application/x-msdownload Content-Length: 1042`
**Engine:**    PCRE

---

### 20. Encoded URL Characters (Percent-Encoding)
> *SQL injection, XSS, and path traversal attacks often use URL encoding to bypass WAFs. This targets 3 or more consecutive encoded sequences (like `%2e%2e%2f` which decodes to `../`).*

**Pattern:**   `(?:%[0-9A-Fa-f]{2}){3,}`
**Breakdown:** 
*   `%` = Literal percent sign
*   `[0-9A-Fa-f]{2}` = Two hexadecimal characters
*   `{3,}` = Looks for 3 or more consecutive instances of percent-encoded characters
**Matches:**   `%2e%2e%2f`, `%3C%73%63%72`
**SOC Log:**   `GET /images/logo.png?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1`
**Engine:**    Both

---

### Section 3: Quick Reference Table

| Pattern Target | Regex Reference | Primary Use Case |
| :--- | :--- | :--- |
| **IPv4 Address** | `\b\d{1,3}(?:\.\d{1,3}){3}\b` | Extracting basic IPs from logs. |
| **IPv6 Address** | `\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b` | Extracting uncompressed IPv6 addresses. |
| **MAC Address** | `\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b` | Correlating network devices in DHCP/NAC logs. |
| **Email Address** | `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`| Phishing investigations, mail gateway logs. |
| **URL / Domain** | `https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}...` | Extracting raw links from proxy/email. |
| **Suspicious Ext** | `(?i)\.(exe\|ps1\|bat\|vbs\|js\|dll\|scr\|hta)(?:\s\|"\|'\|$)`| Detecting executable payloads. |
| **File Hashes** | `\b[a-fA-F0-9]{32}\b` *(Use 64 for SHA256)* | Extracting MD5/SHA from Sysmon/EDR. |
| **Base64 String** | `\b(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}...` | Identifying encoded PowerShell/C2 payloads. |
| **Reg/Unix Paths** | `(?i)^(?:HKLM\|HKCU...)\\[a-zA-Z0-9_\\\s-]+` | Detecting persistence mechanisms. |
| **Event ID** | `(?i)EventID[=:\s]+(\d{3,5})` | Pulling specific Windows Event codes. |
| **User-Agent** | `User-Agent:\s+([^\r\n]+)` | Spotting automated scanners/malware. |
| **HTTP Method** | `\b(GET\|POST\|PUT\|DELETE\|CONNECT...)\b` | Hunting for tunneling or unauthorized PUTs. |
| **Port Number** | `(?i)(?:dport\|dst_port\|port)[=:\s]+(\d{1,5})` | Firewall log traffic flow analysis. |
| **LOLBin Flags** | `(?i)(powershell\|cmd).*?(-enc\|-nop|\/c\s+)` | Detecting malicious script execution. |
| **CVE Number** | `\bCVE-\d{4}-\d{4,7}\b` | Alert enrichment from IDS/IPS. |
| **MIME Type** | `Content-Type:\s+([\w]+\/[\w\-\+\.]+)` | Detecting malware served as benign files. |
| **URL Encoded** | `(?:%[0-9A-Fa-f]{2}){3,}` | Spotting WAF bypass, SQLi, and Path Traversal. |

***

