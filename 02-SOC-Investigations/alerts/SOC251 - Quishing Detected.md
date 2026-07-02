

# SOC251 - Quishing Detected (QR Code Phishing) 

## Alert Overview
- **Severity:** Medium
- **Detection Source:** Email Security Gateway
- **Asset Affected:** Claire (172.16.20.3 - Exchange Server)
- **Threat Type:** Quishing (QR Code Phishing) / Credential Harvesting
- **Status:** True Positive

## Strategy and Technical Context
"Quishing" (QR Code Phishing) is a tactical evolution designed to bypass modern email security gateways. Secure Email Gateways (SEGs) are excellent at scanning hyperlinks and attachments. However, they struggle to parse and analyze URLs embedded within an image (a QR code). 

The attacker's strategy here is twofold: 
1. **Gateway Evasion:** Use a QR code image to hide the malicious URL from the corporate firewall.
2. **Cross-Device Execution:** Force the user to move the attack from a heavily monitored corporate endpoint (a laptop) to a less-monitored, potentially unmanaged device (a personal smartphone) by scanning the code with their camera.

## Brief about the Concept
The attack utilizes a classic urgency-based social engineering lure, disguised as an IT department mandate (`New Year's Mandatory Security Update: Implementing Multi-Factor Authentication`). The email instructs the user to scan the attached QR code to set up their MFA. If successful, the QR code redirects the user to a spoofed Microsoft login page hosted on a decentralized network (`ipfs.io`) to harvest their corporate credentials.

## Investigation Steps

### 1. Email Triage and Sender Verification
The investigation began by reviewing the flagged email sent to `claire@letsdefend.io`.
- **Sender Address:** `security@microsecmfa.com`
- **Sender IP:** 158.69.201.47
- **Device Action:** Allowed
- **Subject:** *New Year's Mandatory Security Update: Implementing Multi-Factor Authentication (MFA)*
- **Finding:** The domain `microsecmfa.com` is an unauthorized, typosquatted domain attempting to masquerade as legitimate Microsoft/IT infrastructure. 

### 2. QR Code Decoding and URL Analysis
The QR code image embedded in the email body was extracted and decoded.
- **Hidden Payload URL:** `https://ipfs[.]io/ipfs/Qmbr8wmr41C35c3K2GfiP2F8YGzLhYpKpb4K66KU6mLmL4#`
- **Analysis:** The attacker utilized the InterPlanetary File System (IPFS) network. Threat actors frequently host phishing pages on IPFS because its decentralized nature makes it incredibly difficult for security teams to issue takedown requests. The URL was queried against VirusTotal and confirmed malicious by multiple vendors.

### 3. Threat Intelligence Enrichment
The Sender IP (`158.69.201.47`) was analyzed using external threat intelligence platforms. 
- **Finding:** VirusTotal and other vendors classified the IP as a known malicious source associated with phishing campaigns and spam distribution.

### 4. Endpoint Verification (Scope Assessment)
Internal Log Management and EDR telemetry were reviewed to determine the scope of the attack.
- **Log Correlation:** The email reached the Exchange Server (`172.16.20.3`), confirming delivery.
- **Endpoint Triage:** A review of Claire's workstation showed no suspicious browser history, network connections, or command executions related to the IPFS URL. 

## Analysis and Findings
The incident is a confirmed **True Positive**. The user received a highly deceptive spear-phishing email utilizing QR code obfuscation. While the EDR logs on the corporate workstation appear clean, the unique nature of Quishing means the payload (the malicious URL) was designed to be executed on a *secondary device* (the user's mobile phone). Therefore, a clean workstation log does not guarantee the user's credentials were not compromised via their smartphone.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link (via QR Code) |
| **Defense Evasion** | T1027 | Obfuscated Files or Information (Steganography/Image Obfuscation) |
| **Credential Access** | T1056 | Input Capture (Credential Harvesting via Fake Login) |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| Domain | `microsecmfa.com` | Spoofed IT/Security Domain |
| URL | `https://ipfs[.]io/ipfs/Qmbr8wmr41...` | Malicious IPFS Phishing Page |
| IP Address | 158.69.201.47 | Malicious Sender SMTP IP |
| Email | `security@microsecmfa.com` | Phishing Sender Address |

## Blind Spots
- **The "Air Gap" Execution:** Because the user is expected to scan the QR code with a mobile device, the actual execution of the malicious URL happens off the corporate network entirely (often over a cellular 4G/5G connection). Corporate SIEMs and web proxies have zero visibility into this traffic.

## Mistakes and Lessons Learned
- **The Error (Failed Containment):** Initially, I decided *not* to contain the endpoint because the EDR logs (browser history/network action) showed no interaction with the malicious URL.
- **The Lesson:** In a "Quishing" scenario, a clean EDR log is a false sense of security. If the user scanned the code with their personal phone, they may have entered their corporate credentials into the fake Microsoft portal. If those credentials are stolen, the attacker can use them to access corporate resources (like O365, VPN, or the Exchange server) regardless of whether the user's laptop is "clean." Containment and an immediate password reset are mandatory when dealing with credential-harvesting attacks.

## Response and Closure
- **Action Taken:** The malicious email was deleted from Claire's inbox and purged from the Exchange server to prevent other users from interacting with it. The host was eventually **Contained**.
- **Containment Required:** Yes. (To mitigate potential lateral movement using stolen credentials).
- **Closure Reason:** True Positive. Phishing attack via QR code successfully delivered, requiring credential security protocols.

## Recommendations
1. **Mandatory Password Reset:** Immediately force a password reset for the user `claire@letsdefend.io`, as it is currently unknown if she provided her credentials via her mobile device.
2. **Mobile Device Triage (Tier 2):** Escalate to Tier 2 / IT Support to investigate the user's mobile device (if it is corporate-managed) and interview the user to determine if they scanned the code.
3. **Email Gateway Upgrade:** Ensure the Secure Email Gateway (SEG) utilizes Optical Character Recognition (OCR) and computer vision capabilities. These features allow the gateway to scan images, extract embedded QR codes, and analyze the resulting URLs before delivering the email.
4. **IPFS Blocking:** Unless there is a strict business requirement, block access to IPFS gateways (`ipfs.io`) at the corporate perimeter, as they are heavily abused for decentralized malware hosting.

## Evidence / Screenshots
<img width="369" height="138" alt="image" src="https://github.com/user-attachments/assets/b6f5e5d5-4eff-4aaa-8664-6e3413a9f1ff" />
<img width="700" height="289" alt="image" src="https://github.com/user-attachments/assets/4ff9c677-598b-4504-bcd0-df66f6986719" />
<img width="757" height="177" alt="image" src="https://github.com/user-attachments/assets/a4adb294-fe62-4585-be01-b92ead44a7ae" />




## Skills & Tools Used
Phishing Header Analysis, QR Code Decoding/Deobfuscation, OSINT (VirusTotal), Threat Modeling (Cross-Device Execution), Incident Containment, MITRE ATT&CK Mapping.
