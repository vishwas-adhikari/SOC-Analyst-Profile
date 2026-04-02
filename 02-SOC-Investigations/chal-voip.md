# VoIP Vishing Investigation — Case #VOIP-702

## Alert Overview
- Severity: High
- Detection Source: User Report (James) / Network Traffic Capture (PCAP)
- Asset Affected: Internal VoIP Workstation (192.168.245.128)
- Threat Type: Vishing (Voice Phishing) / Social Engineering
- Status: True Positive

## Brief about the Concept
VoIP (Voice over Internet Protocol) relies on two primary protocols: SIP (Session Initiation Protocol) and RTP (Real-time Transport Protocol). SIP is the signaling protocol used to initiate, manage, and terminate calls. RTP is the transport protocol used to deliver the actual audio data. Vishing (Voice Phishing) occurs when an attacker uses these technologies to impersonate a trusted entity (such as a bank) to deceive victims into surrendering sensitive personal information, such as Social Security Numbers (SSN) or account credentials.

## Investigation Steps

### 1. SIP Signaling Analysis
The investigation began by filtering for SIP traffic to identify the call establishment phase.
- **Action:** Applied the `sip` filter in Wireshark and adjusted the Time Display Format to "Date and Time of Day."
- **Finding:** The call was initiated on **2024-05-03 at 20:36:36**. Frame #5 showed an INVITE request from the source IP 192.168.245.1 to the destination IP 192.168.245.128.

### 2. Caller and Recipient Identification
By examining the SIP "To" and "From" headers, the involved parties were identified.
- **Recipient (James):** Extension **7001** (192.168.245.128).
- **Caller (Bank Impersonator):** Number **01326947697** (192.168.245.1).
- **User-Agent:** The attacker utilized **MicroSIP/3.21.3**, a common softphone application.

### 3. RTP Stream Triage
To quantify the amount of audio data captured, the traffic was filtered for the media stream.
- **Action:** Applied the `rtp` filter.
- **Finding:** A total of **8,799 RTP packets** were identified, confirming a substantial amount of audio data was exchanged.

### 4. VoIP Call Metadata
Utilizing Wireshark’s built-in Telephony tools, I generated an overview of the session.
- **Action:** Accessed `Telephony > VoIP Calls`.
- **Finding:** The call duration was **00:01:35** (95 seconds). The state was marked as "COMPLETED," indicating the session was successfully established and terminated normally.

### 5. Audio Reconstruction and Content Analysis
To confirm the malicious nature of the call, I utilized the RTP Player over a Remote Desktop Protocol (RDP) connection to reconstruct the audio.
- **Action:** Selected the stream in the VoIP Calls window and clicked "Play Streams."
- **Observation:** The attacker identified themselves as being from **Global Trust Bank**. During the conversation, the attacker successfully manipulated the victim into divulging his **Social Security Number**.

## Analysis & Findings
The investigation confirms a successful Vishing attack against the user James. The attacker (192.168.245.1) spoofed a banking entity and utilized a softphone (MicroSIP) to establish a 95-second call. The signaling logs show a legitimate handshake (INVITE -> 100 Trying -> 180 Ringing -> 200 OK), and the reconstructed RTP stream provides definitive evidence of the theft of a Social Security Number. The duration of the call and the victim's compliance indicate a high-impact security breach of personal identifiable information (PII).

## Indicators of Compromise

| Type | Value | Context |
|------|------|--------|
| IP | 192.168.245.1 | Source IP of the Vishing caller. |
| Phone Number | 01326947697 | Malicious "Bank" caller ID. |
| Phone Number | 7001 | Victim extension (James). |
| User-Agent | MicroSIP/3.21.3 | Tool used by the attacker to initiate the call. |

## Decision Tree for VoIP Vishing Scenarios
1. **Identify SIP Signaling:** Is there an INVITE request?
   - If Yes -> Identify Caller/Callee info.
2. **Verify User-Agent:** Is it a standard office phone or a softphone (e.g., MicroSIP, Zoiper)?
   - Softphones are common in both legit and malicious external calls.
3. **Analyze RTP Flow:** Are there RTP packets associated with the SIP Call-ID?
   - If No -> Ghost call/Scanned.
   - If Yes -> Proceed to reconstruction.
4. **Content Analysis (Audio):** Does the caller ask for PII (SSN, Passwords, PINs)?
   - If Yes -> Verdict: True Positive - Vishing/PII Theft.

## Response & Closure
- **Action Taken:** Extracted SIP metadata, calculated packet volume, and reconstructed audio to verify social security number theft. 
- **Containment Required:** Yes. The victim (James) must be notified immediately to contact credit bureaus and his actual financial institution.
- **Closure Reason:** True Positive. Confirmed Vishing attack leading to PII exfiltration.

## Recommendations
1. **Security Awareness Training:** Conduct organization-wide training focusing on Vishing and Social Engineering, emphasizing that banks will never ask for a full SSN over the phone.
2. **Caller ID Verification:** Implement STIR/SHAKEN protocols if applicable to the environment to reduce the effectiveness of caller ID spoofing.
3. **VoIP Network Segmentation:** Ensure the VoIP VLAN is strictly segmented from the data VLAN and monitor for unauthorized softphone User-Agents within the network.
4. **Identity Protection:** For the victim (James), recommend a credit freeze and monitoring of his Social Security Number via identity theft protection services.

## Evidence
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/5f702ebd-fcda-44e4-9c2e-f138587540e1" />
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/36f8d271-f998-42dc-aaee-72200694780c" />
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/0254f0a0-42f4-4f8c-a119-e519a86c9c9d" />
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/2d09849b-9bc6-4401-a985-aad15c8e96c7" />


## Skills & Tools Used
Wireshark, PCAP Analysis, Network Forensics, VoIP/SIP Signaling Analysis, RTP Audio Reconstruction, RDP, Social Engineering Triage.

