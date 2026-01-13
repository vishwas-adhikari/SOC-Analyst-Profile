

# 📘 SOC Analyst Handbook: Antivirus (AV)

**Category:** Endpoint Security
**Severity:** Variable (Low for Adware -> Critical for Ransomware)
**Skill Level:** Core / Fundamental

---

### 1. The Concept

**The Analogy (ELI5)**
*   **Signature Scanning:** Think of a security guard holding a stack of "Wanted" posters. He looks at every person entering. If a person's face matches a poster perfectly, they are stopped. If the criminal puts on a fake mustache (changes the file hash), the guard lets them in.
*   **Heuristic Scanning:** The guard stops looking at faces and looks at *intent*. If he sees someone hiding a crowbar under their coat or sweating nervously (suspicious code structure), he stops them, even if he doesn't know who they are.

**The Technical Definition**
**Antivirus (AV)** is a software solution designed to prevent, detect, and remove malicious software. It operates primarily using **Signatures** (databases of known malicious byte sequences/hashes) and **Heuristics** (static analysis of code structure) to catch threats before they execute. Unlike EDR, AV is usually "prevent-first" and offers less visibility into *what* happened, focusing only on *stopping* it.

---

### 2. The Mechanism (Scanning Types)

1.  **Signature-Based (The Old Standard):**
    *   The AV vendor (McAfee, Symantec) analyzes malware, generates a unique Hash (MD5/SHA256) or byte string, and pushes it to your PC.
    *   *Pro:* Fast and accurate for known threats.
    *   *Con:* Completely blind to zero-day attacks or slightly modified malware (polymorphic).
2.  **Heuristic / Static Analysis:**
    *   The AV scans the code *before* it runs. It looks for commands like "Open Internet Connection" + "Write to System32".
    *   *Pro:* Can catch new/unknown malware.
    *   *Con:* Higher False Positive rate (might block legitimate Admin tools).
3.  **Real-Time Protection (RTP):**
    *   Scans files the moment they are created, opened, or copied. This is the "On-Access" scanner.

---

### 💥 3. Impact Analysis

1.  **System Cleanup:** If effective, the impact is zero (threat removed).
2.  **Quarantine Loop:** If the AV deletes a virus but not the *dropper* (the script creating the virus), the system enters a loop of "Infection -> Delete -> Reinfection," consuming resources.
3.  **False Positives:** AV deleting a critical business file (dll/exe) can crash production applications.

---

### 4. The Detective's Lens (Logs & Patterns)

You don't need to hunt for AV alerts; they are pushed to you. Your job is to check the **Action Taken**.

#### **Key Log Fields**
*   **Threat Name:** `Trojan.Gen`, `Ransom.WannaCry`, `Adware.Toolbar`.
*   **Path:** `C:\Users\Downloads\` (User error) vs. `C:\Windows\System32\` (Deep infection).
*   **Action:**
    *   `Cleaned` / `Quarantined` / `Deleted` (Good).
    *   `Failed` / `Left Alone` / `Access Denied` (BAD).

![log example](../../assets/av_logs.png)

#### **Example Log Snippet (JSON)**
```json
{
  "timestamp": "2023-11-05T08:15:00Z",
  "host": "FINANCE-PC-01",
  "product": "Symantec Endpoint Protection",
  "event": "Malware Found",
  "file_path": "C:\\Users\\John\\AppData\\Local\\Temp\\update_installer.exe",
  "threat_name": "Trojan.Emotet.Gen",
  "action": "Quarantine Failed",
  "status": "Infected"
}
```
*   **Analysis:**
    *   **Threat:** Emotet (High severity Trojan).
    *   **Location:** AppData/Temp (Classic malware staging area).
    *   **Action:** **Quarantine Failed**.
    *   **Verdict:** **Critical.** The AV tried to stop it but failed (maybe the file was in use or permissions locked). The host is likely compromised.

---

### 🌳 5. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Nuisance)**
    *   `Threat: Adware/PUA` + `Action: Quarantined` + `Source: Browser Cache`
    *   *Action:* It's just a popup blocker or toolbar. Clear browser cache.

*   **🟡 Medium Priority (Successful Block)**
    *   `Threat: Trojan/Backdoor` + `Action: Quarantined`
    *   *Action:* AV did its job. Check *how* it got there (Phishing email? USB?).

*   **🔴 High Priority (Action Failed)**
    *   `Threat: Any Malware` + `Action: Failed / Access Denied`
    *   *Action:* **Isolate Host.** The malware is running and fighting back.

*   **🟣 Critical Priority (Outbreak)**
    *   `Threat: Ransomware` + `Multiple Hosts`
    *   *Action:* **Disconnect Network.** Mass infection in progress.

---

### 6. Investigation Steps (The Playbook)

**Step 1: Check the Action Status**
*   Did the AV win?
*   *Success:* Investigation is "Post-Mortem" (finding the root cause).
*   *Failure:* Investigation is "Live Response" (Stopping the bleeding).

**Step 2: Check the Hash (VirusTotal)**
*   Copy the file hash from the log.
*   Search it on VirusTotal.com.
*   *Result:* If 50/60 vendors flag it, it's malware. If only 1/60 flags it, it might be a False Positive.

**Step 3: Check the File Path**
*   **User Downloads:** User likely downloaded it.
*   **Temp/AppData:** Malware dropping itself.
*   **System32/Windows:** Malware trying to establish persistence or rootkit.

**Step 4: Check Frequency**
*   Is this alert firing every 5 seconds?
*   This indicates a **Persistence Mechanism**. The AV cleans the file, but a scheduled task or registry key recreates it immediately.

---

### 💻 7. Code Lab: Signature vs. Heuristic

Understanding the difference in how AV "thinks."

```python
# 1. SIGNATURE DETECTION (Exact Match)
# The AV has a list of "Bad Hashes"
database = ["a1b2c3d4...", "e5f6g7h8..."]

file_hash = calculate_md5("suspicious_file.exe")

if file_hash in database:
    print("ALERT: Known Malware Detected!")
    delete_file()
else:
    print("File is safe.") # <-- Vulnerable if the hacker changes 1 byte!
```

```python
# 2. HEURISTIC DETECTION (Behavior/Pattern)
# The AV looks for "Suspicious logic"
file_content = read_file("suspicious_file.exe")

risk_score = 0

if "OpenNetworkConnection" in file_content:
    risk_score += 10
if "WriteToSystem32" in file_content:
    risk_score += 50
if "EncryptFiles" in file_content:
    risk_score += 100

if risk_score > 80:
    print("ALERT: Suspicious Behavior Detected!")
    quarantine_file()
```

---

### 8. Remediation & Defense

**Immediate Actions (SOC)**
1.  **Full Scan:** If a threat was found, trigger a "Full System Scan" on that host to catch remnants.
2.  **Isolate:** If the logs show "Action Failed," disconnect the machine immediately.
3.  **Delete Email:** If the source was an email attachment, search for that email subject in the Mail Server and delete it from *all* other users' inboxes.

**Long-term Fixes (Engineering)**
1.  **Update Signatures:** Ensure endpoints are checking for updates hourly.
2.  **Exclusions:** Don't scan Database files or large Log files (causes performance issues). Exclude them carefully.

---

### 🛑 SOC Pro-Tips (Beyond the Basics)

1.  **PUA vs. Malware:**
    *   **PUA (Potentially Unwanted Application):** Things like "Game Cheats," "Crypto Miners," or "PC Speed Up Tools."
    *   They aren't *viruses*, but they introduce risk.
    *   *Policy:* Decide if your company blocks PUAs. Usually, yes.

2.  **The "Compressed File" Trap:**
    *   AV often cannot scan inside a password-protected ZIP file.
    *   The alert won't trigger until the user *unzips* the file. This is why email filters often block encrypted zips.

3.  **False Positives on Admin Tools:**
    *   Tools like `PsExec`, `Nmap`, or `Wireshark` are flagged by AV as "HackTools."
    *   If you see this on an Admin's PC, it's likely fine. If you see `Nmap` on a Receptionist's PC, it's a compromised host.

---

### TL;DR for Interviews / Quick Recall
*   **What:** Software to detect/remove malware using Signatures and Heuristics.
*   **Signatures:** Database of known bad file hashes. Fast, but misses new attacks.
*   **Heuristics:** Behavioral analysis. Catches new attacks, but higher False Positives.
*   **Critical Log:** **"Action Failed"** or **"Access Denied"** (Means the infection is active).
*   **Response:** If Quarantined -> Investigate Source. If Failed -> Isolate Host.
*   **Blind Spot:** Encrypted files (Zips/PDFs) and Fileless Malware (Memory-only attacks).

### 🎯 MITRE ATT&CK Mapping
*   **T1562.001:** Impair Defenses: Disable or Modify Tools (Malware killing the AV).
*   **T1204.002:** User Execution: Malicious File.
*   **T1027:** Obfuscated Files or Information (Using packers to change the signature).