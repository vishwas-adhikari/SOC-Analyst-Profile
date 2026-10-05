
# SOC341 - Local Privilege Escalation via chroot (CVE-2025-32463)

## 🚨 Raw Alert Details
```text
EventID : 319
Event Time : 2025-07-04T08:10:00+03:00
Rule : SOC341 - Local Privilege Escalation via chroot CVE-2025-32463
Role : Incident Responder
Hostname : ubuntu-dev
Ip Address : 172.16.20.56
Process Name : bash
Process User : root
Device Action : Allowed
Trigger Reason : Detected suspicious use of 'sudo -R' inside Docker container, indicating potential CVE-2025-32463 exploitation
Process Command Line : sudo -R woot woot
```

## Alert Overview
- **Severity:** High
- **Detection Source:** EDR / SIEM
- **Asset Affected:** `ubuntu-dev` (172.16.20.56) / Docker Container
- **Threat Type:** Local Privilege Escalation (LPE) / Container Breakout / Persistence
- **Status:** True Positive (Compromised)

## 🧠 Deep Dive: Understanding CVE-2025-32463 (`sudo -R`)
**CVE-2025-32463** is a critical Local Privilege Escalation (LPE) vulnerability affecting `sudo` versions 1.9.14 through 1.9.17. 

**The Mechanics:** The vulnerability exists in how `sudo` handles the `-R` (chroot) flag. When an attacker creates a custom, fake directory structure containing maliciously crafted dynamically linked libraries (`.so` files) and passes it to `sudo -R`, `sudo` fails to drop privileges correctly before loading the libraries. The attacker forces the `sudo` process to execute their custom C code (`woot1337.c`) under the context of `root`. This allows a low-privileged user (like `devuser`) to instantly spawn a root shell, bypassing all password checks and environment restrictions.

## Investigation Steps

### 1. Initial Access Verification (SSH Brute Force)
The investigation began by tracing how the attacker gained initial access to the `ubuntu-dev` host.
- **Log Correlation:** Raw authentication logs revealed two consecutive `Failed password for devuser` attempts originating from `212.102.51.94` on Port 2222.
- **Successful Logon:** Immediately following the failures, an `Accepted password` log was generated for `devuser` from the same IP, confirming a successful brute-force/credential-stuffing attack.
- *Analyst Note: Port 2222 is non-standard for SSH, heavily indicating this traffic was destined for a Docker container port-mapped to the host.*

<img width="655" height="226" alt="image" src="https://github.com/user-attachments/assets/5e537c45-fded-41c4-a3bd-f1fe5710aeb1" />
<img width="642" height="222" alt="image" src="https://github.com/user-attachments/assets/bc6fc7b9-e5a2-472b-8b1c-90f3f7badcb0" />
<img width="688" height="248" alt="image" src="https://github.com/user-attachments/assets/8b80b67d-8b98-4e95-9617-3057dbe105c7" />


### 2. Payload Delivery & Exploitation (EDR Terminal History)
Once authenticated, the attacker's terminal history was captured by the EDR.
- **Payload Download (19:56:10):** The attacker used `wget` to pull the CVE-2025-32463 PoC exploit script directly from GitHub: `https://raw.githubusercontent.com/pr0v3rbs/CVE-2025-32463_chwoot/main/sudo-chwoot.sh`.
- **Preparation (19:56:40):** The attacker granted execution permissions: `chmod +x /home/devuser/sudo-chwoot.sh`.
- **Execution (19:57:10):** The script was executed, triggering the local privilege escalation.

<img width="652" height="275" alt="image" src="https://github.com/user-attachments/assets/90b35f75-e33e-4abc-ab51-e6ccdeba1014" />
<img width="1480" height="793" alt="image" src="https://github.com/user-attachments/assets/68603086-b997-4156-9d5f-cc8751152c80" />
<img width="1282" height="700" alt="image" src="https://github.com/user-attachments/assets/3e22eee5-ce10-478a-ad20-3870b9a3f2d8" />


### 3. Deep Forensics & Container Triage (Live VM Investigation)
Because the initial EDR logs indicated Docker activity (`docker run -d --name ubuntu-dev-env -p 2222:22`), I initiated an interactive shell on the host to investigate the specific container (`bcef94ac9312`).
- **Command:** `cat /home/devuser/.bash_history`
- **Exploit Artifacts:** The history revealed the raw exploit payload generation. The attacker used `cat > woot1337.c` to compile a C payload that sets User ID 0 (`setreuid(0,0)`) and executes `/bin/sh`.
- **LPE Execution:** The script concluded with `sudo -R woot woot`, confirming the CVE trigger.

<img width="1083" height="587" alt="image" src="https://github.com/user-attachments/assets/94b87215-5606-4f7a-a5fc-8012411df71b" />
<img width="958" height="492" alt="image" src="https://github.com/user-attachments/assets/ab21df0a-9fb8-48bd-9f2d-41f2d05cc896" />




### 4. Post-Exploitation Persistence (SSH Key Injection)
With `root` privileges secured inside the container, the attacker established persistence.
- **Action:** The attacker executed `mkdir -p /root/.ssh` and appended a public RSA key to `/root/.ssh/authorized_keys`.
- **Attacker Identity:** The appended SSH key contained the email address tag `apt@malwareee.com`. This ensures the attacker can seamlessly SSH back into the root account without needing a password.

<img width="1083" height="587" alt="image" src="https://github.com/user-attachments/assets/dde8c9c5-2fd7-4373-82be-6d5663777741" />
<img width="1061" height="103" alt="image" src="https://github.com/user-attachments/assets/211fad10-5c39-4ddb-91fe-ac2e87696720" />



## Analysis and Findings
The incident is a confirmed **True Positive**. The threat actor (`212.102.51.94`) gained Initial Access to a Docker container by brute-forcing SSH credentials on Port 2222. Once inside as `devuser`, the attacker downloaded an exploit script from GitHub targeting CVE-2025-32463. The attacker successfully compiled the payload and executed `sudo -R`, granting them `root` access. Finally, the attacker injected an SSH key for persistence. The container is completely compromised.

## MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | T1078 | Valid Accounts |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell |
| **Privilege Escalation**| T1068 | Exploitation for Privilege Escalation (CVE-2025-32463) |
| **Privilege Escalation**| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| **Persistence** | T1098.004 | Account Manipulation: SSH Authorized Keys |
| **Defense Evasion** | T1609 | Container Administration Command |

## Indicators of Compromise (IOCs)
| Type | Value | Context |
| :--- | :--- | :--- |
| IP Address | 212.102.51.94 | Attacker Initial Access IP (SSH) |
| URL | `https://raw.githubusercontent.com/pr0v3rbs/...` | Exploit Payload Delivery URL |
| Email / Tag | `apt@malwareee.com` | Attacker SSH Key Identifier |
| File Name | `sudo-chwoot.sh` | LPE Exploit Script |
| File Name | `woot1337.c` | Compiled LPE C Payload |

## 🛠️ Detection Engineering & Hunting Logic
To improve automated detection of this attack chain, the following logic should be implemented in the SIEM:
- **Detection 1 (CVE-2025-32463 Signature):** Alert when `Image="*\sudo"` AND `CommandLine` contains `-R` OR `--chroot`. (Legitimate use of `sudo` with chroot is exceedingly rare in standard dev environments).
- **Detection 2 (SSH Key Manipulation):** Alert on File Modify events targeting `*/.ssh/authorized_keys` combined with parent processes other than `sshd` or legitimate configuration management tools (e.g., Ansible).
- **Detection 3 (GitHub Scripting):** Alert when `wget` or `curl` are executed with URLs containing `raw.githubusercontent.com` piped to `chmod +x` or `sh`.

## 🚀 Decision Tree for Linux LPE Alerts
1. **Analyze Initial Vector:** Was there a recent authentication event (SSH) preceding the alert?
   - *Confirmed brute-force success.*
2. **Verify Exploit Execution:** Did the user download and execute scripts (e.g., `.sh`, `.c`) from external sources?
   - *Confirmed download of `sudo-chwoot.sh`.*
3. **Check Target Vulnerability:** Did the user attempt to execute `sudo` with specific, known-vulnerable flags (like `-R`)?
   - *Confirmed `sudo -R woot woot`.*
4. **Verify Privilege Escalation:** Following the exploit attempt, did the user perform actions restricted to `root` (e.g., modifying `/root/.ssh/authorized_keys` or accessing `/etc/shadow`)?
   - If Yes -> **Verdict: True Positive - Successful Root Compromise.**
5. **Action:** Eradicate persistence mechanisms, patch the vulnerable software, and isolate/destroy the compromised container.

## Response and Containment Actions Taken
- **Persistence Eradication:** Accessed the live terminal and manually removed the attacker's public key using `sed -i '/apt@malwareee.com/d' /root/.ssh/authorized_keys` to sever their backdoor access.
- **Container Isolation/Destruction:** Executed `docker stop bcef94ac9312` to halt the compromised environment, followed by `docker rm bcef94ac9312` to completely destroy the infected container.
- **Why:** In containerized environments, "Containment" often means entirely destroying the compromised ephemeral instance and spinning up a clean, patched image.

## Recommendations
1. **Immediate Patching (`sudo`):** Update the base Linux images for all Docker containers to ensure `sudo` is patched against CVE-2025-32463 (Version > 1.9.17).
2. **Password Policies & SSH Hardening:** The root cause of the breach was a weak password for `devuser`. Disable password-based SSH authentication entirely across all environments and mandate Key-Based Authentication only.
3. **Egress Filtering:** Block or restrict containers from making outbound connections to file-sharing sites and GitHub (`raw.githubusercontent.com`) unless explicitly required for the application's function.


## ⚖️ Mistakes and Lessons Learned
- **Analyst Reflection (Playbook vs. Live Forensics):** During the automated playbook phase, I flagged that **Persistence** had occurred because my manual live-machine forensics revealed the attacker injected an RSA key into `/root/.ssh/authorized_keys`. However, the automated playbook graded this as "None" because it strictly checks for account creation (`useradd`) or scheduled tasks. 
- **The Lesson:** This highlights the critical gap between EDR process telemetry and raw system forensics. Automated playbooks often miss file-level persistence mechanisms (like SSH keys or web shells) if they don't spawn a flagged process. An analyst must trust their live-system forensic findings over automated checklist definitions to fully eradicate a threat.

- **Analyst Reflection (MITRE Tactics Categorization):** I initially categorized the Privilege Escalation phase as "Valid Accounts" because the attacker logged in as `devuser`. 
- **The Lesson:** I conflated the **Initial Access** phase with the **Privilege Escalation** phase. "Valid Accounts" (T1078) is how the attacker gained their initial foothold. However, the actual escalation to root was achieved via a vulnerability (CVE-2025-32463), making the correct MITRE classification **Exploitation for Privilege Escalation (T1068)**. Maintaining strict delineation between the phases of the Cyber Kill Chain is vital for accurate threat modeling. 

## 🛠️ Skills & Tools Used
- **Linux Forensics:** Reviewing `.bash_history`, SSH `authorized_keys` management, and container execution.
- **Docker Administration:** Identifying, stopping, and removing compromised Docker instances (`docker stop / rm`).
- **Vulnerability Triage:** Understanding `sudo` privilege escalation mechanics (CVE-2025-32463).
- **Incident Eradication:** Utilizing `sed` to programmatically remove persistent backdoors from live environments.
