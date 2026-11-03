

# 📘 SOC Analyst Handbook: Server-Side Template Injection (SSTI)

**Category:** Web Application Security / Injection
**Severity:** Critical (Leads to RCE)
**Skill Level:** Advanced

---

### 1. The Concept (What & Why)

**The Analogy (ELI5)**
Imagine a "Fill-in-the-Blanks" welcome letter generator. 
*   **Normal:** The letter says "Hello `[Name]`." You type "John", and the machine prints "Hello John."
*   **SSTI:** You type `[System.Print(All_Passwords)]`. Instead of printing the literal text you typed, the machine gets confused, thinks your text is an internal instruction, and prints the passwords on the letter.

**The Technical Definition**
Web applications use **Template Engines** (like Jinja2 for Python, Twig for PHP, or Freemarker for Java) to separate HTML design from backend data. 
**Server-Side Template Injection (SSTI)** occurs when an attacker injects native template syntax into a user input field, and the server unsafely embeds that input directly into a template and evaluates it. Because the template engine runs on the server, the attacker can execute arbitrary code on the backend server, leading to **Remote Code Execution (RCE)**.

**🚨 Interview Gold: SSTI vs. XSS**
*   **XSS (Cross-Site Scripting):** Malicious code (`<script>`) is sent by the server and executed in the **Victim's Browser**.
*   **SSTI:** Malicious code (`{{7*7}}`) is executed by the **Web Server** itself before the page is ever sent to the browser. 

---

### 2. The Attack Mechanism

#### **How it works**
1.  **Vulnerable Code:** A developer takes user input and passes it to a rendering function *without* sanitizing it.
2.  **The Probe:** An attacker wants to know if the site uses a template engine. They input a mathematical equation wrapped in template syntax: `{{ 7 * 7 }}`.
3.  **The Result:** If the webpage returns the text `49`, the attacker knows they have found an SSTI vulnerability. The server actually executed the math!
4.  **The Exploit:** The attacker changes the payload to something malicious, like `{{ config.items() }}` (to dump secret server keys) or `{{ system('whoami') }}` to run OS commands.

---

### 3. The Detective's Lens (Logs & Patterns)

As a SOC Analyst, you are hunting for **Template Syntax Characters** in URL parameters or HTTP POST bodies. 

#### **Key Indicators (The Syntax)**
Template engines use specific character combinations to define variables. Look for these brackets combined with math or system commands:
*   `{{ ... }}` (Jinja2, Twig, Vue)
*   `${ ... }` (Freemarker, Java)
*   `<%= ... %>` (ERB, Ruby)
*   `[[ ... ]]`
*   `#{ ... }`

<img width="1077" height="144" alt="image" src="https://github.com/user-attachments/assets/9f2db4e5-ab3c-4309-b778-8ad8484666dc" />


#### **Example Log Snippet (Nginx)**
```text
203.0.113.3 - - [15/Apr/2023:15:10:05] "GET /greet?name=%7B%7B%20config.items()%20%7D%7D HTTP/1.1" 200 4502 "-" "Mozilla/5.0..."
203.0.113.3 - - [15/Apr/2023:15:12:35] "GET /admin?name=%7B%7B1%2B2%7D%7D HTTP/1.1" 500 234 "-" "Mozilla/5.0..."
```
*   **Log 1 Analysis:** 
    *   **Payload:** `%7B%7B` decodes to `{{`. The full payload is `{{ config.items() }}`.
    *   **Status 200 OK:** The server executed it successfully. **Data Breach!**
*   **Log 2 Analysis:**
    *   **Payload:** `{{1+2}}`.
    *   **Status 500 Error:** The server crashed while trying to evaluate the payload. The attack failed, but the vulnerability likely exists.

---

### 4. Investigation Steps (The Playbook)

**Step 1: Decode & Identify the Engine**
*   Extract the payload and URL-decode it. 
*   If you see `${ }`, it's likely a Java backend. If you see `{{ }}`, it's likely Python/PHP. 

**Step 2: Determine Success (Status Codes)**
*   **200 OK:** Highly critical. If the payload was `{{7*7}}`, check the response size (`rcvdbyte`). If the attacker injected OS commands, the server responded successfully.
*   **500 Internal Error:** The attacker made a syntax error in the template language, crashing the render engine. Monitor the IP closely; they are actively testing exploits.

**Step 3: Check for Exfiltration / Out-of-Band (OOB) Traffic**
*   SSTI often results in RCE. 
*   *Action:* Check your Firewall/NetFlow logs for the Web Server. Did it make an outbound connection to an unknown IP right after the 200 OK log? 

---

### 💻 5. Code Lab: Vulnerable vs. Secure

Understanding why this happens on the backend.

```python
# ❌ VULNERABLE CODE (Python/Flask)
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # Flaw: The raw user input is compiled directly into the template!
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template) 
```

```python
# ✅ SECURE CODE (Input Validation)
import re
from flask import Flask, request, render_template_string, abort
app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    
    # Fix: Validate input. Only allow alphanumeric characters.
    if not re.match("^[a-zA-Z0-9_]*$", name):
        abort(400, "Invalid characters in name parameter")
        
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)
```
*   **The Best Fix:** Never pass user input to `render_template_string`. Instead, pass the data as a *variable* to a static template file (e.g., `render_template('index.html', name=name)`). 

---

### 🌳 6. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Blocked Noise)**
    *   `WAF Action: Blocked` + `Payload: {{7*7}}`
    *   *Action:* Ignore. Automated scanner checking for SSTI.
*   **🟡 Medium Priority (Vulnerability Confirmed, Exploit Failed)**
    *   `Status: 500 Error` + `Payload: {{ system('ls') }}`
    *   *Action:* The attacker proved the site is vulnerable but broke the syntax. Patch the app immediately before they figure it out.
*   **🔴 High Priority (Data Leak)**
    *   `Status: 200 OK` + `Payload: {{ config.items() }}`
    *   *Action:* **Incident.** The attacker dumped the server configuration/keys. Rotate all secrets and API keys on that server.
*   **🟣 Critical Priority (Remote Code Execution)**
    *   `Status: 200 OK` + `Payload: import os; os.popen('whoami')`
    *   *Action:* **Isolate Server.** The attacker has terminal access to the web server.

---

### 7. Remediation & Defense

**Immediate Actions (SOC)**
1.  **Block the IP.**
2.  **SIEM Regex:** Implement this Regex in your SIEM to catch basic SSTI attempts in URLs: `\{\{.*?\}\}` (Catches anything between double curly braces).
3.  **WAF Tuning:** Ensure your WAF explicitly blocks template syntax characters in user-input fields.

**Long-term Fixes (Engineering)**
1.  **Context-Specific Escaping:** Ensure the template engine strips out HTML/Template tags before rendering.
2.  **Sandboxing:** If you *must* allow users to edit templates (e.g., Shopify themes), run the template engine in a restricted Docker container with no access to the host OS.

---

### 🎯 8. MITRE ATT&CK Mapping
*   **T1190:** Exploit Public-Facing Application.
*   **T1059:** Command and Scripting Interpreter (If OS commands are executed via SSTI).
*   **T1082:** System Information Discovery (Using `config.items()` to dump environment variables).
