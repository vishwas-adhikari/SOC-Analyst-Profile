# Section 1: Regex Fundamentals

### What Regex is and Why SOC Analysts Use It
Regular Expressions (Regex) are programmatic sequences of characters used to identify and isolate specific text patterns. In SIEM environments (Splunk, Wazuh, Elastic), SOC analysts use regex for two primary functions:

*   **Detection & Filtering:** Scanning raw logs to find malicious indicators (e.g., identifying command injection characters or encoded payloads) to trigger alerts.
*   **Field Extraction:** Transforming unstructured log text into structured, searchable data (e.g., pulling a dynamic IP address out of a syslog message and assigning it to a `src_ip` field).

### How a Regex Engine Reads a Pattern
Understanding the engine's behavior is critical for writing performant SIEM queries.
*   **Left to Right:** The engine processes the log line character by character, strictly from left to right.
*   **Greedy by Default:** Quantifiers (like `*` or `+`) will match the longest possible string. *Note: In log analysis, unchecked greediness causes severe SIEM performance degradation.*
*   **Backtracking:** If a match fails mid-pattern, the engine steps backward to previous tokens to try alternative paths. Poorly written regex can cause "catastrophic backtracking," crashing search queries.

### Literal vs Metacharacter
*   **Literal Characters:** Characters that match themselves exactly. The pattern `admin` will only match the exact string "admin".
*   **Metacharacters:** Characters with special programmed meaning (e.g., `.` `*` `+` `?` `^` `$`). 
*   **Escaping:** To match a metacharacter as a literal string (like searching for a file extension `.exe` or an IP address `10.0.0.1`), you must "escape" it using a backslash `\`.

**Example: Escaping Metacharacters**
*   **Pattern:**   `10\.0\.0\.1`
*   **Breakdown:** `10` (literal 10) + `\.` (escaped dot matching a literal period) + `0` (literal 0) + `\.` (escaped dot) + `0` (literal 0) + `\.` (escaped dot) + `1` (literal 1).
*   **Matches:**   `10.0.0.1`
*   **SOC Log:**   `Connection established from 10.0.0.1 on port 443`
*   **Engine:**    PCRE (Splunk) / POSIX ERE (Wazuh) / Both

*(Note: If left unescaped, `10.0.0.1` acts as a wildcard and would falsely match `10A0B0C1`)*

### Case Sensitivity and Flags
By default, regex engines are strictly case-sensitive. `Admin` does not equal `admin`. To handle attacker obfuscation (e.g., `cMd.ExE`), analysts use inline flags.

*   **`(?i)` (Case Insensitive):** Ignores capitalization for the remainder of the pattern.
*   **`(?m)` (Multiline):** Changes the behavior of the `^` (start) and `$` (end) anchors to match the start and end of *lines* rather than the entire log event string.
*   **`(?s)` (Dotall):** Forces the `.` metacharacter to match newline characters (useful for multi-line Windows Event logs).

**Example: Case Insensitive Matching**
*   **Pattern:**   `(?i)powershell\.exe`
*   **Breakdown:** `(?i)` (case-insensitive flag) + `powershell` (literal string) + `\.` (escaped dot) + `exe` (literal string).
*   **Matches:**   `POWERSHELL.EXE`, `PowerShell.exe`, `powershell.exe`
*   **SOC Log:**   `Process Create: C:\Windows\System32\WindowsPowerShell\v1.0\PoWeRShElL.ExE`
*   **Engine:**    PCRE (Splunk) / PCRE2 (Wazuh)

***



<img width="731" height="684" alt="image" src="https://github.com/user-attachments/assets/7ae85716-dcc4-43ab-ab2c-bf1dcb0108b8" />
<img width="735" height="683" alt="image" src="https://github.com/user-attachments/assets/ed19edea-452a-4b53-8a75-de442bc9ed82" />


