# Section 2: Core Syntax Cheat Sheet

This section provides a quick-reference table for standard regex operators. Use these building blocks to construct complex detection and extraction rules.

### Core Symbols
| Symbol | Meaning | Example | Matches |
| :--- | :--- | :--- | :--- |
| `.` | Any single character (except newline) | `c.d` | cmd, c-d, c1d |
| `\` | Escapes a metacharacter to treat it as a literal | `10\.0` | 10.0 |
| `\|` | Alternation (Logical OR) | `exe\|bat` | exe, bat |
| `()` | Capturing group (Saves matched data to memory/field) | `(admin\|root)` | admin, root |
| `(?:)` | Non-capturing group (Groups logic but saves memory) | `(?:admin\|root)`| admin, root |
| `[]` | Character set (Matches ANY ONE character inside) | `[a-z]` | a, b, c... z |
| `[^]` | Negated set (Matches ANY character NOT inside) | `[^0-9]` | a, -, ! (No digits) |

### Quantifiers (Multipliers)
*Note: Quantifiers apply only to the single character or group immediately preceding them.*

| Symbol | Meaning | Example | Matches |
| :--- | :--- | :--- | :--- |
| `*` | 0 or more times (Greedy - matches as much as possible) | `a*` | "", a, aa, aaa |
| `+` | 1 or more times (Greedy) | `a+` | a, aa, aaa |
| `?` | 0 or 1 time (Makes preceding token optional) | `a?` | "", a |
| `*?` | 0 or more times (Lazy - matches as little as possible) | `a*?` | "" (stops early) |
| `{n}` | Exactly *n* times | `a{3}` | aaa |
| `{n,}` | *n* or more times | `a{2,}` | aa, aaa, aaaa |
| `{n,m}` | Between *n* and *m* times | `a{2,4}` | aa, aaa, aaaa |

### Anchors & Boundaries
*Anchors do not consume characters; they match specific positions within the log line. Using anchors drastically improves SIEM search performance.*

| Symbol | Meaning | SOC Use Case |
| :--- | :--- | :--- |
| `^` | Start of string/line | `^Failed` ensures "Failed" is the very first word. |
| `$` | End of string/line | `exe$` ensures the log line strictly ends with "exe". |
| `\b` | Word boundary | `\bcat\b` matches "cat", but ignores "catalog" or "tomcat". |
| `\B` | Non-word boundary | `\Bcat\B` matches "cat" inside "locator", but not "cat". |

### Character Classes (Shorthand)
| Symbol | Meaning | Equivalent Set |
| :--- | :--- | :--- |
| `\d` | Any digit | `[0-9]` |
| `\D` | Any non-digit | `[^0-9]` |
| `\w` | Any word character (Alphanumeric + underscore) | `[a-zA-Z0-9_]` |
| `\W` | Any non-word character (Punctuation, spaces, etc.) | `[^a-zA-Z0-9_]` |
| `\s` | Any whitespace (space, tab, newline) | `[ \t\r\n\f]` |
| `\S` | Any non-whitespace (Crucial for SOC extractions) | `[^ \t\r\n\f]` |

### Escape Sequences
| Symbol | Meaning |
| :--- | :--- |
| `\n` | Newline (Line feed) |
| `\r` | Carriage return |
| `\t` | Tab space |
| `\\` | A literal backslash (Common in Windows file paths: `C:\\Windows`) |

---

### Syntax Applied: Quick Examples

**Extracting a specific word using boundaries**
  Pattern:   `\b(root|admin)\b`
  Breakdown: `\b` (word boundary) + `(root|admin)` (captures root OR admin) + `\b` (word boundary)
  Matches:   `root`, `admin` (Will NOT match `administrator` or `rootkit`)
  SOC Log:   `Failed password for root from 10.0.0.5 port 22`
  Engine:    Both

**Extracting an unknown string until the next space (Extremely common SIEM technique)**
  Pattern:   `User:\s(?<username>\S+)`
  Breakdown: `User:\s` (literal "User:" followed by one whitespace) + `(?<username>...)` (named capture group) + `\S+` (one or more non-whitespace characters)
  Matches:   `User: JSmith`, `User: Administrator`
  SOC Log:   `Login attempt rejected. User: JSmith IP: 192.168.1.1`
  Engine:    PCRE (Splunk/Wazuh PCRE2)

***

