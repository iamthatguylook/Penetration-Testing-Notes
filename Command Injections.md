# Intro to Command Injections
## Overview
- Allows execution of unauthorized system commands via user input.
- Ranked #3 in OWASP's Top 10 risks.

## Common Injection Types
- **OS Command Injection**: User input is part of an OS command.
- **SQL Injection**: Input alters SQL queries.
- **XSS (Cross-Site Scripting)**: Input is directly displayed in a webpage.

## Examples
### PHP
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```
### NodeJS
```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

## Prevention
- **Sanitize input** to remove harmful characters.
- **Use allowlists** to restrict valid input.
- **Limit process privileges** to minimize risk.

---

# Detecting Command Injection

## Overview
- Detection follows the same process as exploitation: injecting commands and observing responses.
- Unsanitized input may allow arbitrary command execution.

## Command Injection Detection
- Example: Web app with Host Checker utility using `ping`.
- Expected command structure:
  ```bash
  ping -c 1 OUR_INPUT
  ```
- If input is unsanitized, additional commands can be injected.

## Injection Operators
| Operator | Character | URL Encoded | Execution |
|----------|----------|-------------|------------|
| Semicolon | `;` | `%3b` | Both commands executed |
| New Line | `\n` | `%0a` | Both executed |
| Background | `&` | `%26` | Both (second output shown first) |
| Pipe | `|` | `%7c` | Second command output shown |
| AND | `&&` | `%26%26` | Second executes only if first succeeds |
| OR | `||` | `%7c%7c` | Second executes only if first fails |
| Sub-Shell | `` ` ` | `%60%60` | Both executed (Linux only) |
| Sub-Shell | `$()` | `%24%28%29` | Both executed (Linux only) |

## Notes
- Linux/macOS-only operators: `` ` ``, `$()`.
- Semi-colon (`;`) does not work in Windows CMD but works in PowerShell.

---

# Identifying Filters in Web Applications

## Injection Mitigation
- Blacklisted characters/words block suspicious requests.
- Web Application Firewalls (WAFs) prevent attacks like SQL injection and XSS.

## Detecting Filters/WAF
- Operators like `;`, `&&`, and `||` may trigger an error.
- Errors in the output field → Web app filter.
- Redirected error page → Likely a WAF.

## Example Payload
```bash
127.0.0.1; whoami
```
- Possible blocked elements: **`;`**, **space**, **`whoami` command**.

## Blacklisted Characters
- Example PHP code blocking specific characters:
```php
$blacklist = ['&', '|', ';'];
if (strpos($_POST['ip'], $blacklist) !== false) {
    echo "Invalid input";
}
```
- Testing other inputs can help identify blocked characters.

---

# Bypassing Space Filters in Command Injection

## Detection & Bypassing Techniques
- Web applications often blacklist characters to prevent injection attempts.
- Learning bypass techniques helps in understanding and mitigating vulnerabilities.

## Bypassing Blacklisted Operators
- Operators like `;`, `&&`, and `||` are often blocked.
- **New-line character (`%0a`)** can work as an injection operator.

## Bypassing Blacklisted Spaces
- Spaces may be blacklisted in certain inputs.
- Alternatives to spaces:
  - **Tabs (`%09`)**: Linux & Windows accept tabs between command arguments.
  - **`$IFS` Variable**: Represents a space or tab in Linux.
  - **Brace Expansion (`{cmd,arg}`)**: Automatically adds spaces between arguments in Bash.

## Example Payloads
```bash
127.0.0.1%0a whoami     # Blocked due to space
127.0.0.1%0a%09whoami   # Accepted using tab
127.0.0.1%0a${IFS}whoami # Accepted using $IFS
127.0.0.1%0a{ls,-la}    # Accepted using brace expansion
```
---

