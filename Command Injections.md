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

# Bypassing Blacklisted Characters in Command Injection

## Common Blacklisted Characters
- **Slash (`/` and `\`)**: Required for specifying directories in Linux & Windows.
- **Semi-colon (`;`)**: Often used to chain commands, making it a frequent target for filtering.

## Linux Techniques
### Using Environment Variables
- Some environment variables contain useful characters that can be extracted.
  - Extract `/` from `$PATH`:
    ```bash
    echo ${PATH:0:1}  # Outputs "/"
    ```
  - Extract `;` from `$LS_COLORS`:
    ```bash
    echo ${LS_COLORS:10:1}  # Outputs ";"
    ```
- The `printenv` command can display all environment variables to find useful ones.

### Character Shifting
- A technique using ASCII character shifting:
  ```bash
  echo $(tr '!-}' '"-~'<<<[)  # Converts "[" (ASCII 91) to "\"
  ```
- To find the ASCII value of characters, use `man ascii`.

## Windows Techniques
### Using Environment Variables
- Extract `\` using `%HOMEPATH%`:
  ```cmd
  echo %HOMEPATH:~6,-11%  # Outputs "\"
  ```
- PowerShell equivalent:
  ```powershell
  $env:HOMEPATH[0]  # Outputs "\"
  ```
- Use **Get-ChildItem Env:** to explore environment variables.

## Character Shifting
There are other techniques to produce the required characters without using them, like shifting characters. For example, the following Linux command shifts the character we pass by 1. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with man ascii), then add it instead of [ in the below example. This way, the last printed character would be the one we need:

  Bypassing Other Blacklisted Characters
 ```
man ascii     # \ is on 92, before it is [ on 91
echo $(tr '!-}' '"-~'<<<[)
```
## Additional Techniques
- **String Concatenation**: Some filtered characters can be reconstructed from separate parts.
- **Hex Encoding**: Some applications accept input encoded in hexadecimal rather than raw characters.
- **Base64 Encoding**: Some commands can be encoded in Base64 and decoded dynamically.
- **Variable Expansion**: Using indirect expansion to reference variables containing restricted characters.

---

# Command Injection Prevention

## System Commands
- Avoid using functions that execute system commands, especially with user input.
- Prefer built-in functions for necessary functionality.
- If system commands must be executed, **validate and sanitize** user input.
- Limit the use of system command execution functions whenever possible.

## Input Validation
- Validate user input both on **front-end** and **back-end**.
- Use built-in validation functions:
  - **PHP:** `filter_var($_GET['ip'], FILTER_VALIDATE_IP)`
  - **JavaScript:** Regex validation or libraries like `is-ip`
- Validate non-standard formats using **Regular Expressions (regex)**.

## Input Sanitization
- Remove unnecessary special characters from user input **after validation**.
- Use built-in functions for sanitization:
  - **PHP:** `preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);`
  - **JavaScript:** `ip.replace(/[^A-Za-z0-9.]/g, '');`
  - **NodeJS:** Use `DOMPurify.sanitize(ip);`
- Avoid blacklisting characters; prefer **whitelisting allowed characters**.

## Server Configuration
- Use **Web Application Firewall (WAF)** (e.g., `mod_security`, Cloudflare).
- Implement **Principle of Least Privilege (PoLP)** (run web server as low-privileged user).
- Restrict dangerous functions (`disable_functions=system,` in PHP).
- Limit web application access scope (`open_basedir = '/var/www/html'` in PHP).
- Reject **double-encoded requests** and **non-ASCII characters** in URLs.
- Avoid outdated/insecure modules (e.g., PHP CGI).

## Security Testing
- Perform **penetration testing** to detect vulnerabilities.
- Complement secure coding practices with **continuous security audits**.

