
# Introduction to File Inclusions

**Local File Inclusion (LFI)** occurs when a web application allows users to control file paths, potentially leading to the inclusion of unintended files. This can expose sensitive data or even allow attackers to execute arbitrary code on the server.

### Risks of LFI:
- **Source Code Disclosure**: Attackers can view and analyze the application’s source code for other vulnerabilities.
- **Sensitive Data Exposure**: LFI can expose credentials, configuration files, or other sensitive information.
- **Remote Code Execution**: In some cases, LFI can lead to remote code execution, allowing attackers to fully compromise the server.

### Example of LFI in PHP
```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```
- **Vulnerability:** The `include()` function loads files based on user-controlled input, making it possible for an attacker to include files from the server (e.g., `/etc/passwd`).

### Key Functions in LFI:
| Function                    | Read Content | Execute | Remote URL |
|-----------------------------|--------------|---------|------------|
| `include()`, `require()`     | ✅            | ✅       | ✅          |
| `fs.readFile()`, `sendFile()`| ✅            | ❌       | ❌          |
| `@Html.Partial()`, `Response.WriteFile()` | ✅            | ❌       | ❌          |

