
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

---

# Local File Inclusion (LFI)=

## What is LFI?
- LFI occurs when web applications allow user input to specify file paths, potentially leading to the inclusion of unintended files (e.g., `/etc/passwd`), exposing sensitive data or enabling code execution.

## LFI Exploitation Examples

### 1. **Basic LFI**  
URL: `http://<SERVER_IP>:<PORT>/index.php?language=es.php`  
- **Vulnerability**: The web app includes files based on user input, allowing attackers to read sensitive files by changing the parameter, e.g., `/etc/passwd`.

### 2. **Path Traversal**  
- **Bypassing restrictions**: Use `../../../../` to traverse to the root directory and access files like `/etc/passwd`.  
Example: `http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd`

### 3. **Filename Prefix**  
- **Bypass with `/`**: When a prefix like `lang_` is added, prepend `/` to path traversal to bypass the prefix.  
Example: `http://<SERVER_IP>:<PORT>/index.php?language=/../../../etc/passwd`

### 4. **Appended Extensions**  
- **File extension issues**: When `.php` is appended to the input, use techniques like `%00` (null byte) to bypass the extension filter and access files.  
Example: `http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd%00`

### 5. **Second-Order LFI Attacks**  
- **Poisoning input**: Attackers can exploit LFI through indirect inputs, like user profiles, that are later used to load files (e.g., `/profile/$username/avatar.png`).  
- **Exploit**: Poison a value (like username) to control what file is loaded later.

---

