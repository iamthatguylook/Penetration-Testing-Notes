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
