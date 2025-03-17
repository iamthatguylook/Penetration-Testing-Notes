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




