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
```



