# Introduction 
### 1. HTTP Verb Tampering

- **Definition**: Exploiting web servers that accept multiple HTTP methods (verbs).
- **Risk**: Can bypass authorization mechanisms and security controls.
- **Example**: Using `PUT`, `DELETE`, or `OPTIONS` instead of `GET`/`POST` to gain unauthorized access.
- **Cause**: Misconfigured web servers that don’t restrict HTTP verbs properly.

### 2. Insecure Direct Object References (IDOR)

- **Definition**: Exploiting predictable object references (e.g., file IDs) to access unauthorized data.
- **Risk**: Exposure of other users’ files or sensitive data.
- **Example**: Accessing `/user/102` instead of `/user/101`.
- **Cause**: Lack of robust back-end access control and predictable identifiers.

### 3. XML External Entity (XXE) Injection

- **Definition**: Injecting malicious XML to exploit vulnerable XML parsers.
- **Risk**: Disclosure of local server files, credentials, or even remote code execution.
- **Example**: Sending an XML payload referencing local files (e.g., `/etc/passwd`).
- **Cause**: Use of outdated or insecure XML libraries without proper configuration.

---

# HTTP Verb Tampering

## Overview

- HTTP supports multiple **verbs/methods** (e.g., GET, POST, PUT).
- **Developers usually handle only GET and POST**, but web servers may accept all verbs unless explicitly restricted.
- HTTP Verb Tampering occurs when attackers send unexpected HTTP methods to **bypass access controls or exploit vulnerabilities**.

## Common HTTP Verbs

| Verb    | Description                                                  |
|---------|--------------------------------------------------------------|
| GET     | Retrieves data                                               |
| POST    | Submits data                                                 |
| HEAD    | Like GET, but returns only headers                           |
| PUT     | Uploads/replaces resource at the specified URI               |
| DELETE  | Deletes resource at the specified URI                        |
| OPTIONS | Returns allowed methods for the target resource              |
| PATCH   | Applies partial modifications to a resource                  |


## Causes of HTTP Verb Tampering

### 1. Insecure Web Server Configurations

- Servers may apply access controls **only to specific verbs**.
- Example:
  ```xml
  <Limit GET POST>
      Require valid-user
  </Limit>
  ```

* Only GET and POST requests require authentication.
* An attacker may use `HEAD` or `OPTIONS` to bypass controls.

### 2. Insecure Coding Practices

* Filters may be applied **only to specific methods**.
* Example (PHP):

  ```php
  $pattern = "/^[A-Za-z\s]+$/";
  if(preg_match($pattern, $_GET["code"])) {
      $query = "SELECT * FROM ports WHERE port_code LIKE '%" . $_REQUEST["code"] . "%'";
  }
  ```
  * GET input is sanitized, but query uses `$_REQUEST`, which includes POST.
  * Attacker sends malicious input via POST → bypasses filter → **SQL Injection** possible.
---

# Bypassing Basic Authentication with HTTP Verb Tampering

## Overview

- HTTP Verb Tampering can exploit **misconfigured authentication** in web servers.
- This type of attack can **bypass HTTP Basic Authentication** using lesser-checked HTTP methods.
- Vulnerability is often due to server restricting only certain HTTP methods (e.g., GET, POST).

## Identification

- File Manager web app has a **Reset** function at `/admin/reset.php` which is **protected by Basic Auth**.
- Accessing `/admin/` or `/admin/reset.php` directly results in a **401 Unauthorized**.
- Indicates that the **entire `/admin/` directory is protected**.

## Exploitation Steps

1. **Intercept original request** (GET) to `/admin/reset.php`.
2. **Change method to POST** in Burp Suite.
   - Still returns **401 Unauthorized** → GET and POST are both protected.
3. **Send OPTIONS request** to see allowed HTTP methods:
   ```bash
   curl -i -X OPTIONS http://SERVER_IP:PORT/
    ```

* Response includes: `Allow: POST, OPTIONS, HEAD, GET`
* Indicates server accepts **HEAD requests**.

4. **Send HEAD request** to `/admin/reset.php`.

   * No login prompt.
   * No response body (expected behavior of HEAD).
   * Reset function is executed successfully → **authentication bypassed**.

## Key Points

* **HEAD** method can be used like GET but without a response body.
* Some servers **don’t enforce auth** checks on all methods (e.g., HEAD, OPTIONS).
* Vulnerability stems from **incomplete server-side access control configuration**.

---

# Bypassing Security Filters with HTTP Verb Tampering

## Overview

- **Insecure coding** during web app development can cause vulnerabilities in security filters.
- Filters may only cover specific HTTP methods (e.g., POST), allowing attackers to bypass them by using other methods (e.g., GET).
- This is a common vulnerability that arises from **incomplete filter application** across HTTP methods.

## Identification

1. **File Manager Web Application** blocks special characters in file names (e.g., `test;`) to prevent injection attacks.
   - Displays message: **"Malicious Request Denied!"**
   - Security filters are in place to detect and block malicious requests (e.g., command injections).

2. The filter **properly blocks** requests using special characters in the file name to prevent injection.

## Exploitation Steps

1. **Intercept request** in Burp Suite.
2. **Change HTTP method** from POST to GET.
   - Send a **GET request** with the file name `test%3B` (URL-encoded `test;`).
   - **Result**: The file is successfully created, and no filter message is displayed.

3. **Test for command injection** by attempting to create multiple files with the payload `file1; touch file2;`:
   - Payload: `file1%3B+touch+file2%3B` (URL-encoded).
   - **Change request method** to GET.
   
4. **Send the request**, and both files (`file1` and `file2`) are created, showing successful command injection:
   - **Files created**: `file1`, `file2`, `test`, `notes.txt`.

## Key Points

- **Insecure coding** causes the vulnerability when security filters are not applied across all HTTP methods.
- Attackers can **bypass filters** by sending requests with HTTP methods the filters don’t account for (e.g., GET instead of POST).
- HTTP Verb Tampering allows **Command Injection** by bypassing filters.

---
