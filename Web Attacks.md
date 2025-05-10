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

# Preventing HTTP Verb Tampering

## Overview

- **HTTP Verb Tampering** vulnerabilities arise from insecure web server configurations and insecure coding practices.
- The vulnerability occurs when **HTTP methods** are not properly restricted, allowing attackers to bypass security measures.
- This section discusses how to **patch** and **prevent** these vulnerabilities.
## Insecure Configuration

1. **Apache Configuration Vulnerability**:
   - Limiting authorization to **specific HTTP methods** (e.g., GET) exposes the application to other methods (POST, HEAD, etc.).
   ```xml
   <Directory "/var/www/html/admin">
       AuthType Basic
       AuthName "Admin Panel"
       AuthUserFile /etc/apache2/.htpasswd
       <Limit GET>
           Require valid-user
       </Limit>
   </Directory>
   ```

* **Fix**: Use `<LimitExcept>` to restrict all methods except the specified ones.

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <LimitExcept GET POST>
        Require valid-user
    </LimitExcept>
</Directory>
```

2. **Tomcat Configuration Vulnerability**:

   * Restricting HTTP methods (e.g., GET) leaves the app vulnerable to other methods.

   ```xml
   <security-constraint>
       <web-resource-collection>
           <url-pattern>/admin/*</url-pattern>
           <http-method>GET</http-method>
       </web-resource-collection>
       <auth-constraint>
           <role-name>admin</role-name>
       </auth-constraint>
   </security-constraint>
   ```

   * **Fix**: Avoid restricting methods with `<http-method>`, or use proper configuration to cover all methods.

3. **ASP.NET Configuration Vulnerability**:

   * Limiting HTTP methods (e.g., GET) exposes the application to attacks via other methods.

   ```xml
   <system.web>
       <authorization>
           <allow verbs="GET" roles="admin">
               <deny verbs="GET" users="*"/>
           </allow>
       </authorization>
   </system.web>
   ```

   * **Fix**: Use proper access controls across all methods, or consider using `add/remove` statements to handle method restrictions.

4. **General Recommendations**:

   * Avoid restricting authorization to specific HTTP verbs.
   * Use safe keywords to limit or allow methods across web servers:

     * **Apache**: `<LimitExcept>`
     * **Tomcat**: `http-method-omission`
     * **ASP.NET**: `add/remove`
   * Consider **disabling HEAD** requests unless specifically needed.

## Insecure Coding

1. **PHP Code Vulnerability**:

   * The code below checks for special characters only in `$_POST['filename']`, but **uses both GET and POST** parameters via `$_REQUEST['filename']`.

   ```php
   if (isset($_REQUEST['filename'])) {
       if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
           system("touch " . $_REQUEST['filename']);
       } else {
           echo "Malicious Request Denied!";
       }
   }
   ```

   * **Exploit**: By using GET requests, attackers bypass the filter as `$_POST` parameters are empty, and GET parameters are used in the command, leading to **Command Injection**.

2. **Solution**: Ensure **consistency in HTTP method usage** across all code functions:

   * Avoid mixing GET and POST methods.
   * Ensure that **security filters** cover all HTTP methods.
   * Use **appropriate security functions** that test all request parameters across methods:

     * **PHP**: `$_REQUEST['param']`
     * **Java**: `request.getParameter('param')`
     * **C#**: `Request['param']`

3. **Testing**:

   * Expand the scope of your **security filters** to cover all request parameters, regardless of HTTP method.


## Key Takeaways

* **Insecure Configurations**: Avoid restricting methods like GET and POST. Use proper configurations to handle all HTTP methods.
* **Insecure Coding**: Always maintain **consistent HTTP method usage** in security filters to avoid method-specific vulnerabilities.
* **Testing**: Ensure that security tests cover **all parameters** from all HTTP methods (GET, POST, etc.).

