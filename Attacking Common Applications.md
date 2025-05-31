
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

