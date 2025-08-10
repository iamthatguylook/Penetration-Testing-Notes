
# 🐧 Introduction to Linux Privilege Escalation

The **root account** on Linux provides full administrative access.
If you gain a **low-privileged shell**, privilege escalation is necessary to obtain root-level control.

## Why Privilege Escalation Matters

* Capture network traffic
* Access sensitive files
* Move laterally in the environment
* On domain-joined systems:

  * Extract NTLM hashes
  * Enumerate & attack Active Directory

## 1️⃣ Enumeration – The Key Step

Enumeration is critical before attempting privilege escalation. Use tools like **LinEnum**, but also know how to enumerate manually.

### OS & Kernel Version

* Identify Linux distribution & version: `Ubuntu`, `Debian`, `Fedora`, `CentOS`, etc.
* Check kernel version for known exploits.
* Be cautious: kernel exploits may cause crashes.

### Running Services

* List services, especially those running as root.
* Examples of vulnerable services:

  * Nagios (CVE-2016-9566)
  * Exim
  * Samba
  * ProFTPd

### 2️⃣ Process Enumeration

```bash
ps aux | grep root
```

Check root-owned processes for potential weaknesses.

### 3️⃣ Installed Packages & Versions

* Outdated packages may have known vulnerabilities.
* Example: **GNU Screen 4.05.00** privilege escalation vulnerability.

### 4️⃣ Logged-In Users

```bash
ps au
```

* Check for other active sessions.
* Possible **local lateral movement** opportunities.

### 5️⃣ Home Directories

```bash
ls /home
```

* Look for **.bash\_history**, **.ssh/**, and configuration files.
* Possible finds:

  * SSH keys for persistence or pivoting.
  * Credentials in config files.
  * Scripts containing passwords.

Example:

```bash
ls -la /home/stacey.jenkins/
```

### 6️⃣ SSH Keys

```bash
ls -l ~/.ssh
```

* `id_rsa` (private key) and `id_rsa.pub` (public key).
* Check ARP cache for reachable hosts.

### 7️⃣ Bash History

```bash
history
```

* May contain passwords, commands, or system information.


### 8️⃣ Sudo Privileges

```bash
sudo -l
```

* Look for **NOPASSWD** entries.
* Some commands run as root can lead to privilege escalation.
* Example:

  ```bash
  (root) NOPASSWD: /usr/sbin/tcpdump
  ```

### 9️⃣ Configuration Files

* Search for `.conf` or `.config` files containing credentials.


### 🔟 Password Hashes

* **Shadow File** (if readable): `/etc/shadow`
* **Passwd File** (with hashes present):

```bash
cat /etc/passwd
```

Hashes can be cracked offline.

### 1️⃣1️⃣ Cron Jobs

```bash
ls -la /etc/cron.daily/
```

* Weak permissions or writable scripts can be abused.
* Example writable backup script: `/etc/cron.daily/backup`

### 1️⃣2️⃣ File Systems & Additional Drives

```bash
lsblk
```

* Unmounted drives may contain sensitive files.

### 1️⃣3️⃣ SETUID & SETGID Binaries

* Allow execution as root without full privileges.
* May be exploitable.

### 1️⃣4️⃣ Writable Directories

```bash
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

* `/tmp`, `/var/tmp`, and custom dirs like `/dmz-backups`.


### 1️⃣5️⃣ Writable Files

```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

* Modifiable scripts run by root (via cron jobs) are prime targets.

---

