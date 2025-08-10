
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

# 🛠 Linux Environment Enumeration — Detailed Notes

## 1. **Initial Orientation**

When you first get access to a machine (reverse shell, SSH, etc.), it’s important to know **who you are, where you are, and what you can do**.

```bash
whoami
```

* Shows the current username.
* If it’s `root`, you already have full control.
* If it’s a system account (`www-data`, `nobody`), you’ll likely need privilege escalation.

```bash
id
```

* Displays UID, GID, and group memberships.
* Check if you belong to privileged groups like:

  * `sudo` → can run commands as root
  * `docker` → can escape to host
  * `lxd` → can escalate via container mounting
  * `adm` → can read `/var/log` (possible creds in logs)

```bash
hostname
```

* Machine’s network name.
* Useful for pivoting in multi-host networks — can reveal naming conventions.

```bash
ifconfig` or `ip a
```

* Lists network interfaces, assigned IPs, and MAC addresses.
* Look for multiple interfaces (may indicate different networks to pivot into).

```bash
sudo -l
```

* Shows which commands you can run with `sudo` **without** a password.
* Dangerous entries:

  * `ALL` → full root
  * `/bin/bash` or `/bin/sh` → instant root shell
  * Scripts or binaries you can modify → escalation via privilege abuse

## 2. **OS & Kernel Information**

Determining OS and kernel helps you **target known vulnerabilities**.

```bash
cat /etc/os-release
```

* Lists OS name, version, codename.
* Useful for finding OS-specific privilege escalation exploits.

```bash
uname -a
```

* Shows kernel version and architecture.
* Vulnerable kernels may have public exploits (search in `searchsploit`).

💡 Example:
Kernel `5.4.0-42-generic` → Search: `searchsploit linux kernel 5.4.0`

## 3. **Environment Variables & PATH**

Knowing `$PATH` tells you **where the shell looks for binaries** — important for path hijacking attacks.

```bash
echo $PATH
```

* If current directory `.` appears before `/usr/bin`, you could create malicious scripts with the same name as common commands.

```bash
env
```

* Dumps all environment variables.
* Things to look for:

  * `USER`, `HOME` — user info
  * `SHELL` — current shell
  * `HISTFILE` — bash history file
  * `LD_PRELOAD`, `LD_LIBRARY_PATH` — potential shared library injection points
## 4. **System Hardware Info**

Sometimes, system type matters for container escapes, virtual machine exploits, or CPU bugs.

```bash
lscpu
```

* Architecture (x86\_64, ARM, etc.)
* Hypervisor vendor (e.g., KVM, VMware)
* Number of cores (useful for stress testing or DoS attacks)

## 5. **Available Shells**

```bash
cat /etc/shells
```

* Lists installed shells.
* If `bash` is not available but `sh` or `zsh` is, you may need to adapt payloads.
* May find `rbash` (restricted shell) — can look for breakout methods.

## 6. **Security Mechanisms**

```bash
lsmod
```

* Check loaded kernel modules (may reveal security tools).

```bash
ps aux
```

* Check for processes like:

  * `fail2ban` → brute-force protection
  * `auditd` → logs system calls
  * `snort` → IDS
  * `tripwire` → file integrity monitoring

Also check:

```bash
sestatus         # SELinux status
aa-status        # AppArmor profiles
ufw status       # Firewall rules
```

## 7. **Drives & File Systems**

```bash
lsblk
```

* Lists all storage devices and partitions.

```bash
df -h
```

* Shows mounted partitions and free space.
* Writable mounts (especially `/mnt`, `/media`) may allow placing binaries or scripts for escalation.

```bash
cat /etc/fstab
```

* Lists persistent mounts.
* Sometimes contains plaintext credentials for NFS/SMB shares.

## 8. **Networking**

```bash
route
```

* Shows the routing table.
* A `0.0.0.0` route is the default gateway (often another machine to target).

```bash
cat /etc/resolv.conf
```

* Shows DNS servers — can lead to internal DNS enumeration.

```bash
arp -a
```

* Lists nearby devices on the LAN (possible lateral movement targets).

## 9. **Users & Groups**

```bash
cat /etc/passwd
```

* Lists all system accounts.
* Look for unusual accounts with `/bin/bash` (means they can log in).

```bash
grep "sh$" /etc/passwd
```

* Quickly filter only accounts with shell access.

```bash
cat /etc/group
```

* Shows group memberships.
* If you’re in `docker`, `lxd`, or `adm`, you might have escalation paths.

```bash
ls /home
```

* Lists home directories — good place to check for `.ssh` keys or configs.

## 10. **Sensitive Files**

```bash
find / -type f -name "*.conf" 2>/dev/null
find / -type f -name "*.config" 2>/dev/null
```

* Config files may store DB passwords, API tokens, etc.

## 11. **Hidden Files & Directories**

```bash
find / -type f -name ".*" 2>/dev/null
find / -type d -name ".*" 2>/dev/null
```

* Look for `.git`, `.ssh`, `.env`, `.bash_history` — often store secrets.

## 12. **Temporary Files**

```bash
ls -l /tmp /var/tmp /dev/shm
```

* `/tmp` → cleared on reboot (\~10 days)
* `/var/tmp` → persists longer (\~30 days)
* `/dev/shm` → RAM disk, fast storage (also good for hiding malicious files)

## 13. **Quick Exploit Check**

Once OS, kernel, and service versions are known:

```bash
searchsploit <kernel_version>
searchsploit <service_name> <version>
```

* Directly find public exploits to test.

---
