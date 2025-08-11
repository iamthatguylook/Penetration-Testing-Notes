
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

# 🛠 Linux Environment Enumeration

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

# Linux Services & Internals Enumeration

## Overview

* After gathering info about users, groups, files, binaries, scripts, directories, etc., next step is to **deep dive into OS internals**.
* Key objectives:

  * Identify installed services & applications.
  * Identify running services and used sockets.
  * Enumerate users, admins, groups.
  * Check currently logged in and recent login users.
  * Investigate password policies.
  * Check if host is joined to Active Directory domain.
  * Analyze history, logs, backups.
  * Detect recently modified files and cron jobs.
  * Gather IP and network info.
  * Review `/etc/hosts` for interesting entries.
  * Check network connections (internal/external).
  * Identify installed useful tools (e.g. netcat, python, nmap).
  * Access and analyze bash histories for secrets.
  * Detect hijackable cron jobs.
  * Identify multiple interfaces for pivoting potential.

## Internals & Network Interfaces

* The term **internals** means internal configuration & integrated processes.
* Key interfaces are how system communicates externally.

```bash
ip a
```

Example output insights:

* Loopback interface (`lo`) with `127.0.0.1`
* Ethernet interface (`ens192`) with dynamic IP `10.129.203.168/16`
* IPv6 addresses present.
* Multiple interfaces might indicate pivot opportunities.

## /etc/hosts File

```bash
cat /etc/hosts
```

Typical entries:

```
127.0.0.1 localhost
127.0.1.1 hostname
# IPv6 entries for localhost and multicast groups
::1 ip6-localhost ip6-loopback
```

* Useful to map hostnames to IPs locally.
* Sometimes may contain interesting internal network names.

## User Login Information

* Check last login for users to gauge usage frequency:

```bash
lastlog
```

* Look for users who **never logged in** and users with recent logins.

* Analyze typical login times for patterns.

* Check who is currently logged in:

```bash
w
```

* Provides info about active users, their terminals, origin IPs, and idle times.

## Bash History & Command History

* Review shell history for passwords or clues:

```bash
history
```

* Look for:

  * Passwords passed as arguments.
  * Use of git, cron, SSH commands.
  * Any suspicious or privileged commands.

* Search for other history files:

```bash
find / -type f \( -name '*_hist' -o -name '*_history' \) -exec ls -l {} \; 2>/dev/null
```

## Cron Jobs

* Scheduled tasks may run as root or privileged users.
* Enumerate cron jobs for potential hijacking:

```bash
ls -la /etc/cron.daily/
```

* Also check `/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/crontab`.
* Look for scripts with weak permissions or relative paths.

## Proc Filesystem

* `/proc` is a virtual filesystem providing real-time system/process info.
* Can inspect running processes, kernel parameters, system memory, devices.
* Use for reconnaissance of system internals.

```bash
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```

## Installed Packages

* List all installed packages (Debian/Ubuntu example):

```bash
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
```

* Helps identify potentially vulnerable or exploitable software versions.

## Sudo Version

* Check sudo version for known vulnerabilities:

```bash
sudo -V
```

## Binaries on System

* Check common executable directories:

```bash
ls -l /bin /usr/bin /usr/sbin/
```

* Important to find potentially exploitable binaries or setuid programs.

## GTFObins Check

* Compare installed packages/binaries with known exploitable binaries:

```bash
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d'); do
  if grep -q "$i" installed_pkgs.list; then
    echo "Check GTFO for: $i"
  fi
done
```

## Using strace for Tracing Syscalls

* `strace` can trace program syscalls and signals.
* Useful for:

  * Understanding program behavior.
  * Detecting system calls accessing files, network, credentials.

Example:

```bash
strace ping -c1 10.129.112.20
```

* Can reveal network socket usage, file opens, and other internals.

## Configuration Files & Scripts

* Configuration files often reveal service setups, credentials, paths:

```bash
find / -type f \( -name '*.conf' -o -name '*.config' \) -exec ls -l {} \; 2>/dev/null
```

* Search for scripts that might run regularly or have exploitable permissions:

```bash
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```
## Running Services & Processes

* Check running processes by user (e.g., root):

```bash
ps aux | grep root
```

* Identify important services running with high privileges.
* Check if any scripts or binaries with weak permissions are running.

---

# Credential Hunting

When enumerating a system, note down any **credentials** you find.  
They can be useful for:
- Escalating privileges (to other users or root)
- Accessing databases
- Accessing other systems in the environment

## Common Locations for Credentials

- **Configuration files**: `.conf`, `.config`, `.xml`
- **Shell scripts**
- **Bash history**: `.bash_history`
- **Backup files**: `.bak`
- **Database files**
- **Plain text files**


## /var Directory & Web Root

- `/var` often contains the **web root** for the web server.
- May contain database credentials or other sensitive information.
- Example: WordPress config file with MySQL credentials

```bash
grep 'DB_USER\|DB_PASSWORD' wp-config.php
````

## Searching for Config Files

Search for config files across the system (excluding `/proc`):

```bash
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

Example results:

```
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/python3/debian_config
/etc/kbd/config
/etc/manpath.config
/boot/config-4.4.0-116-generic
...
```

## SSH Keys

* Look for **SSH private keys** — they may belong to more privileged users or allow access to other hosts.
* Check `known_hosts` to identify previously connected systems for potential **lateral movement**.

Example:

```bash
ls ~/.ssh
```

* **`id_rsa`** → Private key
* **`id_rsa.pub`** → Public key
* **`known_hosts`** → Past host connections

---



