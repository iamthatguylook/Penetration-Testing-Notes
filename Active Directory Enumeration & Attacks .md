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
