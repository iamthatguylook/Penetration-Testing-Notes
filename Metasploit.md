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
