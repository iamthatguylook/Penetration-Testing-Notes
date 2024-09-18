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
