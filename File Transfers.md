# File Transfer

During penetration testing, it's crucial to understand different methods to transfer files between systems. Network controls like **firewalls**, **application whitelisting**, and **antivirus/EDR** systems can block certain actions, making it important to have multiple techniques at your disposal.

### Scenario

- **Initial Access**: We gained remote code execution (RCE) on an IIS web server through an unrestricted file upload vulnerability.
- **Web Shell to Reverse Shell**: After uploading a web shell, we switched to a reverse shell for better control.
- **Privilege Escalation**: We manually enumerated the system and found that we had `SeImpersonatePrivilege`.
- **Blocked Transfers**: We couldn't use PowerShell or download tools from GitHub due to **content filtering**.
- **File Transfer Options**:
  1. **Certutil**: Blocked by web filters.
  2. **FTP**: Blocked by firewall (port 21).
  3. **SMB**: Allowed through port 445, and successfully used with `smbserver` to transfer files.

### Key Points

- **Host Controls**: Restrictions like application whitelisting or AV may block tools such as PowerShell or FTP.
- **Network Controls**: Firewalls may block common file transfer ports, like 21 (FTP) or 80/443 (HTTP/HTTPS).

### File Transfer Methods

- **Certutil**: Windows tool, often blocked by content filtering.
- **FTP**: Standard file transfer protocol, but may be blocked by firewalls.
- **SMB**: Works on port 445, can be useful when FTP is blocked.
- **Impacket Tools**: Useful for SMB and other file-sharing methods.

