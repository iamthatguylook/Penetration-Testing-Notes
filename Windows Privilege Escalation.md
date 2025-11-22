# 🧭 Situational Awareness 

Situational awareness is essential during penetration tests or any security assessment. Before attempting privilege escalation, we must fully understand the host, its environment, protections, and its network placement. This allows us to make informed, proactive decisions rather than reactive ones.

## 🌐 Network Information

Gathering network information early can reveal:

* **Dual-homed systems** (hosts with multiple interfaces on different networks)
* **Potential lateral movement paths**
* **Domain infrastructure details**
* **Recently communicated hosts** (from ARP tables)
* **Routing behavior**

This information may help directly or indirectly in privilege escalation or in pivoting deeper into the environment.

## 🔌 Interface / IP / DNS Enumeration

### `ipconfig /all` Output Highlights

| Interface                         | IP Address    | Notes                        |
| --------------------------------- | ------------- | ---------------------------- |
| **Ethernet1**                     | 192.168.20.56 | Static, DNS = 8.8.8.8        |
| **Ethernet0**                     | 10.129.43.8   | DHCP, DNS = 1.1.1.1, 8.8.8.8 |
| Multiple ISATAP & Teredo adapters | —             | IPv6 tunneling, disconnected |

### Key Observations

* The host is **dual-homed**:

  * **192.168.20.0/24**
  * **10.129.0.0/16**
* Appears to belong to the **.htb domain** (DNS suffix).
* Two different gateways:

  * 10.129.0.1
  * 192.168.20.1
* Could serve as a **pivot point** between network segments.

## 🧩 ARP Table Enumeration

### `arp -a`

Shows recently communicated hosts for each interface.

* On **10.129.43.8**, several dynamic ARP entries → potential targets for lateral movement.
* On **192.168.20.56**, mostly broadcast/multicast entries → minimal local activity.

### Why ARP Matters

* Identifies **active hosts** the machine talks to.
* Indicates systems admins may use (e.g., RDP/WinRM connections).
* Helps map reachable systems without scanning (stealthier).


## 🧭 Routing Table Analysis

### Key Observations from `route print`

* Two default routes exist:

  * Primary: **10.129.0.1** (metric 25)
  * Secondary: **192.168.20.1** (metric 271)
* Confirms the system is dual-homed and prefers the **10.129.x.x** interface.
* IPv6 routing also enabled.

### Why This Matters

* Defines where traffic exits the host.
* Helps identify pivoting routes.
* Useful for SOCKS tunnels, proxies, and redirectors during escalation or lateral movement.


## 🛡️ Windows Defender Status

### `Get-MpComputerStatus` Highlights

| Feature                   | Status     |
| ------------------------- | ---------- |
| Antivirus Enabled         | ✔          |
| Antispyware Enabled       | ✔          |
| Real-Time Protection      | ❌ Disabled |
| On-Access Protection      | ❌ Disabled |
| Network Inspection System | ❌ Disabled |

### Implications

* Defender is installed but **most active protections are disabled**.
* May permit unsigned tools or enumeration scripts without alerting.
* Still must consider signature-based detection.

## 📦 AppLocker Policy Enumeration

### `Get-AppLockerPolicy -Effective`

Default rules include:

* Allow all **signed packaged apps**
* Allow execution of files in:

  * `%PROGRAMFILES%\*`
  * `%WINDIR%\*`
* Administrators can run **all files/scripts**
* Everyone can run signed installers & scripts in specific directories

### Notable Finding

* Execution **outside Program Files/Windows** may be restricted for non-admin users.
* Generic paths like `C:\Users\*\Desktop\tool.exe` may be blocked.

## 🧪 Testing AppLocker Enforcement

### Command

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```

### Result

```
PolicyDecision: Denied
MatchingRule: c:\windows\system32\cmd.exe
```

### Meaning

* Even though cmd.exe is in the Windows directory, its execution may be restricted for **Everyone**.
* Indicates the presence of **AppLocker enforcement** that must be bypassed.

---
