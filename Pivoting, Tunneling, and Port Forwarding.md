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

# Networking Concepts for Pivoting

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

# Port Forwarding and SSH Notes

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

