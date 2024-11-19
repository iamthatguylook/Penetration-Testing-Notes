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
