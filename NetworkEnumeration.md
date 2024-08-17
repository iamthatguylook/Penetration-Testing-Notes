# Enumeration
This phase aims to improve our knowledge and understanding of the technologies, protocols, and how they work and learn to deal with new information and adapt to our already acquired knowledge.

When scanning and inspecting, we look exactly for these two possibilities. Most of the information we get comes from misconfigurations or neglect of security for the respective services. Misconfigurations are either the result of ignorance or a wrong security mindset. For example, if the administrator only relies on the firewall, Group Policy Objects (GPOs), and continuous updates, it is often not enough to secure the network.

Manual enumeration is a critical component. Many scanning tools simplify and accelerate the process.

# Introduction to NMAP
Network Mapper (Nmap) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua. It is designed to scan networks and identify which hosts are available on the network using raw packets, and services and applications, including the name and version, operating system.

### Nmap Archietecture
Nmap offers scans to find various results about our target
1) Host Discovery
2) Port Scanning
3) Service Enumeration and detection
4) Os Detection
5) Scriptable communication with target (NSE)

### Scan Techniques
Nmap offers many different scanning techniques, making different types of connections and using differently structured packets to send.

TCP-SYN scan (-sS) Sends packet with Flag SYN. Target Replies with SYN-ACK flag port is OPEN. Target replies with RST flag port is CLOSED. Target does not reply it is port is identified is FILTERED

# Host Discovery

Nmap offers techniques to confirm whether a system is alive on a network or not. Most effective host discovery method is ICMP ECHO requests.

### Scan Network Range

```Code
nmap 10.129.2.0/24 -sn -oA tnet
```
This scan only works if firewall allows it.
10.129.2.0/24 - Target network range
-sn - disables port scanning
-oA tnet - Stores the results in all formats starting with the name 'tnet'.

#### Nmap scan with list 

This can is to find the live targets in the provided list. (this may mean that the other hosts ignore the default ICMP echo requests because of their firewall configurations.)
```code
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```
-iL - Performs defined scans against targets in provided 'hosts.lst' list.

#### Scan multiple IPs
```code
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20
```
using respective octet
```code
sudo nmap -sn -oA tnet 10.129.2.18-20
```
If we disable port scan (-sn), Nmap automatically ping scan with ICMP Echo Requests (-PE). Target usally replies with ICMP reply if alive. Before Nmap sends ICMP request it could sent an ARP ping which will result in ARP reply. show packets sent and received (--packet-trace). To disable ARP ping (--disable-arp-ping).

# Host and Port Scanning

After figuring out system is live. We need more information on the system.
1) Open ports and its services
2) Service Versions and information from the Service
3) Operation System

| State           | Description                                                                                                           |
|-----------------|-----------------------------------------------------------------------------------------------------------------------|
| **open**        | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations. |
| **closed**      | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |
| **filtered**    | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target. |
| **unfiltered**  | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed. |
| **open|filtered** | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port. |
| **closed|filtered** | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall. |

### Discoverting Open TCP ports

SYN scan (-sS) this default for root otherwise -sT will be performed. Define ports by (-p21) or range (-p21-445) or top ports (--top-ports=10) this is for most frequesnt used ports for scans,(-p-) is scan all ports.

#### Scanning top 10 TCP ports
```code
sudo nmap 10.129.2.28 --top-ports=10
```

#### Nmap - Trace the Packets
```code
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```
To have a clear view of the SYN scan, we disable the ICMP echo requests (-Pn), DNS resolution (-n), and ARP ping scan (--disable-arp-ping).

#### Connect Scan

The Nmap TCP Connect Scan (-sT) uses the TCP three-way handshake to determine if a specific port on a target host is open or closed (establishes a full connection then sends to RST to kill connection). Sends SYN to target port. OPEN when recieves SYN-ACK and closed if RST packet. Connect scan is most accurate amd stealthy. Connect scan does not leave unfinished scans or unsent packets on the target host less likely tp get detected by IPS And IDS.

### Filtered Ports

Packets have been dropped or rejected due to firewall or certain restrictions (Target side). 

### Discovering open UDP ports 

UDP is a stateless protocol and does not require a three-way handshake like TCP. We do not receive any acknowledgment.Another disadvantage of this is that we often do not get a response back because Nmap sends empty datagrams to the scanned UDP ports, and we do not receive any response. So we cannot determine if the UDP packet has arrived at all or not. If the UDP port is open, we only get a response if the application is configured to do so. If we get an ICMP response with error code 3 (port unreachable), we know that the port is indeed closed. For all other ICMP responses, the scanned ports are marked as (open|filtered).

UDP port scan 
```
sudo nmap 10.129.2.28 -F -sU
```


# Saving Nmap Scans

### Different Formats 

1) Normal output (-oN) with the .nmap file extension
2) Grepable output (-oG) with the .gnmap file extension
3) XML output (-oX) with the .xml file extension
 (-oA) For all formats

Scan to save in all formats
```
sudo nmap 10.129.2.28 -p- -oA target
```
### Style sheets

With the XML output, we can easily create HTML reports that are easy to read, even for non-technical people. This is later very useful for documentation, as it presents our results in a detailed and clear way. To convert the stored results from XML format to HTML, we can use the tool xsltproc.

Save nmap results in HTML
```
xsltproc target.xml -o target.html
```

# Service Enumeration

 It is essential to determine the application and its version as accurately as possible. Exact version number allows us to search for a more precise exploit. (-sV)  option (--stats-every=5s) Shows status of scan every 5 seconds.We can also increase the verbosity level (-v / -vv), which will show us the open ports directly when Nmap detects them.

### Version Scan

On OPEN ports using (-sV) to find version of service running on the port.
```
sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason  -sV
```

### Banner Grabbing

Nmap looks at the banners of the scanned ports and prints them out. If it cannot identify versions through the banners, Nmap attempts to identify them through a signature-based matching system, but this significantly increases the scan's duration.

Banner can be grabbed through successfully connecting to the service. You can use NETCAT (nc) to connect to client with specified port. Usually when u connect TCP is used (three-way handshake) then server sends PSH flag which indicateds server is sending data to you (usually banner at first). Then the you send the ACK flag to achknowledge data sent to you.
```
nc -nv 10.129.2.28 25
```
# Nmap Scripting Engine

Nmap Scripting Engine (NSE) is another handy feature of Nmap. It provides us with the possibility to create scripts in Lua for interaction with certain services, (-sC) default script.

### Default Script
```
sudo nmap <target> -sC
```
### Specific Scripts Category
```
sudo nmap <target> --script <category>
```
### Defined Scripts
```
sudo nmap <target> --script <script-name>,<script-name>
```
### nmap aggressive scan (-A)
This scans the target with multiple options as service detection (-sV), OS detection (-O), traceroute (--traceroute), and with the default NSE scripts (-sC).
```
sudo nmap 10.129.2.28 -p 80 -A
```
### Vulnerability Assessment
The scripts used for the last scan interact with the webserver and its web application to find out more information about their versions and check various databases to see if there are known vulnerabilities.
```
nmap 10.129.2.28 -p 80 -sV --script vuln
```
# Performance

Scanning performance is significant on large networks or low network bandwidth.

### Nmap timeouts

nmap sends packet to target and takes some time to recieve response from port(Round-Trip-Time - RTT)(--initial-rtt-timeout 50ms 	Sets the specified time value as initial RTT timeout). If RTT is reduced some hosts might be overlooked.

nmap round trip scan
```
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

### Nmap Max Retries

This is retry rate of sent packets. (-F is top100 ports)
```
sudo nmap 10.129.2.0/24 -F --max-retries 0
```

### Rates
If we know the network bandwidth, we can work with the rate of packets sent, which significantly speeds up our scans with Nmap. Minimum rate (--min-rate <number>) for sending packets.
```
sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
```
Nmap offers six different timing templates (-T <0-5>) for us to use. These values (0-5) determine the aggressiveness of our scans. If scan aggressive can be detected.
```
sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
```

# Firewall and IDS/IPS Evasion

Nmap bypasses using techniques like fragmentation,decoys,etc.

### Firewall

Firewall is security system based on specific ALLOW/DENY rules that decides how to handle connection based on rules.

### IPS/IDS
IDS scans the network for potential attacks, analyzes them, and reports any detected attacks. IPS complements IDS by taking specific defensive measures if a potential attack should have been detected. The analysis of such attacks is based on pattern matching and signatures. IPS prevents if signature is matched.

IDS systems examine all connections between hosts. If the IDS finds packets containing the defined contents or specifications, the administrator is notified and takes appropriate action in the worst case.
IPS systems take measures configured by the administrator independently to prevent potential attacks automatically. It is essential to know that IDS and IPS are different applications and that IPS serves as a complement to IDS.

### Decoys
Decoy scanning method (-D) With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (RND) a specific number (for example: 5) of IP addresses separated by a colon (:). Our real IP address is then randomly placed between the generated IP addresses. Decoys must be live.
The spoofed packets are often filtered out by ISPs and routers, even though they come from the same network range. Therefore, we can also specify our VPS servers' IP addresses and use them in combination with "IP ID" manipulation in the IP headers to scan the target. Manually specify the source IP address (-S) to test if we get better results with this one.

Scan using Decoys
```
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```
Scan by Using Different Source IP
```
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

### DNS Proxying

1) Default Behavior:
 Nmap performs reverse DNS resolution by default to gather more information about the target.
 DNS queries are typically made over UDP port 53.
2) TCP Port 53 Usage:
 Historically, TCP port 53 was used for DNS zone transfers and data transfers larger than 512 bytes. 
 With the advent of IPv6 and DNSSEC, more DNS requests are now made via TCP port 53.
3) Specifying DNS Servers:
 Nmap allows specifying DNS servers using the --dns-server <ns>,<ns> option.
 This is particularly useful in a demilitarized zone (DMZ) where company DNS servers are more trusted than external ones.
4) Using TCP Port 53 as Source Port:
 The --source-port option can be used to specify TCP port 53 for scans.
 This can help bypass firewalls that trust traffic on this port, especially if IDS/IPS are not properly configured.
5) Practical Applications:
 Using trusted DNS servers in a DMZ to interact with internal network hosts.
 Leveraging TCP port 53 to pass through firewalls and avoid detection by IDS/IPS.

Change source port
```
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```
## Evasion Disclaimer

During nmap scans make sure to disable arp ping (--disable-arp-ping) and reverse dns resolution (-n) and ICMP Echo requests (-Pn) as this can be flagged by the firewall. 
use source port 53(--source-port 53) as this is trusted.

Some times firewalls are misconfigured and can allow UDP (-sU) scans.
Make sure when you scan all ports use --max-retries=1 as it wont be loud.
