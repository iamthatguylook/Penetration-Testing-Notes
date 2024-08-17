# Footprinting

## Enumeration Principles

| No. | Principle                                                   |
|-----|-------------------------------------------------------------|
| 1   | There is more than meets the eye. Consider all points of view. |
| 2   | Distinguish between what we see and what we do not see.     |
| 3   | There are always ways to gain more information. Understand the target. |

## Enumeration Methadology

| Layer               | Description                                                                 | Information Categories                                                                 |
|---------------------|-----------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| 1. Internet Presence| Identification of internet presence and externally accessible infrastructure.| Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures |
| 2. Gateway          | Identify the possible security measures to protect the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare     |
| 3. Accessible Services | Identify accessible interfaces and services that are hosted externally or internally. | Service Type, Functionality, Configuration, Port, Version, Interface                  |
| 4. Processes        | Identify the internal processes, sources, and destinations associated with the services. | PID, Processed Data, Tasks, Source, Destination                                       |
| 5. Privileges       | Identification of the internal permissions and privileges to the accessible services. | Groups, Users, Permissions, Restrictions, Environment                                 |
| 6. OS Setup         | Identification of the internal components and systems setup.                | OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files list |

Layer 1 - We find find targets to investigate
Layer 2 - This is what protecting the targets and its interface.
Layer 3 - This is the services the targets offer.
Layer 4 - The processes that are launched by the system. The data exchanged between the processes.
Layer 5 - Each service or process is run with certain priveledges. The priveledges used need to be understood.
Layer 6 - Understanding the host itself the Enviornment. Understanding how the admins maintain the system.
