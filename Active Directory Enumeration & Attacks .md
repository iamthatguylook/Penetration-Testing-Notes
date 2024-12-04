# External Recon and Enumeration Principles

#### Purpose of External Reconnaissance:
1. **Validation:** Confirm scoping document information, ensuring accurate alignment with the client's target.
2. **Scope Assurance:** Avoid unintended interactions with systems outside the authorized scope.
3. **Information Gathering:** Identify publicly available data that could facilitate the penetration test, like leaked credentials or infrastructure details.

---

### What to Look For:

| **Data Point**      | **Description**                                                                                                   |
|----------------------|-------------------------------------------------------------------------------------------------------------------|
| **IP Space**         | Identifying ASN, netblocks, DNS entries, and cloud infrastructure.                                               |
| **Domain Information** | Subdomains, domain services, defenses like SIEM, AV, and IPS/IDS.                                               |
| **Schema Format**    | Email/AD username conventions and password policies for attacks like password spraying or credential stuffing.    |
| **Data Disclosures** | Metadata in public documents, links to intranet, or credentials in repositories like GitHub.                     |
| **Breach Data**      | Publicly leaked usernames, passwords, or hashes for unauthorized access to services.                             |

---

### Where to Look:

| **Resource**              | **Examples**                                                                                               |
|---------------------------|-----------------------------------------------------------------------------------------------------------|
| **ASN/IP Registrars**      | IANA, ARIN, RIPE, BGP Toolkit for IP/ASN research.                                                        |
| **Domain/DNS Records**     | Domaintools, PTRArchive, ICANN, and manual DNS queries to find subdomains and validate information.        |
| **Social Media**           | LinkedIn, Twitter, Facebook for organizational details, user roles, or infrastructure clues.              |
| **Public Websites**        | Check the "About Us" and "Contact Us" pages for embedded documents, emails, and organizational charts.     |
| **Cloud & Dev Repos**      | GitHub, AWS S3 buckets, and Google Dorks for accidentally exposed credentials or sensitive files.          |
| **Breach Sources**         | HaveIBeenPwned, Dehashed to find corporate emails, plaintext passwords, or hashes in breach databases.     |

---

### Steps and Tools:

1. **Finding Address Spaces:**  
   - Use BGP Toolkit or similar to identify ASN/IP ranges tied to the target.
   - Validate addresses with tools like
     ```
     nslookup
     ```
     and online DNS services (e.g., viewdns.info ,https://bgp.he.net/ ,https://research.domaintools.com/ ). 

2. **Hunting Documents and Emails:**  
   - **Search:** Use Google Dorks like
     ```
     filetype:pdf inurl:target.com
     ```
     or
     ```
     intext:"@target.com"
     ```
     to find sensitive files and email addresses.
   - **Save Locally:** Keep all findings organized for deeper inspection.

3. **Username Harvesting:**  
   - Tools like `linkedin2username` can generate potential username formats based on public employee data.

4. **Credential Hunting:**  
   - Search breach databases (e.g., Dehashed) to find leaked credentials for external-facing services.  
   - **Example Dork:**
     ```
     sudo python3 dehashed.py -q inlanefreight.local -p
     ```
     

---

### Key Enumeration Principles:

1. **Passive to Active Approach:** Begin with passive recon (no direct engagement) and gradually move to active enumeration once you identify potential targets.
2. **Iterative Process:** Continuously revisit and refine findings based on new data.
3. **Validate Results:** Cross-check data from multiple sources for consistency and accuracy.
4. **Stay In Scope:** Always ensure your actions are authorized and documented.

This methodology ensures thorough preparation and minimizes the risk of errors during penetration testing. Let me know if you'd like more specific examples or a focus on tools for automation!
