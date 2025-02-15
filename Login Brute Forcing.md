
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
