# Intro to Web proxies

- **Web & Mobile Apps**: Rely on back-end servers for data processing. Securing and testing these servers is crucial.
- **Penetration Testing**: Capturing and analyzing web traffic between apps and servers is a key part of web app penetration testing.

### What Are Web Proxies?

- **Function**: Tools that act as a "man-in-the-middle" between a browser/app and a back-end server, capturing web requests.
- **Difference from Network Sniffers**: Unlike tools like Wireshark, web proxies focus on web traffic (HTTP/80, HTTPS/443).
- **Why Essential**: Simplifies capturing, modifying, and replaying HTTP requests during penetration testing.

### Uses of Web Proxies

1. **Vulnerability Scanning**
2. **Web Fuzzing**
3. **Web Crawling**
4. **Application Mapping**
5. **Request Analysis**
6. **Configuration Testing**
7. **Code Reviews**

### Burp Suite

- **Overview**: Popular web proxy with a user-friendly interface.
- **Versions**:
  - **Community Edition**: Free, sufficient for most tests.
  - **Burp Pro**: Paid version with advanced features like Active Web App Scanner and Burp Extensions.
- **Tip**: Free trial available for educational/business email holders.

### OWASP Zed Attack Proxy (ZAP)

- **Overview**: Free, open-source web proxy maintained by the community with no paid-only features.
- **Strengths**: Free, growing features, and no subscription limits.

### Burp vs ZAP

- **Similarities**: Both offer essential features for web pentesting.
- **Choosing**:
  - **ZAP**: Best for a free, open-source solution.
  - **Burp Pro**: Ideal for advanced or corporate testing where paid features are needed.


# Proxy Setup

#### Purpose
- **Web Proxy**: Tools like Burp Suite and ZAP act as a proxy to intercept, examine, and modify web traffic between an app and its back-end server.
- **Benefits**: Helps understand application behavior, intercept requests, modify data, and test how the app responds.

#### Pre-Configured Browser
- Both Burp and ZAP provide a pre-configured browser that automatically routes all traffic through the respective proxy:
  - **Burp**: Go to **Proxy > Intercept** and click **Open Browser** to use Burp's pre-configured browser.
  - **ZAP**: Click the Firefox icon on the top bar to open the pre-configured browser.

#### Configuring a Real Browser (e.g., Firefox)
1. **Set Proxy in Firefox**:
   - Go to Firefox preferences and configure it to use Burp or ZAP’s proxy.
   - Both Burp and ZAP use **port 8080** by default (can be changed if needed).
   - **Warning**: If port 8080 is in use, an error message will appear.

2. **Changing Proxy Port**:
   - Burp: **Proxy > Options**
   - ZAP: **Tools > Options > Local Proxies**
   - Ensure the proxy port in Firefox matches the one set in Burp/ZAP.

3. **Using Foxy Proxy Extension**:
   - **Install Foxy Proxy**: Pre-installed in PwnBox or available from the [Firefox Extensions page](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/).
   - **Configure Foxy Proxy**:
     - Add a new proxy with IP: `127.0.0.1` and port: `8080`.
     - Name it **Burp** or **ZAP**.

4. **Selecting Proxy**:
   - After configuring, click the Foxy Proxy icon in Firefox and select **Burp** or **ZAP**.

#### Installing CA Certificates
1. **Why?**: Without the CA certificates, some HTTPS traffic won’t be routed properly or will prompt for acceptance every time.
2. **Burp Certificate**:
   - Go to `http://burp` in the browser and download the CA certificate.
   - **ZAP Certificate**:
     - Go to **Tools > Options > Dynamic SSL Certificate** and click **Save** to download it.

3. **Install Certificate in Firefox**:
   - Open Firefox and go to `about:preferences#privacy`.
   - Scroll to **View Certificates**, go to the **Authorities** tab, click **Import**, and select the downloaded certificate.
   - Select **Trust this CA to identify websites** and **Trust this CA to identify email users**, then click **OK**.

#### Final Steps
- Once the certificate is installed and the Firefox proxy is configured, all Firefox web traffic will route through the web proxy for examination and testing.

# Intercepting Web Requests

#### Purpose
- **Web Proxy**: Intercept and manipulate HTTP requests between the web app and server to analyze app behavior and test for vulnerabilities.

#### Intercepting Requests

1. **Burp Suite**:
   - **Enable Intercept**: Go to the **Proxy** tab and ensure **Intercept is on**.
   - Once interception is on, open the pre-configured browser and visit the target website.
   - Requests will appear in Burp, and you can click **Forward** to send them to their destination.
   - **Note**: If multiple requests are intercepted, click **Forward** until the target request appears.

2. **ZAP (OWASP)**:
   - **Enable Intercept**: By default, interception is off (green button). Click it to turn on, or use shortcut [CTRL+B].
   - After enabling, open the pre-configured browser and revisit the exercise webpage.
   - Intercepted requests will appear in the **top-right pane**, and you can click on them to forward.
   - **HUD (Heads Up Display)**: ZAP's HUD allows controlling intercepts from within the browser. Enable the HUD by clicking the button at the top menu bar.
     - **Step**: Examines each request in detail.
     - **Continue**: Sends the request and forwards remaining requests.
   - **Tip**: Take the HUD tutorial for a better understanding of its features.

#### Manipulating Intercepted Requests
- Once requests are intercepted, you can examine and modify them before forwarding.
- **Testing for Vulnerabilities**: Manipulating requests can help test for common web vulnerabilities, such as:
  - SQL Injection
  - Command Injection
  - Authentication Bypass
  - XSS, XXE
  - Error Handling
  - Deserialization, etc.

#### Example: Manipulating a Web Request

1. **Intercept a POST request**:
   - Example HTTP request for a `ping` feature:
     ```
     POST /ping HTTP/1.1
     Host: 46.101.23.188:30820
     Content-Length: 4
     ...
     ip=1
     ```
2. **Manipulate the IP Parameter**:
   - Normally, the IP field accepts only numbers, but by intercepting the request, you can change the value.
   - **Example Manipulation**: Change `ip=1` to `ip=;ls;` (attempting a command injection).
3. **Forward the Request**:
   - Once the request is forwarded, the response changes from the default ping output to the results of `ls` (command injection successful).

---

# Intercepting Responses

#### Purpose
- **Intercepting HTTP Responses** allows penetration testers to modify the server’s response before it reaches the browser. This is useful for manipulating the content or behavior of a webpage, such as enabling disabled fields or revealing hidden fields, which could help identify vulnerabilities or facilitate exploiting certain web application behaviors.

#### Burp Suite

1. **Enable Response Interception**:
   - Navigate to **Proxy > Options** in Burp Suite.
   - In the **Intercept Server Responses** section, enable the **Intercept Responses** option. This ensures that responses from the server can be intercepted before being sent to the browser.
   
2. **Intercept & Modify the Response**:
   - Once response interception is enabled, refresh the page in the pre-configured browser (`CTRL + SHIFT + R`), forcing a full reload of the page.
   - Burp will intercept the request and show it in the **Intercept** tab.
   - After forwarding the request, the **Intercepted Response** will appear. This allows us to inspect and modify the response before it reaches the browser.

3. **Example Modification**:
   - Suppose a page contains an input field that only accepts numeric values (type="number"). If we intercept the response, we can modify the field type from `type="number"` to `type="text"`. This would allow us to enter any value, bypassing the numeric input restriction.
   - We can also modify attributes such as `maxlength="3"` to `maxlength="100"` to increase the allowed input length for the field. After making these changes, we can click **Forward** to send the modified response to the browser.
   
4. **Use Case**:
   - This feature is especially useful for modifying how the page is rendered by the browser, allowing us to interact with form fields or buttons that might be disabled or hidden in the default view. For example, we could enable disabled HTML buttons, modify form validation rules, or show hidden fields that are not visible to the user by default.

#### ZAP (OWASP)

1. **Intercept Responses**:
   - Like Burp, ZAP allows you to intercept responses. When requests are intercepted, you can click the **Step** button to send the request and automatically intercept the corresponding response.
   - After the response is intercepted, you can modify it and click **Continue** to forward the modified response to the browser.
   - This allows you to modify aspects of the page like field types or form validation rules before they are rendered to the user.

2. **Enable Disabled Fields or Show Hidden Fields**:
   - ZAP’s **Heads Up Display (HUD)** provides a feature that lets you manipulate form fields and elements directly in the browser, without needing to manually intercept the response and modify it.
   - In the HUD, you can click the **light bulb icon** (third button from the top on the left) to enable or show disabled fields and hidden fields, bypassing the need for response interception.
   - This feature makes it easier to directly interact with elements that would typically be hidden or disabled, making it a very useful tool for penetration testing.

3. **Burp Similar Features**:
   - **Unhide Hidden Form Fields**: Burp Suite has a feature under **Proxy > Options > Response Modification** called **Unhide hidden form fields**. When enabled, this feature will automatically unhide hidden fields in the response HTML, making it easier to interact with them during testing.
   - **HTML Comments**: Both Burp and ZAP allow you to view HTML comments that are normally hidden from the page's display but present in the source code. Burp offers a **Comments Button** in the **Proxy > Options** tab. Enabling it will allow you to identify where comments are located within the HTML and provide insight into potential points for testing or exploiting.
     - Clicking the **Comments Button** will display a visual indicator for any HTML comments in the source code, and hovering over the indicator reveals the comment content.
---

# Automatic Modification

In certain situations, we may want to apply modifications automatically to all outgoing HTTP requests or all incoming HTTP responses. Web proxy tools like Burp Suite and ZAP allow us to set up rules for these automatic modifications.

## Automatic Request Modification

Let’s start with an example of automatic request modification. In this case, we want to replace the `User-Agent` string in all outgoing HTTP requests. This is useful when dealing with filters that block certain User-Agents.

### Burp Suite: Match and Replace

1. Go to `Proxy > Options > Match and Replace` and click on `Add`.
2. Set the following options:
   - **Type**: Request header (since the modification is in the request header, not the body)
   - **Match**: `^User-Agent.*$` (regex pattern to match any User-Agent string)
   - **Replace**: `User-Agent: HackTheBox Agent 1.0` (this is the value to replace the matched string)
   - **Regex match**: True (since we’re using a regex pattern to match the User-Agent)
3. Click `OK` to save the rule.

Once added, this rule will automatically replace the `User-Agent` header with `HackTheBox Agent 1.0` in all outgoing requests.

### ZAP: Replacer

ZAP offers a similar feature called **Replacer**. Follow these steps to configure it:

1. Press `[CTRL+R]` or go to the `Replacer` option in ZAP’s menu.
2. Click `Add` and set the following:
   - **Description**: HTB User-Agent.
   - **Match Type**: Request Header (will be added if not present).
   - **Match String**: User-Agent (select from the drop-down menu).
   - **Replacement String**: `HackTheBox Agent 1.0`.
   - **Enable**: True.
3. You can also use a regex pattern here for more advanced matching.
4. Set the **Initiators** option to apply the rule to all HTTP(S) messages by default.

Now, whenever you visit a page using ZAP’s browser, the `User-Agent` will be automatically replaced.

## Automatic Response Modification

Just like requests, we can also modify HTTP responses automatically. This is useful for situations where changes made to the response body (e.g., altering input fields) need to persist across page refreshes.

### Burp Suite: Response Body Match and Replace

1. Go to `Proxy > Options > Match and Replace` in Burp.
2. Add a new rule with the following settings:
   - **Type**: Response body (since we want to modify the response body).
   - **Match**: `type="number"` (the string to match in the response body).
   - **Replace**: `type="text"` (the new value to replace the matched string).
   - **Regex match**: False (since we’re using an exact match and not a regex).
3. Optionally, add another rule to change `maxlength="3"` to `maxlength="100"`.

Now, after refreshing the page with `[CTRL+SHIFT+R]`, you’ll see that the changes you made to the response body are applied automatically. This ensures that modifications persist between page refreshes.

By using these automatic modifications, you can save time and automate tasks like replacing headers or modifying response bodies without having to manually intercept and modify requests each time.

---

# Repeating Requests

#### Overview
Repeating requests and utilizing request history are key features in Burp Suite and ZAP for performing web application penetration testing efficiently. These features help automate the process of re-sending and modifying HTTP requests without having to manually intercept and resend each one, saving significant time during testing and enumeration tasks.

### **Proxy History** (Burp and ZAP)
Both Burp Suite and ZAP maintain a **history** of HTTP requests that have passed through their proxies. This allows testers to view and modify requests they've already seen and interacted with.

- **Burp Suite**:
  - Navigate to **Proxy > HTTP History** to view all intercepted requests.
  - Burp allows filtering and sorting of requests to help locate a specific one, especially useful when dealing with a large number of requests.
  - Each request can be examined in detail, with the ability to view both the **original** and **edited** requests. If the request was modified, you can switch between these views.

- **ZAP**:
  - The **History pane** in ZAP shows the requests, which can be accessed from the bottom of the HUD or the main UI.
  - Like Burp, ZAP offers filtering and sorting features for easier navigation through request history.
  - ZAP maintains WebSockets history, which is useful for tracking real-time connections initiated by the web application (e.g., asynchronous updates, data fetching).

#### **Request Repeating** (Burp Suite and ZAP)

Repetition of requests is useful for quickly modifying and re-sending HTTP requests, without needing to manually re-intercept or rebuild requests.

- **Burp Suite**:
  - Once you locate the desired request in the **HTTP History**, you can **right-click** and select **Send to Repeater**, or use the shortcut **CTRL+R**.
  - After sending it to the **Repeater** tab, you can modify the request and click **Send** to resend the modified request.
  - Burp also allows you to change the HTTP method between **POST/GET** using **Change Request Method**, saving time when testing different request types.

- **ZAP**:
  - In **ZAP**, after finding the request in the history, right-click and choose **Open/Resend with Request Editor**.
  - The **Request Editor** window will open, where you can modify the request and use the **Send** button to send the updated request.
  - You can also easily switch HTTP methods (e.g., from GET to POST) using the **Method drop-down**.
  - ZAP **HUD** (Heads-Up Display) lets you resend requests directly from the browser with **Replay in Console** for the response in the HUD or **Replay in Browser** to see the rendered response in the browser.

#### **Modifying Requests**
- **Modifying Requests in Burp Suite**:
  - Once the request is in **Repeater**, you can modify its parameters (e.g., replacing payloads, changing headers, etc.).
  - Burp Repeater allows quick testing and enumeration by modifying specific parts of the request and instantly viewing the results.
  
- **Modifying Requests in ZAP**:
  - Similar to Burp, you can modify requests in the **Request Editor** and **HUD**.
  - Changes can be made in specific fields of the request (like the body or headers), and you can resend it with the modified input.

#### **URL-Encoding in POST Requests**
- When working with HTTP requests, especially **POST** requests, data is often **URL-encoded** (for example, when sending form data).
- URL encoding ensures that special characters (e.g., `&`, `=`, `#`) are encoded properly for transmission over HTTP.
- This is crucial when modifying requests with custom payloads because you may need to ensure the new data is properly encoded (if needed).

### **Practical Example:**
For a command injection test:
- **Intercept** the request with Burp Suite or ZAP.
- **Modify** the body of the request (e.g., add a different payload).
- **Repeat** the request using the **Repeater** or **Request Editor**.
- **View** the response to check the outcome.
- Using Burp or ZAP for repeating requests allows quick iterations of payload testing without needing to manually intercept each request.

---

# Encoding/Decoding 

Encoding and decoding are essential for modifying and interacting with web requests properly during penetration testing. This ensures that the data is transmitted correctly and allows for effective manipulation of requests and responses.

### **URL Encoding**

- **Why URL Encoding is Important**:  
  Certain characters in URLs need to be encoded, such as:
  - **Spaces** → `%20`
  - **`&`** → `%26`
  - **`#`** → `%23`

- **How to URL-encode in Burp**:
  - Right-click the text in **Burp Repeater** and select **Convert Selection > URL > URL encode key characters** or use **CTRL+U**.
  - Burp supports **auto URL encoding** while typing.

- **How ZAP Handles URL Encoding**:
  - ZAP automatically URL-encodes request data before sending.

### **Decoding Data**

- **Why Decoding is Important**:  
  Web applications often encode data (e.g., cookies, tokens), and decoding allows you to view and manipulate the original content.

- **Common Encoding Types**:
  - **Base64** (e.g., for cookies)
  - **URL Encoding**
  - **HTML Encoding**
  - **Unicode Encoding**

### **Burp Suite: Encoding/Decoding Tools**

- **Decoder Tab**:
  - Use the **Decoder** tab in Burp to quickly encode or decode data (e.g., Base64, URL encoding).
  - **Base64 Example**: Decode `eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=` to `{"username":"guest", "is_admin":false}`.

- **Inspector Tool**:  
  Available in Burp's **Proxy** and **Repeater**, this helps with encoding and decoding data quickly.

### **ZAP: Encoding/Decoding Tools**

- **Encoder/Decoder/Hash Tool**:  
  ZAP allows for quick encoding and decoding (Base64, URL encoding, etc.) and supports custom tabs for different encoding methods.

### **Encoding Example**

1. **Base64 Example**:
   - **Original**: `eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=`
   - **Decoded**: `{"username":"guest", "is_admin":false}`
   - **Modified**: `{"username":"admin", "is_admin":true}`
   - **Re-encoded**: `eyJ1c2VybmFtZSI6ImFkbWluIiwgImlzX2FkbWluIjp0cnVlfQ==`

2. **Testing**: Replace the old encoded string in your request to test changes like privilege escalation.

### **Tips for Efficient Workflow**

1. **Burp**:
   - Use the **Decoder** tab and enable **auto URL encoding** while typing.
   - **Burp Inspector** simplifies encoding/decoding across different modules.

2. **ZAP**:
   - Use **Encoder/Decoder/Hash** for various encodings and custom tabs for convenience.

---

# Proxying Tools

An important aspect of using web proxies is enabling the interception of web requests made by command-line tools and thick client applications. This allows us to monitor the web requests and utilize proxy features with these tools.

## Setup Web Proxy for Tools

To route web requests from a tool through a web proxy, you need to set the proxy for each tool (e.g., `http://127.0.0.1:8080`). The process may vary depending on the tool, so you'll need to investigate how to configure the proxy for each.

Note: Proxying tools often slows them down, so only proxy when necessary for investigating requests.

## Proxychains

Proxychains is a useful Linux tool that routes all traffic from command-line tools through any proxy we specify.

### Setup Proxychains

1. Edit `/etc/proxychains.conf`.
2. Comment out the final line and add the following line at the end:
   ```
   http 127.0.0.1 8080
   ```
3. Uncomment `quiet_mode` to reduce noise.
4. Use `proxychains` before any command to route its traffic through the proxy. For example, with `curl`:
   ```
   proxychains curl http://SERVER_IP:PORT
   ```

This routes the `curl` request through the web proxy, and you should see the request in the proxy tool (e.g., Burp or ZAP).

### Example Output
```
ProxyChains-3.1 (http://proxychains.sf.net)
<!DOCTYPE html>
<html lang="en">
  <head>...</head>
  <body>...</body>
</html>
```

## Nmap

Nmap can also be proxied through a web proxy.

### Use Proxy with Nmap

1. To find out the proxy option, use the help page:
   ```
   nmap -h | grep -i prox
   ```
   This shows the `--proxies` option for HTTP/SOCKS4 proxies.

2. Use `--proxies` flag to route Nmap traffic:
   ```
   nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC
   ```

### Example Output
```
Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for SERVER_IP
Host is up (0.11s latency).

PORT      STATE SERVICE
PORT/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

If successful, you'll see Nmap requests in your proxy history. Note that Nmap's proxy support is still experimental, so some traffic may not be routed through the proxy. In that case, use Proxychains as a workaround.

## Metasploit

Metasploit also allows us to route web traffic through a proxy.

### Setup Proxy for Metasploit

1. Start Metasploit with `msfconsole`.
2. Use the `set PROXIES` command to specify the proxy for any exploit. For example:
   ```
   msfconsole
   msf6 > use auxiliary/scanner/http/robots_txt
   msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080
   msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP
   msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT
   msf6 auxiliary(scanner/http/robots_txt) > run
   ```

### Example Output
```
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

After running the module, you can check the proxy history to see the requests made by Metasploit.

## Other Tools

This method can be used with other command-line tools, scripts, and thick clients by configuring them to use the web proxy. By doing so, you can investigate and modify their requests during web application penetration testing.

---

# Burp Intruder

Both Burp Suite and ZAP offer additional features beyond their default web proxy capabilities, which are essential for web application penetration testing. Among the most useful features are web fuzzers and web scanners. Burp's fuzzer is called **Burp Intruder** and serves as an alternative to CLI-based web fuzzing tools like ffuf, dirbuster, gobuster, and wfuzz.

## Burp Intruder Features
- **Web Fuzzing**: Allows you to fuzz web pages, directories, sub-domains, parameters, and values.
- **Speed**: The free version of Burp Suite limits requests to 1 per second. The Pro version has unlimited speed, which makes it comparable to CLI-based fuzzers.
- **Use Case**: Ideal for small fuzzing tasks or for those with Burp Pro.

## Setup and Configuration
### Target
- **Sending Request to Intruder**: In Burp's Proxy History, locate a request and right-click to select **Send to Intruder**, or use **[CTRL+I]**.
- **Intruder Tab**: Open the Intruder tab (**[CTRL+SHIFT+I]**), where you'll configure the attack.

### Positions Tab
- **Payload Position**: Specify where to insert the payloads. Select the part of the request you want to fuzz (e.g., directory names).
- **Attack Type**: Select the type of attack. For simplicity, choose the **Sniper** attack type (single position).

### Payloads Tab
1. **Payload Sets**: This identifies the payload number based on the attack type.
2. **Payload Options**: Configure the wordlist for the payload. Choose **Simple List** or a **Runtime file** to load a wordlist.
   - Example: Load **/opt/useful/seclists/Discovery/Web-Content/common.txt**.
3. **Payload Processing**: Apply rules to modify the wordlist before fuzzing. For example, use regex to skip lines starting with a dot (`^\..*$`).
4. **Payload Encoding**: Enable URL encoding for payloads (usually enabled by default).

### Options Tab
- **Retry Options**: Set retries on failure and pause before retrying to 0.
- **Grep - Match**: Configure rules to match responses with specific strings (e.g., HTTP 200 OK) to filter the results.
- **Grep - Extract**: Useful for extracting specific parts of the response if needed.
- **Resource Pool**: Define how much network resource to allocate for the attack (use default for smaller attacks).

### Attack
- **Start Attack**: Click **Start Attack** to initiate the fuzzing process.
- **Results**: Review the results for hits (e.g., `/admin` directory).
- **Sorting Results**: You can sort the results by status code (e.g., 200 OK), length, or other parameters.

## Additional Uses
- Burp Intruder is versatile for:
  - Brute-forcing passwords.
  - Fuzzing for PHP parameters.
  - Password spraying for applications using Active Directory (AD) authentication, such as Outlook Web Access (OWA), SSL VPN portals, Remote Desktop Services (RDS), and Citrix.

## Considerations
- **Free Version**: The free version of Burp Intruder is throttled to 1 request per second, which is slow for large wordlists. 
- **Pro Version**: The Pro version removes the speed limit and provides additional features for larger-scale fuzzing.

---

# ZAP Fuzzer 

ZAP's Fuzzer is a powerful tool for fuzzing web endpoints, offering advantages over Burp's free Intruder due to its lack of throttling on fuzzing speed. While ZAP Fuzzer may lack some of the advanced features of Burp Intruder, it is highly effective for web directory fuzzing and other types of fuzzing.

## Setup and Configuration

### Fuzzing Process
To begin fuzzing with ZAP Fuzzer:
1. Visit the target URL (e.g., `<http://SERVER_IP:PORT/test/>`) to capture a sample request.
2. From the Proxy History, right-click on the request and select **Attack > Fuzz** to open the Fuzzer window.

### Main Configuration Options

#### Locations
- **Fuzz Location**: This is similar to Burp's Payload Position, where you define where the payloads will be placed in the request.
  - Select the target word (e.g., "test") and click **Add**.
  - This will mark the selected word with a green marker and open the Payloads window to configure the attack payloads.

#### Payloads
- **Payload Types**: ZAP Fuzzer offers 8 different payload types:
  - **File**: Select a wordlist from a file.
  - **File Fuzzers**: Choose wordlists from built-in databases.
  - **Numberzz**: Generates sequences of numbers with custom increments.
- **Advantage**: ZAP Fuzzer includes built-in wordlists, eliminating the need to provide your own. Additional wordlists can be installed from the ZAP Marketplace.
- For example, select **File Fuzzers** and choose a wordlist (e.g., from DirBuster).

#### Processors
- **Payload Processors**: Apply transformations to the payloads before sending them, including:
  - **Base64 Decode/Encode**
  - **MD5 Hash**
  - **Postfix String / Prefix String**
  - **SHA-1/256/512 Hash**
  - **URL Decode/Encode**
  - **Script**: Apply custom scripts to manipulate payloads.
- **Processor Example**: Select **URL Encode** to ensure payloads with special characters are properly encoded, avoiding server errors.

#### Options
- **Concurrent Threads**: Set the number of threads for the scan. For fast fuzzing, set to **20** threads, depending on server and machine limits.
- **Scan Mode**: Choose between **Depth first** (try all words for one payload position before moving to the next) or **Breadth first** (apply each word from the wordlist to all payload positions before moving to the next word).

### Fuzzing Attack

Once configured:
1. Click **Start Fuzzer** to initiate the attack.
2. **Results**: Sort results by **Response Code** to focus on those with HTTP code 200 (successful responses).
   - For example, you may find a directory like `/skills/` which returns a 200 OK, indicating it exists on the server.

### Analyzing Results
- **Response Code**: Focus on responses with HTTP code **200 OK** to identify accessible directories or resources.
- **Size Resp. Body**: Different page sizes may indicate unique responses, useful for detecting varying types of content.
- **RTT (Round-Trip Time)**: Can be useful for attacks like time-based SQL injections, where the server response time is an indicator.

## Conclusion
ZAP Fuzzer is an effective tool for fuzzing web endpoints, especially with its speed advantage over Burp’s free version. While it lacks some of Burp's advanced features, ZAP Fuzzer's built-in wordlists and customizability through processors make it a strong choice for web directory fuzzing and other fuzzing tasks.

---


# Burp Scanner

Burp Scanner is a powerful feature available in **Burp Suite Pro** for scanning web vulnerabilities. It uses a **Crawler** to build a website structure and the **Scanner** for both passive and active scanning. Burp Scanner is only available in the Pro version and offers advanced scanning features making it suitable for enterprise-level use.

## Target Scope

To start a scan in Burp Suite, we have several options:
- **Scan a specific request** from Proxy History.
- **Start a new scan** on a set of targets.
- **Scan in-scope items** defined in the Target Scope.

### Configuring the Scope
1. **Right-click on an item** in Proxy History and select **Scan** to configure or **Passive/Active Scan** to start the scan quickly.
2. To scan a set of custom targets, go to **New Scan** in the Dashboard and configure the scan based on your in-scope targets.
3. **Target Scope**: Limit scans to specific targets, which saves resources by ignoring out-of-scope URLs.
4. Add items to scope by right-clicking on them and selecting **Add to scope**.
5. **Excluding Items**: Right-click on any item to **Remove from scope**, such as login pages or session-ending items.
6. **Advanced Scope Control**: Use regex patterns to include/exclude URLs in the **Target > Scope** section.

### Example Workflow:
- Go to **Target > Site map** to see directories/files Burp has detected.
- Right-click on an item and **Add to scope** to include it for future scans.
- Optionally, configure Burp to limit features to in-scope items only.

## Crawler

The **Crawler** maps the website by navigating links, accessing forms, and analyzing requests. It helps build a comprehensive map of the site for further scanning.

- **Crawl and Audit**: Burp performs a crawl and then an audit (scanning for vulnerabilities).
- **Crawl Only**: Only maps links and directories. For hidden pages (like those not referenced in links), use Burp Intruder or other content discovery tools, then add to scope.

### Configuring a Crawl Scan:
1. Click **New Scan** from the Dashboard.
2. Select **Crawl and Audit** for a complete scan (crawl + vulnerability audit).
3. Use preset configurations or create a custom configuration.
4. **Crawl Strategy**: Choose a crawl speed and limit.
5. **Login Configuration**: Add credentials if you need to access authenticated sections of the application.

Once the scan starts, monitor progress in the **Dashboard > Tasks** tab.

## Passive Scanner

The **Passive Scanner** analyzes already-visited pages without sending new requests. It identifies vulnerabilities based on the data already retrieved during crawling.

- **Vulnerabilities Detected**: Passive scan suggests vulnerabilities like missing HTML tags or potential DOM-based XSS.
- **Confidence Level**: Provides confidence levels for each identified vulnerability to prioritize actions.
  
### Running a Passive Scan:
1. Right-click on a request or target in **Target > Site map** and select **Do passive scan**.
2. View identified vulnerabilities in the **Issue activity** tab of the Dashboard.

## Active Scanner

The **Active Scanner** is the most comprehensive scanning tool in Burp. It sends active requests to test for vulnerabilities such as XSS, SQL Injection, and Command Injection.

### Active Scan Process:
1. **Crawl**: Identifies all possible pages and performs a web fuzzing scan (like DirBuster).
2. **Passive Scan**: Runs on all identified pages.
3. **Vulnerability Verification**: Verifies vulnerabilities identified in the Passive Scan by sending specific requests to confirm their existence.
4. **JavaScript Analysis**: Checks for vulnerabilities related to JavaScript.
5. **Fuzzing**: Attempts to exploit vulnerabilities like XSS, Command Injection, SQL Injection, etc.

### Configuring Active Scans:
1. Choose **Crawl and Audit** in the scan configuration.
2. Set the **Crawl Configuration** (speed, login details) and **Audit Configuration** (types of vulnerabilities).
3. Select an **Audit Check** preset (e.g., **Critical issues only**).
4. After starting the scan, monitor it through the **Tasks** tab in the Dashboard.

### Viewing Active Scan Results:
1. As the scan progresses, view the requests in the **Logger** tab.
2. After completion, review vulnerabilities in the **Issue activity** pane.
3. Filter results based on severity and confidence (e.g., **High Severity**, **Certain Confidence**).

## Reporting

After scanning is complete, export the results for documentation or client reporting.

1. Right-click on the target in **Target > Site map** and select **Report issues for this host**.
2. Choose the export format and customize the report content.
3. Burp’s report includes detailed information on vulnerabilities, proof-of-concept exploitation, and remediation steps.

### Key Features in Reporting:
- **Vulnerability Details**: Lists severity, confidence, and detailed exploitation steps.
- **Proof-of-Concept**: Provides evidence of exploitability.
- **Remediation Steps**: Offers recommendations for fixing vulnerabilities.
