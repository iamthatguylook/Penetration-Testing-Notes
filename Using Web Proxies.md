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

