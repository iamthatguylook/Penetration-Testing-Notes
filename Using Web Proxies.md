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
