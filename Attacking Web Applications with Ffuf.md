
# Web Fuzzing

## What is Fuzzing?

Fuzzing is a technique where random or semi-random input is sent to a web server to identify hidden directories or pages. For example, a non-existent page might return a 404 error, while a valid page returns a 200 OK.

## Wordlists

A **wordlist** contains common directory names (like `/admin`, `/login`) used for fuzzing. You can find wordlists on the [SecLists GitHub repo](https://github.com/danielmiessler/SecLists). We’ll use the `directory-list-2.3-small.txt` wordlist for this exercise.

### Finding the Wordlist

Use the `locate` command to find the wordlist:

```bash
locate directory-list-2.3-small.txt
```

This will return the location of the wordlist, typically something like:

```
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

## Using ffuf for Web Fuzzing

To fuzz directories using ffuf, use the following command:

```bash
ffuf -u http://SERVER_IP:PORT/FUZZ -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -ic
```

- `-u`: Target URL with `FUZZ` as a placeholder for each word in the wordlist.
- `-w`: Path to the wordlist.
- `-ic`: Ignore case (removes comments from the wordlist).

---
# Value Fuzzing

**Overview:**
- After successfully fuzzing for parameters, the next step is to fuzz for the **correct parameter values** that return the flag or the desired result.
- This process is similar to fuzzing for parameters but focuses on finding the appropriate value for the parameter.

**Custom Wordlist:**
- For fuzzing parameter values, we may not always find pre-made wordlists, especially for custom parameters.
- Common values, like usernames, may be found in existing wordlists, but for other parameters like IDs, we may need to generate our own list.
- In this case, we are targeting the `id` parameter, which likely accepts a **numeric value**. We will create a custom wordlist with IDs ranging from 1 to 1000.

**Creating the Wordlist:**
- Use the following Bash command to generate a list of numbers from 1 to 1000:
  ```bash
  for i in $(seq 1 1000); do echo $i >> ids.txt; done
  ```

**Fuzzing the Values:**
- Once the wordlist is created, we can start fuzzing the parameter values using the `ffuf` tool.
- The command will be similar to the previous POST fuzzing, but this time the `FUZZ` keyword will be replaced with the list of IDs from the `ids.txt` file.

**Example Command:**
```bash
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

**Results:**
- The tool will iterate through all the IDs and try them as the value for the `id` parameter.
- Once a valid ID is found, a new response will be received, potentially giving us access to the flag.

**Sending the Valid Request:**
- Once a valid ID is found, use `curl` to send a POST request with the correct `id` value to retrieve the flag.

**Example Using curl:**
```bash
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=valid_id' -H 'Content-Type: application/x-www-form-urlencoded'
```



### What Happens?

ffuf sends requests with words from the wordlist and reports which pages exist (status code 200). This helps quickly identify valid directories.

## Tips

- Not all pages may be discovered, especially if they have unique or random names.
- Use different wordlists for specific types of directories.
- Use `-ic` to ignore comment lines in the wordlist.

This method allows you to quickly discover hidden directories on a website using **ffuf**.

---

# Directory Fuzzing with ffuf

## Overview

**ffuf** is a fast web fuzzing tool that helps discover hidden directories or pages by sending multiple requests to a website based on a wordlist. 

### Key Commands:

- **`-w`**: Specifies the wordlist to use for fuzzing.
- **`-u`**: Specifies the target URL, with the `FUZZ` keyword indicating where to apply the wordlist.

## Basic Command Structure:

```bash
ffuf -w /path/to/wordlist:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

- Replace `/path/to/wordlist` with the path to your wordlist (e.g., `/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`).
- `FUZZ` is the placeholder for the directory names in the URL.

### Example Command:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

### ffuf Output:

The output shows the status codes, sizes, and other details of the directories tested. For example:

```bash
blog                    [Status: 301, Size: 326, Words: 20, Lines: 10]
:: Progress: [87651/87651] :: Job [1/1] :: 9739 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

Here, `blog` returned a **301** status, indicating a redirect. The test ran almost 90,000 requests in under 10 seconds.

### Verifying Discovered Directories:

If a directory like `/blog` returns a status code 200 or 301 and doesn't show a "404 Not Found" or "403 Forbidden," it means the directory exists but may not have a visible page. You can then check further to see if there are hidden files.

### Speed Considerations:

To speed up fuzzing, you can increase threads with the `-t` flag (e.g., `-t 200`), but avoid overdoing it to prevent overloading the server or causing disruptions.

---

# Page Fuzzing

## Overview

In this section, we will use **ffuf** to fuzz for hidden pages within a directory. After discovering a directory (e.g., `/blog`), we want to search for pages in that directory by guessing the file extensions.

## Identifying File Extensions

To begin, we need to identify which file extensions the website might use. For this, we can **fuzz for extensions** (e.g., `.php`, `.html`, `.aspx`). 

To do this, we will use a wordlist of common file extensions. A helpful wordlist is `web-extensions.txt` from the SecLists repository.

### Fuzzing Extensions

The command below will fuzz the extensions of `index` (e.g., `index.php`, `index.html`) within the `/blog` directory:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```

- `FUZZ` replaces the extension in the `indexFUZZ` URL, testing each extension in the wordlist.
  
### Example Output:

```bash
.php                    [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps                   [Status: 403, Size: 283, Words: 20, Lines: 10]
```

- `.php` returned a **200 OK** response, indicating it's a valid extension.
- `.phps` returned a **403 Forbidden**, meaning it's not accessible.

## Fuzzing Pages

Once we identify the extension (e.g., `.php`), we can further fuzz for actual pages under the `/blog` directory.

### Example Command for Page Fuzzing:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

This command will test for pages like `index.php`, `login.php`, etc.

- `index.php` returned a **200 OK** but with **0 size**, indicating an empty page.
- A different page, `REDACTED.php`, also returned **200 OK**, but with content.

---

# Recursive Fuzzing

## Overview

Recursive fuzzing allows us to automate the process of scanning directories and subdirectories for hidden files and pages. When scanning large websites with complex directory structures, recursive fuzzing can help us reach deeper levels without manually specifying each subdirectory.

## Recursive Flags in ffuf

To enable recursive scanning, use the following flags:
- `-recursion`: Enables recursion to scan newly identified directories.
- `-recursion-depth`: Specifies how deep the scan should go. For example, `-recursion-depth 1` will only scan the main directories and their immediate subdirectories.
- `-e .php`: Specifies the file extension (e.g., `.php`) to be used for fuzzing pages.
- `-v`: Outputs full URLs for better visibility of scanned paths.

### Example Command for Recursive Fuzzing:
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

## Results of Recursive Fuzzing

The recursion will automatically identify new subdirectories (e.g., `/forum`, `/blog`) and continue scanning them for pages and files. The scan output will list all URLs it discovers, including those it recursively finds under directories.

### Example Output:

```bash
[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/
[INFO] Adding a new job to the queue: http://SERVER_IP:PORT/forum/FUZZ
[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/index.php
[Status: 301, Size: 326, Words: 20, Lines: 10] | URL | http://SERVER_IP:PORT/blog
[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://SERVER_IP:PORT/blog/index.php
```

In this example:
- The scan identifies multiple directories like `/blog` and `/forum`.
- The `index.php` page under `/blog` was identified.
- A large number of requests were sent, with results showing both base URLs and their recursive directories.

### Key Observations:
- Recursive fuzzing can discover a lot of hidden content with minimal effort.
- Specifying the recursion depth helps manage the scope of the scan, ensuring it doesn't go too deep.
- The `-v` flag provides detailed information on the exact URL paths discovered.

---

# DNS Records

## Overview
In environments like HTB, private websites may not be accessible by public DNS. To access them, you need to add local domain mappings in your `/etc/hosts` file.

## Steps to Access a Local Website

1. **Accessing `academy.htb`**
   - Visiting `http://academy.htb:PORT` may fail because the domain isn’t resolved by your system.

2. **Reason for Connection Failure**
   - Since `academy.htb` is a local domain, it’s not found in public DNS servers or your local `/etc/hosts` file by default.

3. **Solution: Add to `/etc/hosts`**
   - Add the following entry to your `/etc/hosts` file to map `academy.htb` to the server’s IP:

   ```bash
   sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
   ```

4. **Access the Website**
   - Once added, visit `http://academy.htb:PORT` to access the site.

## Next Steps: Subdomain Enumeration
- No "admin" or "panel" pages were found. The next step is to search for subdomains under `*.academy.htb`.

---

# Sub-domain Fuzzing

## Overview
Sub-domain fuzzing helps identify sub-domains (e.g., `subdomain.website.com`) for a target domain by checking if they have a public DNS record.

## Process

1. **Prepare Tools and Wordlist**
   - **Wordlist**: Use `subdomains-top1million-5000.txt` from SecLists (`/opt/useful/seclists/Discovery/DNS/`).
   - **Target**: Run the scan on a domain (e.g., `inlanefreight.com`).

2. **Fuzz for Sub-domains**
   - Use ffuf to scan for sub-domains by placing the `FUZZ` keyword in place of the sub-domain part of the URL:
   
     ```bash
     ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
     ```

3. **Results Example for `inlanefreight.com`**:
   - The scan finds some sub-domains, such as `support.inlanefreight.com`, `ns3.inlanefreight.com`, etc.

4. **Testing on `academy.htb`**
   - When running the scan on `academy.htb`, no hits were returned. This indicates there are no public sub-domains available.

5. **Explanation**
   - The absence of results for `academy.htb` means that it does not have any public DNS records for sub-domains. Although `academy.htb` was added to `/etc/hosts`, ffuf looks for sub-domains that aren’t listed, and without DNS records, it cannot find them.


---

# Vhost Fuzzing

**VHosts vs Sub-domains:**
- **VHosts (Virtual Hosts)** refer to different websites hosted on the same server/IP, often using the same domain but with different sub-domains.
- A key difference is that VHosts may or may not have public DNS records, unlike public sub-domains that are mapped via DNS.
- **VHost Fuzzing** allows testing for both public and non-public sub-domains on a server by manipulating the `Host` header in HTTP requests, even without DNS records.

**VHost Fuzzing Process:**
1. **Tools Required:**
   - Fuzzing is performed using `ffuf` with a wordlist containing common sub-domain names.
   - The `-H` flag is used to specify the custom `Host` header to test VHosts.
   
2. **Command for VHost Fuzzing:**
   ```bash
   ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
   ```

3. **Expected Results:**
   - The scan returns **200 OK** for each entry in the wordlist.
   - Different VHosts should show variations in response size if they point to unique web pages or content. If no VHost exists, the page may look identical to the main domain.

4. **Key Takeaway:**
   - By fuzzing the `Host` header, you can discover hidden VHosts on the target server, even if they don't have a public DNS record. If a VHost is valid, the response will differ, indicating the presence of a new site or resource under that sub-domain.

---

# Filtering Results

- When fuzzing with `ffuf`, we often get many results with HTTP status code 200 (OK). To narrow down results, we can apply filters based on response size, number of words, or HTTP status codes.

**Filtering Options:**
- `-mc`: Match HTTP status codes (default: 200,204,301,302,307,401,403).
- `-ml`: Match number of lines in response.
- `-mr`: Match a regular expression in the response.
- `-ms`: Match HTTP response size.
- `-mw`: Match number of words in the response.
- **Filter options**:
  - `-fc`: Filter HTTP status codes.
  - `-fl`: Filter by the number of lines in the response.
  - `-fr`: Filter using regular expressions.
  - `-fs`: Filter by response size (in bytes).
  - `-fw`: Filter by the number of words in the response.

**Example of Filtering Response Size:**
- In this case, to avoid results with size 900 (non-relevant responses), we can use `-fs 900` to filter them out.

**Command to Filter Results:**
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900
```

**Expected Results:**
- The filter ensures that responses with a size of 900 bytes are excluded.
- After filtering, we can see a potential new VHost like `admin.academy.htb`.

**Verification:**
- Visit `https://admin.academy.htb:PORT/` (don't forget to add it to `/etc/hosts`) to check the page.
- The page appears empty, confirming it's a different VHost.
- Trying `https://admin.academy.htb:PORT/blog/index.php` returns a 404, verifying the page is on a separate VHost.

**Next Step:**
- Perform a recursive scan on `admin.academy.htb` to explore further pages.

---
# Parameter Fuzzing - GET

- Parameter fuzzing helps identify hidden or unpublished parameters that may be used to interact with a page.
- This is important because such parameters might expose vulnerabilities or give access to sensitive data.

**GET Request Fuzzing:**
- Parameters in a GET request are typically passed after the URL with a `?`, e.g., `http://example.com/page.php?param1=value`.
- To fuzz for parameters, we replace the parameter with `FUZZ` and run the scan using `ffuf`.

**Steps for Fuzzing GET Parameters:**
1. **Choose a wordlist**: 
   - Use `burp-parameter-names.txt` from SecLists, located at `/opt/useful/seclists/Discovery/Web-Content/`.
   
2. **Run `ffuf` with GET request fuzzing:**
   ```bash
   ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
   ```
   - `FUZZ` is replaced with each word in the wordlist to test different parameters.

3. **Filter Results**:
   - Use `-fs` to filter responses based on size to exclude default responses.

**Expected Results:**
- The scan will return different parameters. If any parameter changes the page’s response or exposes new functionality, it could be an entry point.

**Example of Result:**
- A hit might look like this: `http://admin.academy.htb:PORT/admin/admin.php?REDACTED=key`.
- After adding the parameter to the URL, if it’s valid, you may gain access to the flag or other resources.

---

# Parameter Fuzzing - POST

**Introduction:**
- **POST requests** differ from GET requests in that they send data in the body of the request, not as part of the URL.
- Fuzzing POST parameters helps find hidden inputs or endpoints not visible in the URL.

**Fuzzing POST Parameters with ffuf:**
1. **Key Setup:**
   - Use `ffuf` with the `-d` flag to specify the data field for POST requests.
   - Use `-X POST` to indicate a POST request method.
   - Set the `Content-Type` to `application/x-www-form-urlencoded` for PHP compatibility.

2. **Command Example:**
   ```bash
   ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
   ```
   - `FUZZ` is replaced with each parameter name from the wordlist.
   - Filter results by response size (`-fs xxx`) to avoid default responses.

3. **Expected Results:**
   - The scan returns any parameters that cause a difference in the response, indicating potential parameters to test.
   - For example, if "id" is discovered as a parameter, it might be used for further interactions.

**Example of Post Fuzzing Result:**
- We get a hit for the parameter `id`.
  - Test this by sending a POST request with `id=key`.
  - Example using `curl`:
    ```bash
    curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
    ```
- The response:
  ```html
  <div class='center'><p>Invalid id!</p></div>
  ```
  - The server responds with "Invalid id!", indicating that the `id` parameter exists but requires valid data.

---

# Value Fuzzing

##  Overview
- **Goal:** Find correct values for a parameter to retrieve sensitive information.
- **Example:** Fuzzing the `id` parameter in a web request.

##  Creating a Custom Wordlist
- Some parameters (e.g., `usernames`) may have pre-made wordlists.
- Other parameters (e.g., `id`) may require a **custom wordlist**.
- Generate numbers **1-1000** using Bash:
  ```sh
  for i in $(seq 1 1000); do echo $i >> ids.txt; done
  ```
- Verify:
  ```sh
  cat ids.txt
  ```

##  Value Fuzzing with `ffuf`
Use `ffuf` to test different values:
```sh
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php \
-X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
###  Breakdown:
- `-w ids.txt:FUZZ` → Uses `ids.txt` as a wordlist.
- `-X POST` → Sends a **POST request**.
- `-d 'id=FUZZ'` → Replaces `FUZZ` with values from `ids.txt`.
- `-H 'Content-Type: application/x-www-form-urlencoded'` → Sets content type.
- `-fs xxx` → Filters out responses of a specific size.

##  Extracting the Flag with `curl`
Once a valid `id` is found, send a **manual request**:
```sh
curl -X POST "http://admin.academy.htb:PORT/admin/admin.php" \
-d "id=VALID_ID" \
-H "Content-Type: application/x-www-form-urlencoded" -v
```

##  Next Steps:
- Try **different parameter names** (`user`, `token`, `access_code`).
- Use **burp intruder** for deeper testing.
- Bypass restrictions with **headers** (`X-Forwarded-For`, `Referer`).


