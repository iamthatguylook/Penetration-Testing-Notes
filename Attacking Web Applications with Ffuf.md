
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

