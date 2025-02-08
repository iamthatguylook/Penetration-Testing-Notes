
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

