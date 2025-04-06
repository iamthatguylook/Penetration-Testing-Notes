# Intro to Command Injections
## Overview
- Allows execution of unauthorized system commands via user input.
- Ranked #3 in OWASP's Top 10 risks.

## Common Injection Types
- **OS Command Injection**: User input is part of an OS command.
- **SQL Injection**: Input alters SQL queries.
- **XSS (Cross-Site Scripting)**: Input is directly displayed in a webpage.

## Examples
### PHP
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```
### NodeJS
```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

## Prevention
- **Sanitize input** to remove harmful characters.
- **Use allowlists** to restrict valid input.
- **Limit process privileges** to minimize risk.

---
