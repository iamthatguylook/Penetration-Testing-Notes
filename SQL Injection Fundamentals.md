
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

