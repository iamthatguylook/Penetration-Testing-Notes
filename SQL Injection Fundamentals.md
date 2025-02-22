
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
