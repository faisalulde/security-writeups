# The Altered Grimoire - 0xV01D CTF 2026

> *An old vault carries migration scars and a few too many trusted assumptions. Find the path that turns a normal account into something more.*

**Difficulty:** Medium  
**Category:** Web Exploitation  
**Attack Chain:** `Information Disclosure` -> `Type Juggling` -> `Authentication Bypass` -> `Broken Access Control` -> `Privilege Escalation`

---

## What Was Vulnerable

The website's page source revealed an endpoint to a `users.txt` path. The `users.txt` endpoint exposed a list of credentials including an anomalous hash.

The website used loose comparison logic for the password check in the login functionality, which allowed logging in using known Magic Hashes.

The server trusted the role value submitted by the client without verifying it server-side, meaning any user could promote themselves to admin simply by changing a form field.

---

## How I Found It

### 1. Reconnaissance

The website displays a login page for "SecureVault" where you have to login to access the vault console.

After intercepting the login functionality using Burp, I tried various credentials:

- `test:test` - says "User not found!" but gives 302 Found Response
- `admin:admin` - same response
- `username=admin' OR '1'='1--&password=admin` - same response

Testing various credentials got me nowhere.

I then started looking for other endpoints:

```
/register
/signup
/admin
/console
/setup
/migrate
/api
/api/users
/api/register
```

All of them gave me `404 Page Not Found - The requested route does not exist.`

On further inspection, I checked the page source for any hidden fields, comments, or JavaScript files that might reveal endpoints or logic. The page source had a comment block:

```html
<!--
    sometimes paths are not written as they appear...
    think in segments, not full routes

    /thjslfgblkf/jdfj546j/kjfhgstnjkn4/users.txt
-->
```

Visiting this endpoint gave me a list of 21 usernames, hashed passwords, and their designated roles:

```
1:!root:df12063dba28f3de6484b024e4aa8cb4dc4b291cc6ed3e5b3c129b015c93ef7c:user
2:$ALOC$:e3d4946c0035bef8f158121298fdafe1cb37df8b71bb6bd50faae9add407ac2c:user
3:$SRV:9bee95b192306ce06a0aaa4c3990a4c20b42c0a5cf8bb2831c8090110bf3a446:user
4:$system:b966e0de428b2b20c9fbd91b7099d327253bae3f93dd2972def2752d1d4adeb1:user
5:(NULL):070562c0d856335a2273773be3b58756168e37ae4971dd4c813bc98bfac06ac0:user
6:(any):c14d69662a25704f3f48b23dec9f63dec224cac0318466fb2590bd8fecf67cd4:user
7:(created):18d7b4eef7a3762bb4493e2c351af60ad21088d31967b8e6033268d796942cc5:user
8:1:34b867036bca9f964dd03e9a047028375481dbfb68e472370380923366815384:user
9:11111111:7017e9fce1cae69237437580745be69f314152da031819f318591dad0b509543:user
10:12.x:39131c26bf265e154bb500c1f3a5ea124caae034a1b3b94cebc1f8939495ec55:user
11:1502:6f6f884a47962127f989a8c9189d88755b6f6e1131989098f41cb6b470276d61:user
12:18140815:36a9637ca2228c97a727d9e156d58f07385ef67e4638f6ee07b62edce3d31ffd:user
13:1nstaller:658ad8e931bac113e4652fee56b25968c92a03df7d4a2f3e9c13049fd638ba2c:user
14:2:7443a295ccc561c01a10659a72d0437d2640911ee9abccd44d5f78f4e1ceb9c4:user
15:22222222:212e5adbcbf28218106cad4eb77b8fc1d37b8c6f662a353c9c4c910778527dcb:user
16:30:f58eb3da115f6fc9bf51456d24ee8b9c36badb66befd109955db316e30f4961f:user
17:31994:7d3faaf3aac76b76177b8efb2cb4c7216ce3fe9d10b8cc284a3abb566f38a89b:user
18:4Dgifts:24e9e693438cd65c5cad6dc316c5ea34c73d04fa9d6fd08bedd7840435834c48:user
19:5:8a5859a2206b8a65ed1d4cb3f411563c4d8e814330b6198ab266f3f5270132d9:user
20:6.x:a25b1df463c8131f076af931db74b28bb4de5b9b7569e59863a316949d0ab8e9:user
21:EAdmin:0e46289032038065916139621039085883773413820991920706299695051332:user
```

The hashes look like SHA256 (64 hexadecimal characters).

Silly me tried logging in as `!root` and `EAdmin` using their hashed passwords directly - got "Wrong password!" for both. The non-generic error message confirmed both are valid usernames though.

I then noticed something important - EAdmin's hash is different from all the other hashes. All others are standard SHA256. EAdmin's hash starts with `0e` - that's a **Magic Hash**.

### What is a Magic Hash?

In PHP, when you compare two values using `==` (loose comparison) instead of `===` (strict comparison), PHP does type juggling.

If a string looks like a number in scientific notation, PHP converts it to a number before comparing. `0e` followed by digits looks like `0 × 10^[anything]` which always equals zero.

So in PHP:
```php
"0e462097..." == "0e830400..."
```
Both get converted to `0` and the comparison returns `true` - even though the strings are completely different.

This means if the app compares password hashes with `==`, you just need a password whose hash also starts with `0e` followed only by digits. The app thinks both hashes equal zero and lets you in.

These known magic hash values are documented by the security community - where someone ran a script trying millions of strings until they found ones producing `0e` hashes, then published them.

---

### 2. Authentication Bypass

Testing known SHA256 Magic Hash passwords on username `EAdmin`:

- `sha256magic1` - Wrong Password
- `TyNOQHUS` - **Login Successful**

The webpage now shows:

```
SecureVault - You have successfully logged in.

User ID: 21
Username: EAdmin
Current role: user

[Profile] [Admin path] [Logout]
```

### 3. Privilege Escalation

Clicking "Admin Path" returned: `Access Denied - Your current role is user.`

The Profile page showed:

```
Profile
ID: 21
Username: EAdmin
Role: user
Role sync value: user
[Save] [Back]
```

I changed the "Role sync value" field from `user` to `admin` and clicked Save. The response said "Profile role Updated."

Visiting Admin Path now returned:

```
Admin Access Granted
The vault accepted your current role.

0xV01D{04b50618-2856-47ef-965a-d3f28a1e33a1}
```

**Flag:** `0xV01D{04b50618-2856-47ef-965a-d3f28a1e33a1}`

---

## Techniques Used

1. Reconnaissance leading to Information Disclosure
2. Detecting an anomalous hash in a credential list
3. Authentication bypass using SHA256 Magic Hash (PHP type juggling)
4. Broken Access Control via client-side role manipulation
5. Privilege Escalation from user to admin

---

## Real World Impact

A company's internal admin portal where a legacy migration left a `users.txt` file exposed on an obscure path. An attacker who finds it gains a list of all usernames, identifies the anomalous hash, bypasses authentication entirely, and escalates to admin role - all without knowing any actual password.

---

## Lessons Learned

1. Always check the page source of every endpoint visited - comments left by developers can expose critical paths
2. Never leave comments in production code that reference internal file paths or endpoints
3. Don't hesitate to research anything unusual that you find - the `0e` prefix meant nothing until I looked it up
4. When you see an anomalous value in a dataset, don't move past it - EAdmin's hash stood out from 20 others and that difference was the entire vulnerability

---

*Written by [Faisal Ulde](https://github.com/faisalulde) | 0xV01D CTF 2026*
