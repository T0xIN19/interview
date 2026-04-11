# 🔐 API Authentication Methods – Complete Guide

This README explains different authentication mechanisms used in APIs and applications, with examples, use cases, and security comparison.

---

# 📌 Why Authentication is Needed
Authentication ensures:
- Only authorized users access systems
- Data confidentiality and integrity
- Protection from unauthorized access and attacks

---

# 🔑 Types of Authentication

## 1. Basic Authentication
### 📖 Explanation
- Uses Base64 encoding of `username:password`
- Sent in HTTP headers

### 📌 Example
```
Authorization: Basic dXNlcjpwYXNz
```

### ⚠️ Risk
- Easily decoded
- Not secure without HTTPS

---

## 2. Digest Authentication
### 📖 Explanation
- Uses hashing (MD5) instead of sending plain password
- Server sends nonce → client responds with hash

### 📌 Example Flow
1. Server → nonce
2. Client → hashed response

### ⚠️ Risk
- Still vulnerable to replay attacks
- Rarely used today

---

## 3. API Keys
### 📖 Explanation
- Unique key passed in headers or query

### 📌 Example
```
GET /api/data
x-api-key: 12345abcde
```

### ⚠️ Risk
- No user identity
- Can be leaked easily

---

## 4. JWT (JSON Web Token)
### 📖 Explanation
- Token with header, payload, signature
- Stateless authentication

### 📌 Example
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### ✅ Advantages
- No session storage
- Fast and scalable

### ⚠️ Risk
- Token leakage = full access
- Cannot be revoked easily

---

## 5. OAuth 2.0
### 📖 Explanation
- Delegated authorization
- Used for "Login with Google/Facebook"

### 📌 Example Flow
1. User → OAuth provider login
2. App receives access token

### ✅ Advantages
- Secure delegation
- No password sharing

---

## 6. Session Authentication
### 📖 Explanation
- Server creates session ID after login
- Stored in cookies

### 📌 Example
```
Set-Cookie: session_id=abc123
```

### ✅ Advantages
- Easy to revoke
- Widely used

### ⚠️ Risk
- Session hijacking

---

## 7. OpenID Connect (OIDC)
### 📖 Explanation
- Built on OAuth 2.0
- Adds identity layer (authentication)

### 📌 Example
- ID Token (JWT) contains user info

### ✅ Advantages
- Modern standard
- Used in enterprise apps

---

## 8. SSO (Single Sign-On)
### 📖 Explanation
- One login for multiple applications

### 📌 Example
- Login once → access Gmail, Drive

### ✅ Advantages
- Better user experience
- Centralized authentication

---

## 9. SAML (Security Assertion Markup Language)
### 📖 Explanation
- XML-based authentication used in enterprises

### 📌 Example
- Corporate login portals

### ⚠️ Risk
- Complex
- XML vulnerabilities possible

---

## 10. Refresh Token
### 📖 Explanation
- Used to generate new access tokens
- Long-lived token

### 📌 Example Flow
1. Access token expires
2. Refresh token → new token

### ⚠️ Risk
- If stolen, attacker can maintain access

---

# 🔒 Security Comparison

| Method            | Security Level | Use Case                |
|------------------|--------------|------------------------|
| Basic Auth       | ❌ Low        | Testing only           |
| Digest Auth      | ❌ Low        | Legacy systems         |
| API Keys         | ⚠️ Medium     | Public APIs            |
| Session Auth     | ✅ Medium     | Web apps               |
| JWT              | ✅ Medium-High| APIs, Microservices    |
| OAuth 2.0        | ✅ High       | Third-party login      |
| OIDC             | ✅ High       | Identity systems       |
| SAML             | ✅ High       | Enterprise SSO         |
| Refresh Token    | ⚠️ Depends    | Token lifecycle        |

---

# 🏆 Which One is Most Secure?

### 🔥 Best Modern Approach:
- OAuth 2.0 + OpenID Connect
- JWT with short expiry + Refresh Tokens

### 🏢 Enterprise:
- SAML + SSO

### 🚀 APIs:
- JWT + OAuth 2.0

---

# ⚡ Best Practices

- Always use HTTPS
- Use short-lived tokens
- Rotate API keys
- Implement MFA
- Store tokens securely
- Use secure cookies (HttpOnly, Secure)

---

# 📌 Conclusion

Different authentication methods serve different purposes:
- Simple → API Keys
- Scalable → JWT
- Enterprise → SAML / SSO
- Modern secure → OAuth 2.0 + OIDC

Choose based on your application architecture and security requirements.

---

# 👨‍💻 Author
Security Notes for VAPT & API Testing
