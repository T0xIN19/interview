# JWT Security – Advanced Interview Notes

## What is JWT
JSON Web Token (JWT) is a stateless authentication mechanism consisting of:
- Header
- Payload
- Signature

---

## Types of JWT

### 1. JWS (Signed JWT)
- HS256, RS256, ES256
- Payload is Base64URL encoded, not encrypted

### 2. JWE (Encrypted JWT)
- Payload is encrypted
- Used for sensitive data transfer

### 3. Stateless JWT
- No server-side session
- Fully trust-based

### 4. Stateful / Hybrid JWT
- JWT + backend validation

---

## Common JWT Vulnerabilities

- alg:none
- Algorithm confusion (RS256 ↔ HS256)
- Weak HMAC secrets
- Missing claim validation (exp, aud, iss)
- Privilege escalation via claims
- JWT stored in localStorage
- Token leakage
- No token revocation

---

## JWT Payload Categories (Testing View)

1. Algorithm manipulation
2. Signature manipulation
3. Claim tampering
4. Key confusion
5. Token replay
6. Transport & storage abuse

---

## WAF Bypass – Conceptual
- JWT is Base64URL encoded
- WAFs are ineffective against logic flaws
- Attacks focus on verification logic, not injection

---

## How to Identify Successful Exploit
- Unauthorized API access
- Privileged endpoint execution
- Expanded data scope
- Role-based response changes

---

## Scenario-Based Notes

### Role changed but UI unchanged
Backend trusts JWT, frontend caches role

### Token works on one API but not another
Missing aud validation

### Logout but token still valid
Stateless JWT, no revocation

---

## JWT Chaining

- XSS → JWT theft → Account takeover
- IDOR + JWT claim abuse
- JWT bypass → Admin APIs
- JWT + CORS misconfiguration

---

## Mitigation

- Enforce algorithms strictly
- Reject alg:none
- Prefer RS256
- Validate all claims
- Short expiry + refresh tokens
- HttpOnly cookies
- Token revocation
- Key rotation

---

## Expert Interview Quote
"JWT vulnerabilities break trust assumptions, not cryptography."
