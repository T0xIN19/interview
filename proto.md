# Prototype Pollution – Expert Guide

## What is Prototype Pollution?
Prototype Pollution is a JavaScript vulnerability where an attacker can modify Object.prototype, Array.prototype, or other built-in prototypes via user-controlled input. This impacts all objects inheriting from them.

---

## Types of Prototype Pollution

### 1. Object Prototype Pollution
- Target: Object.prototype
- Impact: Global property injection (e.g., isAdmin, role)

### 2. Array Prototype Pollution
- Target: Array.prototype
- Impact: Logic bypass, DoS, broken loops

### 3. Function Prototype Pollution
- Target: Function.prototype
- Impact: Middleware and callback abuse

### 4. Constructor-based Pollution
- Target: constructor.prototype
- Impact: Authorization bypass

### 5. Client-side Prototype Pollution
- Target: DOM / frontend frameworks
- Impact: DOM XSS, UI manipulation

---

## Root Causes
- Unsafe deep merge functions
- Object.assign with user input
- JSON parsing without validation
- Query string parsers

---

## Payload Categories (Conceptual)
- Prototype key injection
- Constructor abuse
- Nested object pollution
- JSON body pollution
- Client-side pollution

---

## How to Identify Successful Pollution

### Backend Indicators
- Unexpected privileges
- Global object properties changed
- Authorization bypass

### Frontend Indicators
- UI behavior changes
- Unexpected console object properties

### API Indicators
- Same privileged response for different users

---

## Detection Techniques
- Static code review
- Dynamic testing
- Runtime behavior comparison

---

## WAF Limitations (Conceptual)
- Logic-level vulnerability
- Deep JSON nesting ignored
- Prototype keys not signature-based

---

## Mitigation
- Block dangerous keys (__proto__, constructor, prototype)
- Use safe merge libraries
- Freeze prototypes
- Apply strict schema validation
- Avoid deep merge on user input

---

## Real-world Scenarios
- Admin privilege escalation
- Feature flag abuse
- Stored XSS
- Denial of Service

---

## Chaining Prototype Pollution
- Auth bypass
- XSS
- RCE (Node.js)
- Business logic abuse

---

## Expert Note
Prototype Pollution is a multiplier vulnerability that corrupts trust at the inheritance level and often bypasses traditional defenses like WAFs.
