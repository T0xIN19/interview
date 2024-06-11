# interview

100 Web Vulnerabilities, categorized into various types : 😀

## ⚡️ Injection Vulnerabilities:
1. SQL Injection (SQLi)
     What is SQL injection (SQLi)?<br>
      > Ans - A web security vulnerability that allows an attacker to manupulate the database with the help of quaries.<br>
     * What is the impact of a successful SQL injection attack?<br>
       > Ans - A successful SQL injection attack can result in unauthorized access to sensitive data, such as:<br>
           >  Passwords.<br>
             Credit card details.<br>
             Personal user information.<br>
     * How to detect SQL injection vulnerabilities.<br>
       > Ans - You can detect SQL injection manually using a systematic set of tests against every entry point in the application. To do this, you would typically submit:<br>
             The single quote character ' and look for errors or other anomalies.<br>
              Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the               application responses.<br>
              Boolean conditions such as OR 1=1 and OR 1=2, and look for differences in the application's responses.<br>
              Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.<br>
     * Blind SQL injection vulnerabilities.<br>
       > Ans - Blink SQL Injection is a type of SQL Injection attack where the attacker indirectly discovers information by analyzing server reactions to injected SQL                      queries, even though the injection results are not visible.<br>
     * Second-order SQL injection.<br>
       > Ans - First-order SQL injection occurs when the application processes user input from an HTTP request and incorporates the input into a SQL query in an unsafe way.<br>
              Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the               input into a database, but no vulnerability occurs at the point where the data is stored. Later, when handling a different HTTP request, the application                     retrieves the stored data and incorporates it into a SQL query in an unsafe way. For this reason, second-order SQL injection is also known as stored SQL                     injection.<brr>
     * How to prevent SQL injection.<br>
         >   Ans - Whitelisting permitted input values.<br>
              Using different logic to deliver the required behavior.<br>
     
3. Cross-Site Scripting (XSS)<br>
   * What is cross-site scripting (XSS)?<br>    
      >  Xss its client side vulnerability which allow an attcker to inject malicious script into websites.<br>

   * Impact of XSS vulnerabilities<br>
      > The actual impact of an XSS attack generally depends on the nature of the application, its functionality and data, and the status of the compromised user. For                example:

      > In a brochureware application, where all users are anonymous and all information is public, the impact will often be minimal.<br>
    
      >  In an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.<br>
    
      >  If the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of            the vulnerable application and compromise all users and their data.<br>
     
   * What are the types of XSS attacks?<br>
     
      >  Reflected XSS, where the malicious script comes from the current HTTP request.<br>
      >  Stored XSS, where the malicious script comes from the website's database.<br>
      >  DOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.<br>

    * Reflected Xss
      > Reflected xss accour when an attcker able to send malicious script to the web application using URL or submission & the web application reflect those                        scripts without validation.<br>
       
3. Authentication vulnerabilities<br>
   > Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality. They also expose additional attack surface for further                exploits.<br>
   
   * What is authentication? <br>
     > ANS - Authentication is the process of verifying the identity of a user or client.<br>
                     Something you know, such as a password or the answer to a security question. These are sometimes called "knowledge factors".<br>
                     Something you have, This is a physical object such as a mobile phone or security token. These are sometimes called "possession factors".<br>
                     Something you are or do. For example, your biometrics or patterns of behavior. These are sometimes called "inherence factors".<br>
                     
   * What is the difference between authentication and authorization?<br>
     > Authentication is the process of verifying that a user is who they claim to be.<BR>
                     Authorization involves verifying whether a user is allowed to do something.<BR>

     For example, authentication determines whether someone attempting to access a website with the username Carlos123 really is the same person who created the account.

    * How do authentication vulnerabilities arise? <br> 
      > The authentication mechanisms are weak because they fail to adequately protect against brute-force attacks.<br>
           Logic flaws or poor coding in the implementation allow the authentication mechanisms to be bypassed entirely by an attacker. This is sometimes called "broken                authentication".<br>

   * How to secure your authentication mechanisms.<br>
     > Take care with user credentials - SOLID CREDENTIALS<br>
          Don't count on users for security. - require some additional effort from your users.<br>
          Prevent username enumeration - NOT  reveal that a user exists on the system.<br>
          Implement robust brute-force protection -  implement strict, IP-based user rate limiting. This should involve measures to prevent attackers from manipulating                their apparent.<BR>
          Triple-check your verification logic<br>
          Don't forget supplementary functionality<br>
          Implement proper multi-factor authentication.<br>
          
4. What is path traversal?
   * Path traversal is also known as directory traversal. These vulnerabilities enable an attacker to read arbitrary files on the server that is running an application.<br>
     > Application code and data.<br>
        Credentials for back-end systems.<br>
        Sensitive operating system files.<br>

      > ex- %2e%2e%2f represents ../ - encoding & double encoding <br>
            ..%c0%af represents ../  -  percent URL encoding <br>
            ?file=secret.doc%00.pdf - null byte <br>

     * How to prevent a path traversal attack.<br>
       > verify that the input contains only permitted content, such as alphanumeric characters only.<br>
       > Verify that the canonicalized path starts with the expected base directory.<br>
       > Many application functions that do this can be rewritten to deliver the same behavior in a safer way.<br>
     
       
6. Cross-Site Request Forgery (CSRF)
7. Remote Code Execution (RCE)
8. Command Injection
9. XML Injection
10. LDAP Injection
11. XPath Injection
12. HTML Injection
13. Server-Side Includes (SSI) Injection
14. OS Command Injection
15. Blind SQL Injection
16. Server-Side Template Injection (SSTI)



⚡️ Broken Authentication and Session Management:
14. Session Fixation
15. Brute Force Attack
16. Session Hijacking
17. Password Cracking
18. Weak Password Storage
19. Insecure Authentication
20. Cookie Theft
21. Credential Reuse

⚡️ Sensitive Data Exposure:
22. Inadequate Encryption
23. Insecure Direct Object References (IDOR)
24. Data Leakage
25. Unencrypted Data Storage
26. Missing Security Headers
27. Insecure File Handling

⚡️ Security Misconfiguration:
28. Default Passwords
29. Directory Listing
30. Unprotected API Endpoints
31. Open Ports and Services
32. Improper Access Controls
33. Information Disclosure
34. Unpatched Software
35. Misconfigured CORS
36. HTTP Security Headers Misconfiguration

⚡️ XML-Related Vulnerabilities:
37. XML External Entity (XXE) Injection
38. XML Entity Expansion (XEE)
39. XML Bomb

⚡️ Broken Access Control:
40. Inadequate Authorization
41. Privilege Escalation
42. Insecure Direct Object References
43. Forceful Browsing
44. Missing Function-Level Access Control

⚡️ Insecure Deserialization:
45. Remote Code Execution via Deserialization
46. Data Tampering
47. Object Injection

⚡️ API Security Issues:
48. Insecure API Endpoints
49. API Key Exposure
50. Lack of Rate Limiting
51. Inadequate Input Validation

⚡️ Insecure Communication:
52. Man-in-the-Middle (MITM) Attack
53. Insufficient Transport Layer Security
54. Insecure SSL/TLS Configuration
55. Insecure Communication Protocols

⚡️ Client-Side Vulnerabilities:
56. DOM-based XSS
57. Insecure Cross-Origin Communication
58. Browser Cache Poisoning
59. Clickjacking
60. HTML5 Security Issues

⚡️ Denial of Service (DoS):
61. Distributed Denial of Service (DDoS)
62. Application Layer DoS
63. Resource Exhaustion
64. Slowloris Attack
65. XML Denial of Service

⚡️ Other Web Vulnerabilities:
66. Server-Side Request Forgery (SSRF)
67. HTTP Parameter Pollution (HPP)
68. Insecure Redirects and Forwards
69. File Inclusion Vulnerabilities
70. Security Header Bypass
71. Clickjacking
72. Inadequate Session Timeout
73. Insufficient Logging and Monitoring
74. Business Logic Vulnerabilities
75. API Abuse

⚡️ Mobile Web Vulnerabilities:
76. Insecure Data Storage on Mobile Devices
77. Insecure Data Transmission on Mobile Devices
78. Insecure Mobile API Endpoints
79. Mobile App Reverse Engineering

⚡️ IoT Web Vulnerabilities:
80. Insecure IoT Device Management
81. Weak Authentication on IoT Devices
82. IoT Device Vulnerabilities

⚡️ Web of Things (WoT) Vulnerabilities:
83. Unauthorized Access to Smart Homes
84. IoT Data Privacy Issues

⚡️ Authentication Bypass:
85. Insecure "Remember Me" Functionality
86. CAPTCHA Bypass

⚡️ Server-Side Request Forgery (SSRF):
87. Blind SSR
88. Time-Based Blind SSRF

⚡️ Content Spoofing:
89. MIME Sniffing
90. X-Content-Type-Options Bypass
91. Content Security Policy (CSP) Bypass

⚡️ Business Logic Flaws:
92. Inconsistent Validation
93. Race Conditions
94. Order Processing Vulnerabilities
95. Price Manipulation
96. Account Enumeration
97. User-Based Flaws

⚡️ Zero-Day Vulnerabilities:
98. Unknown Vulnerabilities
99. Unpatched Vulnerabilities
100. Day-Zero Exploits
