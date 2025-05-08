# Cookie Parsing Vulnerabilities

This document outlines the common vulnerabilities in cookie parsing that the Cookie Confusion Toolkit is designed to identify and test. Understanding these vulnerability classes is essential for properly interpreting test results and implementing effective mitigations.

## Vulnerability Classes

### 1. Session Fixation via Cookie Collisions

#### Description
Session fixation vulnerabilities occur when an attacker can force a user's session identifier to a value known to the attacker. In cookie parsing contexts, this often happens through collision attacks where multiple cookies with the same name (but different cases or whitespace) are handled inconsistently.

#### Example
```
Cookie: SessionID=legitimateValue
Cookie: sessionid=attackerControlledValue
```

If the server treats these as the same cookie but prioritizes one over the other (often the last occurrence), the attacker can override legitimate session tokens.

#### Impact
- Authentication bypass
- Session hijacking
- Privilege escalation
- Persistent unauthorized access

#### Detection
The CookieBomb module's `test_key_collisions()` and ServerDrift module's `test_key_overwrite()` methods specifically test for this vulnerability.

#### Remediation
- Implement case-insensitive cookie name matching
- Reject requests with duplicate cookie names
- Use signed or encrypted session tokens
- Implement additional session validation mechanisms

### 2. CSRF Protection Bypass via Cookie Injection

#### Description
Cross-Site Request Forgery (CSRF) protections often rely on special cookies containing anti-CSRF tokens. If an attacker can inject or override these cookies, they may bypass CSRF protections.

#### Example
Through CRLF injection:
```
GET /page?payload=data%0D%0ASet-Cookie:%20csrf_token=attacker_controlled HTTP/1.1
Host: victim.com
```

#### Impact
- CSRF protection bypass
- Unauthorized actions performed with user's identity
- Data modification
- Privilege escalation

#### Detection
The ClientFork module's `test_header_injection()` method tests for CRLF injection vulnerabilities that could lead to cookie injection.

#### Remediation
- Implement strict CRLF filtering in HTTP headers
- Use cryptographically signed CSRF tokens
- Implement proper validation of CSRF token origins
- Add secondary CSRF protections (e.g., custom headers)

### 3. JWT Token Shadowing

#### Description
JSON Web Tokens (JWTs) are often stored in cookies. If a server truncates cookie values at a certain length, an attacker might be able to construct a malicious JWT that, when truncated, becomes a valid token with elevated privileges.

#### Example
```
Original: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6ZmFsc2V9.signature

Malicious: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.invalid_but_truncated
```

If the server truncates at a specific length, it might only validate the first part of the token, accepting the elevated privileges.

#### Impact
- Authentication bypass
- Privilege escalation
- Unauthorized access to protected resources
- Identity spoofing

#### Detection
The CookieBomb module's `test_overlong_values()` method and BypassGen module's `generate_jwt_shadowing_exploit()` method test for this vulnerability.

#### Remediation
- Validate complete JWT tokens
- Implement proper signature verification
- Set appropriate cookie size limits
- Use strong encryption for sensitive tokens

### 4. Path Override Reversal

#### Description
Cookie path restrictions can sometimes be bypassed through path encoding differences. If a browser and server interpret encoded paths differently, an attacker might send cookies to paths they shouldn't have access to.

#### Example
```
Original: Set-Cookie: admin_session=value; Path=/admin
Bypass: Set-Cookie: admin_session=attacker_value; Path=/%61dmin
```

If the server normalizes the path but the browser doesn't (or vice versa), the attacker's cookie might be sent to the protected path.

#### Impact
- Cookie scope bypass
- Access to restricted areas
- Session hijacking
- Information disclosure

#### Detection
The CookieBomb module's `test_path_scoping()` method and BypassGen module's `generate_path_override_exploit()` method test for this vulnerability.

#### Remediation
- Implement consistent path normalization
- Validate full path hierarchies, not just prefixes
- Use additional authentication for sensitive areas
- Consider using domain separation for critical functions

### 5. Casing Inversion Drift

#### Description
Some frameworks (particularly Java-based ones) handle cookie case sensitivity differently during cookie setting vs. cookie reading. This can lead to situations where an attacker sets a cookie with a different case that takes precedence.

#### Example
```
Legitimate: Cookie: SessionID=legitimate_value
Attack: Cookie: sessionid=attacker_value
```

If the framework accesses cookies case-insensitively but stores them case-sensitively, the framework might use `sessionid` instead of `SessionID`.

#### Impact
- Session hijacking
- Authentication bypass
- Session fixation
- Persistent unauthorized access

#### Detection
The ServerDrift module's `test_key_overwrite()` with case variations and BypassGen module's `generate_casing_inversion_exploit()` method test for this vulnerability.

#### Remediation
- Implement consistent case handling for cookies
- Normalize cookie names to a standard case
- Reject duplicate cookies regardless of case
- Use signed or encrypted session tokens

### 6. Quote Leak Reflection

#### Description
Quotes in cookie values can confuse parsers, especially when cookies are passed through multiple systems or WAFs. This can lead to WAF bypass or SSRF (Server-Side Request Forgery) vulnerabilities.

#### Example
```
Cookie: host="internal-api.local"
```

If a WAF or proxy parses this differently than the backend application, it might allow access to internal resources.

#### Impact
- WAF bypass
- SSRF
- Information disclosure
- Access to internal networks

#### Detection
The ServerDrift module's `test_malformed_cookies()` and BypassGen module's `generate_quote_leak_exploit()` method test for this vulnerability.

#### Remediation
- Implement consistent quote handling
- Validate and sanitize cookie values
- Use the same parser across all layers
- Implement proper WAF rules for cookie inspection

### 7. Trailing Delimiter Exploit

#### Description
Browsers generally drop trailing delimiters in cookies, but some server-side parsers might handle them differently. This can lead to validation bypasses if servers use regex-based cookie validation.

#### Example
```
Cookie: session=value;;;
```

A browser would send this as `session=value`, but a server might parse it differently or get confused by the trailing delimiters.

#### Impact
- Validation bypass
- WAF evasion
- Parser confusion
- Potential for injection attacks

#### Detection
The CookieBomb module's `test_whitespace_ambiguity()` and BypassGen module's `generate_delimiter_exploit()` method test for this vulnerability.

#### Remediation
- Implement robust delimiter handling
- Use parser libraries instead of custom regex
- Normalize cookie strings before parsing
- Validate cookie values after parsing

### 8. Shadow Cookie Attack

#### Description
In some scenarios, an attacker can set a parallel cookie with the same name but different attributes, potentially bypassing security restrictions like HttpOnly or Secure flags.

#### Example
```
Secure cookie (set by server): Set-Cookie: session=legitimate; HttpOnly; Secure
Shadow cookie (set by attacker): document.cookie = "session=attacker_controlled"
```

If the application doesn't verify security context when reading cookies, it might use the non-secure version.

#### Impact
- HttpOnly bypass enabling XSS cookie theft
- Secure flag bypass allowing cookie interception
- Session hijacking
- Authentication bypass

#### Detection
The ClientFork module's `test_cookie_shadowing()` and BypassGen module's `generate_shadow_cookie_exploit()` method test for this vulnerability.

#### Remediation
- Verify security context when reading cookies
- Implement additional token validation
- Use signed or encrypted cookies
- Consider using token binding to prevent theft

## Framework-Specific Vulnerabilities

### Express.js (Node.js)

- Cookie priority issues (last cookie wins)
- connect.sid parsing inconsistencies
- JSON parsing in cookies

### Flask/Django (Python)

- Flask session cookie deserialization issues
- Werkzeug parser inconsistencies
- CSRF token validation bypasses

### Spring (Java)

- Case sensitivity issues in cookie access
- JSESSIONID parsing vulnerabilities
- Header injection through cookies

### PHP

- Serialized data in cookies leading to object injection
- $_COOKIE array manipulation
- PHPSESSID handling issues

## Impact Assessment

When evaluating the impact of cookie parsing vulnerabilities, consider:

### Severity Factors

1. **Authentication Impact**: Can the vulnerability bypass authentication?
2. **Persistence**: Does the attack persist across sessions?
3. **Privilege Escalation**: Does it allow access to higher privileges?
4. **Exploitation Difficulty**: How complex is the exploit to execute?
5. **User Interaction**: Does it require user interaction?

### CVSS Scoring

For standardized impact assessment, consider using CVSS (Common Vulnerability Scoring System):

- **Base Score**: Reflects the intrinsic characteristics of the vulnerability
- **Temporal Score**: Accounts for changes over time
- **Environmental Score**: Customizes the score for your environment

## Conclusion

Cookie parsing vulnerabilities represent a significant and often overlooked attack surface. The Cookie Confusion Toolkit is designed to systematically identify these issues before they can be exploited.

By understanding these vulnerability classes, security professionals can:

1. Properly interpret test results
2. Prioritize remediation efforts
3. Implement effective countermeasures
4. Develop more secure cookie handling practices

Remember that successful exploitation often requires chaining multiple vulnerabilities, which is why the BypassGen module focuses on creating end-to-end exploit chains rather than individual vulnerability tests.

## References

- OWASP Top 10: Session Management Vulnerabilities
- OWASP Testing Guide: Testing for Cookies Attributes (OTG-SESS-002)
- RFC 6265: HTTP State Management Mechanism
- CWE-384: Session Fixation
- CWE-352: Cross-Site Request Forgery
