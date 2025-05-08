# Cookie Shadowing Attacks

Cookie shadowing attacks exploit scenarios where multiple cookies with the same name but different security attributes can coexist. This allows attackers to override or bypass security restrictions like HttpOnly, Secure, or SameSite.

## Technical Background

### Cookie Shadowing Mechanisms

Cookie shadowing occurs when:

1. **Multiple cookies with the same name** exist in the browser's cookie store
2. **Different security attributes** are applied to these cookies
3. **Server-side logic** doesn't properly validate cookie security context

### Common Scenarios

#### HttpOnly Bypass

```
Legitimate cookie: Set-Cookie: session=abc123; HttpOnly; Secure
Shadow cookie:     document.cookie = "session=evil_value"
```

If the application reads `req.cookies.session` without verifying the HttpOnly flag, it may use the shadow cookie.

#### Secure Flag Bypass

```
HTTPS cookie:      Set-Cookie: token=secret; Secure
HTTP shadow:       document.cookie = "token=leaked" (over HTTP)
```

The shadow cookie can be set over HTTP, potentially allowing interception.

## Attack Vectors

### 1. XSS-Based Shadowing

```javascript
// Attacker script injected via XSS
document.cookie = "session=attacker_controlled; path=/";

// This shadows the HttpOnly session cookie
// When server reads cookies, it may get the attacker's value
```

### 2. Subdomain-Based Shadowing

```javascript
// On attacker-controlled subdomain: evil.example.com
document.cookie = "session=evil; domain=.example.com; path=/";

// This cookie will be sent to example.com
// May override more specific cookies
```

### 3. Cross-Protocol Shadowing

```javascript
// Over HTTP (even if main site is HTTPS)
document.cookie = "secure_cookie=attacker_value; path=/";

// May override HTTPS-only cookies in some browsers
```

## Browser Implementation Differences

### Chrome/Edge (Chromium)

- Stricter SameSite enforcement
- Better isolation between secure contexts
- May reject some shadowing attempts

### Firefox

- Different cookie ordering behavior
- Less strict SameSite enforcement
- More permissive shadowing scenarios

### Safari

- Unique path matching algorithm
- ITP (Intelligent Tracking Prevention) effects
- Different HttpOnly enforcement in some contexts

## Exploitation Examples

### Session Hijacking via Shadow Cookies

```python
# Server-side vulnerable code
def get_session():
    # This reads the first 'session' cookie found
    session_id = request.cookies.get('session')
    return load_session(session_id)  # May load attacker's session

# Attack sequence:
# 1. Victim has: session=legitimate; HttpOnly; Secure
# 2. Attacker injects: session=attacker_controlled
# 3. Server uses attacker's session ID
```

### API Key Override

```javascript
// Legitimate API key (HttpOnly, Secure)
// Set-Cookie: api_key=real_key; HttpOnly; Secure; Path=/api

// Attacker shadows it
document.cookie = "api_key=fake_key; Path=/api";

// If server checks cookies without validating context:
fetch('/api/sensitive', {
    credentials: 'include'  // Sends both cookies
});
```

### CSRF Token Manipulation

```html
<!-- Legitimate CSRF protection -->
<!-- Set-Cookie: csrf_token=abc123; SameSite=Strict -->

<!-- Attacker's page -->
<script>
// Set shadow cookie
document.cookie = "csrf_token=attacker_token";

// Submit form
document.getElementById('malicious-form').submit();
</script>
```

## Detection Techniques

### Server-Side Detection

```python
def detect_shadow_cookies(request):
    # Parse all cookies with the same name
    session_cookies = []
    
    for cookie in request.cookies:
        if cookie.name == 'session':
            session_cookies.append({
                'value': cookie.value,
                'secure': cookie.secure,
                'httponly': cookie.httponly,
                'samesite': cookie.samesite,
                'domain': cookie.domain,
                'path': cookie.path
            })
    
    # Check for potential shadowing
    if len(session_cookies) > 1:
        # Log security event
        log_security_event({
            'type': 'potential_cookie_shadowing',
            'cookies': session_cookies,
            'client_ip': request.remote_addr
        })
        
        # Return only the most secure cookie
        return select_most_secure_cookie(session_cookies)
```

### Client-Side Detection

```javascript
// Detect multiple cookies with same name
function detectShadowCookies(cookieName) {
    const allCookies = document.cookie.split(';');
    const matchingCookies = [];
    
    for (let cookie of allCookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === cookieName) {
            matchingCookies.push({name, value});
        }
    }
    
    if (matchingCookies.length > 1) {
        console.warn('Multiple cookies detected:', matchingCookies);
        // Send alert to security monitoring
    }
    
    return matchingCookies;
}
```

## Prevention Strategies

### 1. Strict Cookie Validation

```python
def get_secure_cookie(request, name):
    cookies = request.cookies.getlist(name)
    
    # Only accept the cookie if:
    # 1. There's exactly one cookie with this name
    # 2. It has the expected security attributes
    
    if len(cookies) != 1:
        raise SecurityException("Multiple cookies detected")
    
    cookie = cookies[0]
    
    # Verify security attributes
    if not (cookie.secure and cookie.httponly):
        raise SecurityException("Cookie security attributes missing")
    
    return cookie.value
```

### 2. Cookie Signing

```python
import hmac
import hashlib

def sign_cookie(value, secret_key):
    """Sign cookie value to prevent tampering"""
    signature = hmac.new(
        secret_key.encode(),
        value.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return f"{value}|{signature}"

def verify_signed_cookie(signed_value, secret_key):
    """Verify and extract cookie value"""
    try:
        value, signature = signed_value.rsplit('|', 1)
        expected_signature = hmac.new(
            secret_key.encode(),
            value.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if hmac.compare_digest(signature, expected_signature):
            return value
        else:
            raise SecurityException("Invalid cookie signature")
    except ValueError:
        raise SecurityException("Malformed cookie")
```

### 3. Token Binding

```python
def create_bound_session(user_id, request):
    """Create session token bound to request characteristics"""
    
    # Include request fingerprint in session
    fingerprint = hash_request_fingerprint(request)
    
    session_data = {
        'user_id': user_id,
        'fingerprint': fingerprint,
        'created_at': time.time(),
        'ip_address': request.remote_addr
    }
    
    # Encrypt session data
    encrypted_session = encrypt_json(session_data)
    
    # Set with strict attributes
    response.set_cookie(
        'session',
        encrypted_session,
        secure=True,
        httponly=True,
        samesite='Strict',
        max_age=3600
    )
```

### 4. Domain-Specific Cookies

```javascript
// Use domain-specific cookies to prevent subdomain shadowing
function setDomainCookie(name, value, domain) {
    // Ensure exact domain match
    if (!isValidDomain(domain)) {
        throw new Error("Invalid domain");
    }
    
    document.cookie = `${name}=${value}; Domain=${domain}; Secure; HttpOnly`;
}

// Avoid wildcard domains
function validateDomain(domain) {
    // Reject wildcard domains like .example.com
    return !domain.startsWith('.');
}
```

## Testing for Shadow Cookie Vulnerabilities

### Automated Testing with CCT

```python
# Using Cookie Confusion Toolkit
from cookie_confusion_toolkit import ClientFork

clientfork = ClientFork(target="https://example.com")

# Test cookie shadowing scenarios
shadow_results = clientfork.test_cookie_shadowing(
    cookie_name="session",
    variations=[
        {"name": "session", "value": "secure_value", "httpOnly": True, "secure": True},
        {"name": "session", "value": "shadow_value"}
    ]
)
```

### Manual Testing Steps

1. **Set up test environment**
   - Create HttpOnly/Secure cookies via server
   - Inject JavaScript to set shadow cookies

2. **Test various combinations**
   - HttpOnly vs. non-HttpOnly
   - Secure vs. non-Secure
   - Different domains and paths

3. **Monitor server behavior**
   - Check which cookie value is used
   - Verify security attribute validation

4. **Test cross-browser**
   - Chrome, Firefox, Safari, Edge
   - Different versions and settings

## Real-World Incidents

### Banking Application (2022)

- **Issue**: HttpOnly session cookies could be shadowed
- **Impact**: Account takeover via XSS
- **Root Cause**: Server didn't validate cookie attributes
- **Fix**: Implemented cookie signature verification

### E-commerce Platform (2021)

- **Issue**: Admin cookies shadowable from subdomains
- **Impact**: Administrative privilege escalation
- **Root Cause**: Wildcard domain cookies
- **Fix**: Strict domain validation and cookie signing

## References

1. "Cookie Crimes: Session Hijacking and Security" - DEF CON 29
2. OWASP Session Management Cheat Sheet
3. RFC 6265bis: Cookies: HTTP State Management Mechanism
4. "Advanced Cookie Security Patterns" - BlackHat 2022
5. Mozilla Developer Network: Document.cookie security
