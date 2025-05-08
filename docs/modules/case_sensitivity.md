# Case Sensitivity Issues in Cookie Handling

Case sensitivity variations in cookie handling between browsers and servers can lead to subtle but dangerous security vulnerabilities. These issues arise when different components of a web application handle cookie names with different case sensitivity rules.

## Technical Background

### Cookie Name Case Sensitivity Standards

According to RFC 6265, cookie names should be treated as case-sensitive. However, implementations vary:

1. **Browsers**: Generally case-sensitive
2. **Server Frameworks**: Mixed behavior
3. **Middleware**: Often normalizes case
4. **Load Balancers**: May transform case

### Common Disparities

```
Browser sends:     SessionID=value1; sessionid=value2
Server receives:   sessionid=value2 (only last value)
Framework reads:   req.cookies.get('SessionID') → None
```

## Framework-Specific Behavior

### Java/Spring

```java
// Spring Boot behavior example
@GetMapping("/test")
public String testCookies(HttpServletRequest request) {
    // This uses case-sensitive lookup
    Cookie[] cookies = request.getCookies();
    
    // Finding 'SessionID' won't find 'sessionid'
    for (Cookie cookie : cookies) {
        if ("SessionID".equals(cookie.getName())) {
            return cookie.getValue();
        }
    }
    return "Not found";
}
```

**Issue**: Spring's `@CookieValue` annotation is case-sensitive, but `request.getCookies()` may be affected by servlet container behavior.

### PHP

```php
// PHP $_COOKIE behavior
// PHP converts dots and spaces in names to underscores
// $_COOKIE['session_id'] could come from:
// - session.id
// - session id
// - session_id

// Case sensitivity depends on server configuration
$sessionId = $_COOKIE['SessionID']; // Case sensitive access
```

**Issue**: PHP normalizes some characters in cookie names, but preserves case.

### Python/Django and Flask

```python
# Django
request.COOKIES.get('SessionID')  # Case sensitive

# Flask
request.cookies.get('SessionID')  # Case sensitive

# But Werkzeug (underlying Flask) has:
request.headers.get('Cookie')  # Case insensitive header names
```

### Node.js/Express

```javascript
// Express cookie parser
app.get('/test', (req, res) => {
    // This is case-sensitive
    console.log(req.cookies.SessionID);    // Different from
    console.log(req.cookies.sessionid);    // These values
});
```

## Vulnerability Patterns

### 1. Case Collision Attacks

```
Scenario:
1. Server sets: Set-Cookie: SessionID=legitimate_token
2. Attacker injects: Cookie: sessionid=evil_token
3. Framework inconsistently handles case
4. Security bypass occurs
```

### 2. Authentication Bypass

```python
# Vulnerable code pattern
def authenticate_user(request):
    # Developer assumes one casing
    session_token = request.cookies.get('sessionID')
    
    # But security middleware uses different casing
    if not validate_token(session_token):
        # Attacker can bypass with: sessionId=fake_token
        return False
    
    return True
```

### 3. Session Fixation

```javascript
// Vulnerable JavaScript
function getSessionToken() {
    // This only finds exact case match
    return document.cookie
        .split(';')
        .find(row => row.startsWith('SESSIONID='))
        ?.split('=')[1];
}

// Attack: Set both SESSIONID and sessionid cookies
// Different parts of the application may use different values
```

## Detection Methods

### Automated Testing

```python
def test_case_sensitivity(url, cookie_name):
    """Test case sensitivity handling for a cookie name"""
    
    # Generate case variations
    variations = [
        cookie_name.upper(),
        cookie_name.lower(),
        cookie_name.capitalize(),
        snake_to_camel(cookie_name),
        camel_to_snake(cookie_name)
    ]
    
    results = {}
    
    for variant in variations:
        # Set cookie with variation
        cookies = {variant: f"test_value_{variant}"}
        
        # Test server response
        response = requests.get(url, cookies=cookies)
        
        # Analyze response for evidence of which value was used
        results[variant] = {
            'status': response.status_code,
            'reflected': variant in response.text,
            'set_cookies': dict(response.cookies)
        }
    
    return results
```

### Manual Testing Steps

1. **Set multiple cookies with same name but different cases**
```bash
curl -b "SessionID=value1;sessionid=value2;sessionId=value3" https://example.com
```

2. **Check server logs for which value is processed**

3. **Test with different HTTP methods**

4. **Verify with different user agents**

## Prevention Strategies

### 1. Consistent Case Handling

```python
# Django middleware example
class ConsistentCookieCaseMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Normalize all cookie names to lowercase
        normalized_cookies = {}
        
        for name, value in request.COOKIES.items():
            normalized_name = name.lower()
            if normalized_name in normalized_cookies:
                # Log security event for duplicate cookies
                log_security_event(f"Duplicate cookie detected: {name}")
            normalized_cookies[normalized_name] = value
        
        # Replace with normalized cookies
        request.COOKIES = normalized_cookies
        
        response = self.get_response(request)
        return response
```

### 2. Framework-Specific Solutions

#### Spring Boot

```java
@Component
public class CookieNormalizationFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        // Create wrapper that normalizes cookie names
        HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(httpRequest) {
            @Override
            public Cookie[] getCookies() {
                Cookie[] originalCookies = super.getCookies();
                if (originalCookies == null) return null;
                
                // Normalize cookie names to lowercase
                Cookie[] normalizedCookies = new Cookie[originalCookies.length];
                for (int i = 0; i < originalCookies.length; i++) {
                    Cookie original = originalCookies[i];
                    normalizedCookies[i] = new Cookie(
                        original.getName().toLowerCase(),
                        original.getValue()
                    );
                }
                return normalizedCookies;
            }
        };
        
        chain.doFilter(wrapper, response);
    }
}
```

#### Express.js

```javascript
// Middleware to normalize cookie names
app.use((req, res, next) => {
    if (req.cookies) {
        const normalizedCookies = {};
        for (const [name, value] of Object.entries(req.cookies)) {
            const normalizedName = name.toLowerCase();
            
            // Detect case collisions
            if (normalizedCookies[normalizedName]) {
                console.warn(`Case collision detected for cookie: ${name}`);
            }
            
            normalizedCookies[normalizedName] = value;
        }
        req.cookies = normalizedCookies;
    }
    next();
});
```

### 3. Strict Validation

```python
def validate_cookie_name(name, expected_names):
    """Validate cookie name with strict case checking"""
    
    # Only accept exact case matches
    if name not in expected_names:
        raise SecurityException(f"Invalid cookie name: {name}")
    
    return True

def get_secure_cookie(request, name):
    """Get cookie with case-sensitive validation"""
    
    # Verify exact case match
    if name not in request.cookies:
        return None
    
    # Check for case collision
    lowercase_name = name.lower()
    case_variations = [
        key for key in request.cookies.keys()
        if key.lower() == lowercase_name
    ]
    
    if len(case_variations) > 1:
        # Log security event
        log_security_event({
            'type': 'cookie_case_collision',
            'variations': case_variations,
            'ip': request.remote_addr
        })
        
        # Reject ambiguous cookies
        return None
    
    return request.cookies[name]
```

## Testing Framework Integration

### Cookie Confusion Toolkit Usage

```python
from cookie_confusion_toolkit import ServerDrift

# Test case sensitivity handling
serverdrift = ServerDrift("https://example.com")

# Test key overwrite with case variations
results = serverdrift.test_key_overwrite(
    cookie_name="SessionID",
    variations=[
        {"name": "SessionID", "value": "upper_case"},
        {"name": "sessionid", "value": "lower_case"},
        {"name": "sessionId", "value": "camel_case"},
        {"name": "SESSIONID", "value": "all_caps"}
    ]
)
```

## Real-World Examples

### Banking Application Vulnerability (2021)

```
Issue: Admin interface used sessionID, main app used SessionID
Impact: Admin access via case manipulation
Fix: Normalized all cookie names to lowercase
```

### E-commerce Platform (2022)

```
Issue: Cart cookies case-sensitive, checkout case-insensitive
Impact: Price manipulation via case collision
Fix: Strict case validation across entire application
```

## Best Practices

1. **Choose a consistent case convention**
   - Typically lowercase for cookie names
   - Document the convention clearly

2. **Implement early normalization**
   - Normalize at the edge (middleware/filter)
   - Log any case variations for monitoring

3. **Validate strictly**
   - Reject cookies with unexpected case
   - Alert on case collision attempts

4. **Test comprehensively**
   - Include case variations in security testing
   - Test across different browsers and frameworks

5. **Use signing/encryption**
   - Reduces impact of case manipulation
   - Provides additional security layer

## References

1. RFC 6265: HTTP State Management Mechanism
2. OWASP Session Management Cheat Sheet
3. "Web Application Security: A Beginner's Guide" - Chapter 5
4. CWE-178: Improper Handling of Case Sensitivity
5. Framework-specific documentation for cookie handling
