# Path Override Research

Path override attacks exploit differences in how browsers and servers interpret cookie path attributes. These vulnerabilities can allow attackers to access cookies from restricted paths, potentially circumventing security controls.

## Technical Background

### Path Matching Behavior

Cookie path matching follows specific rules, but implementations often deviate from the standard:

1. **Browser Implementation**: Most browsers perform prefix matching for cookie paths
2. **Server Implementation**: Servers may implement custom path matching logic
3. **URL Encoding**: Different components handle URL-encoded paths differently

### Common Disparities

#### URL Encoding Inconsistencies

```
Browser behavior:    /admin    /admin    /%61dmin
Server behavior:     /admin    /%61dmin  /%61dmin
Cookie sent to:      /admin    both      /%61dmin
```

In this scenario, a cookie set with `Path=/%61dmin` might be sent to `/admin` by browsers, while servers might treat them as distinct paths.

#### Case Sensitivity Differences

```
# Browser (case-insensitive): 
Path=/ADMIN -> cookie sent to /admin, /Admin, /ADMIN

# Server (case-sensitive):
Path=/ADMIN -> only matches /ADMIN
```

## Exploitation Techniques

### Basic Path Override

1. Set a cookie with an encoded path that decodes to a different value
```javascript
document.cookie = "session=attacker_controlled; Path=/%61dmin"
```

2. Browser normalizes the path to `/admin` and sends the cookie to that path
3. Server may not normalize, treating `/%61dmin` and `/admin` as different

### Advanced Techniques

#### Double URL Encoding

```
Original:  /admin
Encoded:   /%61dmin
Double:    /%2561dmin
```

Some browsers or proxies may double-decode paths, leading to unexpected behavior.

#### Path Traversal Combinations

```
Path=/admin/../sensitive
Path=/admin%2f..%2fsensitive
```

Different implementations may handle path traversal differently.

## Vulnerability Examples

### Example 1: Admin Path Bypass

```
# Attack scenario:
1. Attacker sets: Cookie: admin_session=evil; Path=/%41dmin
2. Browser normalizes and sends to /admin
3. Server checks for admin_session without normalizing path
4. Admin access granted with attacker-controlled token
```

### Example 2: API Endpoint Bypass

```
# API protection based on path:
1. Server expects cookies only from /api/v1/
2. Attacker sets: Cookie: api_key=evil; Path=/%61pi/v1/
3. Cookie sent to /api/v1/ by browser
4. Server doesn't normalize, accepts cookie
```

## Detection Methods

### Automated Testing

The CookieBomb module's `test_path_scoping()` method tests for path override vulnerabilities:

```python
# Test various path encodings
paths = [
    "/admin",           # Normal path
    "/%61dmin",         # Encoded 'a'
    "/%41dmin",         # Uppercase encoded 'A'
    "/admin%2f",        # Encoded trailing slash
    "/admin/../login"   # Path traversal
]
```

### Manual Testing

1. Set cookies with encoded paths
2. Navigate to the decoded path
3. Check if the cookie is sent
4. Verify server behavior with different path variants

## Mitigation Strategies

### Server-Side Normalization

```python
def normalize_path(path):
    # Decode URL encoding
    import urllib.parse
    decoded = urllib.parse.unquote(path)
    
    # Normalize path separators
    normalized = os.path.normpath(decoded)
    
    # Remove trailing slashes
    return normalized.rstrip('/')

def validate_cookie_path(cookie_path, request_path):
    normalized_cookie = normalize_path(cookie_path)
    normalized_request = normalize_path(request_path)
    
    # Ensure cookie path is a prefix of request path
    return normalized_request.startswith(normalized_cookie)
```

### Client-Side Validation

```javascript
// Validate cookie paths before setting
function setSecureCookie(name, value, path) {
    // Normalize the path
    const normalizedPath = normalizePath(path);
    
    // Ensure path doesn't contain encoded characters
    if (path !== normalizedPath) {
        throw new Error("Invalid path encoding detected");
    }
    
    document.cookie = `${name}=${value}; Path=${normalizedPath}; Secure; HttpOnly`;
}
```

### Framework-Specific Solutions

#### Express.js
```javascript
app.use((req, res, next) => {
    // Normalize request path
    req.originalUrl = decodeURIComponent(req.originalUrl);
    next();
});
```

#### Flask
```python
from werkzeug.urls import url_unquote

@app.before_request
def normalize_paths():
    request.path = url_unquote(request.path)
```

#### Spring Boot
```java
@Component
public class PathNormalizationFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String normalizedPath = URLDecoder.decode(httpRequest.getRequestURI(), "UTF-8");
        // Apply normalized path
    }
}
```

## Real-World Examples

### CVE-Style Vulnerabilities

1. **Framework X Path Bypass (2023)**
   - Impact: Authentication bypass
   - Cause: Inconsistent path normalization
   - Fix: Server-side path validation

2. **Admin Panel Access (2022)**
   - Impact: Privilege escalation
   - Cause: URL-encoded path cookies
   - Fix: Strict path matching

### Industry Impact

- Banking applications affected by admin path bypasses
- E-commerce platforms with API access control issues
- Content management systems with role-based path restrictions

## Testing Checklist

When testing for path override vulnerabilities:

1. **Identify path-restricted cookies**
   - Admin interfaces
   - API endpoints
   - Sensitive areas

2. **Test encoding variations**
   - Single URL encoding
   - Double URL encoding
   - Mixed case encoding

3. **Check server behavior**
   - Path normalization
   - Case sensitivity
   - Trailing slash handling

4. **Verify impact**
   - Cookie scope bypass
   - Authentication bypass
   - Privilege escalation

## References

1. RFC 6265 Section 5.1.4 - Path Attribute
2. OWASP Testing Guide - Cookie Attributes
3. Mozilla Developer Network - HTTP cookies
4. "Web Security Testing Cookbook" by Paco Hope
