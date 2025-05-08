# Utility Modules

The Cookie Confusion Toolkit includes several utility modules that provide shared functionality across the main testing modules. These utilities handle common tasks like HTTP requests, cookie manipulation, result storage, and authentication.

## Common Utilities

Located in `src/utils/common.py`, this module provides:

### HTTP Request Handling

```python
from cookie_confusion_toolkit.utils.common import safe_request

# Make a safe HTTP request with proper error handling
response = safe_request(
    url="https://example.com",
    method="GET",
    headers={"User-Agent": "Mozilla/5.0..."},
    cookies={"session": "value"},
    timeout=10,
    verify=True,
    allow_redirects=True,
    browser="chrome"
)

# Extract Set-Cookie headers
set_cookie_headers = get_set_cookie_headers(response)
```

Key functions:

- `safe_request()`: Make HTTP requests with proper error handling
- `get_set_cookie_headers()`: Extract Set-Cookie headers from responses
- `is_valid_target()`: Validate that a URL is a legitimate test target
- `rate_limit()`: Implement rate limiting to prevent overloading targets

### Data Handling

```python
from cookie_confusion_toolkit.utils.common import save_results, load_results

# Save test results to a file
save_results(results, "results/test_results.json")

# Load results from a file
previous_results = load_results("results/previous_test.json")
```

Key functions:

- `save_results()`: Save test results to a JSON file
- `load_results()`: Load results from a JSON file
- `calculate_checksum()`: Calculate a checksum for data
- `generate_random_string()`: Generate random strings for testing

### Authentication and Authorization

```python
from cookie_confusion_toolkit.utils.common import validate_authorization, ethical_check

# Check if testing is authorized
if validate_authorization("https://example.com", "auth.json"):
    # Proceed with testing
    pass

# Perform ethical checks
if ethical_check("https://example.com"):
    # Proceed with testing
    pass
```

Key functions:

- `validate_authorization()`: Validate testing authorization against a config file
- `ethical_check()`: Perform ethical checks before targeting a domain

## Cookie Utilities

Located in `src/utils/cookie_utils.py`, this module provides cookie-specific functionality:

### Cookie Class

```python
from cookie_confusion_toolkit.utils.cookie_utils import Cookie

# Create a cookie
cookie = Cookie(
    name="session",
    value="test_value",
    domain="example.com",
    path="/",
    expires=None,
    max_age=3600,
    secure=True,
    http_only=True,
    same_site="Strict"
)

# Convert to Set-Cookie header
set_cookie_header = cookie.to_set_cookie_header()

# Convert to dictionary
cookie_dict = cookie.to_dict()

# Parse from header
parsed_cookie = Cookie.from_set_cookie_header(
    "session=value; Path=/; Secure; HttpOnly",
    "https://example.com"
)
```

### Cookie Manipulation

```python
from cookie_confusion_toolkit.utils.cookie_utils import (
    create_malformed_cookie, create_cookie_collision,
    simulate_browser_cookie_jar, detect_cookie_parser
)

# Create a malformed cookie
malformed = create_malformed_cookie(
    name="session",
    value="test",
    malformation_type="trailing_separators",
    count=3
)

# Create colliding cookies
collisions = create_cookie_collision("session", [
    {"name": "session", "value": "value1"},
    {"name": "Session", "value": "value2"}
])

# Simulate browser cookie jar
filtered_cookies = simulate_browser_cookie_jar(
    cookies=[cookie1, cookie2, cookie3],
    browser="chrome",
    url="https://example.com/admin"
)

# Detect server's cookie parser
parser = detect_cookie_parser(
    response_headers=response.headers,
    request_headers=request.headers
)
```

Key functions:

- `parse_cookies_from_response()`: Parse Set-Cookie headers from responses
- `create_malformed_cookie()`: Create malformed cookies for testing
- `create_cookie_collision()`: Create sets of colliding cookies
- `simulate_browser_cookie_jar()`: Simulate browser cookie jar behavior
- `detect_cookie_parser()`: Attempt to detect the server's cookie parser

## Using Utilities in Custom Code

These utilities can be imported and used in your own custom code:

```python
from cookie_confusion_toolkit.utils.common import safe_request, save_results
from cookie_confusion_toolkit.utils.cookie_utils import Cookie, create_malformed_cookie

# Make a request
response = safe_request("https://example.com")

# Create a malformed cookie
cookie_str = create_malformed_cookie("session", "test", "trailing_separators")

# Make another request with the malformed cookie
response2 = safe_request(
    "https://example.com",
    headers={"Cookie": cookie_str}
)

# Save the results
results = {
    "original": {
        "status": response.status_code,
        "cookies": dict(response.cookies)
    },
    "malformed": {
        "cookie": cookie_str,
        "status": response2.status_code,
        "cookies": dict(response2.cookies)
    }
}
save_results(results, "custom_test_results.json")
```

## Constants and Configuration

The utilities include several constants that can be customized:

### User Agents

```python
USER_AGENTS = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
}
```

### Cookie Attributes

```python
COOKIE_ATTRIBUTES = [
    "Path", 
    "Domain", 
    "Secure", 
    "HttpOnly", 
    "SameSite", 
    "Max-Age", 
    "Expires"
]
```

## Extending the Utilities

You can extend the utility modules by adding custom functions or subclassing the Cookie class:

```python
from cookie_confusion_toolkit.utils.cookie_utils import Cookie

class EnhancedCookie(Cookie):
    def __init__(self, name, value, **kwargs):
        super().__init__(name, value, **kwargs)
        self.custom_attribute = kwargs.get("custom_attribute")
    
    def to_set_cookie_header(self):
        header = super().to_set_cookie_header()
        if self.custom_attribute:
            header += f"; CustomAttr={self.custom_attribute}"
        return header

# Use your enhanced cookie
cookie = EnhancedCookie(
    name="session",
    value="test",
    custom_attribute="custom_value"
)
```

## Troubleshooting

Common issues with the utility modules:

1. **HTTP request failures**: Check connectivity, target availability, and rate limiting
2. **Cookie parsing errors**: Ensure cookie strings are properly formatted
3. **Authorization failures**: Verify the auth file exists and contains the target
4. **Result saving failures**: Ensure the output directory exists and is writable

## See Also

- [CookieBomb Module](cookiebomb.md)
- [ClientFork Module](clientfork.md)
- [ServerDrift Module](serverdrift.md)
- [BypassGen Module](bypassgen.md)
