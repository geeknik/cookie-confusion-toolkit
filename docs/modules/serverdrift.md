# ServerDrift Module

The ServerDrift module tests server-side cookie parsing inconsistencies across frameworks. It identifies how servers handle malformed or edge-case cookies that might be processed differently from how browsers send them.

## Overview

ServerDrift is designed to identify server-side vulnerabilities in cookie parsing, including:

- Key overwrite behavior for duplicate cookies
- Attribute truncation and malformed attribute handling
- SameSite and Domain attribute logic
- Framework-specific cookie parsing quirks

This module helps identify server-side vulnerabilities that may be exploitable due to parsing inconsistencies.

## Usage

### Command Line

```bash
cct serverdrift [options] target
```

#### Options

- `--cookie-name NAME`: Cookie name to use for testing (default: session)
- `--test {all,key_overwrite,attribute_truncation,samesite_domain_logic,malformed_cookies}`: Specific test to run (default: all)

### Programmatic Usage

```python
from cookie_confusion_toolkit import ServerDrift

serverdrift = ServerDrift(
    target="https://example.com",
    output_dir="./results",
    auth_file="./auth.json",  # Optional
    rate_limit_delay=1.0,
    verbose=True
)

# Run all tests
results = serverdrift.run_all_tests(cookie_name="session")

# Or run specific tests
overwrite_results = serverdrift.test_key_overwrite(cookie_name="session")
truncation_results = serverdrift.test_attribute_truncation(cookie_name="session")
domain_results = serverdrift.test_samesite_domain_logic(cookie_name="session")
malformed_results = serverdrift.test_malformed_cookies()

# Run framework-specific tests
framework_results = serverdrift.analyze_framework_specific()
```

## Test Types

### Key Overwrite

Tests server behavior when receiving multiple cookies with the same name:

- Sends cookies with the same name but different values
- Tests different formats (single header, multiple headers)
- Tests case variations (e.g., "session" vs "Session")

This can identify vulnerabilities where attackers can override security cookies with their own values.

### Attribute Truncation

Tests server handling of truncated or malformed cookie attributes:

- Creates cookies with truncated attributes (e.g., "Pat" instead of "Path")
- Tests various truncation points for each attribute
- Checks server handling of malformed attribute values

This can reveal parsing vulnerabilities where security attributes can be bypassed.

### SameSite and Domain Logic

Tests server handling of SameSite and Domain attributes:

- Creates cookies with various domain specifications
- Tests different SameSite values and casing
- Checks for domain validation vulnerabilities

This can identify weaknesses in domain validation or SameSite enforcement.

### Malformed Cookies

Tests server handling of various malformed cookies:

- Cookies with duplicate names
- Cookies with trailing separators
- Cookies with spaces in names
- Cookies with missing separators
- Cookies with encoded paths
- Cookies with quotes in values
- Cookies with null bytes
- Cookies with case variations

This comprehensive test identifies parsing anomalies that could lead to security bypasses.

## Framework Detection

The module automatically attempts to detect the server framework:

```python
server_info = serverdrift.server_info
print(f"Detected framework: {server_info['framework']} with {server_info['confidence']}% confidence")
```

Supported frameworks for detection include:

- Express.js (Node.js)
- Flask/Django (Python)
- Spring (Java)
- ASP.NET
- Ruby on Rails
- PHP (including Laravel, Symfony)
- Golang
- Apache/Nginx/IIS server software

## Results Format

The module generates JSON results with the following structure:

```json
{
  "target": "https://example.com",
  "timestamp": 1714577867,
  "tests": {
    "key_overwrite": {
      "description": "Testing server key overwrite behavior",
      "cookie_name": "session",
      "variations": [...],
      "results": [...]
    },
    "attribute_truncation": {
      "description": "Testing server attribute truncation handling",
      "cookie_name": "session",
      "attributes": [...],
      "results": [...]
    },
    ...
  }
}
```

## Interpreting Results

When analyzing ServerDrift results, look for:

1. **Unexpected cookie acceptance** for malformed inputs
2. **Inconsistent overwrite behavior** for duplicate cookie names
3. **Truncated attribute acceptance** indicating loose parsing
4. **Domain validation bypasses** through unusual domain formats
5. **Parser errors or warnings** in server responses

## Example Findings

- **Vulnerability**: Server accepts truncated security attributes (e.g., "HttpOn" instead of "HttpOnly")
  - **Impact**: Security attribute bypass, cookie theft
  - **Remediation**: Implement strict attribute parsing, validate complete attribute names

- **Vulnerability**: Server uses last occurrence of duplicate cookie names
  - **Impact**: Session fixation, authentication bypass
  - **Remediation**: Consistent duplicate handling, reject requests with duplicate cookie names

- **Vulnerability**: Server accepts encoded paths that bypass path restrictions
  - **Impact**: Cookie scope bypass, unauthorized access
  - **Remediation**: Normalize paths before validation, implement stricter path checking

## Framework-Specific Tests

The module includes framework-specific tests based on the detected server:

```python
# For Express/Node.js
if serverdrift.server_info["framework"] == "express":
    # Test connect.sid parsing
    # Test JSON parsing in cookies
    
# For Flask/Python
elif serverdrift.server_info["framework"] in ["flask", "django"]:
    # Test flask session cookie parsing
    # Test Django CSRF token handling
    
# For Java/Spring
elif serverdrift.server_info["framework"] in ["spring", "java"]:
    # Test JSESSIONID parsing
    # Test Spring case sensitivity
    
# For PHP
elif serverdrift.server_info["framework"] == "php":
    # Test PHPSESSID parsing
    # Test PHP serialized data handling
```

## Extending ServerDrift

You can extend ServerDrift by adding custom server tests:

```python
from cookie_confusion_toolkit import ServerDrift

class CustomServerDrift(ServerDrift):
    def test_custom_behavior(self, cookie_name="session", **kwargs):
        """Test custom server behavior."""
        results = {
            "description": "Testing custom server behavior",
            "cookie_name": cookie_name,
            "results": []
        }
        
        # Implement your custom test here
        
        self.results["tests"]["custom_behavior"] = results
        return results

# Use your custom class
custom_drift = CustomServerDrift("https://example.com")
custom_drift.test_custom_behavior()
```

## Troubleshooting

Common issues when using ServerDrift:

1. **Rate limiting**: Server may block requests if sent too quickly, increase `rate_limit_delay`
2. **WAF blocking**: Web Application Firewalls may block tests, try adjusting test parameters
3. **Inconsistent results**: Server load balancing may route to different backends, try with sticky sessions
4. **Framework detection failures**: Add custom detection logic for your specific server

## See Also

- [CookieBomb Module](cookiebomb.md) - Generate degenerate cookie jars
- [ClientFork Module](clientfork.md) - Test browser-specific cookie handling
