# ClientFork Module

The ClientFork module emulates browser-specific cookie handling to detect client-side inconsistencies. It uses browser automation to test how different browsers handle cookies, especially in edge cases.

## Overview

ClientFork is designed to identify how different browsers handle unusual cookie scenarios, including:

- Header injection and CRLF handling
- Cookie policy enforcement (Secure, HttpOnly, SameSite)
- Cookie shadowing between secure and insecure contexts
- Browser-specific cookie handling quirks

This module helps identify client-side vulnerabilities that may be exploitable due to browser inconsistencies.

## Usage

### Command Line

```bash
cct clientfork [options] target
```

#### Options

- `--browsers BROWSER [BROWSER ...]`: Browsers to test (default: auto-detect)
- `--no-headless`: Disable headless browser mode
- `--test {all,header_injection,cookie_policy,cookie_shadowing}`: Specific test to run (default: all)

### Programmatic Usage

```python
from cookie_confusion_toolkit import ClientFork

clientfork = ClientFork(
    target="https://example.com",
    output_dir="./results",
    auth_file="./auth.json",  # Optional
    rate_limit_delay=1.0,
    use_headless=True,
    verbose=True
)

# Run all tests
results = clientfork.run_all_tests()

# Or run specific tests
header_results = clientfork.test_header_injection(
    header_name="Location", 
    malformed_value="https://example.com%0d%0aSet-Cookie:+injected=value",
    browsers=["chrome", "firefox"]
)

policy_results = clientfork.test_cookie_policy(
    test_cases=[
        {"name": "secure_cookie", "value": "test", "secure": True},
        {"name": "samesite_cookie", "value": "test", "sameSite": "Strict"}
    ],
    browsers=["chrome", "firefox", "safari"]
)

shadow_results = clientfork.test_cookie_shadowing(
    cookie_name="session",
    browsers=["chrome", "firefox"]
)
```

## Test Types

### Header Injection

Tests browser handling of CRLF injection in HTTP headers that may lead to cookie injection:

- Attempts to inject Set-Cookie headers via CRLF in custom headers
- Tests browser handling of malformed header values
- Identifies potential vectors for cookie injection through headers

This can reveal vulnerabilities where attackers can set cookies through header manipulation.

### Cookie Policy

Tests browser enforcement of cookie security policies:

- Creates cookies with different security attributes (Secure, HttpOnly, SameSite)
- Checks browser handling of cookies in different contexts (secure/insecure)
- Identifies inconsistencies in security policy enforcement

This can reveal vulnerabilities where security restrictions can be bypassed.

### Cookie Shadowing

Tests browser handling of shadow cookies (same name, different attributes):

- Sets both secure and non-secure cookies with the same name
- Tests which cookie takes precedence in different contexts
- Checks for HttpOnly bypass opportunities

This can identify vulnerabilities where attackers can override HttpOnly or Secure cookies.

## Browser Support

The module supports the following browsers:

- Chrome/Chromium
- Firefox
- Safari (macOS only)
- Edge (Windows only)

For each browser, the module can:

- Use a real browser via Selenium WebDriver
- Emulate browser behavior when the actual browser is not available
- Compare behavior across multiple browsers to identify inconsistencies

## Results Format

The module generates JSON results with the following structure:

```json
{
  "target": "https://example.com",
  "timestamp": 1714577845,
  "tests": {
    "header_injection": {
      "description": "Testing CRLF header injection handling",
      "header_name": "Location",
      "malformed_value": "https://example.com%0d%0aSet-Cookie:+injected=value",
      "browser_results": {
        "chrome": {
          "cookies": [...],
          "cookie_names": [...],
          "injection_succeeded": true|false
        },
        "firefox": {
          "cookies": [...],
          "cookie_names": [...],
          "injection_succeeded": true|false
        },
        ...
      }
    },
    ...
  }
}
```

## Interpreting Results

When analyzing ClientFork results, look for:

1. **Differences between browsers** in handling the same cookie scenarios
2. **Security policy bypasses** where a browser accepts cookies it should reject
3. **Header injection success** indicating potential CRLF vulnerabilities
4. **Cookie shadowing effects** where secure cookies can be overridden
5. **Browser-specific quirks** that could be exploited in targeted attacks

## Example Findings

- **Vulnerability**: Chrome accepts CRLF in custom headers, allowing cookie injection
  - **Impact**: Session fixation, authentication bypass
  - **Remediation**: Implement server-side CRLF filtering, validate cookie origins

- **Vulnerability**: Safari doesn't enforce SameSite=Strict for specific request types
  - **Impact**: CSRF protection bypass
  - **Remediation**: Add additional CSRF tokens, don't rely solely on SameSite

- **Vulnerability**: Firefox allows shadow cookies to override HttpOnly in specific contexts
  - **Impact**: Cookie theft via XSS despite HttpOnly
  - **Remediation**: Use additional session validation, don't rely solely on HttpOnly

## Cross-Browser Comparison

The module includes functionality to compare behavior across browsers:

```python
results = clientfork.compare_browsers({
    "headerInjection": True,
    "headerName": "Location",
    "malformedValue": "https://example.com%0d%0aSet-Cookie:+injected=value"
})
```

This will run the same test across all available browsers and highlight any differences in behavior.

## Extending ClientFork

You can extend ClientFork by adding custom browser tests:

```python
from cookie_confusion_toolkit import ClientFork

class CustomClientFork(ClientFork):
    def test_custom_behavior(self, browsers=None, **kwargs):
        """Test custom browser behavior."""
        if browsers is None:
            browsers = self.available_browsers
            
        results = {
            "description": "Testing custom browser behavior",
            "browser_results": {}
        }
        
        for browser_name in browsers:
            # Implement your custom test here
            browser = self._setup_browser(browser_name)
            if browser:
                # Test behavior
                browser.quit()
            
        self.results["tests"]["custom_behavior"] = results
        return results

# Use your custom class
custom_fork = CustomClientFork("https://example.com")
custom_fork.test_custom_behavior()
```

## Troubleshooting

Common issues when using ClientFork:

1. **WebDriver not found**: Ensure the appropriate WebDriver is installed and in your PATH
2. **Browser crashes**: Try disabling headless mode with `--no-headless`
3. **Permission issues**: Ensure you have permission to launch browsers in your environment
4. **Slow tests**: Browser automation is inherently slower than pure HTTP requests

## See Also

- [CookieBomb Module](cookiebomb.md) - Generate degenerate cookie jars
- [ServerDrift Module](serverdrift.md) - Test server-side cookie parsing
