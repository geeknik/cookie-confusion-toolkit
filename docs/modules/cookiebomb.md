# CookieBomb Module

The CookieBomb module generates degenerate cookie jars to test parsing inconsistencies in cookie handling. It focuses on creating cookies with edge-case properties that might be handled differently by various browsers and servers.

## Overview

CookieBomb is designed to identify how targets handle unusual cookie scenarios, such as:

- Multiple cookies with the same name but different casing
- Cookies with extremely long values
- Path-scoped cookies with unusual path values
- Cookies with ambiguous whitespace and delimiters

This module is typically the first step in a thorough cookie security assessment.

## Usage

### Command Line

```bash
cct cookiebomb [options] target
```

#### Options

- `--cookie-names NAME [NAME ...]`: Cookie names to test (default: session, sessionid, SESSIONID)
- `--test {all,key_collisions,overlong_values,path_scoping,whitespace_ambiguity}`: Specific test to run (default: all)

### Programmatic Usage

```python
from cookie_confusion_toolkit import CookieBomb

cookiebomb = CookieBomb(
    target="https://example.com",
    output_dir="./results",
    auth_file="./auth.json",  # Optional
    rate_limit_delay=1.0,
    verbose=True
)

# Run all tests
results = cookiebomb.run_all_tests(cookie_names=["session", "auth", "token"])

# Or run specific tests
collision_results = cookiebomb.test_key_collisions(cookie_names=["session"])
overlong_results = cookiebomb.test_overlong_values(cookie_name="session")
path_results = cookiebomb.test_path_scoping(cookie_name="session")
whitespace_results = cookiebomb.test_whitespace_ambiguity(cookie_name="session")
```

## Test Types

### Key Collisions

Tests how the target handles multiple cookies with the same name but different variations:

- Different casing (e.g., "session" vs "Session" vs "SESSION")
- Trailing/leading whitespace (e.g., "session" vs "session ")
- Duplicate cookies in a single request

This can identify vulnerabilities where attackers can override security cookies with their own values.

### Overlong Values

Tests the handling of cookies with extremely long values:

- Creates cookies with values of varying lengths (100, 1000, 4000, 8000 characters)
- Detects truncation behaviors
- Identifies potential buffer overflow or denial of service vulnerabilities

This can reveal vulnerabilities where tokens are truncated and partially replaced.

### Path Scoping

Tests path-based cookie scoping behaviors:

- Sets cookies with different path attributes (/, /admin, /api)
- Tests encoded path variations (e.g., /admin vs /%61dmin)
- Checks how cookies are sent to different paths

This can identify vulnerabilities where path restrictions can be bypassed.

### Whitespace Ambiguity

Tests handling of whitespace and delimiters in cookie headers:

- Creates cookies with various separator patterns (; vs ; vs ;  )
- Tests handling of trailing separators
- Checks how attribute parsing handles whitespace

This can reveal parser inconsistencies that lead to security bypasses.

## Results Format

The module generates JSON results with the following structure:

```json
{
  "target": "https://example.com",
  "timestamp": 1714577823,
  "tests": {
    "key_collisions": {
      "description": "Testing cookie key collisions",
      "cookie_names": ["session", "sessionid", "SESSIONID"],
      "variations": [...],
      "results": [...]
    },
    "overlong_values": {
      "description": "Testing cookies with overlong values",
      "cookie_name": "session",
      "lengths": [100, 1000, 4000, 8000],
      "results": [...]
    },
    ...
  }
}
```

## Interpreting Results

When analyzing CookieBomb results, look for:

1. **Different status codes** for similar cookies, indicating parser sensitivity
2. **Truncation of values** at unexpected boundaries
3. **Cookie reflection** in responses with different values than sent
4. **Path scoping inconsistencies** where cookies are sent to unexpected paths
5. **Parser errors** indicated by error messages in responses

## Example Findings

- **Vulnerability**: Server accepts both "SessionID" and "sessionid" as distinct cookies
  - **Impact**: Session fixation, authentication bypass
  - **Remediation**: Implement case-insensitive cookie name handling

- **Vulnerability**: Server truncates cookie values after 4095 bytes
  - **Impact**: JWT token truncation, token manipulation
  - **Remediation**: Validate complete token integrity

- **Vulnerability**: Path-scoped cookies with encoded paths bypass restrictions
  - **Impact**: Admin cookie leakage, privilege escalation
  - **Remediation**: Implement proper URL normalization before path matching

## Extending CookieBomb

You can extend CookieBomb by adding custom test types:

```python
from cookie_confusion_toolkit import CookieBomb

class CustomCookieBomb(CookieBomb):
    def test_custom_behavior(self, cookie_name="session", **kwargs):
        """Test custom cookie behavior."""
        results = {
            "description": "Testing custom cookie behavior",
            "cookie_name": cookie_name,
            "results": []
        }
        
        # Implement your custom test here
        
        self.results["tests"]["custom_behavior"] = results
        return results

# Use your custom class
custom_bomb = CustomCookieBomb("https://example.com")
custom_bomb.test_custom_behavior()
custom_bomb.run_all_tests()  # Will include your custom test
```

## See Also

- [ClientFork Module](clientfork.md) - Test browser-specific cookie handling
- [ServerDrift Module](serverdrift.md) - Test server-side cookie parsing
