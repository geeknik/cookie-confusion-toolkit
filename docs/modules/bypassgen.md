# BypassGen Module

The BypassGen module auto-generates exploit chains for cookie parsing vulnerabilities. It analyzes results from the other modules (CookieBomb, ClientFork, ServerDrift) to identify potential security bypasses.

## Overview

BypassGen is designed to:

- Analyze test results from other modules
- Identify applicable exploit types based on detected vulnerabilities
- Generate proof-of-concept exploit chains
- Create HTML demos for testing exploits

This module helps demonstrate the real-world impact of cookie parsing inconsistencies.

## Usage

### Command Line

```bash
cct bypassgen [options] target
```

#### Options

- `--results-dir DIR`: Directory containing test results (default: output-dir)
- `--verify`: Verify generated exploits
- `--exploit {all,session_fixation,csrf_disable,jwt_shadowing,path_override,casing_inversion,quote_leak,delimiter_exploit,shadow_cookie}`: Specific exploit to generate (default: all)

### Programmatic Usage

```python
from cookie_confusion_toolkit import BypassGen

bypassgen = BypassGen(
    target="https://example.com",
    output_dir="./results",
    results_dir="./results",  # Directory with previous test results
    auth_file="./auth.json",  # Optional
    rate_limit_delay=1.0,
    verify_exploits=True,  # Whether to test exploits
    verbose=True
)

# Generate all applicable exploits
results = bypassgen.generate_all_exploits()

# Or generate specific exploits
session_exploit = bypassgen.generate_session_fixation_exploit()
csrf_exploit = bypassgen.generate_csrf_disable_exploit()
jwt_exploit = bypassgen.generate_jwt_shadowing_exploit()
path_exploit = bypassgen.generate_path_override_exploit()
case_exploit = bypassgen.generate_casing_inversion_exploit()
quote_exploit = bypassgen.generate_quote_leak_exploit()
delimiter_exploit = bypassgen.generate_delimiter_exploit()
shadow_exploit = bypassgen.generate_shadow_cookie_exploit()
```

## Exploit Types

### Session Fixation

Exploits trailing space collisions in cookie names to perform session fixation:

- Creates a malicious cookie with trailing spaces in the name
- Exploits servers that treat "session" and "session " as the same cookie
- Demonstrates potential session fixation vulnerabilities

### CSRF Token Bypass

Exploits ghost cookie injection through header manipulation:

- Injects Set-Cookie headers via CRLF
- Overrides CSRF tokens with attacker-controlled values
- Demonstrates potential CSRF protection bypasses

### JWT Shadowing

Exploits token truncation to manipulate JWT tokens:

- Creates overly long JWT tokens that will be truncated
- Places a malicious token after the truncation point
- Demonstrates potential token manipulation vulnerabilities

### Path Override

Exploits path encoding inconsistencies:

- Creates cookies with encoded path attributes (e.g., /admin vs /%61dmin)
- Bypasses path restrictions through encoding differences
- Demonstrates potential path restriction bypasses

### Casing Inversion

Exploits case sensitivity differences in cookie handling:

- Sets cookies with different casing (e.g., SessionID vs sessionid)
- Targets frameworks that lower-case during access but not assignment
- Demonstrates potential cookie override vulnerabilities

### Quote Leak

Exploits quote handling in cookie values:

- Creates cookies with quotes in values that confuse parsers
- Targets WAFs and SSRF detection logic
- Demonstrates potential WAF bypass vulnerabilities

### Delimiter Exploit

Exploits trailing delimiter handling:

- Creates cookies with trailing delimiters (e.g., "session=value;;;")
- Bypasses regex-based cookie validators
- Demonstrates potential validation bypass vulnerabilities

### Shadow Cookie

Exploits the ability to override HttpOnly cookies:

- Sets a parallel cookie with the same name but different attributes
- Bypasses HttpOnly or Secure attributes in specific contexts
- Demonstrates cookie shadowing vulnerabilities

## Results Format

The module generates JSON results with the following structure:

```json
{
  "target": "https://example.com",
  "timestamp": 1714577890,
  "exploits": {
    "session_fixation": {
      "name": "Session Fixation via Trailing-Space Collision",
      "status": "generated",
      "description": "...",
      "impact": "Session fixation, authentication bypass",
      "cookie_name": "session",
      "variations": [...],
      "test_results": [...],
      "steps": [...],
      "poc_html": "..."
    },
    ...
  }
}
```

## HTML Proof of Concepts

For each generated exploit, the module creates an HTML proof-of-concept file:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Session Fixation PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Session Fixation via Trailing Space</h1>
    <script>
    // Set the malicious cookie with trailing space
    document.cookie = "session =attacker_session; path=/";
    
    // Check what cookies are set
    console.log("Cookies:", document.cookie);
    </script>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    </script>
</body>
</html>
```

These files are saved to the `html_exploits` directory within the output directory.

## Interpreting Results

When analyzing BypassGen results, look for:

1. **Exploit status**: Check if the exploit was successfully generated or skipped
2. **Test results**: If verification was enabled, check if the exploit was successful
3. **Vulnerable browsers**: For client-side exploits, note which browsers are vulnerable
4. **Exploit steps**: Review the step-by-step exploitation process
5. **HTML proof of concept**: Use the generated HTML to test the vulnerability

## Extending BypassGen

You can extend BypassGen by adding custom exploit types:

```python
from cookie_confusion_toolkit import BypassGen

class CustomBypassGen(BypassGen):
    def generate_custom_exploit(self):
        """Generate a custom exploit."""
        exploit_info = {
            "name": "Custom Exploit",
            "description": "A custom exploit for testing",
            "prerequisites": ["key_collisions", "overlong_values"],
            "impact": "Custom impact"
        }
        
        # Check if prerequisites are met
        if not self.cookiebomb_results or "key_collisions" not in self.cookiebomb_results.get("tests", {}):
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "Missing key_collisions test results"
            }
        
        # Generate exploit
        cookie_name = "session"
        exploit_value = "custom_exploit"
        
        # Generate exploit steps
        exploit_steps = [
            f"1. Step one...",
            f"2. Step two...",
            # ...
        ]
        
        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": cookie_name,
            "exploit_value": exploit_value,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc("custom", cookie_name, exploit_value)
        }

# Use your custom class
custom_bypass = CustomBypassGen("https://example.com")
custom_result = custom_bypass.generate_custom_exploit()
custom_bypass.results["exploits"]["custom_exploit"] = custom_result
```

## Responsible Usage

The BypassGen module is designed for security research and legitimate testing only:

1. Only use against systems you own or have permission to test
2. Follow responsible disclosure practices for any vulnerabilities found
3. Do not use exploits against production systems without proper authorization
4. Use the provided exploit chains for educational purposes and defensive testing

## See Also

- [CookieBomb Module](cookiebomb.md) - Generate degenerate cookie jars
- [ClientFork Module](clientfork.md) - Test browser-specific cookie handling
- [ServerDrift Module](serverdrift.md) - Test server-side cookie parsing
