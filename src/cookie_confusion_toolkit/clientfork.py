"""
ClientFork: Emulate browser-specific cookie handling and detect inconsistencies.

This module emulates how different browsers handle cookies, especially in edge cases,
to identify potential security vulnerabilities due to client-server inconsistencies.
"""

import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.safari.options import Options as SafariOptions

from .utils.common import (
    USER_AGENTS,
    ethical_check,
    logger,
    rate_limit,
    safe_request,
    save_results,
    validate_authorization,
)
from .utils.cookie_utils import Cookie, parse_cookies_from_response, simulate_browser_cookie_jar


class ClientFork:
    """
    Emulate browser cookie handling to detect inconsistencies with server-side parsing.
    """

    # Browser implementations
    BROWSERS = {
        "chrome": {"name": "Chrome", "ua": USER_AGENTS["chrome"], "engine": "Chromium"},
        "firefox": {"name": "Firefox", "ua": USER_AGENTS["firefox"], "engine": "Gecko"},
        "safari": {"name": "Safari", "ua": USER_AGENTS["safari"], "engine": "WebKit"},
        "edge": {"name": "Edge", "ua": USER_AGENTS["edge"], "engine": "Chromium"},
    }

    def __init__(
        self,
        target: str,
        output_dir: str = "./results",
        auth_file: Optional[str] = None,
        rate_limit_delay: float = 1.0,
        use_headless: bool = True,
        verbose: bool = False,
    ):
        """
        Initialize the ClientFork module.

        Args:
            target: Target URL to test
            output_dir: Directory to save results
            auth_file: Path to authorization file
            rate_limit_delay: Delay between requests in seconds
            use_headless: Use headless browser mode
            verbose: Enable verbose logging
        """
        self.target = target
        self.output_dir = output_dir
        self.auth_file = auth_file
        self.rate_limit_delay = rate_limit_delay
        self.use_headless = use_headless
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

        # Initialize results
        self.results = {"target": target, "timestamp": time.time(), "tests": {}}

        # Check available browsers
        self.available_browsers = self._detect_available_browsers()
        logger.info(f"Available browsers: {', '.join(self.available_browsers)}")

    def _detect_available_browsers(self) -> List[str]:
        """
        Detect which browsers are available on the system.

        Returns:
            List[str]: List of available browser names
        """
        available = []
        system = platform.system().lower()

        # Try Chrome
        try:
            if self._is_binary_available("chrome", system) or self._is_binary_available(
                "google-chrome", system
            ):
                available.append("chrome")
        except Exception:
            pass

        # Try Firefox
        try:
            if self._is_binary_available("firefox", system):
                available.append("firefox")
        except Exception:
            pass

        # Try Edge
        try:
            if system == "windows" and self._is_binary_available("msedge", system):
                available.append("edge")
        except Exception:
            pass

        # Try Safari (macOS only)
        try:
            if system == "darwin" and self._is_binary_available("safari", system):
                available.append("safari")
        except Exception:
            pass

        # If no browsers detected, we'll fall back to emulation mode
        if not available:
            logger.warning("No physical browsers detected. Using emulation mode.")
            available = ["chrome_emulated", "firefox_emulated", "safari_emulated"]

        return available

    def _is_binary_available(self, binary_name: str, system: str) -> bool:
        """
        Check if a binary is available on the system.

        Args:
            binary_name: Name of the binary to check
            system: Operating system name

        Returns:
            bool: True if the binary is available, False otherwise
        """
        if system == "windows":
            binary_name = f"{binary_name}.exe"
            check_cmd = f"where {binary_name}"
        else:
            check_cmd = f"which {binary_name}"

        try:
            result = subprocess.run(
                check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            return result.returncode == 0
        except Exception:
            return False

    def _setup_browser(self, browser_name: str) -> Optional[webdriver.Remote]:
        """
        Set up a browser instance using Selenium.

        Args:
            browser_name: Name of the browser to set up

        Returns:
            webdriver.Remote or None: Browser instance or None if setup failed
        """
        if self.verbose:
            logger.debug(f"Setting up {browser_name} browser")

        if browser_name not in self.available_browsers and not browser_name.endswith("_emulated"):
            logger.warning(f"Browser {browser_name} is not available")
            return None

        try:
            if browser_name == "chrome" or browser_name == "chrome_emulated":
                options = ChromeOptions()
                if self.use_headless:
                    options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument(f"--user-agent={USER_AGENTS['chrome']}")
                return webdriver.Chrome(options=options)

            elif browser_name == "firefox" or browser_name == "firefox_emulated":
                options = FirefoxOptions()
                if self.use_headless:
                    options.add_argument("--headless")
                options.set_preference("general.useragent.override", USER_AGENTS["firefox"])
                return webdriver.Firefox(options=options)

            elif browser_name == "edge" and browser_name in self.available_browsers:
                # Edge uses Chromium options
                options = ChromeOptions()
                if self.use_headless:
                    options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument(f"--user-agent={USER_AGENTS['edge']}")
                return webdriver.Edge(options=options)

            elif browser_name == "safari" and browser_name in self.available_browsers:
                # Safari doesn't support headless mode
                options = SafariOptions()
                return webdriver.Safari(options=options)

            elif browser_name == "safari_emulated":
                # For Safari emulation, use Chrome with Safari UA
                options = ChromeOptions()
                if self.use_headless:
                    options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument(f"--user-agent={USER_AGENTS['safari']}")
                return webdriver.Chrome(options=options)

            else:
                logger.error(f"Unsupported browser: {browser_name}")
                return None

        except WebDriverException as e:
            logger.error(f"Failed to set up {browser_name}: {str(e)}")
            return None

    def test_header_injection(
        self,
        header_name: str = "Location",
        malformed_value: str = "https://example.com%0d%0aSet-Cookie:+injected=value",
        browsers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Test browser handling of CRLF injection in HTTP headers.

        Args:
            header_name: Name of the header to inject
            malformed_value: Malformed header value with CRLF
            browsers: List of browsers to test

        Returns:
            Dict[str, Any]: Test results
        """
        if browsers is None:
            browsers = [b for b in self.available_browsers if not b.endswith("_emulated")]
            if not browsers:
                browsers = ["chrome_emulated", "firefox_emulated", "safari_emulated"]

        results = {
            "description": "Testing CRLF header injection handling",
            "header_name": header_name,
            "malformed_value": malformed_value,
            "browser_results": {},
        }

        # Create a test endpoint that sets the malformed header
        # In real tests, you would have a test server; here we'll simulate it
        test_url = f"{self.target}/test-injection"

        # First, perform a baseline test using the requests library
        logger.info("Testing baseline with requests library")
        headers = {header_name: malformed_value}
        response = safe_request(self.target, headers=headers)

        if response:
            results["baseline"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
            }

        # Now test with real browsers
        for browser_name in browsers:
            logger.info(f"Testing with {browser_name}")

            try:
                browser = self._setup_browser(browser_name)
                if not browser:
                    results["browser_results"][browser_name] = {
                        "error": "Failed to initialize browser"
                    }
                    continue

                # Create a temporary HTML file that triggers the header injection
                with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
                    f.write(
                        f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>CRLF Injection Test</title>
                        <script>
                        function sendRequest() {{
                            var xhr = new XMLHttpRequest();
                            xhr.open('GET', '{self.target}', true);
                            xhr.setRequestHeader('{header_name}', '{malformed_value}');
                            xhr.withCredentials = true;
                            xhr.onload = function() {{
                                document.getElementById('result').textContent = 'Request completed';
                            }};
                            xhr.send();
                        }}
                        </script>
                    </head>
                    <body onload="sendRequest()">
                        <h1>CRLF Injection Test</h1>
                        <div id="result">Testing...</div>
                    </body>
                    </html>
                    """
                    )
                    temp_file_path = f.name

                # Navigate to the temporary file
                file_url = f"file://{temp_file_path}"
                browser.get(file_url)

                # Wait for the request to complete
                time.sleep(2)

                # Check for cookies
                cookies = browser.get_cookies()

                # Clean up
                os.unlink(temp_file_path)
                browser.quit()

                results["browser_results"][browser_name] = {
                    "cookies": cookies,
                    "cookie_names": [cookie["name"] for cookie in cookies],
                    "injection_succeeded": any(cookie["name"] == "injected" for cookie in cookies),
                }

            except Exception as e:
                logger.error(f"Error testing {browser_name}: {str(e)}")
                results["browser_results"][browser_name] = {"error": str(e)}

        self.results["tests"]["header_injection"] = results
        return results

    def test_cookie_policy(
        self, test_cases: List[Dict[str, Any]], browsers: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Test browser cookie policy handling for various attributes.

        Args:
            test_cases: List of cookie test cases
            browsers: List of browsers to test

        Returns:
            Dict[str, Any]: Test results
        """
        if browsers is None:
            browsers = [b for b in self.available_browsers if not b.endswith("_emulated")]
            if not browsers:
                browsers = ["chrome_emulated", "firefox_emulated", "safari_emulated"]

        results = {
            "description": "Testing cookie policy handling",
            "test_cases": test_cases,
            "browser_results": {},
        }

        for browser_name in browsers:
            logger.info(f"Testing with {browser_name}")
            browser_results = []

            try:
                browser = self._setup_browser(browser_name)
                if not browser:
                    results["browser_results"][browser_name] = {
                        "error": "Failed to initialize browser"
                    }
                    continue

                for i, test_case in enumerate(test_cases):
                    logger.info(f"Running test case {i+1}/{len(test_cases)}")

                    # Create a cookie setting page
                    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
                        # Create JavaScript to set the cookie
                        cookie_name = test_case.get("name", "test_cookie")
                        cookie_value = test_case.get("value", "test_value")
                        cookie_domain = test_case.get("domain", "")
                        cookie_path = test_case.get("path", "/")
                        cookie_secure = test_case.get("secure", False)
                        cookie_http_only = test_case.get("httpOnly", False)
                        cookie_same_site = test_case.get("sameSite", "")
                        cookie_expires = test_case.get("expires", "")

                        js_code = f"""
                        document.cookie = "{cookie_name}={cookie_value}";
                        """

                        if cookie_domain:
                            js_code = f"""
                            document.cookie = "{cookie_name}={cookie_value}; Domain={cookie_domain}";
                            """

                        if cookie_path:
                            js_code = f"""
                            document.cookie = "{cookie_name}={cookie_value}; Path={cookie_path}";
                            """

                        if cookie_secure:
                            js_code = f"""
                            document.cookie = "{cookie_name}={cookie_value}; Secure";
                            """

                        if cookie_http_only:
                            # Note: HttpOnly can't be set via JavaScript, so we'll need to use a server response
                            pass

                        if cookie_same_site:
                            js_code = f"""
                            document.cookie = "{cookie_name}={cookie_value}; SameSite={cookie_same_site}";
                            """

                        if cookie_expires:
                            js_code = f"""
                            document.cookie = "{cookie_name}={cookie_value}; Expires={cookie_expires}";
                            """

                        # Full cookie string with all attributes
                        full_cookie_str = f"{cookie_name}={cookie_value}"

                        if cookie_domain:
                            full_cookie_str += f"; Domain={cookie_domain}"

                        if cookie_path:
                            full_cookie_str += f"; Path={cookie_path}"

                        if cookie_secure:
                            full_cookie_str += "; Secure"

                        if cookie_http_only:
                            full_cookie_str += "; HttpOnly"

                        if cookie_same_site:
                            full_cookie_str += f"; SameSite={cookie_same_site}"

                        if cookie_expires:
                            full_cookie_str += f"; Expires={cookie_expires}"

                        f.write(
                            f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Cookie Policy Test</title>
                            <script>
                            function setCookie() {{
                                try {{
                                    {js_code}
                                    document.getElementById('result').textContent = 'Cookie set';
                                }} catch(e) {{
                                    document.getElementById('result').textContent = 'Error: ' + e.message;
                                }}
                            }}
                            
                            function getCookies() {{
                                document.getElementById('cookies').textContent = document.cookie;
                            }}
                            </script>
                        </head>
                        <body onload="setCookie(); setTimeout(getCookies, 500);">
                            <h1>Cookie Policy Test</h1>
                            <p>Setting cookie: <code>{full_cookie_str}</code></p>
                            <div id="result">Testing...</div>
                            <div>Cookies: <span id="cookies"></span></div>
                        </body>
                        </html>
                        """
                        )
                        temp_file_path = f.name

                    # Navigate to the temporary file
                    file_url = f"file://{temp_file_path}"
                    browser.get(file_url)

                    # Wait for the cookie to be set
                    time.sleep(1)

                    # Check what cookies were actually set
                    cookies = browser.get_cookies()

                    # Clean up
                    os.unlink(temp_file_path)

                    # For HttpOnly cookies (which can't be set via JS), we need a simulated response
                    if cookie_http_only:
                        # Create a simulation of an HttpOnly cookie using a real HTTP request
                        test_response = {
                            "note": "HttpOnly cookies cannot be set via JavaScript, using simulation",
                            "simulated": True,
                        }

                    # Record results
                    test_result = {
                        "test_case": test_case,
                        "full_cookie_string": full_cookie_str,
                        "browser_cookies": cookies,
                        "cookie_names": [cookie["name"] for cookie in cookies],
                        "cookie_set": any(cookie["name"] == cookie_name for cookie in cookies),
                    }

                    if cookie_http_only:
                        test_result["http_only_note"] = (
                            "HttpOnly cookies cannot be set via JavaScript"
                        )

                    browser_results.append(test_result)

                # Clean up
                browser.quit()

                results["browser_results"][browser_name] = browser_results

            except Exception as e:
                logger.error(f"Error testing {browser_name}: {str(e)}")
                results["browser_results"][browser_name] = {"error": str(e)}

        self.results["tests"]["cookie_policy"] = results
        return results

    def test_cookie_shadowing(
        self,
        cookie_name: str = "session",
        variations: List[Dict[str, Any]] = None,
        browsers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Test browser handling of shadow cookies (same name, different attributes).

        Args:
            cookie_name: Name of the cookie to test
            variations: List of cookie variations to test
            browsers: List of browsers to test

        Returns:
            Dict[str, Any]: Test results
        """
        if variations is None:
            variations = [
                {"name": cookie_name, "value": "original", "httpOnly": True, "secure": True},
                {"name": cookie_name, "value": "shadow", "httpOnly": False, "secure": False},
            ]

        if browsers is None:
            browsers = [b for b in self.available_browsers if not b.endswith("_emulated")]
            if not browsers:
                browsers = ["chrome_emulated", "firefox_emulated", "safari_emulated"]

        results = {
            "description": "Testing cookie shadowing",
            "cookie_name": cookie_name,
            "variations": variations,
            "browser_results": {},
        }

        # Create test endpoint URLs
        https_url = f"https://{self.hostname}" if self.scheme == "http" else self.target
        http_url = f"http://{self.hostname}" if self.scheme == "https" else self.target

        for browser_name in browsers:
            logger.info(f"Testing with {browser_name}")

            try:
                browser = self._setup_browser(browser_name)
                if not browser:
                    results["browser_results"][browser_name] = {
                        "error": "Failed to initialize browser"
                    }
                    continue

                # Create a temporary HTML file for the test
                with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
                    # Ensure we're using appropriate URLs for the protocol
                    secure_url = https_url
                    insecure_url = http_url

                    # Create JavaScript to load both secure and insecure versions
                    js_code = f"""
                    async function runTest() {{
                        try {{
                            // First set the secure cookie via fetch to a secure endpoint
                            const secureResp = await fetch('{secure_url}', {{
                                method: 'GET',
                                credentials: 'include'
                            }});
                            
                            // Show the cookies after secure set
                            document.getElementById('secure-cookies').textContent = document.cookie;
                            
                            // Now try to shadow with insecure cookie via a different protocol
                            document.cookie = "{cookie_name}=shadow; Path=/";
                            
                            // Show the cookies after shadowing attempt
                            document.getElementById('after-shadow').textContent = document.cookie;
                            
                            // Now make another secure request to see which cookie gets sent
                            const secondResp = await fetch('{secure_url}', {{
                                method: 'GET',
                                credentials: 'include'
                            }});
                            
                            document.getElementById('result').textContent = 'Test completed';
                        }} catch(e) {{
                            document.getElementById('result').textContent = 'Error: ' + e.message;
                        }}
                    }}
                    """

                    f.write(
                        f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Cookie Shadowing Test</title>
                        <script>
                        {js_code}
                        </script>
                    </head>
                    <body onload="runTest()">
                        <h1>Cookie Shadowing Test</h1>
                        <p>Testing cookie shadowing for: <code>{cookie_name}</code></p>
                        <div>After secure cookie: <span id="secure-cookies"></span></div>
                        <div>After shadow attempt: <span id="after-shadow"></span></div>
                        <div id="result">Testing...</div>
                    </body>
                    </html>
                    """
                    )
                    temp_file_path = f.name

                # Navigate to the temporary file
                file_url = f"file://{temp_file_path}"
                browser.get(file_url)

                # Wait for the test to complete
                time.sleep(3)

                # Check what cookies were actually set
                cookies = browser.get_cookies()
                secure_cookies = [c for c in cookies if c.get("secure", False)]
                insecure_cookies = [c for c in cookies if not c.get("secure", False)]

                # Get the result display
                result_elem = browser.find_element("id", "result")
                result_text = result_elem.text

                secure_cookies_elem = browser.find_element("id", "secure-cookies")
                secure_cookies_text = secure_cookies_elem.text

                after_shadow_elem = browser.find_element("id", "after-shadow")
                after_shadow_text = after_shadow_elem.text

                # Clean up
                os.unlink(temp_file_path)
                browser.quit()

                # Analyze what happened
                # In a secure browser, the secure cookie should not be overwritten
                shadow_success = cookie_name in after_shadow_text and "shadow" in after_shadow_text

                results["browser_results"][browser_name] = {
                    "cookies": cookies,
                    "secure_cookies": secure_cookies,
                    "insecure_cookies": insecure_cookies,
                    "secure_cookies_text": secure_cookies_text,
                    "after_shadow_text": after_shadow_text,
                    "result_text": result_text,
                    "shadow_success": shadow_success,
                }

            except Exception as e:
                logger.error(f"Error testing {browser_name}: {str(e)}")
                results["browser_results"][browser_name] = {"error": str(e)}

        self.results["tests"]["cookie_shadowing"] = results
        return results

    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all browser cookie tests and save results.

        Returns:
            Dict[str, Any]: Complete test results
        """
        logger.info(f"Starting comprehensive browser cookie tests against {self.target}")

        try:
            # Run header injection test
            logger.info("Testing header injection handling...")
            self.test_header_injection()

            # Test cookie policy handling
            logger.info("Testing cookie policy handling...")
            test_cases = [
                {"name": "regular_cookie", "value": "regular_value"},
                {"name": "secure_cookie", "value": "secure_value", "secure": True},
                {"name": "path_cookie", "value": "path_value", "path": "/specific/path"},
                {"name": "same_site_lax", "value": "lax_value", "sameSite": "Lax"},
                {"name": "same_site_strict", "value": "strict_value", "sameSite": "Strict"},
            ]
            self.test_cookie_policy(test_cases)

            # Test cookie shadowing
            logger.info("Testing cookie shadowing...")
            self.test_cookie_shadowing()

            # Save results
            filename = f"{self.output_dir}/clientfork_{self.hostname}_{int(time.time())}.json"
            save_results(self.results, filename)

            logger.info(f"All tests completed. Results saved to {filename}")
            return self.results

        except Exception as e:
            logger.error(f"Error running tests: {str(e)}")
            return {"error": str(e)}

    def compare_browsers(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare cookie handling across different browsers for a specific test case.

        Args:
            test_case: Test case to run across browsers

        Returns:
            Dict[str, Any]: Comparison results
        """
        browsers = [b for b in self.available_browsers if not b.endswith("_emulated")]
        if not browsers:
            browsers = ["chrome_emulated", "firefox_emulated", "safari_emulated"]

        test_name = test_case.get("name", "custom_comparison")

        logger.info(f"Comparing browsers for test: {test_name}")

        # Run the specified test on all browsers
        if "headerInjection" in test_case:
            header_name = test_case.get("headerName", "Location")
            malformed_value = test_case.get(
                "malformedValue", "https://example.com%0d%0aSet-Cookie:+injected=value"
            )
            results = self.test_header_injection(header_name, malformed_value, browsers)

        elif "cookiePolicy" in test_case:
            policy_cases = test_case.get("testCases", [{"name": "test", "value": "value"}])
            results = self.test_cookie_policy(policy_cases, browsers)

        elif "cookieShadowing" in test_case:
            cookie_name = test_case.get("cookieName", "session")
            variations = test_case.get("variations", None)
            results = self.test_cookie_shadowing(cookie_name, variations, browsers)

        else:
            logger.error("Unknown test case type")
            return {"error": "Unknown test case type"}

        # Analyze differences
        comparison = {
            "test_name": test_name,
            "test_case": test_case,
            "browser_count": len(browsers),
            "browsers_tested": browsers,
            "differences": [],
        }

        # Extract and compare results
        if "browser_results" in results:
            # Identify differences in behavior
            first_browser = browsers[0]
            first_result = results["browser_results"].get(first_browser, {})

            for browser in browsers[1:]:
                browser_result = results["browser_results"].get(browser, {})

                # Compare with first browser
                if "error" in first_result or "error" in browser_result:
                    comparison["differences"].append(
                        {
                            "browser_a": first_browser,
                            "browser_b": browser,
                            "note": "Error occurred in one or both browsers",
                            "error_a": first_result.get("error", None),
                            "error_b": browser_result.get("error", None),
                        }
                    )
                    continue

                # Each test has different results structure; handle accordingly
                if "headerInjection" in test_case:
                    # Compare injection success
                    injection_a = first_result.get("injection_succeeded", False)
                    injection_b = browser_result.get("injection_succeeded", False)

                    if injection_a != injection_b:
                        comparison["differences"].append(
                            {
                                "browser_a": first_browser,
                                "browser_b": browser,
                                "behavior": "header_injection",
                                "injection_a": injection_a,
                                "injection_b": injection_b,
                            }
                        )

                elif "cookiePolicy" in test_case or "cookieShadowing" in test_case:
                    # These require deeper comparison of structure which depends on the test
                    # Just record if there are any structural differences
                    if str(first_result) != str(browser_result):
                        comparison["differences"].append(
                            {
                                "browser_a": first_browser,
                                "browser_b": browser,
                                "behavior": "cookie_handling",
                                "note": "Different behavior detected",
                            }
                        )

        self.results["tests"][f"browser_comparison_{test_name}"] = comparison
        return comparison
