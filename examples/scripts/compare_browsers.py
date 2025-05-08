#!/usr/bin/env python3
"""
Browser Cookie Handling Comparison Script

This script compares how different browsers handle cookie-related security
issues. It's useful for identifying browser-specific vulnerabilities and
understanding cross-browser inconsistencies.

Usage:
  python3 compare_browsers.py https://example.com
"""
import argparse
import json
import os
import sys
import textwrap
from datetime import datetime

# Adjust path to import the toolkit modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.clientfork import ClientFork
from src.utils.common import logger


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Browser Cookie Handling Comparison")
    parser.add_argument("target", help="Target URL to test")
    parser.add_argument("--output-dir", default="./results", help="Output directory")
    parser.add_argument("--browsers", nargs="+", help="Browsers to test (default: auto-detect)")
    parser.add_argument("--no-headless", action="store_true", help="Disable headless browser mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def compare_header_injection(clientfork, browsers):
    """Compare how different browsers handle header injection."""
    logger.info("Comparing header injection handling...")

    # Test standard CRLF injection in Location header
    test_case = {
        "headerInjection": True,
        "headerName": "Location",
        "malformedValue": "https://example.com%0d%0aSet-Cookie:+injected=value",
    }

    results = clientfork.compare_browsers(test_case)

    # Test more complex injection scenarios
    advanced_test_case = {
        "headerInjection": True,
        "headerName": "X-Custom-Header",
        "malformedValue": "test%0d%0aSet-Cookie:+advanced=value;%20HttpOnly",
    }

    advanced_results = clientfork.test_header_injection(
        header_name="X-Custom-Header",
        malformed_value="test%0d%0aSet-Cookie:+advanced=value;%20HttpOnly",
        browsers=browsers,
    )

    return {"standard_crlf": results, "advanced_crlf": advanced_results}


def compare_cookie_policies(clientfork, browsers):
    """Compare how different browsers enforce cookie security policies."""
    logger.info("Comparing cookie security policy enforcement...")

    # Basic security attributes test
    basic_test_cases = [
        {"name": "regular_cookie", "value": "regular_value"},
        {"name": "secure_cookie", "value": "secure_value", "secure": True},
        {"name": "httponly_cookie", "value": "httponly_value", "httpOnly": True},
        {"name": "path_cookie", "value": "path_value", "path": "/specific/path"},
    ]

    basic_results = clientfork.test_cookie_policy(basic_test_cases, browsers)

    # SameSite attribute test
    samesite_test_cases = [
        {"name": "samesite_none", "value": "none_value", "sameSite": "None"},
        {"name": "samesite_lax", "value": "lax_value", "sameSite": "Lax"},
        {"name": "samesite_strict", "value": "strict_value", "sameSite": "Strict"},
    ]

    samesite_results = clientfork.test_cookie_policy(samesite_test_cases, browsers)

    # Expiration handling test
    expiration_test_cases = [
        {"name": "expires_future", "value": "future", "expires": "Fri, 31 Dec 2100 23:59:59 GMT"},
        {"name": "expires_past", "value": "past", "expires": "Sat, 01 Jan 2000 00:00:00 GMT"},
        {"name": "max_age_short", "value": "short", "maxAge": 10},
        {"name": "max_age_negative", "value": "negative", "maxAge": -1},
    ]

    expiration_results = clientfork.test_cookie_policy(expiration_test_cases, browsers)

    return {
        "basic_security": basic_results,
        "samesite": samesite_results,
        "expiration": expiration_results,
    }


def compare_cookie_shadowing(clientfork, browsers):
    """Compare how different browsers handle cookie shadowing attempts."""
    logger.info("Comparing cookie shadowing handling...")

    # Standard cookie shadowing test
    standard_results = clientfork.test_cookie_shadowing(cookie_name="session", browsers=browsers)

    # Test with different domain variations
    domain_variations = [
        {
            "cookie_name": "domain_cookie",
            "variations": [
                {
                    "name": "domain_cookie",
                    "value": "original",
                    "domain": "example.com",
                    "secure": True,
                    "httpOnly": True,
                },
                {"name": "domain_cookie", "value": "shadow", "domain": "sub.example.com"},
            ],
        }
    ]

    domain_results = clientfork.compare_browsers(
        {
            "cookieShadowing": True,
            "cookieName": "domain_cookie",
            "variations": domain_variations[0]["variations"],
        }
    )

    # Test with different path variations
    path_variations = [
        {
            "cookie_name": "path_cookie",
            "variations": [
                {
                    "name": "path_cookie",
                    "value": "original",
                    "path": "/admin",
                    "secure": True,
                    "httpOnly": True,
                },
                {"name": "path_cookie", "value": "shadow", "path": "/"},
            ],
        }
    ]

    path_results = clientfork.compare_browsers(
        {
            "cookieShadowing": True,
            "cookieName": "path_cookie",
            "variations": path_variations[0]["variations"],
        }
    )

    return {
        "standard_shadowing": standard_results,
        "domain_shadowing": domain_results,
        "path_shadowing": path_results,
    }


def analyze_differences(comparison_results):
    """Analyze and summarize browser differences."""
    differences = []

    # Analyze header injection differences
    if "standard_crlf" in comparison_results["header_injection"]:
        std_crlf = comparison_results["header_injection"]["standard_crlf"]
        if "differences" in std_crlf and std_crlf["differences"]:
            for diff in std_crlf["differences"]:
                differences.append(
                    {
                        "test": "Header Injection (CRLF)",
                        "browsers": f"{diff.get('browser_a', 'Unknown')} vs {diff.get('browser_b', 'Unknown')}",
                        "behavior": diff.get("behavior", "Unknown"),
                        "description": "Different header injection handling",
                    }
                )

    # Analyze cookie policy differences
    if "basic_security" in comparison_results["cookie_policies"]:
        basic_security = comparison_results["cookie_policies"]["basic_security"]
        browsers_results = basic_security.get("browser_results", {})

        # Compare Secure flag handling
        secure_handling = {}
        for browser, results in browsers_results.items():
            for result in results:
                if isinstance(result, dict) and "test_case" in result:
                    test_case = result["test_case"]
                    if test_case.get("name") == "secure_cookie":
                        secure_handling[browser] = result.get("cookie_set", False)

        # Look for differences
        if len(set(secure_handling.values())) > 1:
            secure_browsers = [b for b, v in secure_handling.items() if v]
            insecure_browsers = [b for b, v in secure_handling.items() if not v]

            if secure_browsers and insecure_browsers:
                differences.append(
                    {
                        "test": "Secure Flag Enforcement",
                        "browsers": f"{', '.join(secure_browsers)} vs {', '.join(insecure_browsers)}",
                        "behavior": "Security Attribute Enforcement",
                        "description": f"Browsers handle Secure flag differently: {secure_browsers} enforce it, {insecure_browsers} don't",
                    }
                )

    # Analyze SameSite differences
    if "samesite" in comparison_results["cookie_policies"]:
        samesite = comparison_results["cookie_policies"]["samesite"]
        browsers_results = samesite.get("browser_results", {})

        # Compare SameSite=None handling
        samesite_none_handling = {}
        for browser, results in browsers_results.items():
            for result in results:
                if isinstance(result, dict) and "test_case" in result:
                    test_case = result["test_case"]
                    if test_case.get("name") == "samesite_none":
                        samesite_none_handling[browser] = result.get("cookie_set", False)

        # Look for differences
        if len(set(samesite_none_handling.values())) > 1:
            accepting_browsers = [b for b, v in samesite_none_handling.items() if v]
            rejecting_browsers = [b for b, v in samesite_none_handling.items() if not v]

            if accepting_browsers and rejecting_browsers:
                differences.append(
                    {
                        "test": "SameSite=None Handling",
                        "browsers": f"{', '.join(accepting_browsers)} vs {', '.join(rejecting_browsers)}",
                        "behavior": "SameSite Policy Enforcement",
                        "description": f"Browsers handle SameSite=None differently",
                    }
                )

    # Analyze cookie shadowing differences
    if "standard_shadowing" in comparison_results["cookie_shadowing"]:
        shadowing = comparison_results["cookie_shadowing"]["standard_shadowing"]
        browser_results = shadowing.get("browser_results", {})

        # Compare shadowing success
        shadowing_success = {}
        for browser, result in browser_results.items():
            if isinstance(result, dict):
                shadowing_success[browser] = result.get("shadow_success", False)

        # Look for differences
        if len(set(shadowing_success.values())) > 1:
            vulnerable_browsers = [b for b, v in shadowing_success.items() if v]
            secure_browsers = [b for b, v in shadowing_success.items() if not v]

            if vulnerable_browsers and secure_browsers:
                differences.append(
                    {
                        "test": "Cookie Shadowing",
                        "browsers": f"{', '.join(vulnerable_browsers)} vs {', '.join(secure_browsers)}",
                        "behavior": "Security Cookie Override",
                        "description": f"Browsers {vulnerable_browsers} allow cookie shadowing, while {secure_browsers} prevent it",
                    }
                )

    return differences


def generate_report(comparison_results, differences, output_dir, target):
    """Generate a comprehensive browser comparison report."""
    logger.info("Generating browser comparison report...")

    # Create a timestamped output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"browser_comparison_{timestamp}.json")
    text_report_file = os.path.join(output_dir, f"browser_comparison_{timestamp}.txt")

    # Create the report structure
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "tests_run": list(comparison_results.keys()),
        "differences_found": len(differences),
        "differences": differences,
        "raw_results": comparison_results,
    }

    # Save the JSON report
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    # Create the text report
    with open(text_report_file, "w") as f:
        f.write(f"BROWSER COOKIE HANDLING COMPARISON\n")
        f.write(f"=================================\n\n")
        f.write(f"Target: {target}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Tests Run: {', '.join(report['tests_run'])}\n\n")

        f.write(f"BROWSER DIFFERENCES SUMMARY\n")
        f.write(f"==========================\n")
        f.write(f"Total Differences Found: {len(differences)}\n\n")

        if differences:
            for i, diff in enumerate(differences, 1):
                f.write(f"Difference #{i}: {diff['test']}\n")
                f.write(f"Browsers: {diff['browsers']}\n")
                f.write(f"Behavior: {diff['behavior']}\n")
                f.write(f"Description: {diff['description']}\n\n")

            f.write(f"SECURITY IMPLICATIONS\n")
            f.write(f"====================\n")
            f.write(
                textwrap.fill(
                    "The differences in browser behavior can lead to security vulnerabilities "
                    "when developers make assumptions about how cookies are handled. Applications "
                    "that work correctly in one browser may have security bypasses in another.",
                    width=80,
                )
                + "\n\n"
            )

            f.write(
                textwrap.fill("Key security concerns from these differences:", width=80) + "\n\n"
            )

            concerns = [
                "Authentication bypasses through cookie manipulation",
                "CSRF protection failures in specific browsers",
                "Session fixation vulnerabilities",
                "HttpOnly cookie leakage",
                "SameSite protection inconsistencies",
            ]

            for concern in concerns:
                f.write(f"- {concern}\n")

            f.write("\n")
            f.write(
                textwrap.fill(
                    "RECOMMENDATION: When developing web applications, test cookie-related "
                    "security in all major browsers and implement defense in depth that doesn't "
                    "rely solely on browser cookie security features.",
                    width=80,
                )
                + "\n"
            )
        else:
            f.write("No significant browser differences detected in the tests run.\n")

    logger.info(f"Report generated at {output_file} and {text_report_file}")
    return report


def main():
    """Main function."""
    args = parse_args()

    # Setup logging level
    if args.verbose:
        logger.setLevel("DEBUG")

    # Setup output directory
    os.makedirs(args.output_dir, exist_ok=True)

    try:
        # Initialize ClientFork
        clientfork = ClientFork(
            target=args.target,
            output_dir=args.output_dir,
            use_headless=not args.no_headless,
            verbose=args.verbose,
        )

        # Get available browsers
        available_browsers = args.browsers if args.browsers else clientfork.available_browsers
        logger.info(f"Testing with browsers: {', '.join(available_browsers)}")

        # Run comparisons
        comparison_results = {
            "header_injection": compare_header_injection(clientfork, available_browsers),
            "cookie_policies": compare_cookie_policies(clientfork, available_browsers),
            "cookie_shadowing": compare_cookie_shadowing(clientfork, available_browsers),
        }

        # Analyze differences
        differences = analyze_differences(comparison_results)

        # Generate report
        report = generate_report(comparison_results, differences, args.output_dir, args.target)

        # Display summary
        print("\nBrowser Comparison Summary:")
        print(f"Target: {args.target}")
        print(f"Browsers compared: {', '.join(available_browsers)}")
        print(f"Differences found: {len(differences)}")

        if differences:
            print("\nKey differences:")
            for i, diff in enumerate(differences, 1):
                print(f"{i}. {diff['test']}: {diff['description']}")
        else:
            print("\nNo significant differences found between tested browsers.")

    except KeyboardInterrupt:
        logger.info("Comparison interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during comparison: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
