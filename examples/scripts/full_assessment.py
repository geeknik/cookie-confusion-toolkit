#!/usr/bin/env python3
"""
Full Cookie Security Assessment Script

This script runs a complete cookie security assessment using all modules
of the Cookie Confusion Toolkit. It's designed to be a starting point for
your own customized assessments.

Usage:
  python3 full_assessment.py https://example.com
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

# Adjust path to import the toolkit modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.bypassgen import BypassGen
from src.clientfork import ClientFork
from src.cookiebomb import CookieBomb
from src.serverdrift import ServerDrift
from src.utils.common import logger


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Full Cookie Security Assessment")
    parser.add_argument("target", help="Target URL to test")
    parser.add_argument("--output-dir", default="./results", help="Output directory")
    parser.add_argument("--auth-file", help="Authorization file path")
    parser.add_argument("--rate-limit", type=float, default=1.0, help="Rate limit delay")
    parser.add_argument("--verify-exploits", action="store_true", help="Verify generated exploits")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def setup_output_dir(output_dir):
    """Setup the output directory structure."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    assessment_dir = os.path.join(output_dir, f"assessment_{timestamp}")
    os.makedirs(assessment_dir, exist_ok=True)
    os.makedirs(os.path.join(assessment_dir, "html_exploits"), exist_ok=True)
    return assessment_dir


def run_cookiebomb(target, assessment_dir, auth_file, rate_limit, verbose):
    """Run the CookieBomb module."""
    logger.info("Starting CookieBomb tests...")
    cookiebomb = CookieBomb(
        target=target,
        output_dir=assessment_dir,
        auth_file=auth_file,
        rate_limit_delay=rate_limit,
        verbose=verbose,
    )
    results = cookiebomb.run_all_tests()

    # Save results to a dedicated file
    output_file = os.path.join(assessment_dir, "cookiebomb_results.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"CookieBomb tests completed. Results saved to {output_file}")
    return results


def run_clientfork(target, assessment_dir, auth_file, rate_limit, verbose):
    """Run the ClientFork module."""
    logger.info("Starting ClientFork tests...")
    clientfork = ClientFork(
        target=target,
        output_dir=assessment_dir,
        auth_file=auth_file,
        rate_limit_delay=rate_limit,
        use_headless=True,
        verbose=verbose,
    )
    results = clientfork.run_all_tests()

    # Save results to a dedicated file
    output_file = os.path.join(assessment_dir, "clientfork_results.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"ClientFork tests completed. Results saved to {output_file}")
    return results


def run_serverdrift(target, assessment_dir, auth_file, rate_limit, verbose):
    """Run the ServerDrift module."""
    logger.info("Starting ServerDrift tests...")
    serverdrift = ServerDrift(
        target=target,
        output_dir=assessment_dir,
        auth_file=auth_file,
        rate_limit_delay=rate_limit,
        verbose=verbose,
    )
    results = serverdrift.run_all_tests()

    # Save results to a dedicated file
    output_file = os.path.join(assessment_dir, "serverdrift_results.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"ServerDrift tests completed. Results saved to {output_file}")
    return results


def run_bypassgen(target, assessment_dir, auth_file, rate_limit, verify_exploits, verbose):
    """Run the BypassGen module."""
    logger.info("Starting BypassGen tests...")
    bypassgen = BypassGen(
        target=target,
        output_dir=assessment_dir,
        results_dir=assessment_dir,
        auth_file=auth_file,
        rate_limit_delay=rate_limit,
        verify_exploits=verify_exploits,
        verbose=verbose,
    )
    results = bypassgen.generate_all_exploits()

    # Save results to a dedicated file
    output_file = os.path.join(assessment_dir, "bypassgen_results.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"BypassGen tests completed. Results saved to {output_file}")
    return results


def generate_summary_report(assessment_dir, all_results):
    """Generate a summary report of all test results."""
    logger.info("Generating summary report...")

    # Extract findings from all modules
    findings = []

    # CookieBomb findings
    if "cookiebomb" in all_results:
        for test_name, test_results in all_results["cookiebomb"].get("tests", {}).items():
            for result in test_results.get("results", []):
                if isinstance(result, dict) and result.get("status_code") != 200:
                    findings.append(
                        {
                            "module": "CookieBomb",
                            "test": test_name,
                            "description": f"Abnormal response detected in {test_name} test",
                            "details": result,
                        }
                    )

    # ClientFork findings
    if "clientfork" in all_results:
        for test_name, test_results in all_results["clientfork"].get("tests", {}).items():
            browser_results = test_results.get("browser_results", {})
            for browser, result in browser_results.items():
                if isinstance(result, dict) and result.get("injection_succeeded", False):
                    findings.append(
                        {
                            "module": "ClientFork",
                            "test": test_name,
                            "description": f"Injection succeeded in {browser}",
                            "details": result,
                        }
                    )

    # ServerDrift findings
    if "serverdrift" in all_results:
        for test_name, test_results in all_results["serverdrift"].get("tests", {}).items():
            for result in test_results.get("results", []):
                if isinstance(result, dict) and (
                    not result.get("status_match", True) or not result.get("cookies_match", True)
                ):
                    findings.append(
                        {
                            "module": "ServerDrift",
                            "test": test_name,
                            "description": f"Parser inconsistency detected in {test_name} test",
                            "details": result,
                        }
                    )

    # BypassGen findings
    if "bypassgen" in all_results:
        for exploit_name, exploit_results in all_results["bypassgen"].get("exploits", {}).items():
            if exploit_results.get("status") == "generated":
                findings.append(
                    {
                        "module": "BypassGen",
                        "test": exploit_name,
                        "description": exploit_results.get("description", "Exploit generated"),
                        "impact": exploit_results.get("impact", "Unknown"),
                        "details": {
                            "steps": exploit_results.get("steps", []),
                            "poc_file": f"html_exploits/{exploit_name}.html",
                        },
                    }
                )

    # Create the summary report
    summary = {
        "timestamp": datetime.now().isoformat(),
        "target": all_results.get("target", "Unknown"),
        "findings_count": len(findings),
        "findings": findings,
        "modules_run": list(all_results.keys()),
    }

    # Save the summary report
    output_file = os.path.join(assessment_dir, "summary_report.json")
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Also create a human-readable text report
    text_report_file = os.path.join(assessment_dir, "summary_report.txt")
    with open(text_report_file, "w") as f:
        f.write(f"COOKIE CONFUSION ASSESSMENT SUMMARY\n")
        f.write(f"==================================\n\n")
        f.write(f"Target: {all_results.get('target', 'Unknown')}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Modules Run: {', '.join(all_results.keys())}\n\n")

        f.write(f"FINDINGS SUMMARY\n")
        f.write(f"================\n")
        f.write(f"Total Findings: {len(findings)}\n\n")

        if findings:
            for i, finding in enumerate(findings, 1):
                f.write(f"Finding #{i}: {finding['description']}\n")
                f.write(f"Module: {finding['module']}\n")
                f.write(f"Test: {finding['test']}\n")

                if "impact" in finding:
                    f.write(f"Impact: {finding['impact']}\n")

                if "details" in finding and "steps" in finding["details"]:
                    f.write(f"Exploitation Steps:\n")
                    for step in finding["details"]["steps"]:
                        f.write(f"  - {step}\n")

                if "details" in finding and "poc_file" in finding["details"]:
                    f.write(f"PoC File: {finding['details']['poc_file']}\n")

                f.write("\n")
        else:
            f.write("No significant findings detected.\n")

    logger.info(f"Summary report generated at {output_file} and {text_report_file}")
    return summary


def main():
    """Main function."""
    args = parse_args()

    # Setup logging level
    if args.verbose:
        logger.setLevel("DEBUG")

    # Setup output directory
    assessment_dir = setup_output_dir(args.output_dir)
    logger.info(f"Assessment results will be saved to {assessment_dir}")

    # Track start time
    start_time = time.time()

    # Run all modules
    all_results = {"target": args.target, "timestamp": start_time}

    try:
        # Run CookieBomb
        all_results["cookiebomb"] = run_cookiebomb(
            args.target, assessment_dir, args.auth_file, args.rate_limit, args.verbose
        )

        # Run ClientFork
        all_results["clientfork"] = run_clientfork(
            args.target, assessment_dir, args.auth_file, args.rate_limit, args.verbose
        )

        # Run ServerDrift
        all_results["serverdrift"] = run_serverdrift(
            args.target, assessment_dir, args.auth_file, args.rate_limit, args.verbose
        )

        # Run BypassGen
        all_results["bypassgen"] = run_bypassgen(
            args.target,
            assessment_dir,
            args.auth_file,
            args.rate_limit,
            args.verify_exploits,
            args.verbose,
        )

        # Generate summary report
        summary = generate_summary_report(assessment_dir, all_results)

        # Calculate duration
        duration = time.time() - start_time
        logger.info(f"Assessment completed in {duration:.2f} seconds")
        logger.info(f"Found {summary['findings_count']} potential issues")
        logger.info(f"Results saved to {assessment_dir}")

    except KeyboardInterrupt:
        logger.info("Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during assessment: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
