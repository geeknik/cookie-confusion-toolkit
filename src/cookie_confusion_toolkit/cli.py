"""
CLI interface for the Cookie Confusion Toolkit.
"""

import argparse
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Change relative imports to absolute imports
import cookie_confusion_toolkit
from cookie_confusion_toolkit import __version__
from cookie_confusion_toolkit.bypassgen import BypassGen
from cookie_confusion_toolkit.clientfork import ClientFork
from cookie_confusion_toolkit.cookiebomb import CookieBomb
from cookie_confusion_toolkit.serverdrift import ServerDrift
from cookie_confusion_toolkit.utils.common import logger


def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """
    Configure logging for the CLI.

    Args:
        verbose: Enable verbose logging
        log_file: Log file path
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)

    # Clear existing handlers
    logger.handlers = []
    logger.addHandler(console_handler)

    # Add file handler if log file specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description=f"Cookie Confusion Toolkit (CCT) v{__version__} - "
        "A tool for testing cookie parsing inconsistencies"
    )

    # Global arguments
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version=f"CCT v{__version__}")
    parser.add_argument("--log-file", help="Log file path")
    parser.add_argument("--output-dir", default="./results", help="Output directory for results")
    parser.add_argument(
        "--auth-file", help="Optional authentication file path (only needed for advanced features)"
    )
    parser.add_argument(
        "--rate-limit", type=float, default=1.0, help="Rate limit delay between requests in seconds"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Common arguments for all modules
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("target", help="Target URL to test")

    # CookieBomb command
    cookiebomb_parser = subparsers.add_parser(
        "cookiebomb",
        help="Generate degenerate cookie jars to test parsing inconsistencies",
        parents=[common_parser],
    )
    cookiebomb_parser.add_argument(
        "--cookie-names",
        nargs="+",
        default=["session", "sessionid", "SESSIONID"],
        help="Cookie names to test",
    )
    cookiebomb_parser.add_argument(
        "--test",
        choices=[
            "all",
            "key_collisions",
            "overlong_values",
            "path_scoping",
            "whitespace_ambiguity",
        ],
        default="all",
        help="Specific test to run",
    )

    # ClientFork command
    clientfork_parser = subparsers.add_parser(
        "clientfork",
        help="Emulate browser cookie handling to detect inconsistencies",
        parents=[common_parser],
    )
    clientfork_parser.add_argument(
        "--browsers", nargs="+", help="Browsers to test (default: auto-detect)"
    )
    clientfork_parser.add_argument(
        "--no-headless", action="store_true", help="Disable headless browser mode"
    )
    clientfork_parser.add_argument(
        "--test",
        choices=["all", "header_injection", "cookie_policy", "cookie_shadowing"],
        default="all",
        help="Specific test to run",
    )

    # ServerDrift command
    serverdrift_parser = subparsers.add_parser(
        "serverdrift",
        help="Test server-side cookie parsing inconsistencies",
        parents=[common_parser],
    )
    serverdrift_parser.add_argument(
        "--cookie-name", default="session", help="Cookie name to use for testing"
    )
    serverdrift_parser.add_argument(
        "--test",
        choices=[
            "all",
            "key_overwrite",
            "attribute_truncation",
            "samesite_domain_logic",
            "malformed_cookies",
        ],
        default="all",
        help="Specific test to run",
    )

    # BypassGen command
    bypassgen_parser = subparsers.add_parser(
        "bypassgen",
        help="Generate exploit chains for cookie parsing vulnerabilities",
        parents=[common_parser],
    )
    bypassgen_parser.add_argument(
        "--results-dir", help="Directory containing test results (default: output-dir)"
    )
    bypassgen_parser.add_argument("--verify", action="store_true", help="Verify generated exploits")
    bypassgen_parser.add_argument(
        "--exploit",
        choices=[
            "all",
            "session_fixation",
            "csrf_disable",
            "jwt_shadowing",
            "path_override",
            "casing_inversion",
            "quote_leak",
            "delimiter_exploit",
            "shadow_cookie",
        ],
        default="all",
        help="Specific exploit to generate",
    )

    # Full command - run all modules
    full_parser = subparsers.add_parser(
        "full", help="Run all modules in sequence", parents=[common_parser]
    )
    full_parser.add_argument("--verify", action="store_true", help="Verify generated exploits")

    return parser.parse_args()


def run_cookiebomb(args: argparse.Namespace) -> None:
    """
    Run the CookieBomb module.

    Args:
        args: Parsed command-line arguments
    """
    cookiebomb = CookieBomb(
        target=args.target,
        output_dir=args.output_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        verbose=args.verbose,
    )

    if args.test == "all":
        cookiebomb.run_all_tests(cookie_names=args.cookie_names)
    elif args.test == "key_collisions":
        cookiebomb.test_key_collisions(cookie_names=args.cookie_names)
    elif args.test == "overlong_values":
        cookiebomb.test_overlong_values(cookie_name=args.cookie_names[0])
    elif args.test == "path_scoping":
        cookiebomb.test_path_scoping(cookie_name=args.cookie_names[0])
    elif args.test == "whitespace_ambiguity":
        cookiebomb.test_whitespace_ambiguity(cookie_name=args.cookie_names[0])


def run_clientfork(args: argparse.Namespace) -> None:
    """
    Run the ClientFork module.

    Args:
        args: Parsed command-line arguments
    """
    clientfork = ClientFork(
        target=args.target,
        output_dir=args.output_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        use_headless=not args.no_headless,
        verbose=args.verbose,
    )

    if args.test == "all":
        clientfork.run_all_tests()
    elif args.test == "header_injection":
        clientfork.test_header_injection(browsers=args.browsers)
    elif args.test == "cookie_policy":
        test_cases = [
            {"name": "regular_cookie", "value": "regular_value"},
            {"name": "secure_cookie", "value": "secure_value", "secure": True},
            {"name": "path_cookie", "value": "path_value", "path": "/specific/path"},
            {"name": "same_site_lax", "value": "lax_value", "sameSite": "Lax"},
            {"name": "same_site_strict", "value": "strict_value", "sameSite": "Strict"},
        ]
        clientfork.test_cookie_policy(test_cases, browsers=args.browsers)
    elif args.test == "cookie_shadowing":
        clientfork.test_cookie_shadowing(browsers=args.browsers)


def run_serverdrift(args: argparse.Namespace) -> None:
    """
    Run the ServerDrift module.

    Args:
        args: Parsed command-line arguments
    """
    serverdrift = ServerDrift(
        target=args.target,
        output_dir=args.output_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        verbose=args.verbose,
    )

    if args.test == "all":
        serverdrift.run_all_tests(cookie_name=args.cookie_name)
    elif args.test == "key_overwrite":
        serverdrift.test_key_overwrite(cookie_name=args.cookie_name)
    elif args.test == "attribute_truncation":
        serverdrift.test_attribute_truncation(cookie_name=args.cookie_name)
    elif args.test == "samesite_domain_logic":
        serverdrift.test_samesite_domain_logic(cookie_name=args.cookie_name)
    elif args.test == "malformed_cookies":
        serverdrift.test_malformed_cookies()


def run_bypassgen(args: argparse.Namespace) -> None:
    """
    Run the BypassGen module.

    Args:
        args: Parsed command-line arguments
    """
    results_dir = args.results_dir if args.results_dir else args.output_dir

    bypassgen = BypassGen(
        target=args.target,
        output_dir=args.output_dir,
        results_dir=results_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        verify_exploits=args.verify,
        verbose=args.verbose,
    )

    if args.exploit == "all":
        bypassgen.generate_all_exploits()
    elif args.exploit == "session_fixation":
        result = bypassgen.generate_session_fixation_exploit()
        bypassgen.results["exploits"]["session_fixation"] = result
    elif args.exploit == "csrf_disable":
        result = bypassgen.generate_csrf_disable_exploit()
        bypassgen.results["exploits"]["csrf_disable"] = result
    elif args.exploit == "jwt_shadowing":
        result = bypassgen.generate_jwt_shadowing_exploit()
        bypassgen.results["exploits"]["jwt_shadowing"] = result
    elif args.exploit == "path_override":
        result = bypassgen.generate_path_override_exploit()
        bypassgen.results["exploits"]["path_override"] = result
    elif args.exploit == "casing_inversion":
        result = bypassgen.generate_casing_inversion_exploit()
        bypassgen.results["exploits"]["casing_inversion"] = result
    elif args.exploit == "quote_leak":
        result = bypassgen.generate_quote_leak_exploit()
        bypassgen.results["exploits"]["quote_leak"] = result
    elif args.exploit == "delimiter_exploit":
        result = bypassgen.generate_delimiter_exploit()
        bypassgen.results["exploits"]["delimiter_exploit"] = result
    elif args.exploit == "shadow_cookie":
        result = bypassgen.generate_shadow_cookie_exploit()
        bypassgen.results["exploits"]["shadow_cookie"] = result


def run_full_scan(args: argparse.Namespace) -> None:
    """
    Run all modules in sequence.

    Args:
        args: Parsed command-line arguments
    """
    logger.info("Starting full scan with all modules")
    start_time = time.time()

    # Run CookieBomb
    logger.info("Running CookieBomb module...")
    cookiebomb = CookieBomb(
        target=args.target,
        output_dir=args.output_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        verbose=args.verbose,
    )
    cookiebomb.run_all_tests()

    # Run ClientFork
    logger.info("Running ClientFork module...")
    clientfork = ClientFork(
        target=args.target,
        output_dir=args.output_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        use_headless=True,
        verbose=args.verbose,
    )
    clientfork.run_all_tests()

    # Run ServerDrift
    logger.info("Running ServerDrift module...")
    serverdrift = ServerDrift(
        target=args.target,
        output_dir=args.output_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        verbose=args.verbose,
    )
    serverdrift.run_all_tests()

    # Run BypassGen
    logger.info("Running BypassGen module...")
    bypassgen = BypassGen(
        target=args.target,
        output_dir=args.output_dir,
        results_dir=args.output_dir,
        auth_file=args.auth_file,
        rate_limit_delay=args.rate_limit,
        verify_exploits=args.verify,
        verbose=args.verbose,
    )
    bypassgen.generate_all_exploits()

    end_time = time.time()
    duration = end_time - start_time

    logger.info(f"Full scan completed in {duration:.2f} seconds")


def main() -> None:
    """
    Main entry point for the CLI.
    """
    args = parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    try:
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)

        if args.command == "cookiebomb":
            run_cookiebomb(args)
        elif args.command == "clientfork":
            run_clientfork(args)
        elif args.command == "serverdrift":
            run_serverdrift(args)
        elif args.command == "bypassgen":
            run_bypassgen(args)
        elif args.command == "full":
            run_full_scan(args)
        else:
            logger.error("No command specified. Use --help for usage information.")
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
