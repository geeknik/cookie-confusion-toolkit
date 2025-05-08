"""
Common utilities for the Cookie Confusion Toolkit.
"""

import hashlib
import json
import logging
import os
import random
import re
import string
import sys
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

import requests
from requests.exceptions import RequestException

# Configure logging
logger = logging.getLogger("cookie-confusion-toolkit")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Constants
USER_AGENTS = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/124.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
}

COOKIE_ATTRIBUTES = ["Path", "Domain", "Secure", "HttpOnly", "SameSite", "Max-Age", "Expires"]


def is_valid_target(url: str) -> bool:
    """
    Validate that a URL is a legitimate target for testing.

    Args:
        url: The URL to validate

    Returns:
        bool: True if the URL is valid, False otherwise
    """
    if not url.startswith(("http://", "https://")):
        return False

    # Check for localhost and common development domains
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname.lower()

    if hostname in ["localhost", "127.0.0.1", "::1"]:
        logger.warning("Testing on localhost is permitted for development purposes only")
        return True

    # Check for common testing/development domains
    if hostname.endswith((".test", ".local", ".example", ".invalid", ".localhost")):
        return True

    # Prevent testing on sensitive domains
    restricted_domains = [
        "gov",
        "mil",
        "edu",
        "bank",
        "healthcare",
        "nhs.uk",
        "irs.gov",
        "cisa.gov",
        "fbi.gov",
        "police",
    ]

    for domain in restricted_domains:
        if domain in hostname:
            logger.error(f"Testing on potentially sensitive domains like {domain} is not permitted")
            return False

    return True


def generate_random_string(length: int = 10) -> str:
    """
    Generate a random string of a specified length.

    Args:
        length: The length of the random string

    Returns:
        str: A random string
    """
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def safe_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    timeout: int = 10,
    verify: bool = True,
    allow_redirects: bool = True,
    browser: str = "chrome",
) -> Optional[requests.Response]:
    """
    Make a safe HTTP request with proper error handling.

    Args:
        url: Target URL
        method: HTTP method to use
        headers: HTTP headers
        cookies: HTTP cookies
        data: Request data
        timeout: Request timeout in seconds
        verify: Verify SSL certificates
        allow_redirects: Allow redirects
        browser: Browser to emulate

    Returns:
        requests.Response or None: The HTTP response or None if the request failed
    """
    if not is_valid_target(url):
        logger.error(f"Invalid or restricted target: {url}")
        return None

    if headers is None:
        headers = {}

    if "User-Agent" not in headers:
        headers["User-Agent"] = USER_AGENTS.get(browser.lower(), USER_AGENTS["chrome"])

    try:
        logger.debug(f"Making {method} request to {url}")
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            data=data,
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
        )
        return response
    except RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return None


def parse_cookie_string(cookie_str: str) -> List[Dict[str, str]]:
    """
    Parse a cookie string into component parts.

    Args:
        cookie_str: The cookie string to parse

    Returns:
        List[Dict[str, str]]: List of cookies with their attributes
    """
    if not cookie_str:
        return []

    result = []
    for cookie in cookie_str.split(";"):
        cookie = cookie.strip()
        if not cookie:
            continue

        if "=" in cookie:
            key, value = cookie.split("=", 1)
            result.append({"name": key.strip(), "value": value.strip()})
        else:
            # Handle flag attributes like Secure or HttpOnly
            result.append({"name": cookie.strip(), "value": ""})

    return result


def get_set_cookie_headers(response: requests.Response) -> List[str]:
    """
    Extract Set-Cookie headers from an HTTP response.

    Args:
        response: The HTTP response

    Returns:
        List[str]: List of Set-Cookie header values
    """
    cookies = []

    # Check both capitalization formats
    for header, value in response.headers.items():
        if header.lower() == "set-cookie":
            cookies.append(value)

    return cookies


def calculate_checksum(data: str) -> str:
    """
    Calculate a checksum for the given data.

    Args:
        data: The data to checksum

    Returns:
        str: The checksum as a hexadecimal string
    """
    return hashlib.sha256(data.encode()).hexdigest()


def save_results(results: Dict[str, Any], filename: str) -> None:
    """
    Save results to a JSON file.

    Args:
        results: The results to save
        filename: The file to save to
    """
    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Results saved to {filename}")


def load_results(filename: str) -> Optional[Dict[str, Any]]:
    """
    Load results from a JSON file.

    Args:
        filename: The file to load from

    Returns:
        Dict[str, Any] or None: The loaded results or None if the file doesn't exist
    """
    if not os.path.exists(filename):
        logger.error(f"Results file {filename} not found")
        return None

    with open(filename, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse results file {filename}")
            return None


def ethical_check(target: str) -> bool:
    """
    Perform ethical checks before targeting a domain.

    Args:
        target: The target URL

    Returns:
        bool: True if the target passes ethical checks, False otherwise
    """
    parsed_url = urlparse(target)
    hostname = parsed_url.hostname.lower() if parsed_url.hostname else ""

    # Check for sensitive domains that should not be tested without explicit permission
    sensitive_domains = [
        # Government
        ".gov",
        ".mil",
        ".gc.ca",
        ".gov.uk",
        ".gouv.fr",
        ".gov.au",
        # Critical infrastructure
        "energy",
        "power",
        "water",
        "utility",
        "nuclear",
        "electric",
        # Financial
        "bank",
        "credit",
        "loan",
        "finance",
        "insurance",
        "investment",
        # Healthcare
        "health",
        "hospital",
        "clinic",
        "medical",
        "patient",
        "pharma",
        # Education
        ".edu",
        ".ac.uk",
        ".edu.au",
        "school",
        "university",
        "college",
    ]

    for domain in sensitive_domains:
        if domain in hostname:
            logger.error(
                f"Testing on {hostname} requires explicit permission as it may be a sensitive domain"
            )
            logger.error("To override, use the --force flag and document your authorization")
            return False

    return True


def validate_authorization(target: str, auth_file: Optional[str] = None) -> bool:
    """
    Validate that testing is authorized for the given target.

    Args:
        target: The target URL
        auth_file: Path to authorization file (optional)

    Returns:
        bool: True if testing is authorized, False otherwise
    """
    if not auth_file:
        # Check environment variable
        auth_file = os.environ.get("CCT_AUTH_FILE")

    if not auth_file or not os.path.exists(auth_file):
        # Authorization file is optional for basic operations
        return ethical_check(target)

    try:
        with open(auth_file, "r") as f:
            auth_data = json.load(f)

        parsed_url = urlparse(target)
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else ""

        authorized_targets = auth_data.get("authorized_targets", [])
        for authorized in authorized_targets:
            if hostname.endswith(authorized) or authorized == hostname:
                logger.info(f"Authorization verified for {hostname}")
                return True

        logger.error(f"No authorization found for {hostname} in authorization file")
        return False
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Failed to parse authorization file: {str(e)}")
        return False


def rate_limit(min_interval: float = 1.0) -> None:
    """
    Implement rate limiting to prevent overloading the target.

    Args:
        min_interval: Minimum interval between requests in seconds
    """
    # Using a simple class-based rate limiter
    if not hasattr(rate_limit, "last_request_time"):
        rate_limit.last_request_time = 0

    current_time = time.time()
    elapsed = current_time - rate_limit.last_request_time

    if elapsed < min_interval:
        sleep_time = min_interval - elapsed
        logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
        time.sleep(sleep_time)

    rate_limit.last_request_time = time.time()
