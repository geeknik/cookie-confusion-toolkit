"""
Utility functions specifically for manipulating and analyzing cookies.
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse

from .common import logger


class Cookie:
    """
    Class representing a cookie and its attributes.
    """

    def __init__(
        self,
        name: str,
        value: str,
        domain: Optional[str] = None,
        path: Optional[str] = None,
        expires: Optional[Union[int, float]] = None,
        max_age: Optional[int] = None,
        secure: bool = False,
        http_only: bool = False,
        same_site: Optional[str] = None,
    ):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path if path else "/"
        self.expires = expires
        self.max_age = max_age
        self.secure = secure
        self.http_only = http_only
        self.same_site = same_site

    def __str__(self) -> str:
        """Return the cookie as a string suitable for Cookie header."""
        return f"{self.name}={self.value}"

    def to_set_cookie_header(self) -> str:
        """Return the cookie as a Set-Cookie header value."""
        result = f"{self.name}={self.value}"

        if self.domain:
            result += f"; Domain={self.domain}"

        if self.path:
            result += f"; Path={self.path}"

        if self.expires:
            # Convert to HTTP date format
            from wsgiref.handlers import format_date_time

            result += f"; Expires={format_date_time(self.expires)}"

        if self.max_age is not None:
            result += f"; Max-Age={self.max_age}"

        if self.secure:
            result += "; Secure"

        if self.http_only:
            result += "; HttpOnly"

        if self.same_site:
            result += f"; SameSite={self.same_site}"

        return result

    def to_dict(self) -> Dict[str, Any]:
        """Return the cookie as a dictionary."""
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "expires": self.expires,
            "max_age": self.max_age,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
        }

    @classmethod
    def from_set_cookie_header(cls, header_value: str, request_url: str) -> "Cookie":
        """
        Parse a Set-Cookie header value into a Cookie object.

        Args:
            header_value: The Set-Cookie header value
            request_url: The URL of the request that received this cookie

        Returns:
            Cookie: A Cookie object
        """
        parts = header_value.split(";")
        main_part = parts[0].strip()

        # Handle the case where there's no value
        if "=" in main_part:
            name, value = main_part.split("=", 1)
        else:
            name, value = main_part, ""

        name = name.strip()
        value = value.strip()

        # Default attributes
        domain = None
        path = None
        expires = None
        max_age = None
        secure = False
        http_only = False
        same_site = None

        # Parse the remaining parts
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue

            # Handle flag attributes (no value)
            if "=" not in part:
                attr_name = part.lower()
                if attr_name == "secure":
                    secure = True
                elif attr_name == "httponly":
                    http_only = True
                continue

            attr_name, attr_value = part.split("=", 1)
            attr_name = attr_name.strip().lower()
            attr_value = attr_value.strip()

            if attr_name == "domain":
                domain = attr_value
            elif attr_name == "path":
                path = attr_value
            elif attr_name == "expires":
                try:
                    from email.utils import parsedate_to_datetime

                    expires = parsedate_to_datetime(attr_value).timestamp()
                except (ValueError, TypeError):
                    # Invalid date format, ignore
                    pass
            elif attr_name == "max-age":
                try:
                    max_age = int(attr_value)
                    # Also set expires based on max-age
                    expires = time.time() + max_age
                except ValueError:
                    # Invalid max-age, ignore
                    pass
            elif attr_name == "samesite":
                same_site = attr_value

        # If domain is not set, use the host from the request URL
        if not domain:
            domain = urlparse(request_url).netloc.split(":")[0]

        # If domain starts with a dot, remove it (modern browsers ignore it)
        if domain and domain.startswith("."):
            domain = domain[1:]

        return cls(
            name=name,
            value=value,
            domain=domain,
            path=path,
            expires=expires,
            max_age=max_age,
            secure=secure,
            http_only=http_only,
            same_site=same_site,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Cookie":
        """
        Create a Cookie object from a dictionary.

        Args:
            data: Dictionary containing cookie attributes

        Returns:
            Cookie: A Cookie object
        """
        return cls(
            name=data.get("name", ""),
            value=data.get("value", ""),
            domain=data.get("domain"),
            path=data.get("path"),
            expires=data.get("expires"),
            max_age=data.get("max_age"),
            secure=data.get("secure", False),
            http_only=data.get("http_only", False),
            same_site=data.get("same_site"),
        )


def parse_cookies_from_response(response_headers: Dict[str, str], request_url: str) -> List[Cookie]:
    """
    Parse Set-Cookie headers from a response.

    Args:
        response_headers: Response headers
        request_url: URL of the request

    Returns:
        List[Cookie]: List of Cookie objects
    """
    cookies = []

    for name, value in response_headers.items():
        if name.lower() == "set-cookie":
            try:
                cookie = Cookie.from_set_cookie_header(value, request_url)
                cookies.append(cookie)
            except Exception as e:
                logger.warning(f"Failed to parse Set-Cookie header: {value}. Error: {str(e)}")

    return cookies


def create_malformed_cookie(name: str, value: str, malformation_type: str, **kwargs) -> str:
    """
    Create a malformed cookie for testing.

    Args:
        name: Cookie name
        value: Cookie value
        malformation_type: Type of malformation to apply
        **kwargs: Additional arguments for specific malformation types

    Returns:
        str: Malformed cookie string
    """
    base = f"{name}={value}"

    if malformation_type == "duplicate_name":
        # Duplicate name with different value
        new_value = kwargs.get("new_value", value + "_alt")
        return f"{name}={value}; {name}={new_value}"

    elif malformation_type == "trailing_separators":
        # Add extra separators at the end
        count = kwargs.get("count", 3)
        separators = kwargs.get("separator", ";") * count
        return f"{base}{separators}"

    elif malformation_type == "space_in_name":
        # Add spaces in the name
        space_pos = kwargs.get("position", 1)
        name_with_space = name[:space_pos] + " " + name[space_pos:]
        return f"{name_with_space}={value}"

    elif malformation_type == "no_value_separator":
        # Omit the equals sign
        return f"{name}{value}"

    elif malformation_type == "attribute_without_semicolon":
        # Add an attribute without a semicolon separator
        attr = kwargs.get("attribute", "Path=/")
        return f"{base} {attr}"

    elif malformation_type == "path_encoding":
        # Percent-encode characters in the path
        path = kwargs.get("path", "/admin")
        encoded_path = path.replace("a", "%61")
        return f"{base}; Path={encoded_path}"

    elif malformation_type == "truncated_attribute":
        # Truncate an attribute
        attr = kwargs.get("attribute", "SameSite=Lax")
        truncate_pos = kwargs.get("position", 5)
        truncated_attr = attr[:truncate_pos]
        return f"{base}; {truncated_attr}"

    elif malformation_type == "quoted_value":
        # Add quotes around the value
        return f'{name}="{value}"'

    elif malformation_type == "null_byte":
        # Insert a null byte in the value
        pos = kwargs.get("position", len(value) // 2)
        value_with_null = value[:pos] + "\0" + value[pos:]
        return f"{name}={value_with_null}"

    elif malformation_type == "case_variation":
        # Change the case of the name
        if kwargs.get("uppercase", False):
            new_name = name.upper()
        else:
            new_name = name.lower()
        return f"{new_name}={value}"

    elif malformation_type == "attribute_casing":
        # Change the case of attributes
        attr_name = kwargs.get("attribute_name", "Path")
        attr_value = kwargs.get("attribute_value", "/")
        return f"{base}; {attr_name.upper()}={attr_value}"

    else:
        logger.warning(f"Unknown malformation type: {malformation_type}")
        return base


def create_cookie_collision(name: str, variations: List[Dict[str, Any]]) -> List[str]:
    """
    Create a set of colliding cookies with variations.

    Args:
        name: Base cookie name
        variations: List of variation dictionaries

    Returns:
        List[str]: List of cookie strings
    """
    cookies = []

    for variant in variations:
        name_variation = variant.get("name", name)
        value = variant.get("value", "test_value")
        path = variant.get("path", "/")
        domain = variant.get("domain", None)
        same_site = variant.get("same_site", None)
        secure = variant.get("secure", False)
        http_only = variant.get("http_only", False)

        cookie = f"{name_variation}={value}; Path={path}"

        if domain:
            cookie += f"; Domain={domain}"

        if same_site:
            cookie += f"; SameSite={same_site}"

        if secure:
            cookie += "; Secure"

        if http_only:
            cookie += "; HttpOnly"

        cookies.append(cookie)

    return cookies


def simulate_browser_cookie_jar(cookies: List[Cookie], browser: str, url: str) -> List[Cookie]:
    """
    Simulate browser cookie jar behavior for different browsers.

    Args:
        cookies: List of cookies
        browser: Browser name (chrome, firefox, safari)
        url: URL of the request

    Returns:
        List[Cookie]: List of cookies that would be included in a request
    """
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme
    host = parsed_url.netloc.split(":")[0]
    path = parsed_url.path or "/"

    result = []

    for cookie in cookies:
        # Check domain matching
        if cookie.domain:
            if not (host == cookie.domain or host.endswith("." + cookie.domain)):
                continue

        # Check path matching
        if cookie.path and not path.startswith(cookie.path):
            continue

        # Check Secure flag
        if cookie.secure and scheme != "https":
            continue

        # Check SameSite (simplified)
        if cookie.same_site:
            # Different browsers have different behaviors for SameSite
            same_site = cookie.same_site.lower()

            if same_site == "strict":
                # All browsers treat Strict similarly
                # In real browsers this would depend on the request's origin
                pass

            elif same_site == "lax":
                # Chrome and Firefox allow cookies on navigation
                # For simplicity, we'll always include Lax cookies
                pass

            elif same_site == "none":
                # Chrome requires Secure for SameSite=None
                if browser == "chrome" and not cookie.secure:
                    continue

        # Check expiry
        if cookie.expires and cookie.expires < time.time():
            continue

        result.append(cookie)

    return result


def detect_cookie_parser(response_headers: Dict[str, str], request_headers: Dict[str, str]) -> str:
    """
    Attempt to detect the server's cookie parser implementation.

    Args:
        response_headers: Response headers
        request_headers: Request headers

    Returns:
        str: Detected parser or 'unknown'
    """
    # Check for server information
    server = response_headers.get("Server", "").lower()

    if "nginx" in server:
        return "nginx"

    if "apache" in server:
        return "apache"

    # Check for framework-specific headers or patterns
    x_powered_by = response_headers.get("X-Powered-By", "").lower()

    if "php" in x_powered_by:
        return "php"

    if "asp.net" in x_powered_by:
        return "asp.net"

    if "express" in x_powered_by:
        return "express"

    if "django" in response_headers.get("X-Framework", "").lower():
        return "django"

    if "rails" in response_headers.get("X-Framework", "").lower():
        return "rails"

    # Check for specific cookie patterns
    set_cookie = response_headers.get("Set-Cookie", "")

    if "laravel_session" in set_cookie:
        return "laravel"

    if "jsessionid" in set_cookie.lower():
        return "java"

    if "aspnet_sessionid" in set_cookie.lower():
        return "asp.net"

    if "phpsessid" in set_cookie.lower():
        return "php"

    if "rack.session" in set_cookie.lower():
        return "rack/ruby"

    return "unknown"
