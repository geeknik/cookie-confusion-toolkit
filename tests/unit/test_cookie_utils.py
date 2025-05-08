"""
Unit tests for cookie utilities.
"""
import time
from unittest.mock import MagicMock

import pytest

from src.cookie_confusion_toolkit.utils.cookie_utils import (
    Cookie,
    create_cookie_collision,
    create_malformed_cookie,
    detect_cookie_parser,
    parse_cookies_from_response,
    simulate_browser_cookie_jar,
)


class TestCookieClass:
    """Test the Cookie class."""

    def test_cookie_creation(self):
        """Test basic cookie creation."""
        cookie = Cookie(
            name="session",
            value="test123",
            domain="example.com",
            path="/",
            secure=True,
            http_only=True,
            same_site="Strict",
        )

        assert cookie.name == "session"
        assert cookie.value == "test123"
        assert cookie.domain == "example.com"
        assert cookie.path == "/"
        assert cookie.secure is True
        assert cookie.http_only is True
        assert cookie.same_site == "Strict"

    def test_cookie_str(self):
        """Test cookie string representation."""
        cookie = Cookie("session", "test123")
        assert str(cookie) == "session=test123"

    def test_to_set_cookie_header(self):
        """Test Set-Cookie header generation."""
        cookie = Cookie(
            name="session",
            value="test123",
            domain="example.com",
            path="/secure",
            secure=True,
            http_only=True,
            same_site="Lax",
            max_age=3600,
        )

        header = cookie.to_set_cookie_header()

        assert "session=test123" in header
        assert "Domain=example.com" in header
        assert "Path=/secure" in header
        assert "Secure" in header
        assert "HttpOnly" in header
        assert "SameSite=Lax" in header
        assert "Max-Age=3600" in header

    def test_to_dict(self):
        """Test dictionary conversion."""
        cookie = Cookie(name="session", value="test123", domain="example.com", secure=True)

        cookie_dict = cookie.to_dict()

        assert cookie_dict["name"] == "session"
        assert cookie_dict["value"] == "test123"
        assert cookie_dict["domain"] == "example.com"
        assert cookie_dict["secure"] is True

    def test_from_set_cookie_header(self):
        """Test parsing from Set-Cookie header."""
        header = "session=abc123; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict"
        cookie = Cookie.from_set_cookie_header(header, "https://example.com")

        assert cookie.name == "session"
        assert cookie.value == "abc123"
        assert cookie.domain == "example.com"
        assert cookie.path == "/"
        assert cookie.secure is True
        assert cookie.http_only is True
        assert cookie.same_site == "Strict"

    def test_from_set_cookie_header_minimal(self):
        """Test parsing minimal Set-Cookie header."""
        header = "minimal=value"
        cookie = Cookie.from_set_cookie_header(header, "https://example.com")

        assert cookie.name == "minimal"
        assert cookie.value == "value"
        assert cookie.domain == "example.com"
        assert cookie.path == "/"

    def test_from_dict(self):
        """Test creating cookie from dictionary."""
        data = {"name": "test", "value": "123", "domain": "example.com", "secure": True}

        cookie = Cookie.from_dict(data)

        assert cookie.name == "test"
        assert cookie.value == "123"
        assert cookie.domain == "example.com"
        assert cookie.secure is True


class TestCookieParsing:
    """Test cookie parsing functions."""

    def test_parse_cookies_from_response(self):
        """Test parsing cookies from HTTP response."""
        mock_response = MagicMock()
        mock_response.headers = {
            "Set-Cookie": "session=abc123; Path=/",
            "set-cookie": "other=value; Secure",  # Test case insensitivity
        }

        cookies = parse_cookies_from_response(mock_response.headers, "https://example.com")

        assert len(cookies) == 2
        assert any(c.name == "session" and c.value == "abc123" for c in cookies)
        assert any(c.name == "other" and c.value == "value" for c in cookies)

    def test_parse_cookies_from_response_no_cookies(self):
        """Test parsing when no cookies are present."""
        mock_response = MagicMock()
        mock_response.headers = {"Content-Type": "text/html"}

        cookies = parse_cookies_from_response(mock_response.headers, "https://example.com")

        assert len(cookies) == 0


class TestMalformedCookies:
    """Test malformed cookie generation."""

    def test_duplicate_name(self):
        """Test creating cookies with duplicate names."""
        cookie = create_malformed_cookie(
            "session", "value1", "duplicate_name", new_value="value2"
        )

        assert "session=value1; session=value2" == cookie

    def test_trailing_separators(self):
        """Test creating cookies with trailing separators."""
        cookie = create_malformed_cookie("session", "value", "trailing_separators", count=3)

        assert "session=value;;;" == cookie

    def test_space_in_name(self):
        """Test creating cookies with spaces in names."""
        cookie = create_malformed_cookie("session", "value", "space_in_name", position=3)

        assert "ses sion=value" == cookie

    def test_quoted_value(self):
        """Test creating cookies with quoted values."""
        cookie = create_malformed_cookie("session", "value", "quoted_value")

        assert 'session="value"' == cookie

    def test_case_variation(self):
        """Test creating cookies with case variations."""
        cookie = create_malformed_cookie("session", "value", "case_variation", uppercase=True)

        assert "SESSION=value" == cookie

    def test_unknown_malformation(self):
        """Test handling unknown malformation type."""
        cookie = create_malformed_cookie("session", "value", "unknown_type")

        # Should return the base cookie on unknown type
        assert "session=value" == cookie


class TestCookieCollision:
    """Test cookie collision creation."""

    def test_create_cookie_collision(self):
        """Test creating collision cookies."""
        variations = [
            {"name": "Session", "value": "value1", "path": "/"},
            {"name": "session", "value": "value2", "path": "/admin"},
            {"name": "SESSION", "value": "value3", "secure": True},
        ]

        cookies = create_cookie_collision("session", variations)

        assert len(cookies) == 3
        assert "Session=value1; Path=/" in cookies
        assert "session=value2; Path=/admin" in cookies
        assert "SESSION=value3; Secure" in cookies

    def test_create_cookie_collision_with_all_attributes(self):
        """Test collision with all attributes."""
        variations = [
            {
                "name": "test",
                "value": "val1",
                "path": "/path",
                "domain": "example.com",
                "same_site": "Strict",
                "secure": True,
                "http_only": True,
            }
        ]

        cookies = create_cookie_collision("test", variations)

        cookie = cookies[0]
        assert "test=val1" in cookie
        assert "Path=/path" in cookie
        assert "Domain=example.com" in cookie
        assert "SameSite=Strict" in cookie
        assert "Secure" in cookie
        assert "HttpOnly" in cookie


class TestBrowserCookieJar:
    """Test browser cookie jar simulation."""

    def test_simulate_browser_cookie_jar_basic(self):
        """Test basic cookie jar simulation."""
        cookies = [
            Cookie("session", "value1", path="/"),
            Cookie("admin", "value2", path="/admin"),
            Cookie("secure", "value3", secure=True),
            Cookie("domain", "value4", domain="example.com"),
        ]

        # Test path matching
        result = simulate_browser_cookie_jar(
            cookies, "chrome", "https://example.com/admin/page"
        )

        # Should include both session and admin cookies
        assert len(result) == 4
        assert any(c.name == "session" for c in result)
        assert any(c.name == "admin" for c in result)

    def test_simulate_browser_cookie_jar_path_filtering(self):
        """Test path-based filtering."""
        cookies = [
            Cookie("public", "value1", path="/"),
            Cookie("admin", "value2", path="/admin"),
            Cookie("api", "value3", path="/api"),
        ]

        # Request to /api should include public and api, but not admin
        result = simulate_browser_cookie_jar(
            cookies, "chrome", "https://example.com/api/endpoint"
        )

        cookie_names = [c.name for c in result]
        assert "public" in cookie_names
        assert "api" in cookie_names
        assert "admin" not in cookie_names

    def test_simulate_browser_cookie_jar_secure_filtering(self):
        """Test Secure attribute filtering."""
        cookies = [Cookie("normal", "value1"), Cookie("secure", "value2", secure=True)]

        # HTTP request should exclude secure cookies
        result = simulate_browser_cookie_jar(cookies, "chrome", "http://example.com/")

        cookie_names = [c.name for c in result]
        assert "normal" in cookie_names
        assert "secure" not in cookie_names

        # HTTPS request should include all cookies
        result = simulate_browser_cookie_jar(cookies, "chrome", "https://example.com/")

        cookie_names = [c.name for c in result]
        assert "normal" in cookie_names
        assert "secure" in cookie_names

    def test_simulate_browser_cookie_jar_samesite_lax(self):
        """Test SameSite=Lax behavior (simplified)."""
        cookies = [
            Cookie("normal", "value1"),
            Cookie("lax", "value2", same_site="Lax"),
            Cookie("strict", "value3", same_site="Strict"),
        ]

        # For our simplified implementation, all cookies are included
        # In real browsers, SameSite behavior depends on request origin
        result = simulate_browser_cookie_jar(cookies, "chrome", "https://example.com/")

        assert len(result) == 3

    def test_simulate_browser_cookie_jar_chrome_samesite_none(self):
        """Test Chrome's handling of SameSite=None."""
        cookies = [
            Cookie("none", "value1", same_site="None", secure=True),
            Cookie("none_insecure", "value2", same_site="None", secure=False),
        ]

        # Chrome should exclude SameSite=None cookies without Secure
        result = simulate_browser_cookie_jar(cookies, "chrome", "https://example.com/")

        cookie_names = [c.name for c in result]
        assert "none" in cookie_names
        assert "none_insecure" not in cookie_names

    def test_simulate_browser_cookie_jar_expired(self):
        """Test handling of expired cookies."""
        # Create expired cookie
        past_time = time.time() - 3600  # 1 hour ago
        cookies = [Cookie("current", "value1"), Cookie("expired", "value2", expires=past_time)]

        result = simulate_browser_cookie_jar(cookies, "chrome", "https://example.com/")

        cookie_names = [c.name for c in result]
        assert "current" in cookie_names
        assert "expired" not in cookie_names


class TestCookieParserDetection:
    """Test cookie parser detection."""

    def test_detect_nginx(self):
        """Test detecting nginx."""
        response_headers = {"Server": "nginx/1.20.1"}
        request_headers = {}

        parser = detect_cookie_parser(response_headers, request_headers)
        assert parser == "nginx"

    def test_detect_apache(self):
        """Test detecting Apache."""
        response_headers = {"Server": "Apache/2.4.41"}
        request_headers = {}

        parser = detect_cookie_parser(response_headers, request_headers)
        assert parser == "apache"

    def test_detect_express(self):
        """Test detecting Express."""
        response_headers = {"X-Powered-By": "Express"}
        request_headers = {}

        parser = detect_cookie_parser(response_headers, request_headers)
        assert parser == "express"

    def test_detect_django(self):
        """Test detecting Django."""
        response_headers = {"X-Framework": "Django/3.2"}
        request_headers = {}

        parser = detect_cookie_parser(response_headers, request_headers)
        assert parser == "django"

    def test_detect_php_via_cookie(self):
        """Test detecting PHP via cookie name."""
        response_headers = {"Set-Cookie": "PHPSESSID=abc123; Path=/"}
        request_headers = {}

        parser = detect_cookie_parser(response_headers, request_headers)
        assert parser == "php"

    def test_detect_java_via_cookie(self):
        """Test detecting Java via cookie name."""
        response_headers = {"Set-Cookie": "JSESSIONID=xyz789; Path=/"}
        request_headers = {}

        parser = detect_cookie_parser(response_headers, request_headers)
        assert parser == "java"

    def test_detect_unknown(self):
        """Test detecting unknown server."""
        response_headers = {"Content-Type": "text/html"}
        request_headers = {}

        parser = detect_cookie_parser(response_headers, request_headers)
        assert parser == "unknown"
