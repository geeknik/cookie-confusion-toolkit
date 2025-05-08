"""
Unit tests for the CookieBomb module.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from src.cookie_confusion_toolkit.cookiebomb import CookieBomb


class TestCookieBombInitialization:
    """Test CookieBomb initialization."""

    def test_init_valid_target(self, temp_dir, auth_file):
        """Test initialization with valid target."""
        cookiebomb = CookieBomb(
            target="http://localhost", output_dir=temp_dir, auth_file=auth_file
        )

        assert cookiebomb.target == "http://localhost"
        assert cookiebomb.output_dir == temp_dir
        assert cookiebomb.hostname == "localhost"
        assert cookiebomb.results["target"] == "http://localhost"

    def test_init_invalid_target(self, temp_dir, auth_file):
        """Test initialization with invalid target."""
        with pytest.raises(ValueError, match="Target URL must start with http://"):
            CookieBomb(target="ftp://example.com", output_dir=temp_dir, auth_file=auth_file)

    def test_init_unauthorized_target(self, temp_dir, auth_file):
        """Test initialization with unauthorized target."""
        with pytest.raises(ValueError, match="Not authorized to test"):
            CookieBomb(
                target="http://unauthorized.com", output_dir=temp_dir, auth_file=auth_file
            )

    def test_init_with_verbose(self, temp_dir, auth_file):
        """Test initialization with verbose mode."""
        cookiebomb = CookieBomb(
            target="http://localhost", output_dir=temp_dir, auth_file=auth_file, verbose=True
        )

        # Logger level should be set to DEBUG in verbose mode
        import logging

        assert logging.getLogger("cookie-confusion-toolkit").level == logging.DEBUG


class TestKeyCollisions:
    """Test key collision testing functionality."""

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_key_collisions_basic(self, mock_request, temp_dir, auth_file):
        """Test basic key collision testing."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {"session": "test_value"}
        mock_response.headers = {"Content-Type": "text/html"}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        cookie_names = ["session", "Session", "SESSION"]
        results = cookiebomb.test_key_collisions(cookie_names)

        assert results["description"] == "Testing cookie key collisions"
        assert results["cookie_names"] == cookie_names
        assert len(results["results"]) == 3  # One for each variation

        # Verify that requests were made
        assert mock_request.call_count == 3

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_key_collisions_with_custom_variations(self, mock_request, temp_dir, auth_file):
        """Test key collision with custom variations."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        variations = [
            {"name": "test", "value": "value1"},
            {"name": "Test", "value": "value2"},
        ]

        results = cookiebomb.test_key_collisions(["test"], variations)

        assert len(results["results"]) == 2
        assert results["variations"] == variations

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_key_collisions_failed_request(self, mock_request, temp_dir, auth_file):
        """Test key collision when request fails."""
        mock_request.return_value = None

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        results = cookiebomb.test_key_collisions(["session"])

        # Should handle failed requests gracefully
        assert len(results["results"]) == 0


class TestOverlongValues:
    """Test overlong value testing functionality."""

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_overlong_values_basic(self, mock_request, temp_dir, auth_file):
        """Test basic overlong value testing."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {"session": "truncated"}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        results = cookiebomb.test_overlong_values("session", [100, 200])

        assert results["description"] == "Testing cookies with overlong values"
        assert results["cookie_name"] == "session"
        assert results["lengths"] == [100, 200]
        assert len(results["results"]) == 2

        # Check that truncation was detected
        for result in results["results"]:
            if result["length"] > len("truncated"):
                assert result["truncated"] is True
                assert result["truncated_length"] == len("truncated")

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_overlong_values_no_truncation(self, mock_request, temp_dir, auth_file):
        """Test when no truncation occurs."""

        def mock_request_side_effect(url, headers=None):
            mock_response = MagicMock()
            mock_response.status_code = 200
            # Extract the cookie value from headers
            cookie_value = (
                headers["Cookie"].split("=")[1]
                if headers and "Cookie" in headers
                else ""
            )
            mock_response.cookies.get_dict.return_value = {"session": cookie_value}
            mock_response.headers = {}
            return mock_response

        mock_request.side_effect = mock_request_side_effect

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        results = cookiebomb.test_overlong_values("session", [50])

        # Check that no truncation was detected
        assert results["results"][0]["truncated"] is False


class TestPathScoping:
    """Test path scoping functionality."""

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_path_scoping_basic(self, mock_request, temp_dir, auth_file):
        """Test basic path scoping."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        paths = ["/", "/admin", "/api"]
        results = cookiebomb.test_path_scoping("session", paths)

        assert results["description"] == "Testing cookie path scoping"
        assert results["paths"] == paths
        assert "path_results" in results

        # Check that requests were made for each path and additional test paths
        assert len(results["path_results"]) >= len(paths)

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_path_scoping_with_encoded_paths(self, mock_request, temp_dir, auth_file):
        """Test path scoping with encoded paths."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {"session": "value"}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        paths = ["/admin", "/%61dmin"]  # Second is URL-encoded
        results = cookiebomb.test_path_scoping("session", paths)

        # Should test accessing various paths
        path_results = results["path_results"]
        assert "/admin" in path_results
        assert "/%61dmin" in path_results


class TestWhitespaceAmbiguity:
    """Test whitespace ambiguity testing."""

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_whitespace_ambiguity_basic(self, mock_request, temp_dir, auth_file):
        """Test basic whitespace ambiguity testing."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        separators = [";", " ;", "; ", " ; "]
        results = cookiebomb.test_whitespace_ambiguity("session", separators)

        assert results["description"] == "Testing whitespace handling in cookies"
        assert results["separators"] == separators
        assert len(results["results"]) == len(separators)

        # Check that each separator was tested
        for i, result in enumerate(results["results"]):
            assert result["separator"] == separators[i]
            assert result["separator_repr"] == repr(separators[i])


class TestRunAllTests:
    """Test running all tests."""

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    @patch("src.cookie_confusion_toolkit.cookiebomb.save_results")
    def test_run_all_tests(self, mock_save, mock_request, temp_dir, auth_file):
        """Test running all tests."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        results = cookiebomb.run_all_tests(cookie_names=["session"])

        # Check that all test types were run
        assert "initial_recon" in results
        assert "key_collisions" in results["tests"]
        assert "overlong_values" in results["tests"]
        assert "path_scoping" in results["tests"]
        assert "whitespace_ambiguity" in results["tests"]

        # Check that results were saved
        mock_save.assert_called_once()
        save_call_args = mock_save.call_args[0]
        assert save_call_args[0] == results  # Results were saved
        assert temp_dir in save_call_args[1]  # Saved to correct directory

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_run_all_tests_exception(self, mock_request, temp_dir, auth_file):
        """Test handling of exceptions during run_all_tests."""
        mock_request.side_effect = Exception("Network error")

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        results = cookiebomb.run_all_tests()

        assert "error" in results
        assert "Network error" in results["error"]


class TestCustomTest:
    """Test custom test generation."""

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_custom_malformed_cookie(self, mock_request, temp_dir, auth_file):
        """Test custom malformed cookie test."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        params = {
            "name": "session",
            "value": "test",
            "malformation_type": "trailing_separators",
            "count": 3,
        }

        results = cookiebomb.generate_custom_test("malformed_cookie", params)

        assert results["description"] == "Custom test: malformed_cookie"
        assert results["params"] == params
        assert "session=test;;;" in results["results"]["sent_cookie"]

    @patch("src.cookie_confusion_toolkit.cookiebomb.safe_request")
    def test_custom_multiple_cookies(self, mock_request, temp_dir, auth_file):
        """Test custom multiple cookies test."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.cookies.get_dict.return_value = {}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        cookiebomb = CookieBomb("http://localhost", temp_dir, auth_file)

        params = {"cookies": ["session=value1", "Session=value2", "SESSION=value3"]}

        results = cookiebomb.generate_custom_test("multiple_cookies", params)

        assert results["results"]["sent_cookies"] == params["cookies"]
        assert (
            "session=value1; Session=value2; SESSION=value3"
            == results["results"]["cookie_header"]
        )
