"""
Unit tests for common utilities.
"""
import pytest
import json
import os
from unittest.mock import patch, mock_open, MagicMock

from src.utils.common import (
    is_valid_target,
    generate_random_string,
    safe_request,
    parse_cookie_string,
    get_set_cookie_headers,
    calculate_checksum,
    save_results,
    load_results,
    ethical_check,
    validate_authorization,
    rate_limit
)


class TestTargetValidation:
    """Test URL validation functions."""
    
    def test_valid_http_urls(self):
        """Test that HTTP URLs are validated correctly."""
        assert is_valid_target("http://example.com")
        assert is_valid_target("https://example.com")
        assert is_valid_target("http://localhost")
        assert is_valid_target("https://127.0.0.1")
    
    def test_invalid_urls(self):
        """Test that invalid URLs are rejected."""
        assert not is_valid_target("ftp://example.com")
        assert not is_valid_target("example.com")
        assert not is_valid_target("")
        assert not is_valid_target("not-a-url")
    
    def test_development_domains(self):
        """Test that development domains are allowed."""
        assert is_valid_target("http://localhost")
        assert is_valid_target("http://127.0.0.1")
        assert is_valid_target("http://example.test")
        assert is_valid_target("http://internal.local")
    
    def test_restricted_domains(self):
        """Test that restricted domains are blocked."""
        assert not is_valid_target("http://example.gov")
        assert not is_valid_target("https://military.mil")
        assert not is_valid_target("http://bank.example.bank")


class TestStringFunctions:
    """Test string manipulation functions."""
    
    def test_generate_random_string(self):
        """Test random string generation."""
        # Test default length
        random_str = generate_random_string()
        assert len(random_str) == 10
        assert random_str.isalnum()
        
        # Test custom length
        random_str = generate_random_string(20)
        assert len(random_str) == 20
        assert random_str.isalnum()
        
        # Test uniqueness
        str1 = generate_random_string()
        str2 = generate_random_string()
        assert str1 != str2
    
    def test_parse_cookie_string(self):
        """Test cookie string parsing."""
        # Test simple cookie
        result = parse_cookie_string("session=value")
        assert len(result) == 1
        assert result[0]["name"] == "session"
        assert result[0]["value"] == "value"
        
        # Test multiple cookies
        result = parse_cookie_string("session=value; csrf=token; user=test")
        assert len(result) == 3
        assert result[0]["name"] == "session"
        assert result[1]["name"] == "csrf"
        assert result[2]["name"] == "user"
        
        # Test flag attributes
        result = parse_cookie_string("session=value; HttpOnly; Secure")
        assert any(item["name"] == "HttpOnly" for item in result)
        assert any(item["name"] == "Secure" for item in result)
        
        # Test empty string
        result = parse_cookie_string("")
        assert len(result) == 0
    
    def test_calculate_checksum(self):
        """Test checksum calculation."""
        data1 = "test data"
        data2 = "test data"
        data3 = "different data"
        
        checksum1 = calculate_checksum(data1)
        checksum2 = calculate_checksum(data2)
        checksum3 = calculate_checksum(data3)
        
        assert checksum1 == checksum2  # Same data should produce same checksum
        assert checksum1 != checksum3  # Different data should produce different checksum
        assert len(checksum1) == 64     # SHA256 produces 64 char hex string


class TestHTTPFunctions:
    """Test HTTP-related functions."""
    
    @patch('src.utils.common.requests.request')
    def test_safe_request_success(self, mock_request):
        """Test successful HTTP request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "test response"
        mock_request.return_value = mock_response
        
        response = safe_request("http://localhost/test")
        
        assert response == mock_response
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[1]["url"] == "http://localhost/test"
        assert call_args[1]["method"] == "GET"
    
    @patch('src.utils.common.requests.request')
    def test_safe_request_failure(self, mock_request):
        """Test failed HTTP request."""
        mock_request.side_effect = Exception("Connection error")
        
        response = safe_request("http://localhost/test")
        assert response is None
    
    @patch('src.utils.common.requests.request')
    def test_safe_request_with_options(self, mock_request):
        """Test HTTP request with various options."""
        mock_response = MagicMock()
        mock_request.return_value = mock_response
        
        response = safe_request(
            "http://localhost/test",
            method="POST",
            headers={"Custom": "Header"},
            cookies={"session": "value"},
            data="test data",
            timeout=5,
            browser="firefox"
        )
        
        call_args = mock_request.call_args
        assert call_args[1]["method"] == "POST"
        assert call_args[1]["headers"]["Custom"] == "Header"
        assert "firefox" in call_args[1]["headers"]["User-Agent"].lower()
        assert call_args[1]["cookies"] == {"session": "value"}
        assert call_args[1]["data"] == "test data"
        assert call_args[1]["timeout"] == 5
    
    def test_get_set_cookie_headers(self):
        """Test Set-Cookie header extraction."""
        mock_response = MagicMock()
        mock_response.headers = {
            "Set-Cookie": "session=value; Path=/",
            "Content-Type": "text/html",
            "set-cookie": "another=value"  # Test case insensitivity
        }
        
        cookies = get_set_cookie_headers(mock_response)
        assert len(cookies) == 2
        assert "session=value; Path=/" in cookies
        assert "another=value" in cookies


class TestFileOperations:
    """Test file I/O functions."""
    
    def test_save_and_load_results(self, temp_dir):
        """Test saving and loading results."""
        test_results = {
            "target": "http://localhost",
            "test_data": {"key": "value"},
            "results": [1, 2, 3]
        }
        
        filename = os.path.join(temp_dir, "test_results.json")
        
        # Save results
        save_results(test_results, filename)
        assert os.path.exists(filename)
        
        # Load results
        loaded_results = load_results(filename)
        assert loaded_results == test_results
    
    def test_load_results_nonexistent_file(self):
        """Test loading results from non-existent file."""
        result = load_results("/non/existent/file.json")
        assert result is None
    
    @patch('builtins.open', mock_open(read_data='{"broken": json'))
    def test_load_results_invalid_json(self):
        """Test loading results with invalid JSON."""
        result = load_results("fake_file.json")
        assert result is None


class TestEthicalValidation:
    """Test ethical validation functions."""
    
    def test_ethical_check_allowed_domains(self):
        """Test ethical check for allowed domains."""
        assert ethical_check("http://localhost")
        assert ethical_check("http://example.test")
        assert ethical_check("http://internal.local")
        assert ethical_check("http://dev.company.com")
    
    def test_ethical_check_sensitive_domains(self):
        """Test ethical check for sensitive domains."""
        assert not ethical_check("http://example.gov")
        assert not ethical_check("https://pentagon.mil")
        assert not ethical_check("http://hospital.health")
        assert not ethical_check("https://education.edu")
    
    def test_validate_authorization_with_file(self, auth_file):
        """Test authorization validation with auth file."""
        assert validate_authorization("http://localhost", auth_file)
        assert validate_authorization("http://example.test", auth_file)
        assert not validate_authorization("http://unauthorized.com", auth_file)
    
    def test_validate_authorization_without_file(self):
        """Test authorization validation without auth file."""
        # Should fall back to ethical check
        assert validate_authorization("http://localhost", None)
        assert not validate_authorization("http://example.gov", None)
    
    def test_validate_authorization_invalid_file(self):
        """Test authorization validation with invalid auth file."""
        assert not validate_authorization("http://localhost", "/nonexistent/auth.json")


class TestRateLimit:
    """Test rate limiting function."""
    
    @patch('time.time')
    @patch('time.sleep')
    def test_rate_limit_sleeps_when_needed(self, mock_sleep, mock_time):
        """Test that rate limit sleeps when requests are too fast."""
        # First call - no rate limit
        mock_time.return_value = 0
        rate_limit.last_request_time = 0
        rate_limit(1.0)
        mock_sleep.assert_not_called()
        
        # Second call too soon - should sleep
        mock_time.return_value = 0.5
        rate_limit.last_request_time = 0
        rate_limit(1.0)
        mock_sleep.assert_called_once_with(0.5)
        
        # Third call after sufficient time - no sleep
        mock_sleep.reset_mock()
        mock_time.return_value = 2.0
        rate_limit.last_request_time = 0
        rate_limit(1.0)
        mock_sleep.assert_not_called()
