"""
Test configuration and fixtures for the Cookie Confusion Toolkit.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def auth_file(temp_dir):
    """Create a temporary auth file for testing."""
    auth_config = {
        "authorized_targets": ["localhost", "127.0.0.1", "example.test", "testserver.local"],
        "excluded_paths": ["/admin", "/internal"],
        "authorization_details": {
            "contact": "test@example.com",
            "document_reference": "Test authorization",
            "expiration": "2100-01-01",
        },
    }

    auth_path = os.path.join(temp_dir, "auth.json")
    with open(auth_path, "w") as f:
        json.dump(auth_config, f)

    return auth_path


@pytest.fixture
def mock_target():
    """Provide a safe mock target URL for testing."""
    return "http://localhost:8888"


@pytest.fixture
def sample_cookies():
    """Provide sample cookies for testing."""
    return {
        "session": "test_session_value",
        "csrf_token": "test_csrf_token",
        "user_prefs": "theme=dark;lang=en",
    }


@pytest.fixture
def results_dir(temp_dir):
    """Create a results directory for testing."""
    results_path = os.path.join(temp_dir, "results")
    os.makedirs(results_path)
    return results_path


@pytest.fixture(autouse=True)
def setup_logging():
    """Configure logging for tests."""
    import logging

    logging.basicConfig(level=logging.DEBUG)
    yield
    # Reset logging after tests
    logging.getLogger().handlers.clear()


@pytest.fixture
def test_server(unused_tcp_port):
    """Start a test server for integration tests."""
    # This would typically start a mock HTTP server
    # For now, we'll just provide the port
    return f"http://localhost:{unused_tcp_port}"
