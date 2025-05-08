"""
Integration tests for the full assessment module.
"""
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from examples.scripts.full_assessment import run_full_assessment


class TestFullAssessmentIntegration:
    """Integration tests for the full assessment script."""

    @patch("src.cookie_confusion_toolkit.cookiebomb.CookieBomb")
    @patch("src.cookie_confusion_toolkit.clientfork.ClientFork")
    @patch("src.cookie_confusion_toolkit.serverdrift.ServerDrift")
    @patch("src.cookie_confusion_toolkit.bypassgen.BypassGen")
    def test_full_assessment_basic(
        self,
        mock_bypassgen,
        mock_serverdrift,
        mock_clientfork,
        mock_cookiebomb,
        temp_dir,
        auth_file,
    ):
        """Test basic full assessment execution."""

        # Setup mocks
        mock_cookiebomb_instance = MagicMock()
        mock_cookiebomb_instance.run_all_tests.return_value = {
            "target": "http://localhost",
            "tests": {"cookie_jar": {"status": "completed"}},
        }
        mock_cookiebomb.return_value = mock_cookiebomb_instance

        mock_clientfork_instance = MagicMock()
        mock_clientfork_instance.run_all_tests.return_value = {
            "target": "http://localhost",
            "tests": {"chrome": {"status": "completed"}},
        }
        mock_clientfork.return_value = mock_clientfork_instance

        mock_serverdrift_instance = MagicMock()
        mock_serverdrift_instance.run_all_tests.return_value = {
            "target": "http://localhost",
            "tests": {"header_parsing": {"status": "completed"}},
        }
        mock_serverdrift.return_value = mock_serverdrift_instance

        mock_bypassgen_instance = MagicMock()
        mock_bypassgen_instance.run_all_tests.return_value = {
            "target": "http://localhost",
            "tests": {"bypass": {"status": "completed"}},
        }
        mock_bypassgen.return_value = mock_bypassgen_instance

        # Run assessment
        results = run_full_assessment(
            target="http://localhost",
            output_dir=temp_dir,
            auth_file=auth_file,
            verbose=True,
        )

        # Verify results
        assert results["target"] == "http://localhost"
        assert "summary" in results
        assert "cookie_jar_results" in results
        assert "client_fork_results" in results
        assert "server_drift_results" in results
        assert "bypass_gen_results" in results

        # Verify all components were initialized and run
        mock_cookiebomb.assert_called_once()
        mock_clientfork.assert_called_once()
        mock_serverdrift.assert_called_once()
        mock_bypassgen.assert_called_once()

        mock_cookiebomb_instance.run_all_tests.assert_called_once()
        mock_clientfork_instance.run_all_tests.assert_called_once()
        mock_serverdrift_instance.run_all_tests.assert_called_once()
        mock_bypassgen_instance.run_all_tests.assert_called_once()

    @patch("src.cookie_confusion_toolkit.cookiebomb.CookieBomb")
    @patch("json.dump")
    def test_full_assessment_saves_results(
        self, mock_json_dump, mock_cookiebomb, temp_dir, auth_file
    ):
        """Test that full assessment saves results to file."""

        # Setup mock
        mock_cookiebomb_instance = MagicMock()
        mock_cookiebomb_instance.run_all_tests.return_value = {"test": "data"}
        mock_cookiebomb.return_value = mock_cookiebomb_instance

        # Mock other components to return None (minimal test)
        with patch("src.cookie_confusion_toolkit.clientfork.ClientFork", return_value=None):
            with patch(
                "src.cookie_confusion_toolkit.serverdrift.ServerDrift", return_value=None
            ):
                with patch(
                    "src.cookie_confusion_toolkit.bypassgen.BypassGen", return_value=None
                ):

                    # Run assessment
                    results = run_full_assessment(
                        target="http://localhost",
                        output_dir=temp_dir,
                        auth_file=auth_file,
                    )

                    # Verify results were saved
                    mock_json_dump.assert_called()
                    save_call = mock_json_dump.call_args
                    assert save_call[0][0] == results  # First arg should be results
                    assert temp_dir in save_call[0][1].name  # Should save to temp_dir

    @patch("src.cookie_confusion_toolkit.cookiebomb.CookieBomb")
    def test_full_assessment_error_handling(self, mock_cookiebomb, temp_dir, auth_file):
        """Test error handling in full assessment."""

        # Setup mock to raise exception
        mock_cookiebomb.side_effect = Exception("Test error")

        # Run assessment and expect it to handle error gracefully
        results = run_full_assessment(
            target="http://localhost", output_dir=temp_dir, auth_file=auth_file
        )

        # Should return error results
        assert "error" in results
        assert "Test error" in results["error"]

    @patch("src.cookie_confusion_toolkit.cookiebomb.CookieBomb")
    @patch("src.cookie_confusion_toolkit.clientfork.ClientFork")
    def test_full_assessment_with_options(
        self, mock_clientfork, mock_cookiebomb, temp_dir, auth_file
    ):
        """Test full assessment with custom options."""

        # Setup mocks
        mock_cookiebomb_instance = MagicMock()
        mock_cookiebomb.return_value = mock_cookiebomb_instance

        mock_clientfork_instance = MagicMock()
        mock_clientfork.return_value = mock_clientfork_instance

        # Run with custom options
        results = run_full_assessment(
            target="http://localhost",
            output_dir=temp_dir,
            auth_file=auth_file,
            browsers=["chrome", "firefox"],
            verbose=True,
            no_screenshots=True,
        )

        # Verify correct parameters were passed
        cookiebomb_call = mock_cookiebomb.call_args
        assert cookiebomb_call[1]["verbose"] is True

        clientfork_call = mock_clientfork.call_args
        assert "browsers" in clientfork_call[1]


class TestCLIIntegration:
    """Integration tests for CLI functionality."""

    @patch("argparse.ArgumentParser.parse_args")
    @patch("examples.scripts.full_assessment.run_full_assessment")
    def test_cli_full_command(self, mock_run_assessment, mock_parse_args):
        """Test CLI full command execution."""

        # Setup mock arguments
        mock_args = MagicMock()
        mock_args.command = "full"
        mock_args.target = "http://localhost"
        mock_args.output_dir = "/tmp/results"
        mock_args.auth_file = "auth.json"
        mock_args.verbose = True
        mock_args.browsers = ["chrome"]
        mock_args.no_screenshots = False
        mock_parse_args.return_value = mock_args

        # Import and run main
        from examples.scripts.full_assessment import main

        # Capture the function call
        with patch("sys.argv", ["cct", "full", "http://localhost"]):
            main()

        # Verify assessment was run with correct parameters
        mock_run_assessment.assert_called_once_with(
            target="http://localhost",
            output_dir="/tmp/results",
            auth_file="auth.json",
            browsers=["chrome"],
            verbose=True,
            no_screenshots=False,
        )

    @patch("argparse.ArgumentParser.parse_args")
    @patch("src.cookie_confusion_toolkit.cookiebomb.CookieBomb")
    def test_cli_cookiebomb_command(self, mock_cookiebomb, mock_parse_args):
        """Test CLI cookiebomb command execution."""

        # Setup mock arguments
        mock_args = MagicMock()
        mock_args.command = "cookiebomb"
        mock_args.target = "http://localhost"
        mock_args.output_dir = "/tmp/results"
        mock_args.auth_file = "auth.json"
        mock_args.verbose = False
        mock_args.cookie_names = ["session", "csrf"]
        mock_parse_args.return_value = mock_args

        # Setup mock CookieBomb
        mock_instance = MagicMock()
        mock_cookiebomb.return_value = mock_instance

        # Import and run main
        from src.cookie_confusion_toolkit.cli import main

        # Run CLI
        with patch("sys.argv", ["cct", "cookiebomb", "http://localhost"]):
            main()

        # Verify CookieBomb was initialized and run
        mock_cookiebomb.assert_called_once()
        init_call = mock_cookiebomb.call_args
        assert init_call[0][0] == "http://localhost"
        assert "auth_file" in init_call[1]

        mock_instance.run_all_tests.assert_called_once()


class TestEndToEndScenarios:
    """End-to-end integration test scenarios."""

    @pytest.mark.slow
    @patch("src.cookie_confusion_toolkit.utils.common.requests.request")
    def test_e2e_assessment_localhost(self, mock_request, temp_dir):
        """End-to-end test against localhost."""

        # Create auth file for localhost
        auth_config = {
            "authorized_targets": ["localhost", "127.0.0.1"],
            "excluded_paths": [],
            "authorization_details": {
                "contact": "test@example.com",
                "document_reference": "Test authorization",
                "expiration": "2100-01-01",
            },
        }

        auth_file = os.path.join(temp_dir, "auth.json")
        with open(auth_file, "w", encoding="utf-8") as f:
            json.dump(auth_config, f)

        # Mock HTTP responses
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Set-Cookie": "session=test123; Path=/",
            "Content-Type": "text/html",
        }
        mock_response.cookies.get_dict.return_value = {"session": "test123"}
        mock_response.text = "<html>Test</html>"
        mock_request.return_value = mock_response

        # Run assessment
        from examples.scripts.full_assessment import run_full_assessment

        results = run_full_assessment(
            target="http://localhost",
            output_dir=temp_dir,
            auth_file=auth_file,
            verbose=True,
        )

        # Verify results structure
        assert "target" in results
        assert "summary" in results
        assert results["target"] == "http://localhost"

        # Verify results were saved
        result_files = [f for f in os.listdir(temp_dir) if f.endswith(".json")]
        assert len(result_files) > 0

    @pytest.mark.slow
    def test_e2e_docker_container(self, temp_dir):
        """Test running the tool in Docker container."""
        import subprocess

        # Create auth file
        auth_config = {
            "authorized_targets": ["example.test"],
            "excluded_paths": [],
            "authorization_details": {
                "contact": "test@example.com",
                "document_reference": "Docker test",
                "expiration": "2100-01-01",
            },
        }

        auth_file = os.path.join(temp_dir, "auth.json")
        with open(auth_file, "w", encoding="utf-8") as f:
            json.dump(auth_config, f)

        # Skip if docker is not available
        try:
            subprocess.run(["docker", "--version"], check=True, capture_output=True)
        except Exception:
            pytest.skip("Docker not available")

        # Build and run Docker container
        dockerfile_path = os.path.join(os.path.dirname(__file__), "..", "..", "Dockerfile")

        if not os.path.exists(dockerfile_path):
            pytest.skip("Dockerfile not found")

        # This is a placeholder for actual Docker test
        # In a real implementation, you would:
        # 1. Build the Docker image
        # 2. Run the container with test parameters
        # 3. Verify the results
        assert True  # Placeholder


class TestReportGeneration:
    """Test report generation functionality."""

    def test_generate_html_report(self, temp_dir):
        """Test HTML report generation."""
        # Create sample results
        results = {
            "target": "http://localhost",
            "timestamp": 1234567890,
            "summary": {
                "total_tests": 10,
                "passed": 8,
                "failed": 2,
                "issues_found": 3,
            },
            "tests": {
                "key_collisions": {"status": "completed", "issues": []},
                "path_scoping": {
                    "status": "completed",
                    "issues": [
                        {"severity": "medium", "description": "Path traversal vulnerability"}
                    ],
                },
            },
        }

        # Save results to file
        results_file = os.path.join(temp_dir, "results.json")
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(results, f)

        # Import and test report generation
        from src.cookie_confusion_toolkit.utils.common import generate_html_report

        html_file = os.path.join(temp_dir, "report.html")
        generate_html_report(results_file, html_file)

        # Verify HTML was generated
        assert os.path.exists(html_file)

        # Basic content verification
        with open(html_file, "r", encoding="utf-8") as f:
            html_content = f.read()
            assert "Cookie Confusion Assessment Report" in html_content
            assert "http://localhost" in html_content
            assert "Path traversal vulnerability" in html_content

    def test_generate_markdown_report(self, temp_dir):
        """Test Markdown report generation."""
        # Similar to HTML test but with Markdown output
        results = {
            "target": "https://example.com",
            "summary": {"total_tests": 5, "passed": 5, "failed": 0},
            "tests": {},
        }

        from src.cookie_confusion_toolkit.utils.common import generate_markdown_report

        md_file = os.path.join(temp_dir, "report.md")
        generate_markdown_report(results, md_file)

        assert os.path.exists(md_file)

        with open(md_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "# Cookie Confusion Assessment Report" in content
            assert "https://example.com" in content
            assert "## Summary" in content
