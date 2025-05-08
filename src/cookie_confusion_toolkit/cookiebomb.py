"""
CookieBomb: Module for generating degenerate cookie jars to test parsing inconsistencies.

This module creates various malformed and edge-case cookies to identify vulnerabilities
in cookie parsing implementations.
"""
import json
import time
import random
import string
from typing import Dict, List, Optional, Union, Tuple, Any
from urllib.parse import urlparse

import requests

from .utils.common import (
    logger, safe_request, save_results, load_results, 
    ethical_check, validate_authorization, rate_limit
)
from .utils.cookie_utils import (
    Cookie, create_malformed_cookie, create_cookie_collision, 
    simulate_browser_cookie_jar
)

class CookieBomb:
    """
    Generate and test degenerate cookie scenarios to identify parsing inconsistencies.
    """
    
    def __init__(self, 
                 target: str, 
                 output_dir: str = "./results",
                 auth_file: Optional[str] = None,
                 rate_limit_delay: float = 1.0,
                 verbose: bool = False):
        """
        Initialize the CookieBomb module.
        
        Args:
            target: Target URL to test
            output_dir: Directory to save results
            auth_file: Path to authorization file
            rate_limit_delay: Delay between requests in seconds
            verbose: Enable verbose logging
        """
        self.target = target
        self.output_dir = output_dir
        self.auth_file = auth_file
        self.rate_limit_delay = rate_limit_delay
        self.verbose = verbose
        
        if verbose:
            logger.setLevel("DEBUG")
        
        parsed_url = urlparse(target)
        self.hostname = parsed_url.netloc
        self.base_domain = ".".join(self.hostname.split(".")[-2:])
        
        # Validation
        if not target.startswith(("http://", "https://")):
            raise ValueError("Target URL must start with http:// or https://")
        
        if not ethical_check(target):
            raise ValueError(f"Target {target} failed ethical check")
        
        if not validate_authorization(target, auth_file):
            raise ValueError(f"Not authorized to test {target}")
        
        self.results = {
            "target": target,
            "timestamp": time.time(),
            "tests": {}
        }
    
    def test_key_collisions(self, cookie_names: List[str], variations: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Test for key collision behaviors by creating cookies with name variations.
        
        Args:
            cookie_names: List of cookie names to test
            variations: List of variation dictionaries
            
        Returns:
            Dict[str, Any]: Test results
        """
        if variations is None:
            variations = [
                {"name": name, "value": f"value_{i}"} 
                for i, name in enumerate(cookie_names)
            ]
        
        results = {
            "description": "Testing cookie key collisions",
            "cookie_names": cookie_names,
            "variations": variations,
            "results": []
        }
        
        # Create and test each cookie variation
        for i, variant in enumerate(variations):
            cookie_str = create_cookie_collision(cookie_names[0] if cookie_names else "session", [variant])[0]
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response is None:
                logger.warning(f"Request failed for variant {i}")
                continue
            
            # Extract cookies from response
            cookies_set = response.cookies.get_dict()
            
            result = {
                "variant": variant,
                "sent_cookie": cookie_str,
                "status_code": response.status_code,
                "received_cookies": cookies_set,
                "headers": dict(response.headers)
            }
            
            results["results"].append(result)
            
            if self.verbose:
                logger.debug(f"Variant {i}: {cookie_str} -> {response.status_code}")
        
        self.results["tests"]["key_collisions"] = results
        return results
    
    def test_overlong_values(self, 
                            cookie_name: str = "session", 
                            lengths: List[int] = [100, 1000, 4000, 8000]) -> Dict[str, Any]:
        """
        Test handling of cookies with very long values.
        
        Args:
            cookie_name: Name of the cookie to test
            lengths: List of value lengths to test
            
        Returns:
            Dict[str, Any]: Test results
        """
        results = {
            "description": "Testing cookies with overlong values",
            "cookie_name": cookie_name,
            "lengths": lengths,
            "results": []
        }
        
        for length in lengths:
            value = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
            cookie_str = f"{cookie_name}={value}"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response is None:
                logger.warning(f"Request failed for length {length}")
                continue
            
            # Check for truncation in response
            cookies_set = response.cookies.get_dict()
            
            result = {
                "length": length,
                "sent_value_length": len(value),
                "status_code": response.status_code,
                "received_cookies": cookies_set,
                "headers": dict(response.headers)
            }
            
            # Check if we can detect truncation
            if cookie_name in cookies_set and len(cookies_set[cookie_name]) < length:
                result["truncated"] = True
                result["truncated_length"] = len(cookies_set[cookie_name])
            else:
                result["truncated"] = False
            
            results["results"].append(result)
            
            if self.verbose:
                logger.debug(f"Length {length}: {cookie_name}=[{length} chars] -> {response.status_code}")
        
        self.results["tests"]["overlong_values"] = results
        return results
    
    def test_path_scoping(self, 
                         cookie_name: str = "session", 
                         paths: List[str] = ["/", "/admin", "/api", "/%61dmin"]) -> Dict[str, Any]:
        """
        Test path scoping behavior with various path patterns.
        
        Args:
            cookie_name: Name of the cookie to test
            paths: List of paths to test
            
        Returns:
            Dict[str, Any]: Test results
        """
        results = {
            "description": "Testing cookie path scoping",
            "cookie_name": cookie_name,
            "paths": paths,
            "results": []
        }
        
        # First, set cookies with different paths
        for i, path in enumerate(paths):
            value = f"value_for_path_{i}"
            cookie = Cookie(
                name=cookie_name,
                value=value,
                path=path
            )
            
            # Set the cookie
            rate_limit(self.rate_limit_delay)
            set_response = safe_request(
                self.target,
                method="GET",
                headers={"Set-Cookie": cookie.to_set_cookie_header()}
            )
            
            if set_response is None:
                logger.warning(f"Failed to set cookie for path {path}")
                continue
        
        # Now test accessing different paths and see which cookies are sent
        path_results = {}
        for test_path in paths + ["/admin/users", "/api/v1", "/admin2"]:
            url = f"{self.target.rstrip('/')}{test_path}"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(url)
            
            if response is None:
                logger.warning(f"Request failed for path {test_path}")
                continue
            
            # Extract cookies from response
            cookies_set = response.cookies.get_dict()
            
            path_results[test_path] = {
                "status_code": response.status_code,
                "received_cookies": cookies_set,
                "headers": dict(response.headers)
            }
            
            if self.verbose:
                logger.debug(f"Path {test_path} -> {response.status_code}, cookies: {cookies_set}")
        
        results["path_results"] = path_results
        self.results["tests"]["path_scoping"] = results
        return results
    
    def test_whitespace_ambiguity(self, 
                                cookie_name: str = "session",
                                separators: List[str] = [";", " ;", "; ", " ; ", "  ;  "]) -> Dict[str, Any]:
        """
        Test handling of whitespace in cookie headers.
        
        Args:
            cookie_name: Name of the cookie to test
            separators: List of separators to test
            
        Returns:
            Dict[str, Any]: Test results
        """
        results = {
            "description": "Testing whitespace handling in cookies",
            "cookie_name": cookie_name,
            "separators": separators,
            "results": []
        }
        
        for sep in separators:
            # Create a cookie with the separator
            cookie_str = f"{cookie_name}=test_value{sep}Path=/"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response is None:
                logger.warning(f"Request failed for separator '{sep}'")
                continue
            
            # Extract cookies from response
            cookies_set = response.cookies.get_dict()
            
            result = {
                "separator": sep,
                "separator_repr": repr(sep),
                "sent_cookie": cookie_str,
                "status_code": response.status_code,
                "received_cookies": cookies_set,
                "headers": dict(response.headers)
            }
            
            results["results"].append(result)
            
            if self.verbose:
                logger.debug(f"Separator '{repr(sep)}': {cookie_str} -> {response.status_code}")
        
        self.results["tests"]["whitespace_ambiguity"] = results
        return results
    
    def run_all_tests(self, cookie_names: List[str] = ["session", "sessionid", "SESSIONID"]) -> Dict[str, Any]:
        """
        Run all cookie tests and save results.
        
        Args:
            cookie_names: List of cookie names to test
            
        Returns:
            Dict[str, Any]: Complete test results
        """
        logger.info(f"Starting comprehensive cookie tests against {self.target}")
        
        try:
            # Initial recon
            response = safe_request(self.target)
            if response is None:
                logger.error("Initial recon request failed")
                return {}
            
            self.results["initial_recon"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies)
            }
            
            # Run all tests
            logger.info("Testing key collisions...")
            self.test_key_collisions(cookie_names)
            
            logger.info("Testing overlong values...")
            self.test_overlong_values()
            
            logger.info("Testing path scoping...")
            self.test_path_scoping()
            
            logger.info("Testing whitespace ambiguity...")
            self.test_whitespace_ambiguity()
            
            # Save results
            filename = f"{self.output_dir}/cookiebomb_{self.hostname}_{int(time.time())}.json"
            save_results(self.results, filename)
            
            logger.info(f"All tests completed. Results saved to {filename}")
            return self.results
            
        except Exception as e:
            logger.error(f"Error running tests: {str(e)}")
            return {"error": str(e)}

    def generate_custom_test(self, 
                            test_type: str, 
                            params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a custom test based on specified parameters.
        
        Args:
            test_type: Type of test to run
            params: Test parameters
            
        Returns:
            Dict[str, Any]: Test results
        """
        results = {
            "description": f"Custom test: {test_type}",
            "params": params,
            "results": []
        }
        
        if test_type == "malformed_cookie":
            cookie_name = params.get("name", "session")
            value = params.get("value", "test_value")
            malformation_type = params.get("malformation_type", "trailing_separators")
            
            cookie_str = create_malformed_cookie(
                cookie_name, value, malformation_type, **params
            )
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response is None:
                logger.warning(f"Request failed for malformed cookie")
                return {"error": "Request failed"}
            
            # Extract cookies from response
            cookies_set = response.cookies.get_dict()
            
            results["results"] = {
                "sent_cookie": cookie_str,
                "status_code": response.status_code,
                "received_cookies": cookies_set,
                "headers": dict(response.headers)
            }
        
        elif test_type == "multiple_cookies":
            cookies = params.get("cookies", [])
            cookie_header = "; ".join(cookies)
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_header}
            )
            
            if response is None:
                logger.warning(f"Request failed for multiple cookies")
                return {"error": "Request failed"}
            
            # Extract cookies from response
            cookies_set = response.cookies.get_dict()
            
            results["results"] = {
                "sent_cookies": cookies,
                "cookie_header": cookie_header,
                "status_code": response.status_code,
                "received_cookies": cookies_set,
                "headers": dict(response.headers)
            }
        
        self.results["tests"][f"custom_{test_type}"] = results
        return results
