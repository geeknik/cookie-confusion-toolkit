"""
ServerDrift: Test server-side cookie parsing inconsistencies across frameworks.

This module tests for server-side parsing bugs across popular web frameworks, focusing on
behaviors like key overwrite order, attribute truncation, and SameSite/Domain handling.
"""
import json
import time
import random
import string
from typing import Dict, List, Optional, Union, Tuple, Any
from urllib.parse import urlparse, urljoin

import requests

from .utils.common import (
    logger, safe_request, save_results, load_results, rate_limit,
    ethical_check, validate_authorization, get_set_cookie_headers
)
from .utils.cookie_utils import (
    Cookie, create_malformed_cookie, detect_cookie_parser
)

class ServerDrift:
    """
    Test server-side cookie parsing inconsistencies across different frameworks.
    """
    
    # Supported server frameworks for fingerprinting
    FRAMEWORKS = [
        "express", "flask", "django", "spring", "aspnet", "rails", 
        "php", "golang", "nodejs", "apache", "nginx", "iis"
    ]
    
    def __init__(self, 
                target: str, 
                output_dir: str = "./results",
                auth_file: Optional[str] = None,
                rate_limit_delay: float = 1.0,
                verbose: bool = False):
        """
        Initialize the ServerDrift module.
        
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
        
        # Detect server framework
        self.server_info = self._detect_server_framework()
        logger.info(f"Detected server: {self.server_info}")
    
    def _detect_server_framework(self) -> Dict[str, Any]:
        """
        Detect server framework based on response headers and behavior.
        
        Returns:
            Dict[str, Any]: Server framework information
        """
        logger.info("Detecting server framework...")
        
        # Initial request to get headers
        response = safe_request(self.target)
        
        if not response:
            logger.warning("Failed to connect to target for framework detection")
            return {"framework": "unknown", "confidence": 0, "server": "unknown"}
        
        headers = response.headers
        server_type = headers.get("Server", "")
        x_powered_by = headers.get("X-Powered-By", "")
        
        # Start building detection results
        result = {
            "headers": {k: v for k, v in headers.items()},
            "cookies": dict(response.cookies),
            "server_header": server_type,
            "x_powered_by": x_powered_by,
            "detected_frameworks": []
        }
        
        # Check for explicit framework indicators
        framework_indicators = {
            "express": ["express", "nodejs"],
            "flask": ["flask", "werkzeug", "python"],
            "django": ["django", "python"],
            "spring": ["spring", "java"],
            "aspnet": ["asp.net", "iis", "microsoft"],
            "rails": ["rails", "ruby", "phusion"],
            "php": ["php", "laravel", "symfony", "wordpress"],
            "golang": ["go ", "golang"],
            "nodejs": ["node", "express", "nextjs"],
            "apache": ["apache"],
            "nginx": ["nginx"],
            "iis": ["iis", "microsoft-iis"]
        }
        
        # Check server header
        detected_frameworks = []
        confidence_scores = {}
        
        # Check headers for framework clues
        all_headers = " ".join([str(v).lower() for k, v in headers.items()]).lower()
        
        for framework, indicators in framework_indicators.items():
            score = 0
            for indicator in indicators:
                if indicator.lower() in server_type.lower():
                    score += 2
                if indicator.lower() in x_powered_by.lower():
                    score += 3
                if indicator.lower() in all_headers:
                    score += 1
            
            if score > 0:
                confidence_scores[framework] = score
                detected_frameworks.append(framework)
        
        # Check cookies for framework-specific names
        cookie_indicators = {
            "php": ["phpsessid"],
            "aspnet": ["asp.net_sessionid", "aspsession"],
            "django": ["sessionid", "csrftoken"],
            "rails": ["_rails_session", "_session_id"],
            "express": ["connect.sid"],
            "laravel": ["laravel_session"]
        }
        
        for cookie_name in response.cookies.keys():
            for framework, indicators in cookie_indicators.items():
                if any(indicator.lower() in cookie_name.lower() for indicator in indicators):
                    confidence_scores[framework] = confidence_scores.get(framework, 0) + 2
                    if framework not in detected_frameworks:
                        detected_frameworks.append(framework)
        
        # Final determination
        if confidence_scores:
            best_framework = max(confidence_scores.items(), key=lambda x: x[1])
            result["framework"] = best_framework[0]
            result["confidence"] = best_framework[1]
            result["score_details"] = confidence_scores
        else:
            result["framework"] = "unknown"
            result["confidence"] = 0
        
        result["detected_frameworks"] = detected_frameworks
        result["server"] = server_type
        
        return result
    
    def test_key_overwrite(self, 
                         cookie_name: str = "session", 
                         variations: List[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Test server behavior when receiving multiple cookies with the same name.
        
        Args:
            cookie_name: Cookie name to test
            variations: List of value variations to test
            
        Returns:
            Dict[str, Any]: Test results
        """
        if variations is None:
            variations = [
                {"value": "first_value"},
                {"value": "middle_value"},
                {"value": "last_value"}
            ]
        
        results = {
            "description": "Testing server key overwrite behavior",
            "cookie_name": cookie_name,
            "variations": variations,
            "results": []
        }
        
        # Test different cookie header formats
        test_formats = [
            # Multiple cookies in one header
            {"name": "single_header_multiple_cookies", 
             "header": lambda values: {"Cookie": "; ".join([f"{cookie_name}={v['value']}" for v in values])}},
            
            # Multiple separate cookie headers
            {"name": "multiple_cookie_headers", 
             "header": lambda values: {f"Cookie{i}": f"{cookie_name}={v['value']}" for i, v in enumerate(values)}},
            
            # Duplicate values with spaces 
            {"name": "space_variations", 
             "header": lambda values: {"Cookie": "; ".join([f"{cookie_name} = {v['value']}" for v in values])}},
             
            # Multiple cookies with different casing
            {"name": "case_variations", 
             "header": lambda values: {"Cookie": f"{cookie_name.lower()}={values[0]['value']}; {cookie_name.upper()}={values[1]['value']}; {cookie_name}={values[2]['value']}"}},
        ]
        
        for test_format in test_formats:
            format_name = test_format["name"]
            header_func = test_format["header"]
            
            headers = header_func(variations)
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers=headers
            )
            
            if response is None:
                logger.warning(f"Request failed for format {format_name}")
                continue
            
            # Get response data
            result = {
                "format": format_name,
                "sent_headers": headers,
                "status_code": response.status_code,
                "received_cookies": dict(response.cookies),
                "headers": dict(response.headers)
            }
            
            # Look for clues about which value was used
            # Some frameworks reflect the cookie value
            response_body = response.text
            values_found = {}
            
            for variation in variations:
                value = variation["value"]
                if value in response_body:
                    values_found[value] = True
            
            result["values_found_in_response"] = values_found
            results["results"].append(result)
            
            if self.verbose:
                logger.debug(f"Format {format_name}: {headers} -> {response.status_code}")
        
        self.results["tests"]["key_overwrite"] = results
        return results
    
    def test_attribute_truncation(self, 
                                cookie_name: str = "session",
                                attributes: List[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Test server handling of truncated or malformed cookie attributes.
        
        Args:
            cookie_name: Cookie name to test
            attributes: List of attributes to test
            
        Returns:
            Dict[str, Any]: Test results
        """
        if attributes is None:
            attributes = [
                {"name": "Path", "value": "/admin", "truncated": "Pa"},
                {"name": "Domain", "value": "example.com", "truncated": "Do"},
                {"name": "SameSite", "value": "Lax", "truncated": "Same"},
                {"name": "Max-Age", "value": "3600", "truncated": "Max"},
                {"name": "Secure", "value": "", "truncated": "Sec"}
            ]
        
        results = {
            "description": "Testing server attribute truncation handling",
            "cookie_name": cookie_name,
            "attributes": attributes,
            "results": []
        }
        
        for attr in attributes:
            attr_name = attr["name"]
            attr_value = attr["value"]
            truncated = attr["truncated"]
            
            # Create a cookie with the truncated attribute
            if attr_value:
                full_cookie = f"{cookie_name}=value; {attr_name}={attr_value}"
                truncated_cookie = f"{cookie_name}=value; {truncated}={attr_value}"
            else:
                # Handle flag attributes like Secure
                full_cookie = f"{cookie_name}=value; {attr_name}"
                truncated_cookie = f"{cookie_name}=value; {truncated}"
            
            # Test with full attribute
            rate_limit(self.rate_limit_delay)
            full_response = safe_request(
                self.target,
                headers={"Cookie": full_cookie}
            )
            
            # Test with truncated attribute
            rate_limit(self.rate_limit_delay)
            truncated_response = safe_request(
                self.target,
                headers={"Cookie": truncated_cookie}
            )
            
            if full_response is None or truncated_response is None:
                logger.warning(f"Request failed for attribute {attr_name}")
                continue
            
            # Compare responses
            result = {
                "attribute": attr_name,
                "value": attr_value,
                "truncated": truncated,
                "full_cookie": full_cookie,
                "truncated_cookie": truncated_cookie,
                "full_response": {
                    "status_code": full_response.status_code,
                    "cookies": dict(full_response.cookies),
                    "headers": dict(full_response.headers)
                },
                "truncated_response": {
                    "status_code": truncated_response.status_code,
                    "cookies": dict(truncated_response.cookies),
                    "headers": dict(truncated_response.headers)
                }
            }
            
            # Determine if truncation affected handling
            if full_response.status_code == truncated_response.status_code:
                result["status_match"] = True
            else:
                result["status_match"] = False
            
            # Check cookies
            if dict(full_response.cookies) == dict(truncated_response.cookies):
                result["cookies_match"] = True
            else:
                result["cookies_match"] = False
            
            results["results"].append(result)
            
            if self.verbose:
                logger.debug(f"Attribute {attr_name}: Full={full_response.status_code}, Truncated={truncated_response.status_code}")
        
        self.results["tests"]["attribute_truncation"] = results
        return results
    
    def test_samesite_domain_logic(self, 
                                 cookie_name: str = "session",
                                 domain_variations: List[str] = None,
                                 samesite_values: List[str] = None) -> Dict[str, Any]:
        """
        Test server handling of SameSite and Domain attributes.
        
        Args:
            cookie_name: Cookie name to test
            domain_variations: List of domain values to test
            samesite_values: List of SameSite values to test
            
        Returns:
            Dict[str, Any]: Test results
        """
        if domain_variations is None:
            # Parse the hostname to generate domain variations
            parsed = urlparse(self.target)
            hostname_parts = parsed.netloc.split(".")
            
            if len(hostname_parts) >= 3:
                # For subdomains like test.example.com
                main_domain = ".".join(hostname_parts[-2:])
                domain_variations = [
                    main_domain,
                    f".{main_domain}",
                    parsed.netloc,
                    f".{parsed.netloc}",
                    # Invalid but potential bypass domains
                    f"{hostname_parts[0]}{main_domain}",
                    f"{main_domain}.",
                    f".{hostname_parts[0]}.{main_domain}"
                ]
            else:
                # For domains like example.com
                domain_variations = [
                    parsed.netloc,
                    f".{parsed.netloc}",
                    f"{parsed.netloc}.",
                    f".{parsed.netloc}."
                ]
        
        if samesite_values is None:
            samesite_values = ["None", "Lax", "Strict", "none", "lax", "strict", "NONE", "LAX", "STRICT"]
        
        results = {
            "description": "Testing SameSite and Domain attribute handling",
            "cookie_name": cookie_name,
            "domain_variations": domain_variations,
            "samesite_values": samesite_values,
            "results": []
        }
        
        # Test Domain attribute handling
        domain_results = []
        for domain in domain_variations:
            cookie_value = f"domain_{domain.replace('.', '_')}"
            cookie_str = f"{cookie_name}={cookie_value}; Domain={domain}"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response is None:
                logger.warning(f"Request failed for domain {domain}")
                continue
            
            # Check if the cookie was accepted
            cookies_set = response.cookies.get_dict()
            set_cookie_headers = get_set_cookie_headers(response)
            
            result = {
                "domain": domain,
                "cookie_string": cookie_str,
                "status_code": response.status_code,
                "cookies_set": cookies_set,
                "set_cookie_headers": set_cookie_headers
            }
            
            # Check for acceptance indicator
            result["accepted"] = cookie_name in cookies_set or any(cookie_name in h for h in set_cookie_headers)
            
            domain_results.append(result)
            
            if self.verbose:
                logger.debug(f"Domain {domain}: {response.status_code}, Accepted: {result['accepted']}")
        
        results["domain_results"] = domain_results
        
        # Test SameSite attribute handling
        samesite_results = []
        for samesite in samesite_values:
            cookie_value = f"samesite_{samesite.lower()}"
            cookie_str = f"{cookie_name}={cookie_value}; SameSite={samesite}"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response is None:
                logger.warning(f"Request failed for SameSite {samesite}")
                continue
            
            # Check if the cookie was accepted
            cookies_set = response.cookies.get_dict()
            set_cookie_headers = get_set_cookie_headers(response)
            
            result = {
                "samesite": samesite,
                "cookie_string": cookie_str,
                "status_code": response.status_code,
                "cookies_set": cookies_set,
                "set_cookie_headers": set_cookie_headers
            }
            
            # Check for acceptance indicator
            result["accepted"] = cookie_name in cookies_set or any(cookie_name in h for h in set_cookie_headers)
            
            samesite_results.append(result)
            
            if self.verbose:
                logger.debug(f"SameSite {samesite}: {response.status_code}, Accepted: {result['accepted']}")
        
        results["samesite_results"] = samesite_results
        
        self.results["tests"]["samesite_domain_logic"] = results
        return results
    
    def run_all_tests(self, cookie_name: str = "session") -> Dict[str, Any]:
        """
        Run all server cookie tests and save results.
        
        Args:
            cookie_name: Cookie name to use for testing
            
        Returns:
            Dict[str, Any]: Complete test results
        """
        logger.info(f"Starting comprehensive server cookie tests against {self.target}")
        
        try:
            # Run key overwrite test
            logger.info("Testing key overwrite behavior...")
            self.test_key_overwrite(cookie_name)
            
            # Test attribute truncation
            logger.info("Testing attribute truncation handling...")
            self.test_attribute_truncation(cookie_name)
            
            # Test SameSite and Domain logic
            logger.info("Testing SameSite and Domain handling...")
            self.test_samesite_domain_logic(cookie_name)
            
            # Save results
            filename = f"{self.output_dir}/serverdrift_{self.hostname}_{int(time.time())}.json"
            save_results(self.results, filename)
            
            logger.info(f"All tests completed. Results saved to {filename}")
            return self.results
            
        except Exception as e:
            logger.error(f"Error running tests: {str(e)}")
            return {"error": str(e)}
    
    def test_malformed_cookies(self, 
                             malformations: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Test server handling of various malformed cookies.
        
        Args:
            malformations: List of malformation tests to run
            
        Returns:
            Dict[str, Any]: Test results
        """
        if malformations is None:
            malformations = [
                {"type": "duplicate_name", "name": "session", "value": "original", "new_value": "duplicate"},
                {"type": "trailing_separators", "name": "session", "value": "value", "count": 3},
                {"type": "space_in_name", "name": "session", "value": "value", "position": 3},
                {"type": "no_value_separator", "name": "session", "value": "value"},
                {"type": "attribute_without_semicolon", "name": "session", "value": "value", "attribute": "Path=/"},
                {"type": "path_encoding", "name": "session", "value": "value", "path": "/admin"},
                {"type": "truncated_attribute", "name": "session", "value": "value", "attribute": "SameSite=Lax", "position": 5},
                {"type": "quoted_value", "name": "session", "value": "value"},
                {"type": "null_byte", "name": "session", "value": "value", "position": 2},
                {"type": "case_variation", "name": "session", "value": "value", "uppercase": True}
            ]
        
        results = {
            "description": "Testing server handling of malformed cookies",
            "malformations": malformations,
            "results": []
        }
        
        for test in malformations:
            malformation_type = test["type"]
            name = test["name"]
            value = test["value"]
            
            # Create the malformed cookie
            cookie_str = create_malformed_cookie(name, value, malformation_type, **test)
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response is None:
                logger.warning(f"Request failed for malformation {malformation_type}")
                continue
            
            # Check the response
            result = {
                "malformation": malformation_type,
                "cookie_string": cookie_str,
                "status_code": response.status_code,
                "cookies_set": dict(response.cookies),
                "headers": dict(response.headers)
            }
            
            # Look for common error indicators in the response
            response_body = response.text.lower()
            error_indicators = [
                "error", "exception", "warning", "invalid", "malformed",
                "syntax", "parse", "cookie", "header", "format"
            ]
            
            errors_found = [indicator for indicator in error_indicators if indicator in response_body[:1000]]
            result["possible_errors"] = errors_found
            
            results["results"].append(result)
            
            if self.verbose:
                logger.debug(f"Malformation {malformation_type}: {cookie_str} -> {response.status_code}")
        
        self.results["tests"]["malformed_cookies"] = results
        return results
    
    def analyze_framework_specific(self) -> Dict[str, Any]:
        """
        Run framework-specific tests based on detected server.
        
        Returns:
            Dict[str, Any]: Framework-specific test results
        """
        framework = self.server_info.get("framework", "unknown").lower()
        
        results = {
            "description": f"Framework-specific tests for {framework}",
            "framework": framework,
            "results": {}
        }
        
        logger.info(f"Running framework-specific tests for {framework}...")
        
        # Express/Node.js specific tests
        if framework in ["express", "nodejs"]:
            # Test connect.sid parsing
            cookie_str = "connect.sid=s%3A1234567890.abcdefghijklmn"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": cookie_str}
            )
            
            if response:
                results["results"]["connect_sid"] = {
                    "cookie_string": cookie_str,
                    "status_code": response.status_code,
                    "cookies_set": dict(response.cookies),
                    "headers": dict(response.headers)
                }
            
            # Test JSON parsing in cookies
            json_cookie = 'json={"key":"value","admin":true}'
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": json_cookie}
            )
            
            if response:
                results["results"]["json_parsing"] = {
                    "cookie_string": json_cookie,
                    "status_code": response.status_code,
                    "cookies_set": dict(response.cookies),
                    "headers": dict(response.headers)
                }
        
        # Flask/Python specific tests
        elif framework in ["flask", "django", "python"]:
            # Test flask session cookie parsing
            flask_cookie = "session=eyJrZXkiOiJ2YWx1ZSJ9.abcdefg"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": flask_cookie}
            )
            
            if response:
                results["results"]["flask_session"] = {
                    "cookie_string": flask_cookie,
                    "status_code": response.status_code,
                    "cookies_set": dict(response.cookies),
                    "headers": dict(response.headers)
                }
            
            # Test Django CSRF token
            django_cookie = "csrftoken=1234567890abcdefghijklmnopqrstuvwxyz"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": django_cookie}
            )
            
            if response:
                results["results"]["django_csrf"] = {
                    "cookie_string": django_cookie,
                    "status_code": response.status_code,
                    "cookies_set": dict(response.cookies),
                    "headers": dict(response.headers)
                }
        
        # Java/Spring specific tests
        elif framework in ["spring", "java"]:
            # Test Spring session cookie parsing
            spring_cookie = "JSESSIONID=1234567890abcdefghijklmnopqrstuvwxyz"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": spring_cookie}
            )
            
            if response:
                results["results"]["jsessionid"] = {
                    "cookie_string": spring_cookie,
                    "status_code": response.status_code,
                    "cookies_set": dict(response.cookies),
                    "headers": dict(response.headers)
                }
            
            # Test Spring case sensitivity
            spring_cookies = [
                "JSESSIONID=uppercase",
                "jsessionid=lowercase"
            ]
            
            case_results = {}
            for cookie in spring_cookies:
                rate_limit(self.rate_limit_delay)
                response = safe_request(
                    self.target,
                    headers={"Cookie": cookie}
                )
                
                if response:
                    case_results[cookie] = {
                        "status_code": response.status_code,
                        "cookies_set": dict(response.cookies),
                        "headers": dict(response.headers)
                    }
            
            results["results"]["case_sensitivity"] = case_results
        
        # PHP specific tests
        elif framework in ["php"]:
            # Test PHP session cookie parsing
            php_cookie = "PHPSESSID=1234567890abcdefghijklmnopqrstuvwxyz"
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": php_cookie}
            )
            
            if response:
                results["results"]["phpsessid"] = {
                    "cookie_string": php_cookie,
                    "status_code": response.status_code,
                    "cookies_set": dict(response.cookies),
                    "headers": dict(response.headers)
                }
            
            # Test for PHP serialized data parsing
            php_serialized = 'serialized=a:1:{s:3:"key";s:5:"value";}'
            
            rate_limit(self.rate_limit_delay)
            response = safe_request(
                self.target,
                headers={"Cookie": php_serialized}
            )
            
            if response:
                results["results"]["php_serialized"] = {
                    "cookie_string": php_serialized,
                    "status_code": response.status_code,
                    "cookies_set": dict(response.cookies),
                    "headers": dict(response.headers)
                }
        
        self.results["tests"]["framework_specific"] = results
        return results
