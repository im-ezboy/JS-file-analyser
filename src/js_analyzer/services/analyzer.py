"""
Core JavaScript analyzer logic.
All processing happens server-side; the browser only receives results.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import requests
import urllib3
from urllib.parse import urlparse, urljoin

from ..models import AnalysisResult, Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB safeguard
REQUEST_TIMEOUT = 60


@dataclass(frozen=True)
class PatternDef:
    regex: str
    label: str
    severity: Optional[str] = None
    strict: bool = False


class JavaScriptAnalyzer:
    """Analyzer focused on reducing false positives while keeping coverage wide."""

    def __init__(self) -> None:
        self.api_key_patterns: List[PatternDef] = [
            PatternDef(r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "high", True),
            PatternDef(r"(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*[\"']([a-zA-Z0-9/+=]{40})[\"']",
                       "AWS Secret Key", "high", True),
            PatternDef(r"AIza[0-9A-Za-z\-]{35}", "Google API Key", "high", True),
            PatternDef(r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", "high", True),
            PatternDef(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "GitHub Fine-grained Token", "high", True),
            PatternDef(r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Live Secret Key", "high", True),
            PatternDef(r"sk_test_[a-zA-Z0-9]{24,}", "Stripe Test Secret Key", "medium", True),
            PatternDef(r"pk_live_[a-zA-Z0-9]{24,}", "Stripe Live Publishable Key", "medium", True),
            PatternDef(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}", "Slack Token", "medium", True),
            PatternDef(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "Firebase Cloud Messaging Token", "medium", True),
            PatternDef(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]{10,}\b", "JWT Token", "medium"),
            PatternDef(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{32,})[\"']",
                       "Generic API Key", "medium"),
            PatternDef(r"(?i)(secret[_-]?key|secret)\s*[:=]\s*[\"']([a-zA-Z0-9_\-/+=]{32,})[\"']",
                       "Secret Key", "medium"),
        ]

        self.credential_patterns: List[PatternDef] = [
            PatternDef(r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']([^\"']{6,})[\"']", "Password", "high"),
            PatternDef(r"(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*[\"']([^\"']{6,})[\"']",
                       "Database Password", "high"),
            PatternDef(r"(?i)(username|user[_-]?name|login)\s*[:=]\s*[\"']([^\"']{3,})[\"']",
                       "Username", "medium"),
        ]

        self.email_patterns: List[PatternDef] = [
            PatternDef(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "Email Address", "low", True),
        ]

        self.comment_patterns: List[PatternDef] = [
            PatternDef(r"//\s*(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING|TEMP)", "Interesting Comment"),
            PatternDef(r"/\*[\s\S]{0,500}?(TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING)[\s\S]{0,500}?\*/",
                       "Interesting Comment (Multi-line)"),
            PatternDef(r"//\s*(password|secret|key|token|admin|backdoor|debug|test|hardcoded)", "Suspicious Comment"),
        ]

        self.xss_patterns: List[PatternDef] = [
            PatternDef(r"\.innerHTML\s*=\s*([^;]+)", "innerHTML Assignment", "high"),
            PatternDef(r"\.outerHTML\s*=\s*([^;]+)", "outerHTML Assignment", "high"),
            PatternDef(r"document\.write\s*\(([^)]+)\)", "document.write()", "high"),
            PatternDef(r"document\.writeln\s*\(([^)]+)\)", "document.writeln()", "high"),
            PatternDef(r"eval\s*\([^)]*(\$|location|window\.|document\.|user|input|param|query|search)",
                       "eval() with user input", "critical"),
            PatternDef(r"dangerouslySetInnerHTML\s*=\s*\{[^}]*\}", "React dangerouslySetInnerHTML", "high"),
            PatternDef(r"\$\([^)]+\)\.html\s*\(([^)]+)\)", "jQuery .html()", "medium"),
            PatternDef(r"\$\([^)]+\)\.append\s*\(([^)]+)\)", "jQuery .append()", "medium"),
            PatternDef(r"location\.(href|hash|search)\s*=\s*([^;]+)", "Location manipulation", "medium"),
            PatternDef(r"innerHTML\s*[+=]\s*[\"']", "innerHTML concatenation", "high"),
        ]

        self.xss_function_patterns: List[PatternDef] = [
            PatternDef(r"function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML|write)", "Function with DOM writes", "high"),
            PatternDef(r"function\s+(\w+)\s*\([^)]*\)\s*\{[^}]*eval\s*\(", "Function with eval()", "critical"),
            PatternDef(r"(\w+)\s*[:=]\s*function\s*\([^)]*\)\s*\{[^}]*\.(innerHTML|outerHTML)", "Function expression DOM write", "high"),
            PatternDef(r"\.(onclick|onerror|onload|onmouseover)\s*=\s*function", "Event handler assignment", "medium"),
        ]

        self.api_patterns: List[Tuple[str, str]] = [
            (r"fetch\s*\(\s*[\"']([^\"']+)[\"']", "fetch()"),
            (r"fetch\s*\(\s*`([^`]+)`", "fetch() (template)"),
            (r"\.open\s*\(\s*[\"'](GET|POST|PUT|DELETE|PATCH)[\"']\s*,\s*[\"']([^\"']+)[\"']", "XMLHttpRequest"),
            (r"axios\.(get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']", "axios"),
            (r"axios\s*\(\s*\{[^}]*url\s*:\s*[\"']([^\"']+)[\"']", "axios (config)"),
            (r"\$\.(ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*[\"']([^\"']+)[\"']", "jQuery AJAX"),
            (r"\$\.(ajax|get|post)\s*\(\s*[\"']([^\"']+)[\"']", "jQuery AJAX (short)"),
            (r"\$\.getJSON\s*\(\s*[\"']([^\"']+)[\"']", "jQuery getJSON"),
            (r"[\"'](/api/[^\"']+)[\"']", "API Path"),
            (r"[\"'](/v\d+/[^\"']+)[\"']", "API Versioned Path"),
            (r"baseURL\s*[:=]\s*[\"']([^\"']+)[\"']", "Base URL"),
            (r"api[_-]?url\s*[:=]\s*[\"']([^\"']+)[\"']", "API URL Variable"),
        ]

        self.parameter_patterns: List[Tuple[str, str]] = [
            (r"[\"']([^\"']*[?&](\w+)\s*=\s*[^\"'&\s]+)[\"']", "URL Query Parameter"),
            (r"[?&](\w+)\s*=\s*([^&\s\"']+)", "Query Parameter"),
            (r"function\s+(\w+)\s*\(([^)]+)\)", "Function Parameters"),
            (r"function\s*\(([^)]+)\)", "Anonymous Function Parameters"),
            (r"(\w+)\s*[:=]\s*function\s*\(([^)]+)\)", "Function Expression Parameters"),
            (r"\(([^)]+)\)\s*=>", "Arrow Function Parameters"),
            (r"\.(\w+)\s*\(([^)]+)\)", "Method Call Parameters"),
            (r"URLSearchParams\s*\([^)]*\)", "URL Parameters Object"),
            (r"\.get\s*\([\"']([^\"']+)[\"']", "URLSearchParams.get()"),
            (r"\.(get|post|put|delete|patch|head|options)\s*\([^,]+,\s*\{([^}]+)\}", "Request Parameters"),
            (r"fetch\s*\([^,]+,\s*\{([^}]+)\}", "Fetch Request Parameters"),
            (r"axios\s*\(\s*\{([^}]+)\}", "Axios Request Parameters"),
        ]

        self.path_patterns: List[Tuple[str, str]] = [
            (r"[\"'](/[a-zA-Z0-9_\-/]+)[\"']", "Path"),
            (r"[\"'](\.\.?/[a-zA-Z0-9_\-/]+)[\"']", "Relative Path"),
            (r"path\s*[:=]\s*[\"']([^\"']+)[\"']", "Path Variable"),
            (r"dir\s*[:=]\s*[\"']([^\"']+)[\"']", "Directory Variable"),
            (r"[\"']([a-zA-Z0-9_\-/]+\.(js|json|html|css|png|jpg|svg))[\"']", "File Path"),
        ]

    def analyze(self, url: str) -> AnalysisResult:
        errors: List[str] = []
        
        # WAF Detection - check before fetching
        waf_info = self._detect_waf(url)
        if waf_info["detected"]:
            # Stop completely if WAF is detected - don't fetch or analyze
            return AnalysisResult(
                url=url,
                errors=[f"WAF Detected: {waf_info['name']} - {waf_info['message']}. Scan stopped."],
                analysis_timestamp=datetime.utcnow().isoformat(),
                waf_detected=waf_info
            )
        
        content = self._fetch_js_file(url)
        if content is None:
            errors.append(self._build_fetch_error(url))
            return AnalysisResult(url=url, errors=errors, analysis_timestamp=datetime.utcnow().isoformat(), waf_detected=waf_info)

        file_size = len(content)

        try:
            api_keys = self._find_patterns(content, self.api_key_patterns, context_lines=5)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"Error analyzing API keys: {exc}")
            api_keys = []

        try:
            credentials = self._find_patterns(content, self.credential_patterns, context_lines=5)
        except Exception as exc:
            errors.append(f"Error analyzing credentials: {exc}")
            credentials = []

        try:
            emails = self._find_patterns(content, self.email_patterns, context_lines=3)
        except Exception as exc:
            errors.append(f"Error analyzing emails: {exc}")
            emails = []

        try:
            comments = self._find_patterns(content, self.comment_patterns, context_lines=3)
        except Exception as exc:
            errors.append(f"Error analyzing comments: {exc}")
            comments = []

        try:
            xss_vulns = self._find_patterns(content, self.xss_patterns, context_lines=4)
            # Add exploit payloads for XSS vulnerabilities
            xss_vulns = self._add_xss_exploits(xss_vulns, url)
        except Exception as exc:
            errors.append(f"Error analyzing XSS vulnerabilities: {exc}")
            xss_vulns = []

        try:
            xss_funcs = self._find_patterns(content, self.xss_function_patterns, context_lines=4)
            # Add exploit payloads for XSS functions
            xss_funcs = self._add_xss_exploits(xss_funcs, url)
        except Exception as exc:
            errors.append(f"Error analyzing XSS functions: {exc}")
            xss_funcs = []

        try:
            api_endpoints = self._extract_api_endpoints(content)
        except Exception as exc:
            errors.append(f"Error extracting API endpoints: {exc}")
            api_endpoints = []

        try:
            parameters = self._extract_parameters(content)
        except Exception as exc:
            errors.append(f"Error extracting parameters: {exc}")
            parameters = []

        try:
            paths = self._extract_paths(content)
        except Exception as exc:
            errors.append(f"Error extracting paths: {exc}")
            paths = []

        return AnalysisResult(
            url=url,
            api_keys=api_keys,
            credentials=credentials,
            emails=emails,
            interesting_comments=comments,
            xss_vulnerabilities=xss_vulns,
            xss_functions=xss_funcs,
            api_endpoints=api_endpoints,
            parameters=parameters,
            paths_directories=paths,
            errors=errors,
            file_size=file_size,
            analysis_timestamp=datetime.utcnow().isoformat(),
            waf_detected=waf_info,
        )

    def _detect_waf(self, url: str) -> Dict[str, Any]:
        """Detect WAF (Web Application Firewall) by checking headers and response."""
        waf_info = {
            "detected": False,
            "name": None,
            "message": "",
            "confidence": "low"
        }
        
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Test with a simple request to check for WAF signatures
            test_headers = {
                "User-Agent": "Mozilla/5.0 (compatible; JSAnalyzer/1.0)",
                "Accept": "*/*",
            }
            
            # Try a suspicious request that would trigger WAF
            test_response = requests.get(
                base_url,
                headers=test_headers,
                timeout=10,
                verify=False,
                allow_redirects=False,
            )
            
            headers = test_response.headers
            
            # Cloudflare detection
            if "cf-ray" in headers or "cf-request-id" in headers or "server" in headers and "cloudflare" in headers.get("server", "").lower():
                waf_info = {
                    "detected": True,
                    "name": "Cloudflare",
                    "message": "Cloudflare WAF is protecting this site",
                    "confidence": "high"
                }
                return waf_info
            
            # AWS WAF detection
            if "x-amzn-requestid" in headers or "x-amzn-trace-id" in headers:
                waf_info = {
                    "detected": True,
                    "name": "AWS WAF",
                    "message": "AWS WAF is protecting this site",
                    "confidence": "high"
                }
                return waf_info
            
            # Akamai detection
            if "x-akamai-request-id" in headers or "server" in headers and "akamai" in headers.get("server", "").lower():
                waf_info = {
                    "detected": True,
                    "name": "Akamai",
                    "message": "Akamai WAF is protecting this site",
                    "confidence": "high"
                }
                return waf_info
            
            # Imperva/Incapsula detection
            if "x-iinfo" in headers or "x-cdn" in headers and "incapsula" in headers.get("x-cdn", "").lower():
                waf_info = {
                    "detected": True,
                    "name": "Imperva (Incapsula)",
                    "message": "Imperva WAF is protecting this site",
                    "confidence": "high"
                }
                return waf_info
            
            # Sucuri detection
            if "x-sucuri-id" in headers or "x-sucuri-cache" in headers:
                waf_info = {
                    "detected": True,
                    "name": "Sucuri",
                    "message": "Sucuri WAF is protecting this site",
                    "confidence": "high"
                }
                return waf_info
            
            # Barracuda detection
            if "barracuda" in headers.get("server", "").lower():
                waf_info = {
                    "detected": True,
                    "name": "Barracuda",
                    "message": "Barracuda WAF is protecting this site",
                    "confidence": "medium"
                }
                return waf_info
            
            # FortiWeb detection
            if "fortiweb" in headers.get("server", "").lower() or "fwb" in headers:
                waf_info = {
                    "detected": True,
                    "name": "FortiWeb",
                    "message": "FortiWeb WAF is protecting this site",
                    "confidence": "medium"
                }
                return waf_info
            
            # Check for common WAF response codes
            if test_response.status_code in [403, 406, 419]:
                # Check response body for WAF signatures
                body = test_response.text.lower()
                waf_signatures = {
                    "cloudflare": ["cloudflare", "cf-ray"],
                    "aws waf": ["aws", "x-amzn"],
                    "akamai": ["akamai"],
                    "sucuri": ["sucuri"],
                    "imperva": ["imperva", "incapsula"],
                    "barracuda": ["barracuda"],
                }
                
                for waf_name, keywords in waf_signatures.items():
                    if any(kw in body for kw in keywords):
                        waf_info = {
                            "detected": True,
                            "name": waf_name.title(),
                            "message": f"{waf_name.title()} WAF may be protecting this site",
                            "confidence": "medium"
                        }
                        return waf_info
                
                # Generic WAF detection
                if any(keyword in body for keyword in ["blocked", "forbidden", "access denied", "security", "firewall"]):
                    waf_info = {
                        "detected": True,
                        "name": "Unknown WAF",
                        "message": "A WAF may be protecting this site (detected by response)",
                        "confidence": "low"
                    }
                    return waf_info
                    
        except Exception:
            # If detection fails, continue without WAF info
            pass
        
        return waf_info

    def extract_js_files_from_page(self, page_url: str) -> List[str]:
        """Extract all JavaScript file URLs from an HTML page."""
        js_urls: List[str] = []
        
        try:
            normalized_url = page_url.replace("0.0.0.0", "localhost") if "0.0.0.0" in page_url else page_url
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            
            response = requests.get(
                normalized_url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            response.raise_for_status()
            
            # Check if it's actually HTML
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                return js_urls
            
            html_content = response.text
            
            # Extract script tags with src attribute
            # Pattern: <script ... src="..." ...> or <script ... src='...' ...>
            script_pattern = r'<script[^>]+src\s*=\s*["\']([^"\']+)["\'][^>]*>'
            matches = re.finditer(script_pattern, html_content, re.IGNORECASE)
            
            base_url = response.url
            seen_urls = set()
            
            for match in matches:
                script_src = match.group(1).strip()
                
                # Skip data: and javascript: URLs
                if script_src.startswith(("data:", "javascript:", "vbscript:")):
                    continue
                
                # Skip empty
                if not script_src:
                    continue
                
                # Convert relative URLs to absolute
                if script_src.startswith("//"):
                    script_src = urlparse(base_url).scheme + ":" + script_src
                elif script_src.startswith("/"):
                    parsed_base = urlparse(base_url)
                    script_src = f"{parsed_base.scheme}://{parsed_base.netloc}{script_src}"
                elif not script_src.startswith("http"):
                    script_src = urljoin(base_url, script_src)
                
                # Only include .js files or URLs that look like JS files
                if script_src.endswith((".js", ".mjs")) or "/js/" in script_src.lower() or "javascript" in script_src.lower():
                    if script_src not in seen_urls:
                        seen_urls.add(script_src)
                        js_urls.append(script_src)
            
            # Also check for inline script tags that might reference external files
            # Look for patterns like: import('...') or require('...')
            import_pattern = r"(?:import|require)\s*\(?\s*['\"]([^'\"]+\.js[^'\"]*)['\"]"
            import_matches = re.finditer(import_pattern, html_content, re.IGNORECASE)
            
            for match in import_matches:
                import_url = match.group(1).strip()
                if import_url.startswith("http") or import_url.startswith("/"):
                    if import_url.startswith("/"):
                        parsed_base = urlparse(base_url)
                        import_url = f"{parsed_base.scheme}://{parsed_base.netloc}{import_url}"
                    
                    if import_url not in seen_urls:
                        seen_urls.add(import_url)
                        js_urls.append(import_url)
        
        except Exception as e:
            # If extraction fails, return empty list
            pass
        
        return js_urls

    def _fetch_js_file(self, url: str) -> Optional[str]:
        """Download JS file content with safeguards."""
        try:
            normalized_url = url.replace("0.0.0.0", "localhost") if "0.0.0.0" in url else url
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/javascript, text/javascript, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": normalized_url.rsplit("/", 1)[0] if "/" in normalized_url else normalized_url,
            }
            response = requests.get(
                normalized_url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                stream=True,
            )
            response.raise_for_status()

            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_FILE_SIZE_BYTES:
                        return None
                except ValueError:
                    pass

            response.encoding = response.apparent_encoding or "utf-8"
            collected: List[str] = []
            size = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                if not chunk:
                    continue
                if isinstance(chunk, bytes):
                    chunk = chunk.decode("utf-8", errors="ignore")
                collected.append(chunk)
                size += len(chunk)
                if size > MAX_FILE_SIZE_BYTES:
                    break
            content = "".join(collected)
            if not content:
                try:
                    content = response.content.decode("utf-8", errors="ignore")
                except Exception:
                    return None
            return content[:MAX_FILE_SIZE_BYTES]
        except requests.RequestException:
            return None
        except Exception:
            return None

    def _find_patterns(self, content: str, patterns: List[PatternDef], context_lines: int = 5) -> List[Finding]:
        findings: List[Finding] = []
        if not content:
            return findings

        lines = content.split("\n")
        single_line_heavy = len(lines) == 1 and len(content) > 10_000
        if single_line_heavy:
            context_lines = 0

        for pattern in patterns:
            matches = re.finditer(pattern.regex, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                match_text = match.group(0)
                if not pattern.strict and self._is_false_positive(match_text, pattern.label):
                    continue

                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                start_line = max(0, line_num - context_lines - 1)
                end_line = min(len(lines), line_num + context_lines)
                context_slice = lines[start_line:end_line]
                context = "\n".join(context_slice)

                if len(context) > 1000:
                    match_start = max(0, start_pos - 200)
                    match_end = min(len(content), start_pos + len(match_text) + 200)
                    context = content[match_start:match_end]

                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                if len(line_content) > 500:
                    line_content = f"{line_content[:200]}...{line_content[-200:]}"

                finding = Finding(
                    type=pattern.label,
                    match=match_text[:200],
                    line=line_num,
                    severity=pattern.severity,
                    line_content=line_content,
                    context=context,
                    context_start_line=start_line + 1,
                    context_end_line=end_line,
                )
                findings.append(finding)

        return findings

    def _extract_api_endpoints(self, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")
        for pattern, label in self.api_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                url_path = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                if len(match.groups()) > 1:
                    url_path = match.group(2) if match.lastindex and match.lastindex >= 2 else url_path
                if any(fp in url_path.lower() for fp in ("example.com", "localhost", "placeholder")):
                    continue
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                findings.append(
                    Finding(
                        type=label,
                        match=url_path[:200],
                        line=line_num,
                        line_content=line_content,
                    )
                )
        return self._dedupe(findings)

    def _extract_parameters(self, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")
        for pattern, label in self.parameter_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                full_match = match.group(0)

                param_name: Optional[str] = None
                param_value: Optional[str] = None
                param_text = full_match

                if "?" in full_match or "&" in full_match:
                    param_part = match.group(1) if match.lastindex and match.lastindex >= 1 else full_match
                    if "=" in param_part:
                        first = param_part.split("&")[0]
                        if "=" in first:
                            parts = first.split("=", 1)
                            param_name = parts[0].lstrip("?&").strip()
                            param_value = parts[1].strip()
                            param_text = f"{param_name}={param_value[:50]}"
                elif "(" in full_match and ")" in full_match and len(match.groups()) > 1:
                    param_text = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
                    first = param_text.split(",")[0] if "," in param_text else param_text
                    if "=" in first:
                        param_name = first.split("=", 1)[0].strip()
                    elif ":" in first:
                        param_name = first.split(":", 1)[0].strip()
                    else:
                        param_name = first.strip()
                elif len(match.groups()) >= 1:
                    param_text = match.group(1)
                    if "=" in param_text:
                        param_name = param_text.split("=", 1)[0].strip()

                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                if len(line_content) > 500:
                    line_content = f"{line_content[:200]}...{line_content[-200:]}"

                context = self._build_context(content, start_pos, full_match, line_num, window=5)

                findings.append(
                    Finding(
                        type=label,
                        match=full_match[:200],
                        line=line_num,
                        param_name=param_name,
                        param_value=param_value,
                        parameter=param_text[:200],
                        line_content=line_content,
                        context=context,
                    )
                )
        return self._dedupe(findings)

    def _extract_paths(self, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")
        for pattern, label in self.path_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                path_text = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                if any(fp in path_text.lower() for fp in ("http://", "https://", "www.", "example.com")):
                    continue
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                findings.append(
                    Finding(
                        type=label,
                        match=path_text[:200],
                        line=line_num,
                        path=path_text[:200],
                        line_content=line_content,
                    )
                )
        return self._dedupe(findings)

    @staticmethod
    def _build_context(content: str, start_pos: int, full_match: str, line_num: int, window: int = 5) -> str:
        lines = content.split("\n")
        start_line = max(0, line_num - window - 1)
        end_line = min(len(lines), line_num + window)
        context_lines = lines[start_line:end_line]
        context = "\n".join(context_lines)
        if len(context) > 1000:
            match_start = max(0, start_pos - 200)
            match_end = min(len(content), start_pos + len(full_match) + 200)
            context = content[match_start:match_end]
        return context

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique: List[Finding] = []
        for f in findings:
            key = (f.type, f.match, f.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _is_false_positive(match: str, label: str) -> bool:
        match_lower = match.lower()
        common_fp = [
            "example.com",
            "example.org",
            "localhost",
            "127.0.0.1",
            "test",
            "demo",
            "sample",
            "placeholder",
            "your_api_key",
            "your_secret",
            "password: false",
            "password: true",
            "password: null",
        ]
        if any(fp in match_lower for fp in common_fp):
            return True
        if label == "JWT Token":
            parts = match.split(".")
            if len(parts) < 3 or len(match) < 50:
                return True
        return False

    def _add_xss_exploits(self, findings: List[Finding], source_url: str) -> List[Finding]:
        """Add exploit payloads and verify URLs to XSS findings."""
        from urllib.parse import urlparse, urlencode
        from dataclasses import fields, asdict
        
        updated_findings = []
        for finding in findings:
            # Generate exploit payload based on vulnerability type
            payload = self._generate_xss_payload(finding)
            
            # Generate verify URL
            parsed_url = urlparse(source_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Create verify URL with payload
            verify_url = self._create_verify_url(base_url, finding, payload)
            
            # Create new finding with exploit info using dataclass replace
            from dataclasses import replace
            updated_finding = replace(
                finding,
                exploit_payload=payload,
                verify_url=verify_url
            )
            updated_findings.append(updated_finding)
        
        return updated_findings

    def _generate_xss_payload(self, finding: Finding) -> str:
        """Generate XSS exploit payload based on vulnerability type."""
        finding_type = finding.type.lower()
        
        # Context-specific payloads
        if "innerhtml" in finding_type or "outerhtml" in finding_type:
            return "<img src=x onerror=alert('XSS')>"
        elif "document.write" in finding_type or "document.writeln" in finding_type:
            return "<script>alert('XSS')</script>"
        elif "eval" in finding_type:
            return "alert('XSS')"
        elif "dangerouslysetinnerhtml" in finding_type:
            return "<img src=x onerror=alert('XSS')>"
        elif "jquery" in finding_type or ".html()" in finding_type:
            return "<img src=x onerror=alert('XSS')>"
        elif "location" in finding_type:
            return "javascript:alert('XSS')"
        elif "onclick" in finding_type or "onerror" in finding_type or "onload" in finding_type:
            return "alert('XSS')"
        else:
            # Default payload
            return "<img src=x onerror=alert('XSS')>"

    def _create_verify_url(self, base_url: str, finding: Finding, payload: str) -> str:
        """Create a verify URL for testing XSS vulnerability."""
        from urllib.parse import urlencode, quote
        
        # Encode payload for URL
        encoded_payload = quote(payload)
        
        # Create verify URL with common parameter names
        params = {
            'xss': encoded_payload,
            'test': encoded_payload,
            'input': encoded_payload,
            'q': encoded_payload,
            'search': encoded_payload,
        }
        
        # Try to extract parameter name from finding if available
        if finding.param_name:
            params = {finding.param_name: encoded_payload}
        
        # Create URL with parameters
        query_string = urlencode(params)
        verify_url = f"{base_url}/?{query_string}"
        
        # Also create hash-based URL for location.hash vulnerabilities
        if "location" in finding.type.lower() or "hash" in finding.type.lower():
            verify_url = f"{base_url}/#{encoded_payload}"
        
        return verify_url

    @staticmethod
    def _build_fetch_error(url: str) -> str:
        hint = " Use 'localhost' or '127.0.0.1' instead." if "0.0.0.0" in url else ""
        return f"Failed to fetch {url}.{hint} The file may be too large, inaccessible, or timed out."

