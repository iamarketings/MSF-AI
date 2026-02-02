"""
Web Automation Tools for MSF-AI v4
"""
import requests
import re
from typing import Dict, Any, List
from urllib.parse import urljoin

def screenshot_url(url: str, output: str = "screenshot.png") -> str:
    """Takes a screenshot of a URL (requires wkhtmltoimage)."""
    import subprocess
    try:
        if not url.startswith("http"): url = "http://" + url
        subprocess.run(["wkhtmltoimage", url, output], check=True, timeout=15)
        return f"Screenshot saved to {output}"
    except Exception as e:
        return f"Error taking screenshot: {e}"

def get_http_headers(url: str) -> Dict[str, str]:
    """Retrieves HTTP headers for a URL."""
    try:
        if not url.startswith("http"): url = "http://" + url
        resp = requests.head(url, timeout=5)
        return dict(resp.headers)
    except Exception as e:
        return {"error": str(e)}

def extract_forms(url: str) -> List[Dict[str, Any]]:
    """Extracts HTML forms from a page."""
    try:
        if not url.startswith("http"): url = "http://" + url
        resp = requests.get(url, timeout=10)
        forms = []
        # Simple regex extract (robust parsing would use BeautifulSoup)
        form_matches = re.findall(r'<form(.*?)>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
        for i, (attrs, content) in enumerate(form_matches):
            action = re.search(r'action=["\'](.*?)["\']', attrs)
            method = re.search(r'method=["\'](.*?)["\']', attrs)
            inputs = re.findall(r'<input(.*?)>', content)
            forms.append({
                "id": i,
                "action": action.group(1) if action else url,
                "method": method.group(1) if method else "GET",
                "input_count": len(inputs)
            })
        return forms
    except Exception as e:
        return [{"error": str(e)}]

def check_waf(url: str) -> str:
    """Basic WAF detection by sending suspicious payload."""
    try:
        if not url.startswith("http"): url = "http://" + url
        payload = {"q": "<script>alert(1)</script>"}
        resp = requests.get(url, params=payload, timeout=5)
        if resp.status_code in [403, 406, 501]:
            return f"Potential WAF detected (Status {resp.status_code})"
        headers = str(resp.headers).lower()
        if "waf" in headers or "cloudflare" in headers:
            return "WAF signature found in headers"
        return "No obvious WAF detected"
    except Exception as e:
        return f"Error: {e}"

def enumerate_directories(url: str, wordlist: List[str] = ["admin", "login", "backup", "db", "test"]) -> List[str]:
    """Simple directory brute-force."""
    found = []
    if not url.startswith("http"): url = "http://" + url
    if not url.endswith("/"): url += "/"
    
    for path in wordlist:
        target = url + path
        try:
            r = requests.head(target, timeout=3)
            if r.status_code < 400:
                found.append(target)
        except:
            pass
    return found

def sql_injection_test(url: str, param: str) -> str:
    """Basic SQLi test on a parameter."""
    try:
        if not url.startswith("http"): url = "http://" + url
        # Error based test
        target = f"{url}?{param}=1'"
        r = requests.get(target, timeout=5)
        errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL"]
        for err in errors:
            if err in r.text:
                return f"VULNERABLE: Found SQL error '{err}'"
        return "Not vulnerable to simple error-based SQLi"
    except Exception as e:
        return f"Error: {e}"

def get_tools() -> Dict[str, Any]:
    return {
        "screenshot_url": screenshot_url,
        "get_http_headers": get_http_headers,
        "extract_forms": extract_forms,
        "check_waf": check_waf,
        "enumerate_directories": enumerate_directories,
        "sql_injection_test": sql_injection_test
    }
