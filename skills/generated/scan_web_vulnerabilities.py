import requests
import time
from urllib.parse import urljoin

def scan_web_vulnerabilities(url):
    """
    Scanne un serveur web pour des vulnérabilités courantes
    """
    results = {
        "target": url,
        "vulnerabilities": [],
        "findings": []
    }
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    try:
        # Test 1: Accès au serveur
        response = session.get(url, timeout=10, verify=False)
        results["status_code"] = response.status_code
        results["server_header"] = response.headers.get('Server', '')
        results["title"] = response.text[:100] if response.text else ""
        
        # Test 2: Directory traversal basique
        traversal_payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for payload in traversal_payloads:
            test_url = urljoin(url, f"?file={payload}")
            try:
                resp = session.get(test_url, timeout=5, verify=False)
                if "root:" in resp.text and "bin/" in resp.text:
                    results["vulnerabilities"].append({
                        "type": "Directory Traversal",
                        "severity": "high",
                        "payload": payload,
                        "evidence": "Found /etc/passwd contents"
                    })
                    break
            except:
                pass
        
        # Test 3: Fichiers sensibles
        sensitive_files = [
            "/.git/config",
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/phpinfo.php",
            "/test.php",
            "/admin",
            "/administrator",
            "/phpmyadmin",
            "/server-status"
        ]
        
        for file in sensitive_files:
            test_url = urljoin(url, file)
            try:
                resp = session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    results["findings"].append({
                        "type": "Sensitive File Accessible",
                        "file": file,
                        "status": resp.status_code
                    })
            except:
                pass
        
        # Test 4: Headers de sécurité
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        ]
        
        missing_headers = []
        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)
        
        if missing_headers:
            results["findings"].append({
                "type": "Missing Security Headers",
                "headers": missing_headers
            })
        
        return results
        
    except Exception as e:
        return {"error": str(e), "target": url}