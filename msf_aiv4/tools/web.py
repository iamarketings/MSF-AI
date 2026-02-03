"""
Outils d'Automatisation Web pour MSF-AI v4
"""
import requests
import re
from typing import Dict, Any, List
from urllib.parse import urljoin
from bs4 import BeautifulSoup

def screenshot_url(url: str, output: str = "screenshot.png") -> str:
    """Prend une capture d'écran d'une URL (nécessite wkhtmltoimage)."""
    import subprocess
    try:
        if not url.startswith("http"): url = "http://" + url
        subprocess.run(["wkhtmltoimage", url, output], check=True, timeout=15)
        return f"Capture d'écran sauvegardée sous {output}"
    except Exception as e:
        return f"Erreur lors de la capture d'écran : {e}"

def get_http_headers(url: str) -> Dict[str, str]:
    """Récupère les en-têtes HTTP pour une URL."""
    try:
        if not url.startswith("http"): url = "http://" + url
        resp = requests.head(url, timeout=5)
        return dict(resp.headers)
    except Exception as e:
        return {"error": str(e)}

def extract_forms(url: str) -> List[Dict[str, Any]]:
    """Extrait les formulaires HTML d'une page en utilisant BeautifulSoup."""
    try:
        if not url.startswith("http"): url = "http://" + url
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = []
        for i, form in enumerate(soup.find_all('form')):
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    "name": input_tag.get('name'),
                    "type": input_tag.get('type', 'text') if input_tag.name == 'input' else input_tag.name,
                    "value": input_tag.get('value')
                })
            forms.append({
                "id": i,
                "action": urljoin(url, action) if action else url,
                "method": method,
                "inputs": inputs
            })
        return forms
    except Exception as e:
        return [{"error": str(e)}]

def check_security_headers(url: str) -> Dict[str, str]:
    """Vérifie la présence d'en-têtes de sécurité courants."""
    try:
        if not url.startswith("http"): url = "http://" + url
        resp = requests.head(url, timeout=5)
        headers = resp.headers
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy"
        ]
        results = {}
        for header in security_headers:
            results[header] = headers.get(header, "Manquant")
        return results
    except Exception as e:
        return {"error": str(e)}

def check_waf(url: str) -> str:
    """Détection basique de WAF en envoyant une charge utile suspecte."""
    try:
        if not url.startswith("http"): url = "http://" + url
        payload = {"q": "<script>alert(1)</script>"}
        resp = requests.get(url, params=payload, timeout=5)
        if resp.status_code in [403, 406, 501]:
            return f"WAF potentiel détecté (Statut {resp.status_code})"
        headers = str(resp.headers).lower()
        if "waf" in headers or "cloudflare" in headers:
            return "Signature WAF trouvée dans les en-têtes"
        return "Aucun WAF évident détecté"
    except Exception as e:
        return f"Erreur : {e}"

def enumerate_directories(url: str, wordlist: List[str] = ["admin", "login", "backup", "db", "test"]) -> List[str]:
    """Brute-force simple de répertoires."""
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
    """Test basique d'injection SQL sur un paramètre."""
    try:
        if not url.startswith("http"): url = "http://" + url
        # Test basé sur l'erreur
        target = f"{url}?{param}=1'"
        r = requests.get(target, timeout=5)
        errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL"]
        for err in errors:
            if err in r.text:
                return f"VULNÉRABLE : Erreur SQL trouvée '{err}'"
        return "Non vulnérable aux injections SQL simples basées sur les erreurs"
    except Exception as e:
        return f"Erreur : {e}"

def get_tools() -> Dict[str, Any]:
    """Retourne les outils web."""
    return {
        "screenshot_url": screenshot_url,
        "get_http_headers": get_http_headers,
        "extract_forms": extract_forms,
        "check_waf": check_waf,
        "enumerate_directories": enumerate_directories,
        "sql_injection_test": sql_injection_test,
        "check_security_headers": check_security_headers
    }
