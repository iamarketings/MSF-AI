import requests
import re

def identify_http_service(target, port=80):
    """
    Identifie le serveur HTTP et ses caractéristiques
    """
    results = {
        "target": f"{target}:{port}",
        "service": "HTTP",
        "findings": []
    }
    
    try:
        # Test HTTP basique
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}:{port}"
        
        # Désactiver la vérification SSL pour HTTPS
        verify_ssl = False if port == 443 else True
        
        response = requests.get(url, timeout=10, verify=verify_ssl, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        results["status_code"] = response.status_code
        results["headers"] = dict(response.headers)
        
        # Extraire le serveur
        server = response.headers.get('Server', '')
        if server:
            results["server"] = server
            results["findings"].append({
                "type": "Server Identification",
                "value": server
            })
        
        # Extraire le titre de la page
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
        if title_match:
            results["title"] = title_match.group(1).strip()
        
        # Vérifier les technologies courantes
        tech_indicators = {
            "Apache": ["Apache", "httpd"],
            "Nginx": ["nginx"],
            "IIS": ["Microsoft-IIS", "IIS"],
            "PHP": ["PHP", "X-Powered-By: PHP"],
            "WordPress": ["wp-content", "wordpress"],
            "Joomla": ["joomla"],
            "Drupal": ["drupal"]
        }
        
        detected_tech = []
        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator in server or indicator in response.text or indicator in str(response.headers):
                    detected_tech.append(tech)
                    break
        
        if detected_tech:
            results["technologies"] = list(set(detected_tech))
        
        # Vérifier les en-têtes de sécurité
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 
                          'Content-Security-Policy', 'Strict-Transport-Security']
        missing_headers = []
        
        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)
        
        if missing_headers:
            results["findings"].append({
                "type": "Security Headers Missing",
                "headers": missing_headers,
                "severity": "medium"
            })
        
        return results
        
    except requests.exceptions.SSLError:
        results["findings"].append({
            "type": "SSL Error",
            "severity": "low",
            "description": "Problème de certificat SSL"
        })
        return results
    except Exception as e:
        results["error"] = str(e)
        return results