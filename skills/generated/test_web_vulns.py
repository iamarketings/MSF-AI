import subprocess
import json
import time

def test_web_vulns(target, port=80):
    """
    Teste les vulnérabilités web courantes
    """
    results = {
        "target": f"{target}:{port}",
        "tests": [],
        "vulnerabilities": []
    }
    
    # Liste des tests à effectuer
    tests = [
        {
            "name": "Directory Traversal",
            "module": "auxiliary/scanner/http/dir_scanner",
            "description": "Scan de répertoires sensibles"
        },
        {
            "name": "PHP Code Injection",
            "module": "auxiliary/scanner/http/php_cgi_arg_injection",
            "description": "Test d'injection PHP CGI"
        },
        {
            "name": "HTTP Methods",
            "module": "auxiliary/scanner/http/http_put",
            "description": "Test des méthodes HTTP dangereuses"
        }
    ]
    
    for test in tests:
        try:
            # Exécuter le module Metasploit
            cmd = [
                "msfconsole", "-q", "-x",
                f"use {test['module']}; set RHOSTS {target}; set RPORT {port}; run; exit"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            test_result = {
                "name": test["name"],
                "module": test["module"],
                "output": result.stdout[-1000:],  # Derniers 1000 caractères
                "success": result.returncode == 0
            }
            
            # Analyser les résultats pour détecter des vulnérabilités
            if "vulnerable" in result.stdout.lower() or "exploit" in result.stdout.lower():
                results["vulnerabilities"].append({
                    "type": test["name"],
                    "severity": "medium",
                    "evidence": "Détecté dans la sortie du scanner"
                })
            
            results["tests"].append(test_result)
            
        except subprocess.TimeoutExpired:
            test_result = {
                "name": test["name"],
                "module": test["module"],
                "error": "Timeout",
                "success": False
            }
            results["tests"].append(test_result)
        except Exception as e:
            test_result = {
                "name": test["name"],
                "module": test["module"],
                "error": str(e),
                "success": False
            }
            results["tests"].append(test_result)
    
    return results