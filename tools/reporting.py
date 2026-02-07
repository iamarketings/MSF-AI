"""
Outils de génération de rapports détaillés pour MSF-AI
"""
import os
import json
import datetime
from typing import Dict, List, Any

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

def save_vulnerability_report(target: str, vulnerability: Dict[str, Any]) -> str:
    """
    Sauvegarde un rapport détaillé de vulnérabilité.
    
    Args:
        target: Cible scannée (domaine/IP)
        vulnerability: Dictionnaire contenant:
            - type: Type de vulnérabilité (SQLi, XSS, etc.)
            - severity: Criticité (low, medium, high, critical)
            - description: Description détaillée
            - evidence: Preuve (requête, réponse, etc.)
            - remediation: Recommandations
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    
    report_path = os.path.join(REPORTS_DIR, "vulnerabilities", f"{safe_target}_{timestamp}.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "vulnerability": vulnerability,
        "scanner": "MSF-AI v4.0"
    }
    
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    return f"Rapport sauvegardé: {report_path}"

def save_exploit_result(target: str, exploit_name: str, result: Dict[str, Any]) -> str:
    """
    Sauvegarde le résultat d'une tentative d'exploitation.
    
    Args:
        target: Cible exploitée
        exploit_name: Nom de l'exploit utilisé
        result: Résultat de l'exploitation (success, output, session_id, etc.)
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    safe_exploit = exploit_name.replace("/", "_")
    
    report_path = os.path.join(REPORTS_DIR, "exploits", f"{safe_target}_{safe_exploit}_{timestamp}.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "exploit": exploit_name,
        "result": result,
        "operator": "MSF-AI v4.0"
    }
    
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    return f"Résultat exploitation sauvegardé: {report_path}"

def save_scan_results(target: str, scan_type: str, results: Any) -> str:
    """
    Sauvegarde les résultats d'un scan (ports, subdomains, etc.).
    
    Args:
        target: Cible scannée
        scan_type: Type de scan (port_scan, subdomain_discovery, etc.)
        results: Résultats du scan
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    
    report_path = os.path.join(REPORTS_DIR, "scans", f"{safe_target}_{scan_type}_{timestamp}.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "scan_type": scan_type,
        "results": results,
        "scanner": "MSF-AI v4.0"
    }
    
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    return f"Résultats scan sauvegardés: {report_path}"

def generate_summary_report(target: str) -> str:
    """
    Génère un rapport de synthèse pour une cible donnée.
    Agrège toutes les vulnérabilités, exploits, et scans.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
    
    # Collecter tous les rapports pour cette cible
    vulnerabilities = []
    exploits = []
    scans = []
    
    # Parcourir les rapports de vulnérabilités
    vuln_dir = os.path.join(REPORTS_DIR, "vulnerabilities")
    if os.path.exists(vuln_dir):
        for filename in os.listdir(vuln_dir):
            if safe_target in filename and filename.endswith(".json"):
                with open(os.path.join(vuln_dir, filename)) as f:
                    vulnerabilities.append(json.load(f))
    
    # Parcourir les rapports d'exploits
    exploit_dir = os.path.join(REPORTS_DIR, "exploits")
    if os.path.exists(exploit_dir):
        for filename in os.listdir(exploit_dir):
            if safe_target in filename and filename.endswith(".json"):
                with open(os.path.join(exploit_dir, filename)) as f:
                    exploits.append(json.load(f))
    
    # Parcourir les scans
    scan_dir = os.path.join(REPORTS_DIR, "scans")
    if os.path.exists(scan_dir):
        for filename in os.listdir(scan_dir):
            if safe_target in filename and filename.endswith(".json"):
                with open(os.path.join(scan_dir, filename)) as f:
                    scans.append(json.load(f))
    
    summary = {
        "generated_at": datetime.datetime.now().isoformat(),
        "target": target,
        "statistics": {
            "total_vulnerabilities": len(vulnerabilities),
            "total_exploits_attempted": len(exploits),
            "total_scans": len(scans),
            "critical_vulns": sum(1 for v in vulnerabilities if v.get("vulnerability", {}).get("severity") == "critical"),
            "high_vulns": sum(1 for v in vulnerabilities if v.get("vulnerability", {}).get("severity") == "high"),
        },
        "vulnerabilities": vulnerabilities,
        "exploits": exploits,
        "scans": scans
    }
    
    summary_path = os.path.join(REPORTS_DIR, f"SUMMARY_{safe_target}_{timestamp}.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    return f"Rapport de synthèse généré: {summary_path}\nVulnérabilités: {len(vulnerabilities)} | Exploits: {len(exploits)} | Scans: {len(scans)}"

def get_tools():
    """Retourne les outils disponibles"""
    return {
        "save_vulnerability_report": save_vulnerability_report,
        "save_exploit_result": save_exploit_result,
        "save_scan_results": save_scan_results,
        "generate_summary_report": generate_summary_report
    }
