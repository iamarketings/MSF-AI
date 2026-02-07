import socket
import ssl
import re
from typing import Optional, Dict

def ftp_banner_grabber(target: str, port: int = 21, timeout: int = 10) -> Dict:
    """
    Récupère la bannière FTP et identifie la version du service.
    
    Args:
        target: Adresse IP ou hostname
        port: Port FTP (défaut: 21)
        timeout: Timeout de connexion en secondes
    
    Returns:
        Dict avec banner, version, et informations détectées
    """
    result = {
        "success": False,
        "banner": "",
        "version": "",
        "service": "unknown",
        "vulnerabilities": []
    }
    
    try:
        # Création de la socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connexion
        sock.connect((target, port))
        
        # Réception de la bannière
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        result["banner"] = banner.strip()
        result["success"] = True
        
        # Fermeture de la connexion
        sock.close()
        
        # Analyse de la bannière pour identifier le service
        banner_lower = banner.lower()
        
        # Détection ProFTPD
        if "proftpd" in banner_lower:
            result["service"] = "ProFTPD"
            # Extraction de la version
            version_match = re.search(r'ProFTPD\s+([\d\.]+)', banner, re.IGNORECASE)
            if version_match:
                result["version"] = version_match.group(1)
                
                # Vérification des vulnérabilités connues
                version_parts = result["version"].split('.')
                if len(version_parts) >= 2:
                    major = int(version_parts[0])
                    minor = int(version_parts[1])
                    
                    # ProFTPD 1.3.5 - CVE-2015-3306 (mod_copy)
                    if major == 1 and minor == 3 and len(version_parts) >= 3:
                        patch = int(version_parts[2]) if version_parts[2].isdigit() else 0
                        if patch == 5:
                            result["vulnerabilities"].append({
                                "cve": "CVE-2015-3306",
                                "name": "ProFTPD 1.3.5 mod_copy RCE",
                                "severity": "critical",
                                "exploit": "proftpd_modcopy_exec"
                            })
                    
                    # ProFTPD 1.3.3c - Backdoor
                    if major == 1 and minor == 3:
                        if "1.3.3c" in banner:
                            result["vulnerabilities"].append({
                                "cve": "CVE-2010-4221",
                                "name": "ProFTPD 1.3.3c Backdoor",
                                "severity": "critical",
                                "exploit": "proftpd_133c_backdoor"
                            })
        
        # Détection vsFTPd
        elif "vsftpd" in banner_lower:
            result["service"] = "vsFTPd"
            version_match = re.search(r'vsFTPd\s+([\d\.]+)', banner, re.IGNORECASE)
            if version_match:
                result["version"] = version_match.group(1)
        
        # Détection Pure-FTPd
        elif "pure-ftpd" in banner_lower:
            result["service"] = "Pure-FTPd"
        
        # Détection Windows FTP
        elif "microsoft ftp service" in banner_lower:
            result["service"] = "Microsoft FTP Service"
        
    except socket.timeout:
        result["error"] = "Connection timeout"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)
    
    return result

def test_ftp_anonymous_login(target: str, port: int = 21) -> Dict:
    """
    Teste la connexion FTP anonyme.
    
    Args:
        target: Adresse IP ou hostname
        port: Port FTP
    
    Returns:
        Dict avec résultat du test
    """
    result = {
        "success": False,
        "anonymous_login": False,
        "writable": False,
        "error": ""
    }
    
    try:
        import ftplib
        
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=10)
        
        # Tentative de connexion anonyme
        try:
            ftp.login()
            result["anonymous_login"] = True
            result["success"] = True
            
            # Test d'écriture
            try:
                ftp.mkd("test_dir_msf")
                result["writable"] = True
                ftp.rmd("test_dir_msf")
            except:
                result["writable"] = False
                
        except ftplib.error_perm as e:
            result["error"] = str(e)
        
        ftp.quit()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result