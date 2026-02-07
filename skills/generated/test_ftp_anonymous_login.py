import ftplib
import socket
from typing import Dict

def test_ftp_anonymous_login(target: str, port: int = 21, timeout: int = 10) -> Dict:
    """
    Teste la connexion FTP anonyme et vérifie les permissions.
    
    Args:
        target: Adresse IP ou hostname
        port: Port FTP
        timeout: Timeout de connexion
    
    Returns:
        Dict avec résultats du test
    """
    result = {
        "success": False,
        "anonymous_login": False,
        "writable": False,
        "directory_listing": False,
        "files": [],
        "error": ""
    }
    
    try:
        # Test de connexion FTP
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=timeout)
        
        # Tentative de connexion anonyme
        try:
            response = ftp.login()
            result["anonymous_login"] = True
            result["success"] = True
            
            # Liste des fichiers
            try:
                files = []
                ftp.dir(files.append)
                result["directory_listing"] = True
                result["files"] = files[:10]  # Limiter à 10 fichiers
            except:
                result["directory_listing"] = False
            
            # Test d'écriture
            test_dir = "test_msf_ai_dir"
            test_file = "test_msf_ai.txt"
            
            try:
                # Essayer de créer un répertoire
                ftp.mkd(test_dir)
                result["writable"] = True
                
                # Nettoyer
                try:
                    ftp.rmd(test_dir)
                except:
                    pass
                    
            except ftplib.error_perm:
                result["writable"] = False
            
            # Fermer la connexion
            ftp.quit()
            
        except ftplib.error_perm as e:
            result["error"] = f"Login failed: {str(e)}"
            ftp.quit()
            
    except socket.timeout:
        result["error"] = "Connection timeout"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)
    
    return result

def brute_ftp_credentials(target: str, port: int = 21, 
                         username_list: list = None, 
                         password_list: list = None) -> Dict:
    """
    Brute force des credentials FTP.
    
    Args:
        target: Adresse IP ou hostname
        port: Port FTP
        username_list: Liste des usernames à tester
        password_list: Liste des passwords à tester
    
    Returns:
        Dict avec credentials trouvés
    """
    if username_list is None:
        username_list = ["admin", "root", "ftp", "user", "test", "administrator"]
    
    if password_list is None:
        password_list = ["password", "123456", "admin", "ftp", "test", "root", ""]
    
    result = {
        "success": False,
        "credentials_found": False,
        "username": "",
        "password": "",
        "attempts": 0,
        "error": ""
    }
    
    for username in username_list:
        for password in password_list:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=5)
                ftp.login(username, password)
                
                # Connexion réussie
                result["success"] = True
                result["credentials_found"] = True
                result["username"] = username
                result["password"] = password
                ftp.quit()
                return result
                
            except ftplib.error_perm:
                result["attempts"] += 1
                continue
            except Exception:
                result["attempts"] += 1
                continue
    
    result["error"] = "No valid credentials found"
    return result