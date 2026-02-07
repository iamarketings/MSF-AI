"""
Module d'Utilitaires Réseau pour MSF-AI v4
"""
import socket
import ipaddress
import requests
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

def expand_cidr(cidr: str) -> List[str]:
    """Étend une notation CIDR en une liste d'adresses IP."""
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    except Exception as e:
        return [f"Erreur : {e}"]

def geolocate_ip(ip: str) -> Dict[str, Any]:
    """Géolocalise une adresse IP en utilisant ip-api.com."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        return response.json()
    except Exception as e:
        return {"status": "fail", "error": str(e)}

def get_public_ip() -> str:
    """Retourne l'adresse IP publique actuelle."""
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except Exception as e:
        return f"Erreur : {e}"

def parse_nmap_xml(file_path: str) -> Dict[str, Any]:
    """Analyse la sortie XML de Nmap pour extraire les ports et services."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        hosts = []
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            ports = []
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                service = port.find('service').get('name') if port.find('service') is not None else "unknown"
                if state == 'open':
                    ports.append({"port": port_id, "service": service})
            if ports:
                hosts.append({"ip": ip, "ports": ports})
        return {"hosts": hosts}
    except Exception as e:
        return {"error": str(e)}

def port_knock(ip: str, ports: List[int]) -> str:
    """Effectue une séquence de port knocking."""
    try:
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect_ex((ip, int(port)))
                sock.close()
            except:
                pass
        return f"Séquence de knock {ports} envoyée à {ip}"
    except Exception as e:
        return f"Erreur : {e}"

def reverse_dns(ip: str) -> str:
    """Effectue une recherche DNS inversée."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Pas d'enregistrement PTR"

def check_port_open(target: str, port: int) -> bool:
    """Vérifie si un port TCP est ouvert."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, int(port)))
        sock.close()
        return result == 0
    except:
        return False

def parallel_port_scan(target: str, ports: List[int], threads: int = 20) -> Dict[str, bool]:
    """Effectue un scan de ports parallèle pour plus d'efficacité."""
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_port_open, target, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                results[str(port)] = future.result()
            except:
                results[str(port)] = False
    return results

def nmap_scan(target: str, options: str = "-sV -F") -> Dict[str, Any]:
    """Exécute un scan Nmap local et retourne les résultats parsés."""
    import subprocess
    import tempfile
    import os
    
    try:
        # Fichier temporaire pour la sortie XML
        fd, temp_path = tempfile.mkstemp(suffix='.xml')
        os.close(fd)
        
        # Commande nmap
        # On utilise --no-stylesheet pour éviter des problèmes de parsing
        cmd = ["nmap", "-oX", temp_path] + options.split() + [target]
        
        # Exécution (timeout 5 min)
        subprocess.run(cmd, check=True, timeout=300, capture_output=True)
        
        # Parsing
        results = parse_nmap_xml(temp_path)
        
        # Nettoyage
        os.remove(temp_path)
        
        return results
    except subprocess.CalledProcessError as e:
        return {"error": f"Erreur nmap: {e.stderr.decode()}"}
    except Exception as e:
        return {"error": str(e)}

def resolve_host(hostname: str) -> str:
    """Résout un nom d'hôte en adresse IP."""
    try:
        return socket.gethostbyname(hostname)
    except Exception as e:
        return f"Erreur de résolution : {e}"

def get_tools() -> Dict[str, Any]:
    """Retourne les définitions des outils pour ce module."""
    return {
        "expand_cidr": expand_cidr,
        "geolocate_ip": geolocate_ip,
        "get_public_ip": get_public_ip,
        "parse_nmap_xml": parse_nmap_xml,
        "port_knock": port_knock,
        "reverse_dns": reverse_dns,
        "resolve_host": resolve_host,
        "check_port_open": check_port_open,
        "parallel_port_scan": parallel_port_scan,
        "nmap_scan": nmap_scan
    }
