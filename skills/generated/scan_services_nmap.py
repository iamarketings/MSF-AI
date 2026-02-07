import subprocess
import json
import re

def scan_services_nmap(target, ports="80,443,22,21"):
    """
    Scanne les services sur les ports spécifiés avec nmap
    """
    try:
        # Exécuter nmap avec détection de version et scripts par défaut
        cmd = ["nmap", "-sV", "-sC", "-p", ports, target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            return {"error": f"nmap failed: {result.stderr}"}
        
        output = result.stdout
        
        # Parser les résultats
        services = []
        current_port = None
        current_service = {}
        
        for line in output.split('\n'):
            # Détecter les lignes de port
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(.+)$', line.strip())
            if port_match:
                if current_port:
                    services.append(current_service)
                
                current_port = port_match.group(1)
                current_service = {
                    "port": current_port,
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                    "version": "",
                    "details": []
                }
            
            # Détecter les informations de version
            elif "Service Info:" in line:
                current_service["version"] = line.replace("Service Info:", "").strip()
            
            # Détecter les scripts nmap
            elif line.strip().startswith("|"):
                current_service["details"].append(line.strip())
        
        # Ajouter le dernier service
        if current_port:
            services.append(current_service)
        
        return {
            "target": target,
            "scan_output": output,
            "services": services,
            "command": " ".join(cmd)
        }
        
    except subprocess.TimeoutExpired:
        return {"error": "nmap scan timed out"}
    except Exception as e:
        return {"error": f"Error running nmap: {str(e)}"}