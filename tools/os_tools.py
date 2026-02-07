"""
Outils d'Identification et d'Interaction OS pour MSF-AI v4
"""
import platform
import subprocess
import logging
from typing import Dict, Any, List

logger = logging.getLogger('MSF_AI.OSTools')

# Configuration partagée (définie par le contrôleur)
config = {"security_mode": "safe"}

def set_config(new_config: Dict[str, Any]):
    """Met à jour la configuration locale."""
    global config
    config.update(new_config)

def identify_local_os() -> Dict[str, str]:
    """Identifie le système d'exploitation local."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "is_wsl": "microsoft" in platform.uname().release.lower()
    }

def identify_session_os(client, session_id: int) -> str:
    """Identifie l'OS d'une session compromise."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return "Session non trouvée"
        return session.get("platform", "Inconnu")
    except Exception as e:
        return f"Erreur : {e}"

def execute_linux_command(command: str) -> str:
    """Exécute une commande sur un système Linux/WSL. Refuse les commandes dangereuses."""
    if platform.system() != "Linux":
        return "Erreur : Cet outil est uniquement disponible sur Linux/WSL."

    cmd_clean = command.strip().lower()

    # Vérification des commandes interdites (toujours active)
    forbidden = config.get("forbidden_commands", [])
    if any(f in cmd_clean for f in forbidden):
        return f"Blocage de sécurité critique : La commande contient un élément interdit ({forbidden})."

    # Vérification du mode safe
    if config.get("security_mode") == "safe":
        # Autoriser uniquement un ensemble très limité de commandes informationnelles
        allowed_prefixes = ["ls", "whoami", "id", "uname", "df", "free", "uptime", "cat /etc/os-release"]
        is_allowed = any(cmd_clean.startswith(prefix) for prefix in allowed_prefixes)
        if not is_allowed:
            return f"Blocage de sécurité : La commande '{command}' n'est pas autorisée en mode 'safe'. Passez en mode 'unsafe' pour exécuter des commandes arbitraires."

    try:
        # Exécution de la commande
        res = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        return res.stdout if res.stdout else res.stderr
    except Exception as e:
        return f"Erreur : {e}"

def execute_windows_command(command: str) -> str:
    """Exécute une commande sur un système Windows. Refuse les commandes dangereuses."""
    if platform.system() != "Windows":
        return "Erreur : Cet outil est uniquement disponible sur Windows."

    cmd_clean = command.strip().lower()

    # Vérification des commandes interdites (toujours active)
    forbidden = config.get("forbidden_commands", [])
    if any(f in cmd_clean for f in forbidden):
        return f"Blocage de sécurité critique : La commande contient un élément interdit ({forbidden})."

    # Vérification du mode safe
    if config.get("security_mode") == "safe":
        allowed_prefixes = ["dir", "whoami", "hostname", "ver", "systeminfo", "get-process"]
        is_allowed = any(cmd_clean.startswith(prefix) for prefix in allowed_prefixes)
        if not is_allowed:
            return f"Blocage de sécurité : La commande '{command}' n'est pas autorisée en mode 'safe'."

    try:
        res = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True, timeout=10)
        return res.stdout if res.stdout else res.stderr
    except Exception as e:
        return f"Erreur : {e}"

def check_wsl_presence() -> bool:
    """Vérifie si WSL est installé ou utilisé."""
    try:
        if platform.system() == "Linux":
            return "microsoft" in platform.uname().release.lower()
        if platform.system() == "Windows":
            res = subprocess.run(["wsl", "-l", "-v"], capture_output=True, text=True)
            return res.returncode == 0
        return False
    except:
        return False

def get_tools() -> Dict[str, Any]:
    """Retourne les outils de ce module."""
    return {
        "identify_local_os": identify_local_os,
        "identify_session_os": identify_session_os,
        "execute_linux_command": execute_linux_command,
        "execute_windows_command": execute_windows_command,
        "check_wsl_presence": check_wsl_presence
    }
