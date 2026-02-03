"""
OS Identification and Interaction Tools for MSF-AI v4
"""
import platform
import subprocess
import logging
from typing import Dict, Any, List

logger = logging.getLogger('MSF_AI.OSTools')

# Shared configuration (will be set by the controller)
config = {"security_mode": "safe"}

def set_config(new_config: Dict[str, Any]):
    global config
    config.update(new_config)

def identify_local_os() -> Dict[str, str]:
    """Identifies the local operating system."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "is_wsl": "microsoft" in platform.uname().release.lower()
    }

def identify_session_os(client, session_id: int) -> str:
    """Identifies the OS of a compromised session."""
    try:
        session = client.sessions.session(str(session_id))
        if not session: return "Session not found"
        return session.get("platform", "Unknown")
    except Exception as e:
        return f"Error: {e}"

def execute_linux_command(command: str) -> str:
    """Executes a command on a Linux/WSL system. Refuses dangerous commands if in safe mode."""
    if platform.system() != "Linux":
        return "Error: This tool is only available on Linux/WSL."

    # Security check
    if config.get("security_mode") == "safe":
        # Allow only a very limited set of informational commands
        allowed_prefixes = ["ls", "whoami", "id", "uname", "df", "free", "uptime", "cat /etc/os-release"]
        is_allowed = any(command.strip().startswith(prefix) for prefix in allowed_prefixes)
        if not is_allowed:
            return f"Security Block: Command '{command}' is not allowed in safe mode. Switch to 'unsafe' mode to execute arbitrary commands."

    try:
        # Use a more secure execution method by avoiding shell=True if possible,
        # but for complex commands shell=True is often needed.
        # Here we still use shell=True but we've added the security check above.
        res = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        return res.stdout if res.stdout else res.stderr
    except Exception as e:
        return f"Error: {e}"

def execute_windows_command(command: str) -> str:
    """Executes a command on a Windows system. Refuses dangerous commands if in safe mode."""
    if platform.system() != "Windows":
        return "Error: This tool is only available on Windows."

    # Security check
    if config.get("security_mode") == "safe":
        allowed_prefixes = ["dir", "whoami", "hostname", "ver", "systeminfo", "get-process"]
        is_allowed = any(command.strip().lower().startswith(prefix) for prefix in allowed_prefixes)
        if not is_allowed:
            return f"Security Block: Command '{command}' is not allowed in safe mode."

    try:
        res = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True, timeout=10)
        return res.stdout if res.stdout else res.stderr
    except Exception as e:
        return f"Error: {e}"

def check_wsl_presence() -> bool:
    """Checks if WSL is installed or being used."""
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
    return {
        "identify_local_os": identify_local_os,
        "identify_session_os": identify_session_os,
        "execute_linux_command": execute_linux_command,
        "execute_windows_command": execute_windows_command,
        "check_wsl_presence": check_wsl_presence
    }
