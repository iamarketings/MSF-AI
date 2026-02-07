import os
import subprocess
import shlex
from typing import Union, Dict

def run_sqlmap(**kwargs) -> Union[str, Dict[str, str]]:
    install_dir = '/home/kali/msf_mcp/msf_aiv4/skills/external/sqlmap'
    for root, dirs, files in os.walk(install_dir):
        for file in files:
            if file.endswith('.py') and file == 'sqlmap.py':
                executable_path = os.path.join(root, file)
                break
    else:
        return {"error": "Executable not found in the specified directory."}

    command = [executable_path]
    for key, value in kwargs.items():
        if value is not None:
            command.extend([f'--{key}', str(value)])
        else:
            command.append(f'--{key}')

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return {"stdout": result.stdout, "stderr": result.stderr}
    except Exception as e:
        return {"error": str(e)}