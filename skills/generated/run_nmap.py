import os
import subprocess
import shlex
from pymetasploit3.msfrpc import MsfRpcClient

def run_nmap(**kwargs):
    nmap_path = "/home/kali/msf_mcp/msf_aiv4/skills/external/nmap"
    for root, dirs, files in os.walk(nmap_path):
        for file in files:
            if file.endswith(("nmap", "nmap.exe")):
                nmap_executable = os.path.join(root, file)
                break
    else:
        return {"error": "Nmap executable not found in the specified directory."}

    nmap_args = " ".join([f"{k} {v}" for k, v in kwargs.items()])
    command = f"{nmap_executable} {nmap_args}"
    try:
        result = subprocess.run(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return {"stdout": result.stdout}
        else:
            return {"stderr": result.stderr}
    except Exception as e:
        return {"error": str(e)}

    msf_password = os.getenv('MSF_PASSWORD')
    if msf_password:
        try:
            client = MsfRpcClient(msf_password, port=int(os.getenv('MSF_PORT', 55553)), user='msf', server='127.0.0.1', ssl=False)
            console = client.consoles.console().cid
            client.consoles.console(console).write(command)
            return {"msf_console_output": client.consoles.console(console).read()}
        except Exception as e:
            return {"msf_error": str(e)}