"""
MSF Model - Handles Metasploit RPC Connection
"""
import ssl
from pymetasploit3.msfrpc import MsfRpcClient

class MSFModel:
    def __init__(self, password, user="msf", port=55553, host="127.0.0.1"):
        self.password = password
        self.user = user
        self.port = port
        self.host = host
        self.client = None
        self.cid = None
        
    def connect(self) -> bool:
        """Connects to the MSF RPC service."""
        try:
            # Create a custom SSL context that ignores verification
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            self.client = MsfRpcClient(
                self.password, 
                port=self.port, 
                username=self.user,
                server=self.host,
                ssl=False
            )
            # SSL is disabled in start_mcp.sh via -S flag, so we must match it here.
            
            self.cid = self.client.consoles.console().cid
            return True
        except Exception as e:
            # print(f"Connection failed: {e}") # Let controller handle logging
            return False

    def search_modules(self, query: str) -> str:
        """Searches for modules."""
        if not self.client: return "Not connected"
        res = self.client.modules.search(query)
        if not res: return "No modules found."
        # Limit output
        return str(res[:10])

    def get_module_info(self, module_path: str) -> str:
        """Gets info about a module."""
        try:
            # Check type
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
            return mod.description
        except Exception as e:
            return f"Error: {e}"

    def get_module_options(self, module_path: str) -> dict:
        """Gets options for a module."""
        try:
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
            return mod.options
        except:
            return {}

    def check_vulnerability(self, module_path: str, options: dict) -> str:
        """Runs check method."""
        try:
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
            # Set options
            for k,v in options.items():
                if k in mod.options:
                    mod[k] = v
                    
            res = mod.check()
            return str(res)
        except Exception as e:
            return f"Check error: {e}"

    def run_exploit(self, module_path: str, options: dict) -> str:
        """Runs exploit."""
        try:
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
             # Set options
            for k,v in options.items():
                if k in mod.options:
                    mod[k] = v
            
            job_id = mod.execute(payload=options.get('PAYLOAD', 'cmd/unix/reverse'))
            return f"Exploit launched. Job ID: {job_id}"
        except Exception as e:
            return f"Exploit error: {e}"

    def list_sessions(self) -> dict:
        if not self.client: return {}
        return self.client.sessions.list

    def session_execute(self, session_id: str, command: str) -> str:
        try:
            shell = self.client.sessions.session(str(session_id))
            shell.write(command)
            return f"Command '{command}' sent to session {session_id}"
        except Exception as e:
            return f"Session error: {e}"
