"""
Modèle MSF - Gère la connexion RPC Metasploit
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
        """Se connecte au service RPC MSF."""
        try:
            # Créer un contexte SSL personnalisé qui ignore la vérification (souvent nécessaire pour MSF RPC)
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
            # Le SSL est souvent désactivé dans les scripts de démarrage via le drapeau -S
            
            self.cid = self.client.consoles.console().cid
            return True
        except Exception as e:
            return False

    def search_modules(self, query: str) -> str:
        """Recherche des modules."""
        if not self.client: return "Non connecté"
        res = self.client.modules.search(query)
        if not res: return "Aucun module trouvé."
        # Limiter la sortie
        return str(res[:10])

    def get_module_info(self, module_path: str) -> str:
        """Récupère les informations d'un module."""
        try:
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
            return mod.description
        except Exception as e:
            return f"Erreur : {e}"

    def get_module_options(self, module_path: str) -> dict:
        """Récupère les options d'un module."""
        try:
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
            return mod.options
        except:
            return {}

    def check_vulnerability(self, module_path: str, options: dict) -> str:
        """Exécute la méthode 'check' d'un module."""
        try:
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
            # Définir les options
            for k,v in options.items():
                if k in mod.options:
                    mod[k] = v
                    
            res = mod.check()
            return str(res)
        except Exception as e:
            return f"Erreur de vérification : {e}"

    def run_exploit(self, module_path: str, options: dict) -> str:
        """Exécute un exploit."""
        try:
            mtype = module_path.split('/')[0]
            mname = '/'.join(module_path.split('/')[1:])
            mod = self.client.modules.use(mtype, mname)
             # Définir les options
            for k,v in options.items():
                if k in mod.options:
                    mod[k] = v
            
            job_id = mod.execute(payload=options.get('PAYLOAD', 'cmd/unix/reverse'))
            return f"Exploit lancé. ID de tâche (Job ID) : {job_id}"
        except Exception as e:
            return f"Erreur d'exploitation : {e}"

    def list_sessions(self) -> dict:
        """Liste les sessions actives."""
        if not self.client: return {}
        return self.client.sessions.list

    def session_execute(self, session_id: str, command: str) -> str:
        """Exécute une commande dans une session."""
        try:
            shell = self.client.sessions.session(str(session_id))
            shell.write(command)
            return f"Commande '{command}' envoyée à la session {session_id}"
        except Exception as e:
            return f"Erreur de session : {e}"
