import os
import sys
import ast
import importlib.util
import traceback
from typing import Dict, Any, List, Callable

class SkillManager:
    """
    Gère la création, la validation et le chargement dynamique de nouvelles compétences (outils).
    Permet à l'IA d'étendre ses propres capacités.
    """
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.skills_dir = os.path.join(base_dir, "skills", "generated")
        self.external_dir = os.path.join(base_dir, "skills", "external")
        self.skills_map: Dict[str, Callable] = {}
        
        # Config de l'Architecte
        self.architect_key = os.getenv("OPENROUTER_API_KEY")
        # Par défaut, on tente le modèle le plus puissant si la variable d'env est manquante
        self.architect_model = os.getenv("ARCHITECT_MODEL", "qwen/qwen-max")
        
        # S'assurer que le répertoire existe
        os.makedirs(self.skills_dir, exist_ok=True)
        os.makedirs(self.external_dir, exist_ok=True)
        
        # Charger les compétences existantes au démarrage
        self.reload_all_skills()

    def install_external_tool(self, tool_name: str, install_cmd: str, usage_description: str) -> str:
        """
        Installe un outil externe et génère un wrapper Python via l'Architecte.
        """
        import subprocess
        import shlex

        print(f"[SkillManager] Installation de l'outil '{tool_name}'...")
        
        # 1. Exécution de la commande d'installation
        try:
            # Sécurité basique : on empêche les ".." pour sortir du dossier
            if ".." in install_cmd or install_cmd.startswith("/"):
                 return "Erreur Sécurité: Chemins absolus ou relatifs parents interdits."

            # On exécute dans le dossier external
            process = subprocess.run(
                install_cmd, 
                shell=True, 
                cwd=self.external_dir, 
                capture_output=True, 
                text=True,
                timeout=300 # 5 minutes max pour install
            )
            
            if process.returncode != 0:
                return f"Erreur Installation: {process.stderr}"
                
            print(f"[SkillManager] Installation réussie. Sortie: {process.stdout[:100]}...")

        except Exception as e:
            return f"Exception Installation: {e}"

        # 2. Génération du Wrapper par l'Architecte
        print(f"[SkillManager] Demande à l'Architecte ({self.architect_model}) de créer le wrapper pour '{tool_name}'...")
        
        prompt_desc = f"""
        L'outil '{tool_name}' a été installé dans le dossier: {os.path.join(self.external_dir, tool_name)} (ou similaire selon la commande git/apt).
        Commande d'installation utilisée: {install_cmd}
        Description d'usage: {usage_description}
        
        TACHE: Créer une fonction Python wrapper nommée 'run_{tool_name}' qui :
        1. Trouve l'exécutable (ex: cherche .py, .sh ou binaire dans le dossier d'install).
        2. Prend des arguments (**kwargs) correspondant aux flags de l'outil.
        3. Construit la commande CLI et l'exécute via subprocess.run.
        4. Retourne stdout ou stderr.
        """
        
        wrapper_name = f"run_{tool_name}"
        wrapper_code = self._generate_code_via_architect(wrapper_name, prompt_desc)
        
        if not wrapper_code:
            return "Erreur: L'Architecte n'a pas pu générer le wrapper."

        # 3. Sauvegarde et Chargement
        return self.create_skill(wrapper_name, wrapper_code, "Wrapper généré automatiquement")

    def create_skill(self, name: str, code: str = None, description: str = "") -> str:
        """
        Crée un nouveau module de compétence.
        
        Args:
            name: Le nom de la fonction.
            code: Le code source. SI NON FOURNI, l'Architecte (OpenRouter) le générera.
            description: Description requise si le code est manquant.
        """
        # 1. Génération par l'Architecte si code manquant
        if not code:
            if not self.architect_key:
                return "Erreur: Code non fourni et OPENROUTER_API_KEY manquante. Impossible de générer."
            if not description:
                return "Erreur: Une description est requise pour la génération automatique."
                
            print(f"[SkillManager] Délégation à l'Architecte ({self.architect_model}) pour '{name}'...")
            code = self._generate_code_via_architect(name, description)
            if not code:
               return "Erreur: L'Architecte n'a pas pu générer le code."
            print(f"[SkillManager] Code généré par l'Architecte (taille: {len(code)})")

        # 2. Validation du nom
        if not name.isidentifier():
            return f"Erreur: '{name}' n'est pas un identifiant Python valide."
            
        # 3. Validation de la syntaxe
        try:
            ast.parse(code)
        except SyntaxError as e:
            return f"Erreur de syntaxe dans le code: {e}"
            
        # 4. Vérification que la fonction existe
        if f"def {name}" not in code:
            return f"Erreur: Le code doit contenir 'def {name}(...)'."

        # 5. Écriture du fichier
        file_path = os.path.join(self.skills_dir, f"{name}.py")
        try:
            with open(file_path, "w") as f:
                f.write(code)
        except Exception as e:
            return f"Erreur écriture fichier: {e}"

        # 6. Test de chargement
        error = self._load_skill_module(name, file_path)
        if error:
            os.remove(file_path)
            return f"Échec chargement (Skill rejeté): {error}"
            
        return f"Succès: Compétence '{name}' créée par l'Architecte et chargée."

    def _generate_code_via_architect(self, name: str, description: str) -> str:
        """Interroge OpenRouter pour générer le code."""
        import requests
        try:
            headers = {
                "Authorization": f"Bearer {self.architect_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/msf-ai", # Requis par OpenRouter
                "X-Title": "MSF-AI"
            }
            prompt = f"""
            Tâche: Écrire une fonction Python autonome pour un outil de test d'intrusion.
            Nom de la fonction: {name}
            Description: {description}
            
            Contraintes:
            - Code Python 3 pur.
            - Doit inclure TOUS les imports nécessaires (subprocess, os, shlex, etc.).
            - **ACCÈS API**: Si l'outil nécessite une clé API, récupérez-la via `os.getenv('NOM_VARIABLE')`.
            - **ACCÈS METASPLOIT**: Si l'outil doit interagir avec Metasploit:
                - Importez `from pymetasploit3.msfrpc import MsfRpcClient`
                - Connectez-vous via: `client = MsfRpcClient(os.getenv('MSF_PASSWORD'), port=int(os.getenv('MSF_PORT', 55553)), user='msf', server='127.0.0.1', ssl=False)`
                - Utilisez `client` pour manipuler consoles, jobs, etc.
            - Doit gérer ses propres erreurs (try/except) et retourner un résultat lisible (str ou dict).
            - PAS de markdown, PAS de commentaires explicatifs hors du code.
            - Code SEULEMENT (pas de ```python).
            """
            
            data = {
                "model": self.architect_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2
            }
            
            resp = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data, timeout=60)
            if resp.status_code == 200:
                content = resp.json()['choices'][0]['message']['content']
                # Nettoyage du markdown ```python
                content = content.replace("```python", "").replace("```", "").strip()
                return content
            else:
                print(f"Erreur API Architecte: {resp.text}")
                return None
        except Exception as e:
            print(f"Exception Architecte: {e}")
            return None

    def _load_skill_module(self, name: str, path: str) -> str:
        """Charge un module dynamiquement."""
        try:
            spec = importlib.util.spec_from_file_location(f"msf_aiv4.skills.generated.{name}", path)
            if not spec or not spec.loader:
                return "Impossible de créer le spec module."
                
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"msf_aiv4.skills.generated.{name}"] = module
            spec.loader.exec_module(module)
            
            # Récupérer la fonction
            if hasattr(module, name):
                func = getattr(module, name)
                if callable(func):
                    self.skills_map[name] = func
                    return None # Succès
                return f"'{name}' a été trouvé mais n'est pas appelable."
            return f"La fonction '{name}' n'a pas été trouvée dans le module."
            
        except Exception as e:
            return f"Exception lors du chargement: {e}\n{traceback.format_exc()}"

    def reload_all_skills(self):
        """Recharge toutes les compétences présentes dans le dossier."""
        loaded = 0
        errors = 0
        for filename in os.listdir(self.skills_dir):
            if filename.endswith(".py") and filename != "__init__.py":
                name = filename[:-3]
                path = os.path.join(self.skills_dir, filename)
                err = self._load_skill_module(name, path)
                if not err:
                    loaded += 1
                else:
                    print(f"[SkillManager] Erreur chargement {name}: {err}")
                    errors += 1
        return loaded, errors

    def get_tools_definitions(self) -> List[Dict[str, Any]]:
        """Génère les définitions JSON pour l'API LLM pour toutes les compétences chargées."""
        defs = []
        for name, func in self.skills_map.items():
            # Création d'une définition basique basée sur la docstring
            doc = func.__doc__ or "Compétence générée automatiquement."
            defs.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": f"[AUTO-GENERATED] {doc}",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "arg1": {"type": "string", "description": "Argument générique (voir code)"} # TODO: Inspection plus fine si possible
                        }
                    }
                }
            })
        return defs
