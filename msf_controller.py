#!/usr/bin/env python3
"""
Contrôleur MSF AI - Modèle MVC
Point d'entrée principal pour la logique de l'application.
"""
import os
import re
import uuid
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from openai import OpenAI

# Ajouter le répertoire parent au chemin
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from msf_aiv4.msf_model import MSFModel
from msf_aiv4.msf_view import MSFView, print_status, print_thinking
from msf_aiv4.msf_rag import create_rag_library
from msf_aiv4.msf_orchestrator import LanggraphOrchestrator
from msf_aiv4.tools import network, web, postexp, reporting, recon, os_tools

# Configuration du logger
logging.basicConfig(
    filename='msf_ai.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MSF_AI.Controller')

class AuditLogger:
    """Gère l'audit détaillé de toutes les actions offensives en format JSON."""
    def __init__(self, log_file="audit.json"):
        self.log_file = log_file

    def log_action(self, action, target, params, result, status="pending", user="system"):
        import time
        import json
        entry = {
            "timestamp": time.time(),
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": user,
            "action": action,
            "target": target,
            "params": params,
            "result": str(result)[:500] if result else None,
            "status": status
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

class MSFAIController:
    """
    Contrôleur responsable de la coordination entre l'Utilisateur, l'IA et Metasploit.
    """
    def __init__(self):
        # Chercher le fichier .env dans le répertoire msf_aiv4
        load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
        self.config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        self.config = self._load_config()

        # Configuration
        self.deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
        self.msf_pass = os.getenv("MSF_RPC_PASS")
        self.msf_user = os.getenv("MSF_RPC_USER", "msf")
        self.msf_port = self.config.get("msf_rpc_port", int(os.getenv("MSF_RPC_PORT", 55553)))

        # Composants
        self.msf = MSFModel(self.msf_pass, port=self.msf_port, user=self.msf_user)
        self.view = MSFView()
        self.rag = None
        self.orchestrator = None
        self.ai_client = None
        self.api_model = self.config.get("api_model", "deepseek-chat")

        # Outils
        self.tools_map = {}
        self.tools_def = []

        # État
        self.conversation = ConversationHistory()
        self.audit = AuditLogger()

    def _load_config(self) -> Dict[str, Any]:
        """Charge la configuration depuis le fichier JSON."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return {"security_mode": "safe", "api_model": "deepseek-chat", "msf_rpc_port": 55553}

    def _save_config(self):
        """Sauvegarde la configuration dans le fichier JSON."""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)

    def set_security_mode(self, mode: str) -> str:
        """Définit le mode de sécurité (safe ou unsafe)."""
        if mode.lower() in ["safe", "unsafe"]:
            self.config["security_mode"] = mode.lower()
            self._save_config()
            return f"Mode de sécurité défini sur {mode}"
        return "Mode invalide. Utilisez 'safe' ou 'unsafe'."

    def initialize(self) -> bool:
        """Initialise tous les sous-systèmes."""
        print_status("Initialisation du système...", "info")

        # 1. RAG
        print_status("Chargement de la base de connaissances RAG...", "info")
        try:
            self.rag = create_rag_library()
        except Exception as e:
            print_status(f"Attention: RAG non disponible ({e})", "warning")

        # 2. Connexion MSF
        print_status(f"Connexion à Metasploit RPC ({self.msf.host}:{self.msf.port})...", "info")
        if not self.msf.connect():
            # Avertir mais autoriser la continuation pour les outils hors-ligne
            print_status("Attention: MSF RPC non connecté. Modules d'exploitation indisponibles.", "warning")
        else:
            print_status("Connexion Metasploit réussie", "success")

        # 3. Connexion IA (Configurable)
        try:
            api_base_url = os.getenv("API_BASE_URL", "https://api.deepseek.com")
            self.api_model = os.getenv("API_MODEL", "deepseek-chat")

            self.ai_client = OpenAI(api_key=self.deepseek_api_key, base_url=api_base_url)
            print_status(f"Connexion API réussie ({api_base_url})", "success")
        except Exception as e:
            print_status(f"Erreur fatale API: {e}", "error")
            return False

        # 4. Construction des outils
        self._build_tools_map()
        self._build_tools_def()

        # 5. Initialisation de l'Orchestrateur
        self.orchestrator = LanggraphOrchestrator(self.ai_client, self.config, self.tools_map, self.api_model)

        return True

    def _build_tools_map(self):
        """Agrège tous les outils dans une carte unique."""
        # Outils MSF de base
        self.tools_map.update({
            "search_knowledge_base": self.rag.retrieve_context if self.rag else lambda q: "RAG Indisponible",
            "search_vulnerabilities": self.rag.retrieve_vulnerabilities if self.rag else lambda p, v=None: [],
            "search_msf_modules": self.msf.search_modules,
            "get_module_info": self.msf.get_module_info,
            "get_module_options": self.msf.get_module_options,
            "check_vulnerability": self.msf.check_vulnerability,
            "run_exploit": self.msf.run_exploit,
            "list_sessions": self.msf.list_sessions,
            "session_execute": self.msf.session_execute,
            "set_security_mode": self.set_security_mode
        })

        # Outils Réseau
        self.tools_map.update(network.get_tools())

        # Outils Web
        self.tools_map.update(web.get_tools())

        # Outils de Rapport
        self.tools_map.update(reporting.get_tools())

        # Outils de Reconnaissance
        self.tools_map.update(recon.get_tools())

        # Outils OS
        os_tools.set_config(self.config)
        self.tools_map.update(os_tools.get_tools())

        # Outils Post-Exploitation (Injection du client/session)
        post_tools = postexp.get_tools()
        # Combiner avec les outils OS nécessitant le client
        client_tools = {**post_tools, "identify_session_os": os_tools.identify_session_os}
        for name, func in client_tools.items():
            # Création d'une fermeture pour capturer la fonction correcte
            def create_wrapper(f):
                return lambda **kwargs: f(self.msf.client, **kwargs)
            self.tools_map[name] = create_wrapper(func)

    def _build_tools_def(self):
        """Construit la définition JSON des outils pour l'IA."""
        self.tools_def = [
            {
                "type": "function",
                "function": {
                    "name": "search_knowledge_base",
                    "description": "Recherche dans la base de connaissances interne pour les exploits, tags et bonnes pratiques. Utilisez ceci pour trouver des vecteurs d'attaque réussis.",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string", "description": "Requête de recherche (ex: 'EternalBlue', 'RCE')"}},
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_vulnerabilities",
                    "description": "Recherche des signatures de vulnérabilité par produit et version. Utilisez ceci pour ANTICIPER les attaques.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "product": {"type": "string", "description": "Nom du produit (ex: 'Apache', 'Windows')"},
                            "version": {"type": "string", "description": "Chaîne de version (optionnel)"}
                        },
                        "required": ["product"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_msf_modules",
                    "description": "Recherche des modules Metasploit par mot-clé (ex: 'bluekeep', 'smb'). Retourne jusqu'à 10 résultats.",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string", "description": "Mot-clé de recherche ou CVE"}},
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_exploit",
                    "description": "Exécute un module Metasploit spécifié avec des options données.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "module_path": {"type": "string", "description": "Chemin complet du module (ex: 'exploit/windows/smb/ms17_010_eternalblue')"},
                            "options": {"type": "object", "description": "Options du module sous forme de paires clé-valeur (ex: {'RHOSTS': '192.168.1.1'})"}
                        },
                        "required": ["module_path", "options"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "check_port_open",
                    "description": "Effectue une vérification rapide de port TCP sur un hôte cible.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Adresse IP ou nom d'hôte"},
                            "port": {"type": "integer", "description": "Numéro de port TCP"}
                        },
                        "required": ["target", "port"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "orchestrate_task",
                    "description": "MODE EXPERT : Exécution autonome hautement efficace d'objectifs de sécurité complexes. Utilisez ceci pour toute opération multi-étapes. Gère automatiquement les dépendances et le contexte.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "objective": {"type": "string", "description": "L'objectif de sécurité de haut niveau à atteindre."}
                        },
                        "required": ["objective"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "set_security_mode",
                    "description": "Définit le mode de sécurité de l'application.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "mode": {"type": "string", "enum": ["safe", "unsafe"], "description": "Le mode de sécurité à définir"}
                        },
                        "required": ["mode"]
                    }
                }
            }
        ]

    def process_input(self, user_input: str):
        """Itération de la boucle principale de traitement."""
        user_input = user_input.strip()
        # On n'accepte plus d'entrée vide pour éviter les boucles infinies de l'IA
        if not user_input:
            return

        # 0. Gestion des commandes locales
        if user_input.lower() in ['exit', 'quit']:
            sys.exit(0)

        if user_input.lower() == 'help':
            self.view.show_help()
            return

        if user_input.lower() == 'stats':
            self.view.show_stats(self.conversation)
            return

        if user_input.lower() == 'config':
            self.view.show_config(self.config)
            return

        if user_input.lower() == 'clear':
            os.system('clear' if os.name == 'posix' else 'cls')
            return

        if user_input.lower() == 'sessions':
            sessions = self.msf.list_sessions()
            print("\n─── 💻 Sessions Actives ────────────────────────────────────────────────────────────────────────────────────────")
            if not sessions:
                print("  Aucune session active.")
            else:
                for sid, info in sessions.items():
                    print(f"  [{sid}] {info.get('type')} - {info.get('info')} ({info.get('session_host')})")
            print("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
            return

        if user_input.lower().startswith('security '):
            parts = user_input.split(' ')
            if len(parts) > 1:
                mode = parts[1]
                print_status(self.set_security_mode(mode), "info")
            return

        if user_input.lower().startswith('set '):
            parts = user_input.split(' ')
            if len(parts) > 2:
                key = parts[1].upper()
                value = parts[2]
                self.orchestrator.context[key] = value
                print_status(f"Contexte mis à jour : {key} = {value}", "success")
            return

        # 1. Ajouter le message utilisateur
        self.conversation.add_message("user", user_input)

        # 2. Amélioration RAG
        enhanced_prompt = user_input
        if self.rag:
            print_status("Recherche de contexte RAG...", "info")
            enhanced_prompt = self.rag.enhance_prompt(user_input)
            self.conversation.add_temporary_context(enhanced_prompt)

        # 3. Lancer la boucle d'exécution (tour de conversation)
        self._execute_turn()

    def _execute_turn(self, recursion_depth=0):
        """
        Exécute un tour de conversation complet de manière récursive.
        Gère l'appel API, le parsing (Natif/DSML), l'exécution des outils, et la boucle de retour.
        """
        if recursion_depth > 10:
            print_status("Limite de récursion atteinte (boucle infinie potentielle).", "warning")
            return

        print_thinking(True)
        try:
            # 4. Appel API (avec définition des outils)
            response = self.ai_client.chat.completions.create(
                model=self.api_model,
                messages=self.conversation.get_messages(),
                tools=self.tools_def,
                tool_choice="auto",
                stream=False,
                temperature=0.3
            )

            msg = response.choices[0].message
            content = msg.content
            tool_calls = msg.tool_calls

            # 5. Détection DSML (Fallback si pas d'appels natifs)
            if not tool_calls and content and "DSML" in content and "invoke" in content:
                print_status("Format DSML détecté - Tentative d'extraction...", "info")
                dsml_tools = self._parse_dsml(content)
                if dsml_tools:
                     print_status(f"  > {len(dsml_tools)} outils extraits via DSML", "info")
                     tool_calls = dsml_tools

            # 6. Traitement des Outils (Natif ou DSML)
            if tool_calls:
                # Ajout du message de l'assistant (avec tool_calls si natif, ou contenu si DSML)
                # Si DSML, on garde le contenu car il contient souvent du texte explicatif utile
                self.conversation.add_message("assistant", content, tool_calls if not (content and "DSML" in content) else None)
                
                # Si c'est du DSML, on doit ajouter les tool_calls manuellement ou simuler ? 
                # L'implémentation de add_message gère nativement tool_calls.
                # Pour DSML, on a extrait des "FakeToolCall". On les traite comme des vrais.
                
                executed_some = False
                for tc in tool_calls:
                    func_name = tc.function.name
                    try:
                        args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        self.conversation.add_tool_result(tc.id, "Erreur: Arguments JSON invalides")
                        continue

                    executed_some = True
                    if func_name == "orchestrate_task":
                        print_status("Mode Orchestration détecté (Langgraph)", "info")
                        results = self.orchestrator.execute_plan(args.get('objective', ''))
                        summary = {
                            "status": "completed",
                            "steps": len(results),
                            "details": [f"{v.get('tool')}: {v.get('success')}" for k,v in results.items()]
                        }
                        self.conversation.add_tool_result(tc.id, json.dumps(summary, indent=2))

                    elif func_name in self.tools_map:
                        print_status(f"Exécution outil: {func_name}", "exec")
                        target = args.get('target', args.get('rhosts', args.get('url', 'N/A')))
                        try:
                            self.audit.log_action(func_name, target, args, None, "pending")
                            res = self.tools_map[func_name](**args)
                            self.conversation.add_tool_result(tc.id, str(res))
                            self.audit.log_action(func_name, target, args, res, "success")
                        except Exception as e:
                            self.conversation.add_tool_result(tc.id, f"Erreur: {e}")
                            self.audit.log_action(func_name, target, args, str(e), "error")
                    else:
                         self.conversation.add_tool_result(tc.id, f"Outil '{func_name}' inconnu")

                # RECURSION : On relance le tour pour que l'IA réagisse aux résultats
                if executed_some:
                    return self._execute_turn(recursion_depth + 1)

            # 7. Réponse Finale (Pas d'outils, juste du texte)
            if content:
                # Si on n'a pas traité d'outils (ou si c'est du texte final après outils)
                # Note: si tool_calls était présent, on a déjà ajouté le message plus haut.
                # MAIS si c'était le dernier tour, on veut afficher.
                if not tool_calls:
                    self.conversation.add_message("assistant", content)
                    self.view.display_response(content)
                elif "DSML" in content:
                     # Cas spécial: DSML traité, mais on veut peut-être afficher le texte autour?
                     # Souvent l'IA affiche le texte PUIS les commandes.
                     # On affiche le texte pour info utilisateur
                     pass # Déjà affiché via display lors de l'input? Non.
                     # On pourrait afficher le texte d'explication.
                     # self.view.display_response(content) 
                     pass

        except Exception as e:
            print_status(f"Erreur traitement: {e}", "error")
            import traceback
            traceback.print_exc()

    def _parse_dsml(self, content: str) -> List[Any]:
        """Parse les balises DSML pour extraire les appels d'outils."""
        tool_calls = []
        
        # Regex pour capturer les blocs invoke
        invoke_pattern = r'<[\|｜]DSML[\|｜]invoke name="([^"]+)"(?:[^>]*?)>([\s\S]*?)<\/[\|｜]DSML[\|｜]invoke>'
        matches = re.finditer(invoke_pattern, content)
        
        class FakeToolCall:
            def __init__(self, id, name, args):
                self.id = id
                self.type = 'function'
                self.function = type('obj', (object,), {'name': name, 'arguments': args})
        
        for match in matches:
            tool_name = match.group(1)
            body = match.group(2)
            
            args = {}
            # Regex permissive pour les paramètres
            param_pattern = r'<[\|｜]DSML[\|｜]parameter name="([^"]+)"(?:[^>]*?)>(.*?)<\/[\|｜]DSML[\|｜]parameter>'
            params = re.finditer(param_pattern, body)
            
            for p in params:
                key = p.group(1)
                val = p.group(2)
                if val.lower() == 'true': val = True
                elif val.lower() == 'false': val = False
                elif val.isdigit(): val = int(val)
                args[key] = val
                
            tool_calls.append(FakeToolCall(
                id=f"call_{uuid.uuid4().hex[:8]}",
                name=tool_name,
                args=json.dumps(args)
            ))
            
        return tool_calls

class ConversationHistory:
    """Gère l'historique de la conversation."""
    def __init__(self):
        self.messages = [{
            "role": "system",
            "content": """Vous êtes MSF-AI, un assistant expert en tests d'intrusion propulsé par Metasploit.
            Votre objectif est d'être hautement efficace dans les évaluations de sécurité.

            Directives :
            1. Utilisez 'orchestrate_task' pour tout objectif complexe ou multi-étapes. C'est plus efficace que l'appel d'outils manuel.
            2. Utilisez 'search_vulnerabilities' et 'search_knowledge_base' pour ANTICIPER PROACTIVEMENT les attaques lorsque des services sont identifiés.
            3. Pour des vérifications simples (ex: vérifier un port), utilisez les outils spécifiques directement.
            4. Vérifiez toujours le 'security_mode' avant d'effectuer toute action potentiellement intrusive.
            5. Si un outil échoue, analysez l'erreur et essayez une approche ou un outil alternatif.
            6. Fournissez des réponses concises et techniques.
            7. Vous pouvez manipuler votre propre configuration via 'set_security_mode' si l'utilisateur le demande.
            """
        }]
        self.temp_context = None

    def add_message(self, role, content, tool_calls=None):
        msg = {"role": role, "content": content}
        if tool_calls: msg["tool_calls"] = tool_calls
        if content: self.messages.append(msg)
        if tool_calls and not content:
             msg["content"] = None
             self.messages.append(msg)

    def add_tool_result(self, tool_call_id, result):
        self.messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result
        })

    def add_temporary_context(self, context):
        """Ajoute un contexte RAG qui ne s'applique qu'au tour suivant."""
        self.temp_context = context

    def get_messages(self):
        # Appliquer le contexte temporaire s'il existe
        if self.temp_context and self.messages[-1]['role'] == 'user':
             msgs = self.messages[:-1] + [{"role": "user", "content": self.temp_context}]
             return msgs
        return self.messages

# Aide globale pour readline
import readline

def setup_readline():
    """Configure readline pour l'historique et la complétion."""
    histfile = os.path.join(os.path.expanduser("~"), ".msf_ai_history")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass

    import atexit
    atexit.register(readline.write_history_file, histfile)

    # Complétion de base
    commands = ['help', 'stats', 'sessions', 'config', 'security', 'clear', 'exit', 'quit', 'safe', 'unsafe']
    def completer(text, state):
        options = [c for c in commands if c.startswith(text)]
        if state < len(options):
            return options[state]
        else:
            return None

    readline.set_completer(completer)
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")

def save_history():
    histfile = os.path.join(os.path.expanduser("~"), ".msf_ai_history")
    readline.write_history_file(histfile)

# Exécution directe
if __name__ == "__main__":
    controller = MSFAIController()
    setup_readline()
    if controller.initialize():
        controller.view.show_banner()
        while True:
            try:
                security = controller.config.get("security_mode", "safe").upper()
                sessions = controller.msf.list_sessions()
                session_count = len(sessions) if sessions else 0
                session_label = f"{session_count} SESSION(S)" if session_count > 0 else "NO SESSION"

                # Cible actuelle
                target = controller.orchestrator.context.get('RHOSTS')

                user_input = controller.view.get_input(session=session_label, security=security, target=target)
                controller.process_input(user_input)
            except KeyboardInterrupt:
                print("\nAu revoir!")
                save_history()
                break
