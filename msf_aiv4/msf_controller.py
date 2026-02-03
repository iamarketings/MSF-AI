#!/usr/bin/env python3
"""
Contrôleur MSF AI - Modèle MVC
Point d'entrée principal pour la logique de l'application.
"""
import os
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
    """Gère l'audit de toutes les actions effectuées par l'assistant."""
    def __init__(self, log_file="audit.log"):
        self.log_file = log_file

    def log_action(self, action, target, result, user="system"):
        import time
        with open(self.log_file, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp},{user},{action},{target},{result}\n")

class MSFAIController:
    """
    Contrôleur responsable de la coordination entre l'Utilisateur, l'IA et Metasploit.
    """
    def __init__(self):
        # Chercher le fichier .env dans le répertoire racine
        load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))
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

        # 3. Réflexion de l'IA
        print_thinking(True)

        try:
            # 4. Appel API
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

            # 5. Exécution des outils
            if tool_calls:
                self.conversation.add_message("assistant", content, tool_calls)

                for tc in tool_calls:
                    func_name = tc.function.name
                    args = json.loads(tc.function.arguments)

                    if func_name == "orchestrate_task":
                        # Passage à l'Orchestrateur
                        print_status("Mode Orchestration détecté (Langgraph)", "info")
                        results = self.orchestrator.execute_plan(args['objective'])

                        # Résumé détaillé renvoyé à l'IA
                        summary = {
                            "status": "completed",
                            "steps_executed": len(results),
                            "details": []
                        }
                        for step_id, res in results.items():
                            summary["details"].append({
                                "step": step_id,
                                "tool": res.get("tool"),
                                "success": res.get("success"),
                                "result_preview": str(res.get("result"))[:200] + "..." if res.get("result") else None,
                                "error": res.get("error")
                            })

                        self.conversation.add_tool_result(tc.id, json.dumps(summary, indent=2))

                    elif func_name in self.tools_map:
                        print_status(f"Exécution outil: {func_name}", "exec")
                        try:
                            # Audit log
                            self.audit.log_action(func_name, args.get('target', args.get('rhosts', 'N/A')), "pending")

                            # Appel de l'outil
                            res = self.tools_map[func_name](**args)
                            self.conversation.add_tool_result(tc.id, str(res))

                            # Update audit
                            self.audit.log_action(func_name, args.get('target', args.get('rhosts', 'N/A')), "success")
                        except Exception as e:
                            self.conversation.add_tool_result(tc.id, f"Erreur: {e}")
                            self.audit.log_action(func_name, args.get('target', args.get('rhosts', 'N/A')), f"error: {e}")
                    else:
                         self.conversation.add_tool_result(tc.id, "Outil non trouvé ou non activé directement.")

                # On finalise l'exécution sans récursion pour éviter les boucles infinies
                return self._finalize_tool_execution()

            # 6. Réponse finale
            if content:
                self.conversation.add_message("assistant", content)
                self.view.display_response(content)

        except Exception as e:
            print_status(f"Erreur traitement: {e}", "error")

    def _finalize_tool_execution(self):
        """Obtient la réponse finale de l'IA après l'exécution d'un ou plusieurs outils."""
        print_thinking(True)
        try:
            response = self.ai_client.chat.completions.create(
                model=self.api_model,
                messages=self.conversation.get_messages(),
                temperature=0.3
            )
            content = response.choices[0].message.content
            if content:
                self.conversation.add_message("assistant", content)
                self.view.display_response(content)
        except Exception as e:
            print_status(f"Erreur lors de la finalisation : {e}", "error")

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
