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
from msf_aiv4.msf_orchestrator import LanggraphOrchestrator, AuditLogger
from msf_aiv4.tools import network, web, postexp, reporting, recon, os_tools
from msf_aiv4.skill_manager import SkillManager

# Configuration du logger
logging.basicConfig(
    filename='msf_ai.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MSF_AI.Controller')



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
        self.audit = AuditLogger("audit_full.jsonl")
        
        # Init Skill Manager
        self.skill_manager = SkillManager(os.path.dirname(__file__))

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

        # 4. Orchestrateur
        self.orchestrator = LanggraphOrchestrator(self.ai_client, self.config, self.tools_map, self.audit, self.api_model)

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
            "wait_for_job": self.msf.wait_for_job,
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

        # Outil d'évolution (SkillManager)
        self.tools_map["create_new_skill"] = self.skill_manager.create_skill
        self.tools_map["install_external_tool"] = self.skill_manager.install_external_tool

        # Ajouter les skills générés
        self.tools_map.update(self.skill_manager.skills_map)

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
                    "name": "wait_for_job",
                    "description": "Attend la fin d'une tâche Metasploit (scan ou exploit) pour récupérer le résultat.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "job_id": {"type": "string", "description": "L'ID de la tâche retourné par run_exploit ou auxiliary."},
                            "timeout": {"type": "integer", "description": "Temps d'attente maximum en secondes (défaut: 60)."}
                        },
                        "required": ["job_id"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "resolve_host",
                    "description": "Résout un nom de domaine en adresse IP (essentiel pour les outils ne supportant pas le DNS).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "hostname": {"type": "string", "description": "Nom de domaine à résoudre (ex: comorestelecom.km)"}
                        },
                        "required": ["hostname"]
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
                    "name": "parallel_port_scan",
                    "description": "Scan de ports multi-threadé rapide (plus rapide que check_port_open).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Adresse IP cible"},
                            "ports": {"type": "array", "items": {"type": "integer"}, "description": "Liste de ports à scanner"},
                            "threads": {"type": "integer", "description": "Nombre de threads (défaut: 20)"}
                        },
                        "required": ["target", "ports"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "nmap_scan",
                    "description": "Exécute un scan Nmap local et retourne les résultats. À PRIVILÉGIER pour la reconnaissance.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "IP ou plage CIDR"},
                            "options": {"type": "string", "description": "Options Nmap (ex: '-sV -F' ou '-p- -A'). Défaut: '-sV -F'"}
                        },
                        "required": ["target"]
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
                    "name": "create_new_skill",
                    "description": "CRITIQUE: Crée un nouvel outil Python pour combler une lacune. Utiliser quand aucun autre outil ne suffit.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Nom de la fonction (ex: 'extract_exif')"},
                            "description": {"type": "string", "description": "Description précise pour l'Architecte (si code absent)."},
                            "code": {"type": "string", "description": "Code complet (OPTIONNEL: Si vide, l'Architecte le générera)."}
                        },
                        "required": ["name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "install_external_tool",
                    "description": "INSTALLE UN OUTIL EXTERNE (ex: git clone) et crée automatiquement un wrapper Python. À utiliser pour les outils complexes (sqlmap, nuclei...).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "tool_name": {"type": "string", "description": "Nom de l'outil (ex: 'sqlmap')"},
                            "install_cmd": {"type": "string", "description": "Commande Bash pour installer (ex: 'git clone ...')"},
                            "usage_description": {"type": "string", "description": "Explication de comment utiliser l'outil en CLI, pour que l'Architecte puisse créer le wrapper."}
                        },
                        "required": ["tool_name", "install_cmd", "usage_description"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "save_vulnerability_report",
                    "description": "OBLIGATOIRE: Sauvegarde un rapport détaillé de vulnérabilité découverte. À utiliser IMMÉDIATEMENT après la découverte d'une faille.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "URL ou IP de la cible"},
                            "vulnerability": {
                                "type": "object",
                                "description": "Objet contenant: type (SQLi/XSS/RCE...), severity (low/medium/high/critical), description, evidence, remediation",
                                "properties": {
                                    "type": {"type": "string"},
                                    "severity": {"type": "string"},
                                    "description": {"type": "string"},
                                    "evidence": {"type": "string"},
                                    "remediation": {"type": "string"}
                                },
                                "required": ["type", "severity", "description"]
                            }
                        },
                        "required": ["target", "vulnerability"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "save_exploit_result",
                    "description": "Sauvegarde le résultat d'une tentative d'exploitation (succès ou échec).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Cible exploitée"},
                            "exploit_name": {"type": "string", "description": "Nom de l'exploit utilisé"},
                            "result": {
                                "type": "object",
                                "description": "Résultat: success (bool), output, session_id, error...",
                                "properties": {
                                    "success": {"type": "boolean"},
                                    "output": {"type": "string"},
                                    "session_id": {"type": "string"}
                                }
                            }
                        },
                        "required": ["target", "exploit_name", "result"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "save_scan_results",
                    "description": "Sauvegarde les résultats d'un scan (ports, subdomains, directories...).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Cible scannée"},
                            "scan_type": {"type": "string", "description": "Type: port_scan, subdomain_discovery, directory_enum..."},
                            "results": {"type": "object", "description": "Résultats du scan sous forme d'objet ou liste"}
                        },
                        "required": ["target", "scan_type", "results"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "generate_summary_report",
                    "description": "Génère un rapport de synthèse complet pour une cible donnée (agrège toutes les vulnérabilités/scans/exploits).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Cible pour laquelle générer le rapport de synthèse"}
                        },
                        "required": ["target"]
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
                
                # Mise à jour du prompt système dynamique
                self.conversation.update_context(key, value)
                if key == "RHOSTS":
                    self.conversation.update_context("TARGET", value)
                    # Tentative de résolution automatique
                    try:
                        resolved_ip = network.resolve_host(value)
                        if "Erreur" not in resolved_ip:
                            self.conversation.update_context("TARGET_IP", resolved_ip)
                            print_status(f"Résolution automatique: {value} -> {resolved_ip}", "success")
                    except:
                        pass
                    
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
        # Augmentation de la limite pour permettre des audits plus longs
        if recursion_depth > 30:
            print_status("Limite d'autonomie atteinte (30 actions). Pause de sécurité.", "warning")
            return

        print_thinking(True)
        try:
            # 4. Appel API (avec définition des outils)
            if self.audit:
                 self.audit.log_action("LLM_REQUEST", "API", self.conversation.get_messages(), None, "pending")
            
            response = self.ai_client.chat.completions.create(
                model=self.api_model,
                messages=self.conversation.get_messages(),
                tools=self.tools_def,
                tool_choice="auto",
                stream=False,
                temperature=0.3
            )
            
            if self.audit:
                 self.audit.log_action("LLM_RESPONSE", "API", None, response.model_dump(), "success")

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

                    elif func_name == "create_new_skill":
                        # CRÉATION DE SKILL
                        print_status(f"🔧 CRÉATION SKILL: {args.get('name')}", "warning")
                        res = self.skill_manager.create_skill(args.get('name'), args.get('code'), args.get('description', ''))
                        
                        if "Succès" in res:
                            # Recharger les outils immédiatement
                            self._build_tools_map()
                        
                        self.conversation.add_tool_result(tc.id, res)

                    elif func_name == "install_external_tool":
                        # INSTALLATION D'OUTIL
                        print_status(f"⬇️ INSTALLATION OUTIL: {args.get('tool_name')}", "warning")
                        res = self.skill_manager.install_external_tool(args.get('tool_name'), args.get('install_cmd'), args.get('usage_description'))
                        
                        if "Succès" in res:
                            self._build_tools_map()
                        
                        self.conversation.add_tool_result(tc.id, res)

                    elif func_name in self.tools_map:
                        print_status(f"Exécution outil: {func_name}", "exec")
                        
                        # Extraction robuste de la cible pour les logs
                        target = "N/A"
                        # 1. Direct keys
                        for key in ['target', 'RHOSTS', 'rhosts', 'hostname', 'ip', 'url', 'host']:
                             if key in args and args[key]:
                                 target = args[key]
                                 break
                        
                        # 2. Nested options (ex: run_exploit)
                        if target == "N/A" and 'options' in args and isinstance(args['options'], dict):
                            for key in ['RHOSTS', 'rhosts', 'RHOST', 'rhost', 'TARGET', 'target']:
                                if key in args['options'] and args['options'][key]:
                                    target = args['options'][key]
                                    break
                                    
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
            "content": """Vous êtes MSF-AI, un assistant expert qualifié et autonome.

**HIERARCHIE DES OUTILS (À RESPECTER STRICTEMENT)**:
1. 🥇 **METASPLOIT / STANDARD** : D'abord, cherchez un module existant (`search_msf_modules`).
2. 🥈 **OUTILS EXTERNES** : Si Metasploit est limité, INSTALLEZ l'outil (`install_external_tool`).
3. 🥉 **CRÉATION** : En dernier recours (`create_new_skill`).

**CONTEXTE DYNAMIQUE**:
{dynamic_context}

**PROTOCOLE DE REPORTAGE OBLIGATOIRE**:
- Rapports détaillés via `save_vulnerability_report`
- Scan results via `save_scan_results`

**Autonomie**:
- Bypassez les erreurs SSL.
- Mode UNSAFE = exploitation automatique.
"""
        }]
        self.base_system_prompt = self.messages[0]["content"]
        self.dynamic_context = {"RHOSTS": "Non défini", "TARGET": "Non défini"}
        self._refresh_system_prompt()
        self.temp_context = None

    def _refresh_system_prompt(self):
        """Met à jour le prompt système avec le contexte actuel."""
        context_str = "\n".join([f"- {k}: {v}" for k,v in self.dynamic_context.items()])
        self.messages[0]["content"] = self.base_system_prompt.replace("{dynamic_context}", context_str)

    def update_context(self, key, value):
        """Met à jour une variable de contexte et rafraîchit le prompt."""
        self.dynamic_context[key] = value
        self._refresh_system_prompt()


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
