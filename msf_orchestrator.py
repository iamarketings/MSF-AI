"""
Orchestrateur MSF AI (Version Langgraph)
Gère la décomposition des objectifs de haut niveau en tâches exécutables via Langgraph.
"""
import json
import logging
import time
import re
from typing import List, Dict, Any, Optional, Annotated, TypedDict
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

logger = logging.getLogger('MSF_AI.Orchestrator')

class AgentState(TypedDict):
    objective: str
    context: Dict[str, Any]
    plan: List[Dict[str, Any]]
    results: Dict[str, Any]
    current_step_index: int
    finished: bool
    error: Optional[str]
    history: List[str]

class LanggraphOrchestrator:
    def __init__(self, ai_client, config_manager, tools_map, api_model="deepseek-chat"):
        # Utilisation de l'enveloppe LangChain ChatOpenAI pour la compatibilité Langgraph
        self.llm = ChatOpenAI(
            model=api_model,
            openai_api_key=ai_client.api_key,
            base_url=str(ai_client.base_url),
            temperature=0.2
        )
        self.config = config_manager
        self.tools_map = tools_map
        self.context = {} # Contexte global partagé entre les exécutions
        self.workflow = self._build_graph()

    def _build_graph(self):
        """Construit le graphe d'état Langgraph."""
        workflow = StateGraph(AgentState)

        workflow.add_node("planner", self._planner_node)
        workflow.add_node("executor", self._executor_node)
        workflow.add_node("analyzer", self._analyzer_node)

        workflow.set_entry_point("planner")

        workflow.add_edge("planner", "executor")
        workflow.add_edge("executor", "analyzer")

        workflow.add_conditional_edges(
            "analyzer",
            self._should_continue,
            {
                "continue": "executor",
                "replan": "planner",
                "end": END
            }
        )

        return workflow.compile()

    def _planner_node(self, state: AgentState):
        """Génère ou met à jour le plan."""
        tools_list = "\n".join([f"- {name}" for name in self.tools_map.keys()])

        prompt = f"""
        Vous êtes un orchestrateur expert en tests d'intrusion.
        Objectif : {state['objective']}
        Contexte : {json.dumps(state['context'])}
        Résultats actuels : {json.dumps(state['results'])}

        Outils disponibles :
        {tools_list}

        Règles :
        1. Créez une séquence logique d'étapes.
        2. Utilisez les modules Metasploit et autres outils de manière appropriée.
        3. Répondez UNIQUEMENT avec une liste JSON de tâches, chacune ayant 'id', 'tool', 'args' et 'description'.

        Exemple :
        [
            {{"id": 1, "tool": "check_port_open", "args": {{"target": "10.0.0.1", "port": 80}}, "description": "Vérifier si le port HTTP est ouvert"}}
        ]
        """

        response = self.llm.invoke([SystemMessage(content="Vous êtes un planificateur ne répondant qu'en JSON."), HumanMessage(content=prompt)])
        try:
            # Extraire le JSON si entouré de blocs de code
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            plan = json.loads(content)
            return {"plan": plan, "current_step_index": 0}
        except Exception as e:
            logger.error(f"Échec de planification : {e}")
            return {"error": f"Erreur de planification : {e}", "finished": True}

    def _validate_context_value(self, key: str, value: Any) -> bool:
        """Valide les valeurs du contexte pour éviter les injections ou erreurs de type."""
        if not value: return False
        str_val = str(value)

        # Validation IP/Hôte
        if key in ['RHOSTS', 'LHOST', 'target', 'host', 'ip']:
            # Validation basique IP ou domaine
            return bool(re.match(r'^[\w\.-]+$', str_val))

        # Validation Port
        if key in ['RPORT', 'LPORT', 'port']:
            try:
                port = int(str_val)
                return 0 < port < 65536
            except:
                return False

        return True

    def _executor_node(self, state: AgentState):
        """Exécute l'étape suivante du plan."""
        if state['current_step_index'] >= len(state['plan']):
            return {"finished": True}

        step = state['plan'][state['current_step_index']]
        tool_name = step['tool']
        args = step['args'].copy()

        # Injection du contexte dans le dictionnaire 'options' s'il existe
        if 'options' in args and isinstance(args['options'], dict):
            for key in ['RHOSTS', 'RPORT', 'LHOST', 'LPORT']:
                if key in state['context'] and key not in args['options']:
                     args['options'][key] = state['context'][key]

        # Injection également dans les arguments de premier niveau
        context_mapping = {
            'RHOSTS': ['target', 'host', 'ip', 'domain'],
            'RPORT': ['port'],
            'LHOST': ['lhost'],
            'LPORT': ['lport']
        }
        for ctx_key, arg_keys in context_mapping.items():
            if ctx_key in state['context']:
                value = state['context'][ctx_key]
                if self._validate_context_value(ctx_key, value):
                    for arg_key in arg_keys:
                        if arg_key in args and not args[arg_key]:
                             args[arg_key] = value

        print(f"[*] Exécution : {step['description']}")

        if tool_name not in self.tools_map:
            res = {"success": False, "error": f"Outil inconnu : {tool_name}"}
        else:
            try:
                func = self.tools_map[tool_name]
                result = func(**args)
                res = {"success": True, "result": result, "tool": tool_name}
            except Exception as e:
                res = {"success": False, "error": str(e), "tool": tool_name}

        new_results = state['results'].copy()
        new_results[str(step['id'])] = res

        return {
            "results": new_results,
            "current_step_index": state['current_step_index'] + 1,
            "history": state['history'] + [f"Étape {step['id']} ({tool_name}) : {'Succès' if res['success'] else 'Échec'}"]
        }

    def _analyzer_node(self, state: AgentState):
        """Analyse les résultats et met à jour le contexte."""
        if not state['plan']: return {"context": state['context']}
        last_step_id = str(state['plan'][state['current_step_index'] - 1]['id'])
        last_result = state['results'][last_step_id]

        new_context = state['context'].copy()
        if last_result['success']:
            str_res = str(last_result['result'])
            # Extraction IP
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str_res)
            if ip_match: new_context['RHOSTS'] = ip_match.group(0)
            # Extraction Port
            port_match = re.search(r'(\d{1,5})/(tcp|udp)\s+open', str_res)
            if port_match: new_context['RPORT'] = int(port_match.group(1))

        return {"context": new_context}

    def _should_continue(self, state: AgentState):
        """Détermine si le workflow doit continuer."""
        if state.get('error'): return "end"
        if state.get('finished'): return "end"
        if state['current_step_index'] < len(state['plan']):
            return "continue"
        return "end"

    def execute_plan(self, objective: str, initial_context: Dict = None) -> Dict[str, Any]:
        """Lance le workflow Langgraph."""
        # Fusion du contexte global avec le contexte initial
        ctx = self.context.copy()
        if initial_context:
            ctx.update(initial_context)

        initial_state = {
            "objective": objective,
            "context": ctx,
            "plan": [],
            "results": {},
            "current_step_index": 0,
            "finished": False,
            "error": None,
            "history": []
        }

        final_state = self.workflow.invoke(initial_state)

        # Mise à jour du contexte global avec les découvertes de l'exécution
        self.context.update(final_state.get('context', {}))

        return final_state['results']

    def decompose_objective(self, objective: str, context: str = "") -> Dict:
        """
        Méthode de compatibilité pour le contrôleur existant.
        NOTE : Dans cette version Langgraph, la planification et l'exécution sont entrelacées.
        Cette méthode retourne un plan vide car l'exécution est gérée par 'execute_plan'.
        """
        return {"tasks": []}
