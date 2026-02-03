"""
MSF AI - Task Orchestrator (Langgraph Version)
Handles the decomposition of high-level objectives into executable tasks using Langgraph.
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
        # We'll use the LangChain ChatOpenAI wrapper for Langgraph compatibility
        self.llm = ChatOpenAI(
            model=api_model,
            openai_api_key=ai_client.api_key,
            base_url=str(ai_client.base_url),
            temperature=0.2
        )
        self.config = config_manager
        self.tools_map = tools_map
        self.workflow = self._build_graph()

    def _build_graph(self):
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
        """Generates or updates the plan."""
        tools_list = "\n".join([f"- {name}" for name in self.tools_map.keys()])

        prompt = f"""
        You are an expert Penetration Testing Orchestrator.
        Objective: {state['objective']}
        Context: {json.dumps(state['context'])}
        Current Results: {json.dumps(state['results'])}

        Available Tools:
        {tools_list}

        Rules:
        1. Create a logical sequence of steps.
        2. Use Metasploit modules and other tools appropriately.
        3. Respond ONLY with a JSON list of tasks, each with 'id', 'tool', 'args', and 'description'.

        Example:
        [
            {{"id": 1, "tool": "check_port_open", "args": {{"target": "10.0.0.1", "port": 80}}, "description": "Check if HTTP is open"}}
        ]
        """

        response = self.llm.invoke([SystemMessage(content="You are a JSON-only planner."), HumanMessage(content=prompt)])
        try:
            # Extract JSON if wrapped in code blocks
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            plan = json.loads(content)
            return {"plan": plan, "current_step_index": 0}
        except Exception as e:
            logger.error(f"Planning failed: {e}")
            return {"error": f"Planning error: {e}", "finished": True}

    def _executor_node(self, state: AgentState):
        """Executes the next step in the plan."""
        if state['current_step_index'] >= len(state['plan']):
            return {"finished": True}

        step = state['plan'][state['current_step_index']]
        tool_name = step['tool']
        args = step['args'].copy()

        # Inject context into 'options' dict if it exists
        if 'options' in args and isinstance(args['options'], dict):
            for key in ['RHOSTS', 'RPORT', 'LHOST', 'LPORT']:
                if key in state['context'] and key not in args['options']:
                     args['options'][key] = state['context'][key]

        # Also inject into top-level args (mapping RHOSTS to target, etc. if needed)
        context_mapping = {
            'RHOSTS': ['target', 'host', 'ip', 'domain'],
            'RPORT': ['port'],
            'LHOST': ['lhost'],
            'LPORT': ['lport']
        }
        for ctx_key, arg_keys in context_mapping.items():
            if ctx_key in state['context']:
                for arg_key in arg_keys:
                    if arg_key in args and not args[arg_key]:
                         args[arg_key] = state['context'][ctx_key]
                    elif arg_key not in args:
                         # For some tools we might want to auto-inject even if not present in args
                         # but let's be careful. Let's only inject if the tool is known to need it.
                         pass

        print(f"[*] Executing: {step['description']}")

        if tool_name not in self.tools_map:
            res = {"success": False, "error": f"Unknown tool: {tool_name}"}
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
            "history": state['history'] + [f"Step {step['id']} ({tool_name}): {'Success' if res['success'] else 'Fail'}"]
        }

    def _analyzer_node(self, state: AgentState):
        """Analyzes results and updates context."""
        last_step_id = str(state['plan'][state['current_step_index'] - 1]['id'])
        last_result = state['results'][last_step_id]

        new_context = state['context'].copy()
        if last_result['success']:
            str_res = str(last_result['result'])
            # Extract IP
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str_res)
            if ip_match: new_context['RHOSTS'] = ip_match.group(0)
            # Extract Port
            port_match = re.search(r'(\d{1,5})/(tcp|udp)\s+open', str_res)
            if port_match: new_context['RPORT'] = int(port_match.group(1))

        return {"context": new_context}

    def _should_continue(self, state: AgentState):
        if state.get('error'): return "end"
        if state.get('finished'): return "end"
        if state['current_step_index'] < len(state['plan']):
            return "continue"

        # Optionally, ask LLM if we need more steps
        return "end"

    def execute_plan(self, objective: str, initial_context: Dict = None) -> Dict[str, Any]:
        """Runs the Langgraph workflow."""
        initial_state = {
            "objective": objective,
            "context": initial_context or {},
            "plan": [],
            "results": {},
            "current_step_index": 0,
            "finished": False,
            "error": None,
            "history": []
        }

        final_state = self.workflow.invoke(initial_state)
        return final_state['results']

    def decompose_objective(self, objective: str, context: str = "") -> Dict:
        """
        Compatibility method for existing controller.
        NOTE: In this Langgraph version, planning and execution are interleaved.
        This method returns an empty plan because the execution is managed by 'execute_plan'.
        """
        return {"tasks": []}
