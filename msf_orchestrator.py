#!/usr/bin/env python3
"""
MSF AI - Task Orchestrator
Handles the decomposition of high-level objectives into executable tasks.
"""
import json
import logging
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger('MSF_AI.Orchestrator')

class TaskOrchestrator:
    """
    Orchestrates complex tasks by decomposing them into sub-steps
    and executing them sequentially with dependency tracking.
    """
    
    def __init__(self, ai_client, config_manager, tools_map, api_model="deepseek-chat"):
        self.ai_client = ai_client
        self.config = config_manager
        self.tools_map = tools_map
        self.current_plan = None
        self.logger = logger
        self.context = {} # Stores shared variables (RHOSTS, RPORT, etc.)
        self.api_model = api_model  # Configurable AI model

    def decompose_objective(self, objective: str, context: str = "") -> Dict[str, Any]:
        """
        Decomposes a high-level objective into structured tasks using AI.
        """
        prompt = f"""
        You are an expert Penetration Testing Orchestrator.
        Your goal is to break down the following high-level objective into a logical sequence of execution steps using Metasploit.

        Objective: {objective}
        Context: {context}

        Available Tools:
        - search_msf_modules(query)
        - get_module_info(module_path)
        - get_module_options(module_path)
        - get_compatible_payloads(module_path)
        - check_vulnerability(module_path, options)
        - run_exploit(module_path, options)
        - session_execute(session_id, command)
        
        Rules:
        1. Always start with reconnaissance/search if the module is not known.
        2. ALWAYS verify options before exploitation.
        3. Use 'check_vulnerability' whenever possible before 'run_exploit'.
        4. Dependency Logic: If step B needs information from step A, mark it.
        5. CONTEXT: The system automatically shares 'RHOSTS', 'RPORT', 'LHOST' between steps. You don't need to repeat them if they were found earlier.
        
        Respond ONLY with a valid JSON object.
        """
        
        try:
            response = self.ai_client.chat.completions.create(
                model=self.api_model,
                messages=[
                    {"role": "system", "content": "You are a JSON-only response bot. Output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.2
            )
            
            content = response.choices[0].message.content
            plan = json.loads(content)
            self.current_plan = plan
            return plan
            
        except Exception as e:
            self.logger.error(f"Failed to decompose objective: {e}")
            return {"error": str(e), "tasks": []}

    def _update_context_from_result(self, result: Any, tool_name: str, args: Dict):
        """Heuristic to extract useful info from results"""
        import re
        str_res = str(result)
        
        # Extract IP/RHOSTS
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str_res)
        if ip_match:
            self.context['RHOSTS'] = ip_match.group(0)
            
        # Extract Port from Nmap/Module output (e.g. "445/tcp open")
        port_match = re.search(r'(\d{1,5})/(tcp|udp)\s+open', str_res)
        if port_match:
            self.context['RPORT'] = int(port_match.group(1))
            
        # Extract from Args (if user provided it explicitly, keep it)
        if 'options' in args:
            for k, v in args['options'].items():
                if k in ['RHOSTS', 'RPORT', 'LHOST', 'LPORT'] and v:
                    self.context[k] = v
        
        # Specific heuristic for scan
        if "scan" in tool_name and "127.0.0.1" in str(args):
             self.context['RHOSTS'] = "127.0.0.1"

    def execute_step(self, step: Dict[str, Any], previous_results: Dict[int, Any]) -> Dict[str, Any]:
        """
        Executes a single step of the plan.
        """
        tool_name = step.get('tool')
        args = step.get('args', {})
        step_id = step.get('id')
        
        self.logger.info(f"Executing step {step_id}: {tool_name}")
        
        # 1. INJECT CONTEXT
        # If the tool takes 'options', merge our global context into it
        if 'options' in args:
            for key in ['RHOSTS', 'RPORT', 'LHOST', 'LPORT']:
                if key in self.context and key not in args['options']:
                     args['options'][key] = self.context[key]
        # Also inject top-level args if matching
        for key in ['RHOSTS', 'RPORT', 'LHOST', 'LPORT']:
            if key in self.context and key not in args:
                # Some tools might take checking arguments directly
                pass 
                
        if tool_name not in self.tools_map:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}
        
        try:
            # Execute tool
            func = self.tools_map[tool_name]
            result = func(**args)
            
            # 2. UPDATE CONTEXT
            self._update_context_from_result(result, tool_name, args)
            
            success = True
            error_msg = None
            if isinstance(result, str) and "Error" in result:
                success = False
                error_msg = result
            
            return {
                "success": success,
                "result": result,
                "error": error_msg,
                "tool": tool_name
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_plan(self, plan: Dict[str, Any], callback=None) -> Dict[str, Any]:
        """
        Executes the entire plan sequentially.
        """
        results = {}
        history = []
        
        print("\n🚀 Starting Task Orchestration...\n")
        
        for step in plan.get('tasks', []):
            step_id = step.get('id')
            desc = step.get('description')
            
            # Use callback for UI updates if provided
            if callback:
                callback(f"Step {step_id}: {desc}")
            else:
                print(f"[*] Step {step_id}: {desc}")
            
            # Check dependencies
            if 'depends_on' in step:
                failed_deps = [d for d in step['depends_on'] if not results.get(d, {}).get('success', False)]
                if failed_deps:
                    print(f"  ❌ Skipping due to failed dependencies: {failed_deps}")
                    results[step_id] = {"success": False, "error": "Dependency failed"}
                    continue
            
            # Execute
            step_result = self.execute_step(step, results)
            results[step_id] = step_result
            
            # Log result
            if step_result['success']:
                print(f"  ✅ Success")
                # Store truncated result for context
                res_str = str(step_result['result'])
                if len(res_str) > 500: res_str = res_str[:500] + "..."
                history.append(f"Step {step_id} Output: {res_str}")
            else:
                print(f"  ❌ Failed: {step_result.get('error')}")
                if step.get('critical', False):
                    print("  ⛔ Critical step failed. stopping plan.")
                    break
                    
        return results
