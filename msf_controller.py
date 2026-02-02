#!/usr/bin/env python3
"""
MSF AI Controller - MVC Pattern
Main entry point for the application logic.
"""
import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from openai import OpenAI

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from msf_aiv4.msf_model import MSFModel
from msf_aiv4.msf_view import MSFView, print_status, print_thinking
from msf_aiv4.msf_rag import create_rag_library
from msf_aiv4.msf_orchestrator import TaskOrchestrator
from msf_aiv4.tools import network, web, postexp, reporting, recon

# Logger setup
logging.basicConfig(
    filename='msf_ai.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MSF_AI.Controller')

class MSFAIController:
    """
    Controller responsible for coordinating User, AI, and Metasploit.
    """
    def __init__(self):
        load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
        
        # Config
        self.deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
        self.msf_pass = os.getenv("MSF_RPC_PASS")
        self.msf_user = os.getenv("MSF_RPC_USER", "msf") 
        self.msf_port = int(os.getenv("MSF_RPC_PORT", 55553))
        
        # Components
        self.msf = MSFModel(self.msf_pass, port=self.msf_port, user=self.msf_user)
        self.view = MSFView()
        self.rag = None
        self.orchestrator = None
        self.ai_client = None
        self.api_model = "deepseek-chat"
        
        # Tools
        self.tools_map = {}
        self.tools_def = []
        
        # State
        self.conversation = ConversationHistory()
        self.config = {"security_mode": "safe"}

    def initialize(self) -> bool:
        """Initializes all subsystems."""
        print_status("Initialisation du système...", "info")
        
        # 1. RAG
        print_status("Chargement de la base de connaissances RAG...", "info")
        try:
            self.rag = create_rag_library()
        except Exception as e:
            print_status(f"Attention: RAG non disponible ({e})", "warning")
            
        # 2. MSF Connection
        print_status(f"Connexion à Metasploit RPC ({self.msf.host}:{self.msf.port})...", "info")
        if not self.msf.connect():
            # Warn but allow continuation for offline tools
            print_status("Attention: MSF RPC non connecté. Modules d'exploitation indisponibles.", "warning")
        else:
            print_status("Connexion Metasploit réussie", "success")
            
        # 3. AI Connection (Configurable)
        try:
            api_base_url = os.getenv("API_BASE_URL", "https://api.deepseek.com")
            self.api_model = os.getenv("API_MODEL", "deepseek-chat")
            
            self.ai_client = OpenAI(api_key=self.deepseek_api_key, base_url=api_base_url)
            print_status(f"Connexion API réussie ({api_base_url})", "success")
        except Exception as e:
            print_status(f"Erreur fatale API: {e}", "error")
            return False
            
        # 4. Build Tools
        self._build_tools_map()
        self._build_tools_def()
        
        # 5. Init Orchestrator
        self.orchestrator = TaskOrchestrator(self.ai_client, self.config, self.tools_map, self.api_model)
        
        return True
        
    def _build_tools_map(self):
        """Aggregates all tools into a single map."""
        # Core MSF Tools
        self.tools_map.update({
            "search_msf_modules": self.msf.search_modules,
            "get_module_info": self.msf.get_module_info,
            "get_module_options": self.msf.get_module_options,
            "check_vulnerability": self.msf.check_vulnerability,
            "run_exploit": self.msf.run_exploit,
            "list_sessions": self.msf.list_sessions,
            "session_execute": self.msf.session_execute
        })
        
        # Network Tools
        self.tools_map.update(network.get_tools())
        
        # Web Tools
        self.tools_map.update(web.get_tools())
        
        # Reporting Tools
        self.tools_map.update(reporting.get_tools())
        
        # Recon Tools
        self.tools_map.update(recon.get_tools())
        
        # Post-Exp Tools (Wrap with client/session injection)
        post_tools = postexp.get_tools()
        for name, func in post_tools.items():
            # We create a closure to capture the correct function
            def create_wrapper(f):
                return lambda **kwargs: f(self.msf.client, **kwargs)
            self.tools_map[name] = create_wrapper(func)
            
    def _build_tools_def(self):
        """Builds JSON tools definition for AI."""
        # This is a focused list to keep context small. Orchestrator can call ALL tools.
        # We define core tools and representative tools from other categories.
        self.tools_def = [
            {
                "type": "function",
                "function": {
                    "name": "search_msf_modules",
                    "description": "Searches for Metasploit modules.",
                    "parameters": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "run_exploit",
                    "description": "Executes a Metasploit module.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "module_path": {"type": "string"},
                            "options": {"type": "object"}
                        },
                        "required": ["module_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "check_port_open",
                    "description": "Checks if a TCP port is open on target.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "port": {"type": "integer"}
                        },
                        "required": ["target", "port"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "geolocate_ip",
                    "description": "Geolocates an IP address.",
                    "parameters": {
                        "type": "object",
                        "properties": {"ip": {"type": "string"}},
                        "required": ["ip"]
                    }
                }
            },
            # Add Orchestrator hook
            {
                "type": "function",
                "function": {
                    "name": "orchestrate_task",
                    "description": "DECOMPOSE complex objectives into multiple steps. Use this for 'scan and exploit', 'full audit', etc.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "objective": {"type": "string", "description": "The complex goal to achieve"}
                        },
                        "required": ["objective"]
                    }
                }
            }
            # Note: We expose limited tools to the chat model to encourage use of orchestration
            # for complex tasks, or specific tools for simple Q&A.
        ]

    def process_input(self, user_input: str):
        """Main processing loop iteration."""
        # 0. Check system commands
        if user_input.strip() in ['exit', 'quit']:
            sys.exit(0)
        if user_input.strip() == 'stats':
            self.view.show_stats(self.conversation)
            return

        # 1. Add User Message
        self.conversation.add_message("user", user_input)
        
        # 2. RAG Enhancement
        enhanced_prompt = user_input
        if self.rag:
            print_status("Recherche de contexte RAG...", "info")
            enhanced_prompt = self.rag.enhance_prompt(user_input)
            # We don't replace the user message in history, but we could add a system context message temporarily
            # For now, let's keep it simple and just rely on the system instruction or injection if supported.
            # A better way for chat API: add a system message with context just before the user message.
            self.conversation.add_temporary_context(enhanced_prompt)

        # 3. AI Thinking
        print_thinking(True)
        
        try:
            # 4. API Call
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
            
            # 5. Tool Execution
            if tool_calls:
                self.conversation.add_message("assistant", content, tool_calls)
                
                for tc in tool_calls:
                    func_name = tc.function.name
                    args = json.loads(tc.function.arguments)
                    
                    if func_name == "orchestrate_task":
                        # Handover to Orchestrator
                        print_status("Mode Orchestration détecté", "info")
                        plan = self.orchestrator.decompose_objective(args['objective'])
                        results = self.orchestrator.execute_plan(plan, callback=lambda s: print_status(s, "exec"))
                        
                        # Summarize results back to AI
                        result_summary = f"Orchestration completed. Results: {len(results)} steps executed."
                        self.conversation.add_tool_result(tc.id, result_summary)
                    
                    elif func_name in self.tools_map:
                        print_status(f"Exécution outil: {func_name}", "exec")
                        try:
                            # Call the tool
                            res = self.tools_map[func_name](**args)
                            self.conversation.add_tool_result(tc.id, str(res))
                        except Exception as e:
                            self.conversation.add_tool_result(tc.id, f"Error: {e}")
                    else:
                         self.conversation.add_tool_result(tc.id, "Tool not found or not enabled directly.")
                
                # Recursive call to get final answer after tool outputs
                self.process_input("") # Trigger re-evaluation with history
                return

            # 6. Final Response
            if content:
                self.conversation.add_message("assistant", content)
                self.view.display_response(content)
                
        except Exception as e:
            print_status(f"Erreur traitement: {e}", "error")

class ConversationHistory:
    """Manages chat history."""
    def __init__(self):
        self.messages = [{"role": "system", "content": "You are MSF-AI, an expert penetration testing assistant. You are helpful, compliant, and focused on security assessment."}]
        self.temp_context = None

    def add_message(self, role, content, tool_calls=None):
        msg = {"role": role, "content": content}
        if tool_calls: msg["tool_calls"] = tool_calls
        if content: self.messages.append(msg) # Only add if content or tool_calls exists (API rules vary, but usually ok)
        # Actually for tool calls, we need to append even if content is None
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
        """Adds RAG context that applies only to the next turn (simplified logic)."""
        # In this simple impl, we just append a system message? 
        # Better: Inject it into the last user message content if possible, or append system msg
        # Let's just modify the last user message in the 'get_messages' view
        self.temp_context = context

    def get_messages(self):
        # Apply temp context if it exists
        if self.temp_context and self.messages[-1]['role'] == 'user':
             # Return a modified copy
             msgs = self.messages[:-1] + [{"role": "user", "content": self.temp_context}]
             return msgs
        return self.messages

# Global helper for readline
def setup_readline():
    pass # Implemented in View usually or simple readline import

def save_history():
    pass

# Direct execution
if __name__ == "__main__":
    controller = MSFAIController()
    if controller.initialize():
        controller.view.show_banner()
        while True:
            try:
                user_input = controller.view.get_input()
                controller.process_input(user_input)
            except KeyboardInterrupt:
                print("\nAu revoir!")
                break
