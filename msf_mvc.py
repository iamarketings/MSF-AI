#!/usr/bin/env python3
"""
MSF-AI v4 MVC Entry Point
"""
import os
import sys

# Ensure package is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from msf_aiv4.msf_controller import MSFAIController, setup_readline, save_history

def main():
    # Setup readline for better input experience if possible
    setup_readline()
    
    # Init Controller
    controller = MSFAIController()
    
    # Show UI immediately
    controller.view.show_banner()
    
    # Start System
    if controller.initialize():
        # Main Loop
        while True:
            try:
                user_input = controller.view.get_input()
                controller.process_input(user_input)
            except KeyboardInterrupt:
                print("\n\n[!] Arrêt demandé par l'utilisateur...")
                save_history()
                break
            except EOFError:
                break
            except Exception as e:
                print(f"[!] Erreur critique: {e}")
                
if __name__ == "__main__":
    main()
