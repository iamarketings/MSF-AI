#!/usr/bin/env python3
"""
MSF-AI v4 - Point d'entrée MVC
"""
import os
import sys

# S'assurer que le package est dans le chemin (path)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from msf_aiv4.msf_controller import MSFAIController, setup_readline, save_history

def main():
    # Configuration de readline pour une meilleure expérience de saisie
    setup_readline()
    
    # Initialisation du Contrôleur
    controller = MSFAIController()
    
    # Affichage immédiat de la bannière
    controller.view.show_banner()
    
    # Démarrage du système
    if controller.initialize():
        # Boucle principale
        while True:
            try:
                # Récupération des données dynamiques pour l'invite (prompt)
                security = controller.config.get("security_mode", "safe").upper()
                sessions = controller.msf.list_sessions()
                session_count = len(sessions) if sessions else 0
                session_label = f"{session_count} SESSION(S)" if session_count > 0 else "NO SESSION"

                # Récupération de la cible actuelle depuis le contexte de l'orchestrateur
                target = controller.orchestrator.context.get('RHOSTS')

                user_input = controller.view.get_input(session=session_label, security=security, target=target)
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
