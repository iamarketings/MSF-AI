"""
Outils de Rapport pour MSF-AI v4
"""
import json
import time
from typing import Dict, Any, List

def generate_markdown_report(results: List[Dict], output_file: str = "report.md") -> str:
    """Génère un rapport Markdown à partir des résultats."""
    try:
        with open(output_file, 'w') as f:
            f.write("# Rapport d'Opération MSF-AI\n\n")
            f.write(f"Généré le : {time.ctime()}\n\n")
            
            for res in results:
                f.write(f"## {res.get('tool', 'Outil Inconnu')}\n")
                f.write(f"**Statut** : {'✅ Succès' if res.get('success') else '❌ Échec'}\n\n")
                
                content = res.get('result', str(res))
                if isinstance(content, (dict, list)):
                    f.write(f"```json\n{json.dumps(content, indent=2)}\n```\n\n")
                else:
                    f.write(f"{content}\n\n")
                    
        return f"Rapport sauvegardé dans {output_file}"
    except Exception as e:
        return f"Erreur : {e}"

def generate_html_report(results: List[Dict], output_file: str = "report.html") -> str:
    """Génère un rapport HTML simple."""
    try:
        html = f"""<html><head><title>Rapport MSF-AI</title>
        <style>body{{font-family:sans-serif;max-width:800px;margin:auto;padding:20px}}
        .success{{color:green}} .fail{{color:red}} .box{{border:1px solid #ddd;padding:10px;margin-bottom:10px}}
        </style></head><body><h1>Rapport d'Opération</h1><p>{time.ctime()}</p>"""
        
        for res in results:
            status = '<span class="success">Succès</span>' if res.get('success') else '<span class="fail">Échec</span>'
            html += f"<div class='box'><h2>{res.get('tool')} - {status}</h2>"
            html += f"<pre>{json.dumps(res.get('result'), indent=2)}</pre></div>"
            
        html += "</body></html>"
        with open(output_file, 'w') as f:
            f.write(html)
        return f"Rapport HTML sauvegardé dans {output_file}"
    except Exception as e:
        return f"Erreur : {e}"

def export_to_json(results: List[Dict], output_file: str = "results.json") -> str:
    """Exporte les résultats au format JSON."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        return f"Exporté dans {output_file}"
    except Exception as e:
        return str(e)

def create_timeline(events: List[Dict]) -> str:
    """Simule la création d'une chronologie."""
    return "Création de chronologie simulée."

def summarize_results(results: List[Dict]) -> str:
    """Résume les résultats des tâches."""
    success = len([r for r in results if r.get('success')])
    return f"Total des tâches : {len(results)}, Succès : {success}, Échecs : {len(results)-success}"

def get_tools() -> Dict[str, Any]:
    """Retourne les outils de rapport."""
    return {
        "generate_markdown_report": generate_markdown_report,
        "generate_html_report": generate_html_report,
        "export_to_json": export_to_json,
        "create_timeline": create_timeline,
        "summarize_results": summarize_results
    }
