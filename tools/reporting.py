"""
Reporting Tools for MSF-AI v4
"""
import json
import time
from typing import Dict, Any, List

def generate_markdown_report(results: List[Dict], output_file: str = "report.md") -> str:
    """Generates a Markdown report from results."""
    try:
        with open(output_file, 'w') as f:
            f.write("# MSF-AI Operation Report\n\n")
            f.write(f"Generated: {time.ctime()}\n\n")
            
            for res in results:
                f.write(f"## {res.get('tool', 'Unknown Tool')}\n")
                f.write(f"**Status**: {'✅ Success' if res.get('success') else '❌ Failed'}\n\n")
                
                content = res.get('result', str(res))
                if isinstance(content, (dict, list)):
                    f.write(f"```json\n{json.dumps(content, indent=2)}\n```\n\n")
                else:
                    f.write(f"{content}\n\n")
                    
        return f"Report saved to {output_file}"
    except Exception as e:
        return f"Error: {e}"

def generate_html_report(results: List[Dict], output_file: str = "report.html") -> str:
    """Generates a simple HTML report."""
    try:
        html = f"""<html><head><title>MSF-AI Report</title>
        <style>body{{font-family:sans-serif;max-width:800px;margin:auto;padding:20px}}
        .success{{color:green}} .fail{{color:red}} .box{{border:1px solid #ddd;padding:10px;margin-bottom:10px}}
        </style></head><body><h1>Operation Report</h1><p>{time.ctime()}</p>"""
        
        for res in results:
            status = '<span class="success">Success</span>' if res.get('success') else '<span class="fail">Failed</span>'
            html += f"<div class='box'><h2>{res.get('tool')} - {status}</h2>"
            html += f"<pre>{json.dumps(res.get('result'), indent=2)}</pre></div>"
            
        html += "</body></html>"
        with open(output_file, 'w') as f:
            f.write(html)
        return f"HTML report saved to {output_file}"
    except Exception as e:
        return f"Error: {e}"

def export_to_json(results: List[Dict], output_file: str = "results.json") -> str:
    """Exports results to JSON."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        return f"Exported to {output_file}"
    except Exception as e:
        return str(e)

def create_timeline(events: List[Dict]) -> str:
    return "Timeline creation simulated."

def summarize_results(results: List[Dict]) -> str:
    success = len([r for r in results if r.get('success')])
    return f"Total Tasks: {len(results)}, Success: {success}, Failed: {len(results)-success}"

def get_tools() -> Dict[str, Any]:
    return {
        "generate_markdown_report": generate_markdown_report,
        "generate_html_report": generate_html_report,
        "export_to_json": export_to_json,
        "create_timeline": create_timeline,
        "summarize_results": summarize_results
    }
