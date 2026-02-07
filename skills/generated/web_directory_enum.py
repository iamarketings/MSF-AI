import os
import subprocess
import shlex

def web_directory_enum(target_url, wordlist_path):
    try:
        if not os.path.exists(wordlist_path):
            return {"error": "Wordlist file not found."}
        
        command = f"ffuf -u {target_url}/FUZZ -w {wordlist_path} -e .php,.html,.txt"
        args = shlex.split(command)
        process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if process.returncode != 0:
            return {"error": process.stderr.strip()}
        
        results = process.stdout
        lines = results.split("\n")
        directories = [line.split(" ")[0] for line in lines if "FUZZ" in line]
        
        return {"directories": directories}
    
    except Exception as e:
        return {"error": str(e)}