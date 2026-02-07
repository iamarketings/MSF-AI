import os
import subprocess
import shlex

def bruteforce_subdomains(domain, wordlist=None):
    if wordlist is None:
        wordlist = ["www", "admin", "mail", "ftp", "test"]
    
    resolved_subdomains = []
    
    try:
        for word in wordlist:
            subdomain = f"{word}.{domain}"
            command = shlex.split(f"nslookup {subdomain}")
            result = subprocess.run(command, capture_output=True, text=True)
            
            if "Non-existent domain" not in result.stdout:
                resolved_subdomains.append(subdomain)
    
    except Exception as e:
        return f"Error: {str(e)}"
    
    return resolved_subdomains