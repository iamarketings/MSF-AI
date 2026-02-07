import subprocess
import os
import shlex

def subdomain_bruteforcer(domain, wordlist_path):
    if not os.path.exists(wordlist_path):
        return {"error": "Wordlist file not found."}
    
    results = {}
    try:
        with open(wordlist_path, 'r') as wordlist:
            for subdomain in wordlist:
                subdomain = subdomain.strip()
                test_url = f"{subdomain}.{domain}"
                try:
                    response = subprocess.run(shlex.split(f"host {test_url}"), capture_output=True, text=True, timeout=5)
                    if "not found" not in response.stdout and "NXDOMAIN" not in response.stdout:
                        results[test_url] = "Exists"
                    else:
                        results[test_url] = "Does not exist"
                except subprocess.TimeoutExpired:
                    results[test_url] = "Timeout"
    except Exception as e:
        return {"error": str(e)}
    
    return results