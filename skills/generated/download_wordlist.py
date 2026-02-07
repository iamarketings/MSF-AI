import os
import subprocess
import shlex

def download_wordlist(url, destination):
    try:
        if not os.path.exists(destination):
            os.makedirs(destination)
        command = f"wget -q -O {os.path.join(destination, 'wordlist.txt')} {url}"
        subprocess.run(shlex.split(command), check=True)
        return {"status": "success", "message": f"Wordlist downloaded to {destination}"}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": f"Error downloading wordlist: {e}"}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected error: {e}"}