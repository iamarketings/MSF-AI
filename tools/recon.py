"""
Outils de Reconnaissance pour MSF-AI v4
"""
import socket
import requests
import whois
import dns.resolver
from typing import Dict, Any, List
from msf_aiv4.tools.cache import cache_result

@cache_result(expiry_seconds=86400) # Cache 24h
def whois_lookup(domain: str) -> str:
    """Effectue une recherche WHOIS en utilisant python-whois."""
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Erreur : {e}"

@cache_result(expiry_seconds=3600) # Cache 1h
def dns_enumeration(domain: str) -> Dict[str, List[str]]:
    """Récupère les enregistrements DNS en utilisant dnspython."""
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            records[rtype] = []
        except Exception as e:
            records[rtype] = [f"Erreur : {e}"]
    return records

import os
from concurrent.futures import ThreadPoolExecutor

def subdomain_discovery(domain: str) -> List[str]:
    """Découvre des sous-domaines via crt.sh ET bruteforce."""
    subdomains_found = set()
    errors = []

    # 1. Certificate Transparency (CRT.sh)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10, verify=False)
        if resp.ok:
            data = resp.json()
            for entry in data:
                subdomains_found.add(entry['name_value'])
    except Exception as e:
        errors.append(f"Crt.sh fail: {e}")

    # 2. Bruteforce DNS
    try:
        # Chemin: msf_aiv4/tools/recon.py -> msf_aiv4/wordlists/subdomains.txt
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "subdomains.txt")
        
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                # Top 1000 pour la rapidité si beaucoup, ou tout si threadé
                candidates = [line.strip() for line in f if line.strip()]
            
            # Fonction interne pour le threading
            def resolve_subdomain(sub):
                full_domain = f"{sub}.{domain}"
                try:
                    # Timeout court pour accélérer
                    socket.gethostbyname(full_domain)
                    return full_domain
                except:
                    return None

            # 50 threads pour aller vite
            with ThreadPoolExecutor(max_workers=50) as executor:
                results = executor.map(resolve_subdomain, candidates)
                
            for res in results:
                if res:
                    subdomains_found.add(res)
        else:
            errors.append("Wordlist locale introuvable")

    except Exception as e:
        errors.append(f"Bruteforce fail: {e}")

    # Nettoyage des wildcards et doublons
    clean_subs = {s.replace('*.', '') for s in subdomains_found}
    
    if not clean_subs:
        return ["Aucun sous-domaine trouvé (ou erreur crt.sh + bruteforce)"] + errors
        
    return list(clean_subs)

def certificate_transparency(domain: str) -> List[str]:
    """Alias pour la découverte de sous-domaines via la transparence des certificats."""
    return subdomain_discovery(domain)

def reverse_ip_lookup(ip: str) -> List[str]:
    """Recherche inverse d'IP via l'API hackertarget."""
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        return r.text.splitlines()
    except:
        return ["Erreur lors de la recherche"]

def check_email_breach(email: str) -> str:
    """Espace réservé pour la vérification de fuite d'e-mail."""
    return f"La vérification de fuite pour {email} nécessite une clé API externe (ex: HaveIBeenPwned)."

def get_tools() -> Dict[str, Any]:
    """Retourne les outils de reconnaissance."""
    return {
        "whois_lookup": whois_lookup,
        "dns_enumeration": dns_enumeration,
        "subdomain_discovery": subdomain_discovery,
        "certificate_transparency": certificate_transparency,
        "reverse_ip_lookup": reverse_ip_lookup,
        "check_email_breach": check_email_breach
    }
