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

def subdomain_discovery(domain: str) -> List[str]:
    """Découvre des sous-domaines via crt.sh."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.ok:
            data = resp.json()
            subs = set()
            for entry in data:
                subs.add(entry['name_value'])
            return list(subs)
        return ["Échec de la requête crt.sh"]
    except:
        return ["Erreur lors de la requête crt.sh"]

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
