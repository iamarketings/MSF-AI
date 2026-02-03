"""
Reconnaissance Tools for MSF-AI v4
"""
import socket
import requests
import whois
import dns.resolver
from typing import Dict, Any, List

def whois_lookup(domain: str) -> str:
    """Performs WHOIS lookup using python-whois."""
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Error: {e}"

def dns_enumeration(domain: str) -> Dict[str, List[str]]:
    """DNS records fetch using dnspython."""
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            records[rtype] = []
        except Exception as e:
            records[rtype] = [f"Error: {e}"]
    return records

def subdomain_discovery(domain: str) -> List[str]:
    """Uses crt.sh for subdomain discovery."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.ok:
            data = resp.json()
            subs = set()
            for entry in data:
                subs.add(entry['name_value'])
            return list(subs)
        return ["Failed to query crt.sh"]
    except:
        return ["Error querying crt.sh"]

def certificate_transparency(domain: str) -> List[str]:
    """Same as subdomain discovery basically."""
    return subdomain_discovery(domain)

def reverse_ip_lookup(ip: str) -> List[str]:
    """Uses hackertarget API."""
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        return r.text.splitlines()
    except:
        return ["Error in lookup"]
        
def check_email_breach(email: str) -> str:
    """Placeholder for email breach check."""
    return f"Breach check for {email} requires an external API key (e.g., HaveIBeenPwned)."

def get_tools() -> Dict[str, Any]:
    return {
        "whois_lookup": whois_lookup,
        "dns_enumeration": dns_enumeration,
        "subdomain_discovery": subdomain_discovery,
        "certificate_transparency": certificate_transparency,
        "reverse_ip_lookup": reverse_ip_lookup,
        "check_email_breach": check_email_breach
    }
