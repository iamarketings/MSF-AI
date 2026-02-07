import dns.resolver
import concurrent.futures
import socket
from typing import List, Dict, Tuple

def dns_bruteforce(domain: str, wordlist: List[str] = None, threads: int = 50) -> Dict[str, List[str]]:
    """
    Effectue un bruteforce DNS sur un domaine donné.
    
    Args:
        domain: Le domaine cible (ex: 'example.com')
        wordlist: Liste de sous-domaines à tester
        threads: Nombre de threads pour le scanning
    
    Returns:
        Dict avec sous-domaines trouvés et leurs adresses IP
    """
    
    # Liste par défaut si aucune fournie
    if wordlist is None:
        wordlist = [
            "www", "mail", "ftp", "admin", "test", "dev", "api", "blog", 
            "shop", "portal", "secure", "vpn", "webmail", "cpanel", "whm",
            "ns1", "ns2", "mx", "smtp", "pop", "imap", "git", "svn",
            "jenkins", "docker", "k8s", "staging", "prod", "beta", "alpha",
            "app", "web", "mobile", "static", "cdn", "assets", "media",
            "support", "help", "status", "monitor", "analytics", "stats",
            "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
            "elastic", "kibana", "grafana", "prometheus", "alertmanager",
            "auth", "login", "signin", "register", "account", "profile",
            "api-docs", "swagger", "graphql", "rest", "soap", "ws",
            "staging", "testing", "qa", "preprod", "demo", "sandbox",
            "backup", "archive", "legacy", "old", "new", "temp", "tmp"
        ]
    
    # Résolveurs DNS publics
    resolvers = [
        "8.8.8.8",  # Google
        "8.8.4.4",  # Google
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",  # Cloudflare
        "9.9.9.9",  # Quad9
    ]
    
    results = {}
    
    def check_subdomain(subdomain: str) -> Tuple[str, List[str]]:
        """Vérifie un sous-domaine spécifique"""
        full_domain = f"{subdomain}.{domain}"
        
        for resolver_ip in resolvers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                
                # Essayer d'abord A records
                try:
                    answers = resolver.resolve(full_domain, 'A')
                    ips = [str(rdata) for rdata in answers]
                    return full_domain, ips
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                
                # Essayer CNAME
                try:
                    answers = resolver.resolve(full_domain, 'CNAME')
                    cnames = [str(rdata.target) for rdata in answers]
                    return full_domain, cnames
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                    
            except Exception as e:
                continue
        
        return full_domain, []
    
    # Scanner avec threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain, subdomain): subdomain 
            for subdomain in wordlist
        }
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                full_domain, addresses = future.result()
                if addresses:
                    results[full_domain] = addresses
                    print(f"[+] Trouvé: {full_domain} -> {addresses}")
            except Exception as e:
                pass
    
    # Ajouter aussi le domaine nu
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolvers[0]]
        answers = resolver.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answers]
        results[domain] = ips
        print(f"[+] Domaine principal: {domain} -> {ips}")
    except:
        pass
    
    return results