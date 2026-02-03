"""
Network Utilities Module for MSF-AI v4
"""
import socket
import ipaddress
import requests
import json
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

def expand_cidr(cidr: str) -> List[str]:
    """Expands a CIDR notation into a list of IPs."""
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    except Exception as e:
        return [f"Error: {e}"]

def geolocate_ip(ip: str) -> Dict[str, Any]:
    """Geolocates an IP address using ip-api.com."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        return response.json()
    except Exception as e:
        return {"status": "fail", "error": str(e)}

def get_public_ip() -> str:
    """Returns the current public IP address."""
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except Exception as e:
        return f"Error: {e}"

def parse_nmap_xml(file_path: str) -> Dict[str, Any]:
    """Parses Nmap XML output for ports and services."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        hosts = []
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            ports = []
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                service = port.find('service').get('name') if port.find('service') is not None else "unknown"
                if state == 'open':
                    ports.append({"port": port_id, "service": service})
            if ports:
                hosts.append({"ip": ip, "ports": ports})
        return {"hosts": hosts}
    except Exception as e:
        return {"error": str(e)}

def port_knock(ip: str, ports: List[int]) -> str:
    """Performs a port knocking sequence."""
    try:
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect_ex((ip, int(port)))
                sock.close()
            except:
                pass
        return f"Knock sequence {ports} sent to {ip}"
    except Exception as e:
        return f"Error: {e}"

def reverse_dns(ip: str) -> str:
    """Performs reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "No PTR record"

def check_port_open(target: str, port: int) -> bool:
    """Checks if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, int(port)))
        sock.close()
        return result == 0
    except:
        return False

def get_tools() -> Dict[str, Any]:
    """Returns tool definitions for this module."""
    return {
        "expand_cidr": expand_cidr,
        "geolocate_ip": geolocate_ip,
        "get_public_ip": get_public_ip,
        "parse_nmap_xml": parse_nmap_xml,
        "port_knock": port_knock,
        "reverse_dns": reverse_dns,
        "check_port_open": check_port_open
    }
