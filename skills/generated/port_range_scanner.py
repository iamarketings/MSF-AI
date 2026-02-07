import socket
import sys

def port_range_scanner(ip, start_port, end_port):
    open_ports = {}
    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports[port] = 'open'
            sock.close()
    except Exception as e:
        return {'error': str(e)}
    return open_ports if open_ports else {'message': 'No open ports found'}