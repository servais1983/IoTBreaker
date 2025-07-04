import socket

def run(ip):
    print(f"[*] Analyse des ports standards IoT sur {ip}...")

    ports = {
        23: "Telnet",
        80: "HTTP",
        1883: "MQTT",
        5683: "CoAP"
    }
    
    open_ports = []
    closed_ports = []
    ports_tested = list(ports.keys())

    for port, name in ports.items():
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((ip, port))
            print(f"[+] Port ouvert {port} ({name})")
            open_ports.append(port)
            sock.close()
        except:
            print(f"[-] Port {port} fermé ou inaccessible")
            closed_ports.append(port)
    
    # Enregistrer les détails pour le reporting
    try:
        from .reporting import add_scan_detail
        scan_info = {
            'target': ip,
            'ports_tested': ports_tested,
            'open_ports': open_ports,
            'closed_ports': closed_ports
        }
        add_scan_detail('port_scans', scan_info)
    except ImportError:
        pass 