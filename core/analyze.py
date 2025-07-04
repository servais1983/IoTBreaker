import socket
import requests
# Ajout de l'importation pour l'analyseur IA
from .ai_analyzer import get_ai_analysis

def run(ip):
    print(f"[*] Analyse intelligente des ports IoT sur {ip} avec l'aide de l'IA...")

    # Ports IoT standards à analyser
    ports = {
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        1883: "MQTT",
        5683: "CoAP",
        22: "SSH",
        21: "FTP",
        8080: "HTTP Alt",
        8883: "MQTT SSL",
        8884: "MQTT SSL Alt"
    }
    
    open_ports = []
    closed_ports = []
    ports_tested = list(ports.keys())
    banners = {}

    # Scan des ports
    for port, name in ports.items():
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((ip, port))
            print(f"[+] Port ouvert {port} ({name})")
            open_ports.append(port)
            
            # Tentative de récupération de bannière
            try:
                sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if banner.strip():
                    banners[port] = banner.strip()
                    print(f"  [+] Bannière: {banner.strip()[:50]}...")
            except:
                pass
                
            sock.close()
        except:
            print(f"[-] Port {port} fermé ou inaccessible")
            closed_ports.append(port)
    
    # Analyse intelligente par l'IA
    if open_ports:
        print("\n[🧠] Analyse intelligente par l'IA...")
        
        # Création du prompt pour l'IA
        prompt = f"""
        Analyse de sécurité IoT pour l'appareil {ip} :
        
        Ports ouverts : {open_ports}
        Services détectés : {[ports[p] for p in open_ports]}
        Bannières : {banners}
        
        En te basant sur ces informations :
        1.  Quel type d'appareil IoT est-ce probablement ?
        2.  Quels sont les risques de sécurité les plus critiques ?
        3.  Quelles vulnérabilités devrais-je tester en priorité ?
        
        Sois concis et spécifique.
        """
        
        ai_analysis = get_ai_analysis(prompt, max_length=256)
        if ai_analysis and "non disponible" not in ai_analysis and "Erreur" not in ai_analysis:
            print(f"  [+] Analyse IA : {ai_analysis}")
    
    # Enregistrer les détails pour le reporting
    try:
        from .reporting import add_scan_detail
        scan_info = {
            'target': ip,
            'ports_tested': ports_tested,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'banners': banners,
            'ai_analysis': ai_analysis if 'ai_analysis' in locals() else None
        }
        add_scan_detail('port_scans', scan_info)
    except ImportError:
        pass 