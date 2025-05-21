import socket

def run(ip):
    print(f"[*] Analyse des ports standards IoT sur {ip}...")

    ports = {
        23: "Telnet",
        80: "HTTP",
        1883: "MQTT",
        5683: "CoAP"
    }

    for port, name in ports.items():
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((ip, port))
            print(f"[+] Port ouvert {port} ({name})")
            sock.close()
        except:
            print(f"[-] Port {port} fermé ou inaccessible")