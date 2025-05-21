import os

def run():
    print("[*] Découverte des appareils IoT via SSDP...")
    os.system("gssdp-discover --timeout=5")  # Utilitaire Kali pour SSDP