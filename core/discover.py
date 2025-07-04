#!/usr/bin/env python3
"""
Module de découverte avancée des dispositifs IoT
"""

import socket
import struct
import time
import subprocess
import re
import threading
import queue
import json
import requests
from typing import List, Dict, Set, Optional
from .utils import log_info, log_error
import logging

logger = logging.getLogger('iotbreaker')

def get_local_network_info():
    """Récupère les informations du réseau local"""
    try:
        # Obtenir l'adresse IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Extraire le réseau (premiers 3 octets)
        network_parts = local_ip.split('.')
        network_base = '.'.join(network_parts[:3])
        
        return {
            'local_ip': local_ip,
            'network_base': network_base,
            'gateway': f"{network_base}.1"
        }
    except Exception as e:
        log_error(f"Erreur lors de la récupération des infos réseau: {str(e)}")
        return None

def scan_network_range_parallel(network_base: str, start: int = 1, end: int = 254, max_threads: int = 50) -> Set[str]:
    """Scanne une plage d'adresses IP en parallèle pour trouver des appareils actifs"""
    active_ips = set()
    ip_queue = queue.Queue()
    results = queue.Queue()
    
    # Remplir la queue avec toutes les IPs à scanner
    for i in range(start, end + 1):
        ip_queue.put(f"{network_base}.{i}")
    
    def scan_worker():
        """Worker thread pour scanner une IP"""
        while True:
            try:
                ip = ip_queue.get_nowait()
            except queue.Empty:
                break
            
            try:
                # Test de connectivité rapide sur plusieurs ports
                for port in [80, 443, 22, 23, 8080]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        results.put(ip)
                        break
            except Exception:
                pass
            finally:
                ip_queue.task_done()
    
    print(f"[*] Scan parallèle du réseau {network_base}.{start}-{end}...")
    
    # Lancer les threads de scan
    threads = []
    for _ in range(min(max_threads, end - start + 1)):
        t = threading.Thread(target=scan_worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Attendre que tous les threads terminent
    for t in threads:
        t.join()
    
    # Collecter les résultats
    while not results.empty():
        active_ips.add(results.get())
    
    return active_ips

def discover_upnp() -> Set[str]:
    """Découverte des appareils UPnP"""
    devices = set()
    try:
        # Création du socket multicast
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        
        # Envoi de la requête M-SEARCH
        msearch = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'ST: ssdp:all\r\n'
            'MX: 3\r\n\r\n'
        )
        sock.sendto(msearch.encode(), ('239.255.255.250', 1900))
        
        # Réception des réponses
        start_time = time.time()
        while time.time() - start_time < 5:  # Timeout de 5 secondes
            try:
                data, addr = sock.recvfrom(1024)
                response = data.decode()
                if 'LOCATION:' in response or 'SERVER:' in response:
                    devices.add(addr[0])
                    print(f"  [+] Appareil UPnP trouvé: {addr[0]}")
            except socket.timeout:
                continue
    except Exception as e:
        log_error(f"Erreur lors de la découverte UPnP: {str(e)}")
    finally:
        sock.close()
    
    logger.info(f"Découverte de {len(devices)} dispositifs UPnP")
    return devices

def discover_mdns() -> Set[str]:
    """Découverte des appareils mDNS"""
    devices = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        
        # Envoi de la requête mDNS pour les services IoT courants
        mdns_queries = [
            # Services IoT courants
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',
            # Caméras IP
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c_ip-camera\x04_udp\x05local\x00\x00\x0c\x00\x01',
            # Imprimantes
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0a_ipp._tcp\x05local\x00\x00\x0c\x00\x01',
            # Smart TVs
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_airplay\x04_tcp\x05local\x00\x00\x0c\x00\x01',
            # Google Nest
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0a_googlecast\x04_tcp\x05local\x00\x00\x0c\x00\x01',
            # Philips Hue
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_philips\x04_tcp\x05local\x00\x00\x0c\x00\x01',
            # HomeKit
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_homekit\x04_tcp\x05local\x00\x00\x0c\x00\x01'
        ]
        
        for query in mdns_queries:
            try:
                sock.sendto(query.encode(), ('224.0.0.251', 5353))
            except Exception:
                pass
        
        # Réception des réponses
        start_time = time.time()
        while time.time() - start_time < 5:  # Timeout de 5 secondes
            try:
                data, addr = sock.recvfrom(1024)
                devices.add(addr[0])
                print(f"  [+] Appareil mDNS trouvé: {addr[0]}")
            except socket.timeout:
                continue
    except Exception as e:
        log_error(f"Erreur lors de la découverte mDNS: {str(e)}")
    finally:
        sock.close()
    
    logger.info(f"Découverte de {len(devices)} dispositifs mDNS")
    return devices

def discover_bluetooth_devices() -> Set[str]:
    """Découverte des appareils Bluetooth (si disponible)"""
    devices = set()
    try:
        # Tentative de découverte Bluetooth (fonctionne sur certains systèmes)
        import subprocess
        result = subprocess.run(['hcitool', 'scan'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if ':' in line and len(line.split()) >= 2:
                    # Extraire l'adresse MAC Bluetooth
                    mac = line.split()[0]
                    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                        devices.add(f"BT:{mac}")
                        print(f"  [+] Appareil Bluetooth trouvé: {mac}")
    except Exception as e:
        # Bluetooth non disponible ou erreur, on continue
        pass
    
    return devices

def discover_wifi_devices() -> Set[str]:
    """Découverte des appareils WiFi visibles"""
    devices = set()
    try:
        # Tentative de découverte des réseaux WiFi (Windows)
        result = subprocess.run(['netsh', 'wlan', 'show', 'networks'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'SSID' in line and ':' in line:
                    ssid = line.split(':')[1].strip()
                    if ssid and ssid != '':
                        devices.add(f"WiFi:{ssid}")
                        print(f"  [+] Réseau WiFi trouvé: {ssid}")
    except Exception as e:
        # WiFi discovery non disponible, on continue
        pass
    
    return devices

def discover_smart_devices() -> List[Dict]:
    """Découverte des appareils intelligents (Google Nest, ampoules, etc.)"""
    smart_devices = []
    
    print("\n[*] Méthode 6: Découverte des appareils intelligents...")
    
    # 1. Découverte Google Nest/Chromecast (version optimisée)
    try:
        # Recherche des appareils Google Cast avec timeout court
        cast_query = '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0a_googlecast\x04_tcp\x05local\x00\x00\x0c\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)  # Timeout réduit
        sock.sendto(cast_query.encode(), ('224.0.0.251', 5353))
        
        start_time = time.time()
        while time.time() - start_time < 2:  # Timeout réduit
            try:
                data, addr = sock.recvfrom(1024)
                device_info = {
                    'ip': addr[0],
                    'type': 'Google Nest/Chromecast',
                    'protocol': 'mDNS',
                    'open_ports': [],
                    'banners': {}
                }
                smart_devices.append(device_info)
                print(f"  [+] Google Nest/Chromecast trouvé: {addr[0]}")
            except socket.timeout:
                continue
        sock.close()
    except Exception:
        pass
    
    # 2. Découverte Philips Hue (version optimisée)
    try:
        # Recherche des bridges Philips Hue avec timeout court
        hue_query = '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_philips\x04_tcp\x05local\x00\x00\x0c\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)  # Timeout réduit
        sock.sendto(hue_query.encode(), ('224.0.0.251', 5353))
        
        start_time = time.time()
        while time.time() - start_time < 2:  # Timeout réduit
            try:
                data, addr = sock.recvfrom(1024)
                device_info = {
                    'ip': addr[0],
                    'type': 'Philips Hue Bridge',
                    'protocol': 'mDNS',
                    'open_ports': [],
                    'banners': {}
                }
                smart_devices.append(device_info)
                print(f"  [+] Philips Hue Bridge trouvé: {addr[0]}")
            except socket.timeout:
                continue
        sock.close()
    except Exception:
        pass
    
    # 3. Découverte des thermostats intelligents (version optimisée)
    try:
        # Recherche des thermostats Nest avec timeout court
        thermostat_query = '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b_thermostat\x04_tcp\x05local\x00\x00\x0c\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)  # Timeout réduit
        sock.sendto(thermostat_query.encode(), ('224.0.0.251', 5353))
        
        start_time = time.time()
        while time.time() - start_time < 2:  # Timeout réduit
            try:
                data, addr = sock.recvfrom(1024)
                device_info = {
                    'ip': addr[0],
                    'type': 'Thermostat intelligent',
                    'protocol': 'mDNS',
                    'open_ports': [],
                    'banners': {}
                }
                smart_devices.append(device_info)
                print(f"  [+] Thermostat intelligent trouvé: {addr[0]}")
            except socket.timeout:
                continue
        sock.close()
    except Exception:
        pass
    
    # 4. Scan spécifique pour les ports IoT intelligents (version optimisée)
    network_info = get_local_network_info()
    if network_info:
        # Ports IoT intelligents les plus courants
        iot_ports = [8008, 8009, 9123, 8883]  # Réduit pour plus de rapidité
        
        # Scan parallèle des ports IoT
        def scan_iot_port(port):
            found_devices = []
            for i in range(1, 255):
                ip = f"{network_info['network_base']}.{i}"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)  # Timeout très court
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        # Identifier le type d'appareil par port
                        device_type = "Appareil IoT"
                        if port == 8008:
                            device_type = "Google Nest/Chromecast"
                        elif port == 9123:
                            device_type = "Philips Hue Bridge"
                        elif port == 8883:
                            device_type = "Appareil MQTT sécurisé"
                        
                        device_info = {
                            'ip': ip,
                            'type': device_type,
                            'protocol': 'TCP',
                            'open_ports': [port],
                            'banners': {}
                        }
                        found_devices.append(device_info)
                        print(f"  [+] {device_type} trouvé: {ip}:{port}")
                except Exception:
                    pass
            return found_devices
        
        # Scan séquentiel pour éviter les blocages
        for port in iot_ports:
            try:
                found = scan_iot_port(port)
                smart_devices.extend(found)
            except Exception:
                continue
    
    return smart_devices

def discover_zigbee_devices() -> List[Dict]:
    """Découverte des appareils Zigbee (via USB dongles)"""
    zigbee_devices = []
    
    print("\n[*] Méthode 7: Découverte des appareils Zigbee...")
    
    try:
        # Tentative de détection des dongles Zigbee USB
        import subprocess
        result = subprocess.run(['lsusb'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if any(keyword in line.lower() for keyword in ['zigbee', 'cc2531', 'cc2530', 'sniffer']):
                    device_info = {
                        'ip': f"USB:{line.strip()}",
                        'type': 'Dongle Zigbee',
                        'protocol': 'USB',
                        'open_ports': [],
                        'banners': {}
                    }
                    zigbee_devices.append(device_info)
                    print(f"  [+] Dongle Zigbee trouvé: {line.strip()}")
    except Exception:
        pass
    
    return zigbee_devices

def grab_banner(ip, port):
    """Tente de récupérer la bannière d'un service sur un port donné."""
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except Exception:
        return None

def identify_device(banners, ip, open_ports):
    """Tente d'identifier un appareil à partir de ses bannières et ports ouverts."""
    if not banners and not open_ports:
        return "Inconnu"
    
    # Fingerprints basés sur les bannières
    fingerprints = {
        'lighttpd': 'Appareil embarqué (caméra/NAS)',
        'mini_httpd': 'Appareil embarqué (caméra/NAS)',
        'Linux telnetd': 'Appareil Linux (Routeur/Raspberry Pi)',
        'Hikvision': 'Caméra IP Hikvision',
        'Dahua': 'Caméra IP Dahua',
        'Foscam': 'Caméra IP Foscam',
        'nginx': 'Serveur web (Routeur/NAS)',
        'apache': 'Serveur web (Routeur/NAS)',
        'router': 'Routeur/Point d\'accès',
        'gateway': 'Passerelle réseau',
        'printer': 'Imprimante réseau',
        'tv': 'Smart TV',
        'xbox': 'Console Xbox',
        'playstation': 'Console PlayStation',
        'nas': 'Serveur NAS',
        'thermostat': 'Thermostat intelligent',
        'light': 'Ampoule connectée',
        'switch': 'Interrupteur intelligent',
        'sensor': 'Capteur IoT',
        'camera': 'Caméra IP',
        'google': 'Google Nest/Chromecast',
        'philips': 'Philips Hue',
        'nest': 'Google Nest',
        'chromecast': 'Google Chromecast'
    }
    
    # Vérifier les bannières
    if banners:
        full_banner_text = " ".join(banners.values()).lower()
        for keyword, device_type in fingerprints.items():
            if keyword.lower() in full_banner_text:
                return device_type
    
    # Vérifier les ports ouverts pour identifier le type d'appareil
    port_fingerprints = {
        (80, 443): 'Appareil web (Routeur/Caméra/NAS)',
        (22,): 'Appareil Linux/Unix',
        (23,): 'Appareil avec Telnet (potentiellement vulnérable)',
        (21,): 'Serveur FTP',
        (1883,): 'Broker MQTT (IoT)',
        (5683,): 'Appareil CoAP (IoT)',
        (8080,): 'Appareil avec interface web alternative',
        (9100,): 'Imprimante réseau',
        (5353,): 'Appareil avec service mDNS',
        (1900,): 'Appareil UPnP',
        (8008, 8009): 'Google Nest/Chromecast',
        (9123,): 'Philips Hue Bridge',
        (8883,): 'Appareil MQTT sécurisé'
    }
    
    open_ports_set = set(open_ports)
    for ports, device_type in port_fingerprints.items():
        if any(port in open_ports_set for port in ports):
            return device_type
    
    return "Appareil IoT"

def run() -> Optional[List[Dict]]:
    """Fonction principale de découverte et de fingerprinting - Version portable universelle."""
    print("[*] Démarrage de la découverte avancée des dispositifs IoT...")
    
    # Récupérer les informations du réseau local actuel
    network_info = get_local_network_info()
    if not network_info:
        print("[-] Impossible de récupérer les informations réseau")
        return []
    
    print(f"[*] 🌐 Réseau détecté automatiquement: {network_info['network_base']}.0/24")
    print(f"[*] 📱 IP locale: {network_info['local_ip']}")
    print(f"[*] 🏠 Passerelle: {network_info['gateway']}")
    print(f"[*] 🔍 Découverte IoT portable activée - Scan de tous les appareils intelligents...")
    
    # Combiner différentes méthodes de découverte
    discovered_ips = set()
    devices_found = []
    
    print("\n[*] Méthode 1: Découverte UPnP universelle...")
    upnp_ips = discover_upnp()
    discovered_ips.update(upnp_ips)
    
    print("\n[*] Méthode 2: Découverte mDNS universelle...")
    mdns_ips = discover_mdns()
    discovered_ips.update(mdns_ips)
    
    print("\n[*] Méthode 3: Scan réseau parallèle universel...")
    network_ips = scan_network_range_parallel(network_info['network_base'])
    discovered_ips.update(network_ips)
    
    print("\n[*] Méthode 4: Découverte Bluetooth portable...")
    bluetooth_devices = discover_bluetooth_devices()
    
    print("\n[*] Méthode 5: Découverte WiFi portable...")
    wifi_devices = discover_wifi_devices()
    
    # Découverte des appareils intelligents (version portable)
    smart_devices = discover_smart_devices()
    
    # Découverte des appareils Zigbee (version portable)
    zigbee_devices = discover_zigbee_devices()
    
    # Ajouter la passerelle si elle n'est pas déjà trouvée
    discovered_ips.add(network_info['gateway'])
    
    # Filtrer pour ne garder que les IPs du réseau local actuel
    local_network_ips = {ip for ip in discovered_ips if ip.startswith(network_info['network_base'])}
    
    print(f"\n[+] 📊 RÉSUMÉ DE LA DÉCOUVERTE PORTABLE:")
    print(f"[+]   • {len(local_network_ips)} appareil(s) réseau trouvé(s)")
    print(f"[+]   • {len(bluetooth_devices)} appareil(s) Bluetooth trouvé(s)")
    print(f"[+]   • {len(wifi_devices)} réseau(x) WiFi trouvé(s)")
    print(f"[+]   • {len(smart_devices)} appareil(s) intelligent(s) trouvé(s)")
    print(f"[+]   • {len(zigbee_devices)} appareil(s) Zigbee trouvé(s)")
    
    print(f"\n[+] 🔍 Démarrage du fingerprinting intelligent de {len(local_network_ips)} appareil(s)...")
    
    # Analyser les appareils réseau avec identification intelligente
    for ip in local_network_ips:
        print(f"\n--- 📱 Analyse de l'appareil : {ip} ---")
        device_info = {
            'ip': ip,
            'open_ports': [],
            'banners': {},
            'type': 'Inconnu',
            'protocol': 'IP',
            'network': network_info['network_base'],
            'location': 'Réseau local'
        }
        
        # Ports IoT intelligents à scanner (optimisés pour tous les appareils)
        ports_to_scan = [
            23, 80, 443, 8080, 1883, 5683, 22, 21, 9100, 5353, 1900,  # Ports classiques
            8008, 8009, 9123, 8883, 8081, 8082, 8083, 8084, 8085,     # Ports IoT intelligents
            9000, 9001, 9002, 9003, 9004, 9005,                       # Ports alternatifs
            1884, 1885, 1886, 1887, 1888, 1889,                       # Ports MQTT alternatifs
            5684, 5685, 5686, 5687, 5688, 5689,                       # Ports CoAP alternatifs
            8884, 8885, 8886, 8887, 8888, 8889,                       # Ports sécurisés alternatifs
            9124, 9125, 9126, 9127, 9128, 9129                        # Ports Hue alternatifs
        ]
        
        for port in ports_to_scan:
            banner = grab_banner(ip, port)
            if banner:
                print(f"  [+] Port {port} ouvert. Bannière : {banner[:50]}...")
                device_info['open_ports'].append(port)
                device_info['banners'][port] = banner
        
        # Identification intelligente du type d'appareil
        device_info['type'] = identify_device(device_info['banners'], ip, device_info['open_ports'])
        
        # Identification spéciale pour la passerelle
        if ip == network_info['gateway']:
            device_info['type'] = 'Routeur/Passerelle réseau'
        
        print(f"  [>] Type d'appareil estimé : {device_info['type']}")
        devices_found.append(device_info)
    
    # Ajouter les appareils Bluetooth avec informations de localisation
    for bt_device in bluetooth_devices:
        device_info = {
            'ip': bt_device,
            'open_ports': [],
            'banners': {},
            'type': 'Appareil Bluetooth',
            'protocol': 'Bluetooth',
            'network': network_info['network_base'],
            'location': 'Proximité immédiate'
        }
        devices_found.append(device_info)
        print(f"\n--- 📱 Appareil Bluetooth : {bt_device} ---")
        print(f"  [>] Type d'appareil : Appareil Bluetooth")
    
    # Ajouter les réseaux WiFi avec informations de localisation
    for wifi_network in wifi_devices:
        device_info = {
            'ip': wifi_network,
            'open_ports': [],
            'banners': {},
            'type': 'Réseau WiFi',
            'protocol': 'WiFi',
            'network': network_info['network_base'],
            'location': 'Zone de couverture WiFi'
        }
        devices_found.append(device_info)
        print(f"\n--- 📱 Réseau WiFi : {wifi_network} ---")
        print(f"  [>] Type d'appareil : Réseau WiFi")
    
    # Ajouter les appareils intelligents avec informations de localisation
    for smart_device in smart_devices:
        smart_device['network'] = network_info['network_base']
        smart_device['location'] = 'Réseau local intelligent'
        devices_found.append(smart_device)
        print(f"\n--- 📱 Appareil intelligent : {smart_device['ip']} ---")
        print(f"  [>] Type d'appareil : {smart_device['type']}")
    
    # Ajouter les appareils Zigbee avec informations de localisation
    for zigbee_device in zigbee_devices:
        zigbee_device['network'] = network_info['network_base']
        zigbee_device['location'] = 'Réseau local Zigbee'
        devices_found.append(zigbee_device)
        print(f"\n--- 📱 Appareil Zigbee : {zigbee_device['ip']} ---")
        print(f"  [>] Type d'appareil : {zigbee_device['type']}")
    
    # Enregistrer les détails pour le reporting
    try:
        from .reporting import add_scan_detail
        for device in devices_found:
            add_scan_detail('discovered_devices', device)
    except ImportError:
        pass
    
    print(f"\n--- 🎯 FIN DE LA DÉCOUVERTE PORTABLE ---")
    print(f"[+] 🌍 Total: {len(devices_found)} appareil(s) découvert(s)")
    print(f"[+] 📍 Réseau scanné: {network_info['network_base']}.0/24")
    print(f"[+] 🔄 Prêt pour le prochain réseau...")
    
    return devices_found