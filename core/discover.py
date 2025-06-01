#!/usr/bin/env python3
"""
Module de découverte des dispositifs IoT
"""

import socket
import struct
import time
from typing import List, Dict, Set, Optional
from .utils import log_info, log_error
import logging

logger = logging.getLogger('iotbreaker')

def discover_upnp() -> Set[str]:
    """Découverte des appareils UPnP"""
    devices = set()
    try:
        # Création du socket multicast
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        
        # Envoi de la requête M-SEARCH
        msearch = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'ST: ssdp:all\r\n'
            'MX: 2\r\n\r\n'
        )
        sock.sendto(msearch.encode(), ('239.255.255.250', 1900))
        
        # Réception des réponses
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                response = data.decode()
                if 'LOCATION:' in response:
                    devices.add(addr[0])
            except socket.timeout:
                break
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
        sock.settimeout(2)
        
        # Envoi de la requête mDNS
        mdns_query = (
            '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            '\x09_services\x07_dns-sd\x04_udp\x05local\x00'
            '\x00\x0c\x00\x01'
        )
        sock.sendto(mdns_query.encode(), ('224.0.0.251', 5353))
        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                devices.add(addr[0])
            except socket.timeout:
                break
    except Exception as e:
        log_error(f"Erreur lors de la découverte mDNS: {str(e)}")
    finally:
        sock.close()
    
    logger.info(f"Découverte de {len(devices)} dispositifs mDNS")
    return devices

def run() -> Optional[Set[str]]:
    """Fonction principale de découverte"""
    logger.info("Démarrage de la découverte des dispositifs IoT...")
    
    # Découverte UPnP
    upnp_devices = discover_upnp()
    
    # Découverte mDNS
    mdns_devices = discover_mdns()
    
    # Combinaison des résultats
    all_devices = upnp_devices.union(mdns_devices)
    
    # Affichage des résultats
    if all_devices:
        print("\nDispositifs découverts:")
        for device in all_devices:
            if device in upnp_devices:
                print(f"- {device} (UPnP)")
            if device in mdns_devices:
                print(f"- {device} (mDNS)")
    else:
        print("Aucun dispositif découvert")
    
    return all_devices