#!/usr/bin/env python3
"""
Module d'analyse Shodan pour la reconnaissance externe
"""

import os
import time
from typing import Dict, List, Optional

# Variable globale pour stocker la clé API
SHODAN_API_KEY = None

def set_api_key(api_key: str):
    """Configure la clé API Shodan"""
    global SHODAN_API_KEY
    SHODAN_API_KEY = api_key

def get_api_key() -> Optional[str]:
    """Récupère la clé API Shodan"""
    global SHODAN_API_KEY
    if SHODAN_API_KEY:
        return SHODAN_API_KEY
    
    # Essayer de récupérer depuis une variable d'environnement
    return os.getenv('SHODAN_API_KEY')

def check_api_key() -> bool:
    """Vérifie si une clé API Shodan est disponible"""
    api_key = get_api_key()
    if not api_key:
        print("[!] AVERTISSEMENT: Aucune clé API Shodan configurée.")
        print("[!] Pour utiliser Shodan, configurez votre clé API :")
        print("[!]   - Variable d'environnement: SHODAN_API_KEY")
        print("[!]   - Ou utilisez set_api_key() dans votre code")
        return False
    return True

def get_info_for_ip(ip: str) -> Optional[Dict]:
    """
    Récupère les informations Shodan pour une IP donnée.
    Retourne un dictionnaire avec les informations ou None si erreur.
    """
    if not check_api_key():
        return None
    
    try:
        import shodan
        
        api_key = get_api_key()
        api = shodan.Shodan(api_key)
        
        print(f"[*] Recherche d'informations Shodan pour {ip}...")
        
        # Recherche d'informations sur l'IP
        host_info = api.host(ip)
        
        # Extraction des informations pertinentes
        result = {
            'ip': ip,
            'country': host_info.get('country_name', 'Inconnu'),
            'org': host_info.get('org', 'Inconnu'),
            'ports': host_info.get('ports', []),
            'services': []
        }
        
        # Extraction des services détectés
        for item in host_info.get('data', []):
            service = {
                'port': item.get('port'),
                'service': item.get('product', 'Inconnu'),
                'version': item.get('version', 'Inconnu'),
                'banner': item.get('data', '')[:100] + '...' if len(item.get('data', '')) > 100 else item.get('data', '')
            }
            result['services'].append(service)
        
        print(f"[+] Informations Shodan trouvées pour {ip}:")
        print(f"    Pays: {result['country']}")
        print(f"    Organisation: {result['org']}")
        print(f"    Ports ouverts: {result['ports']}")
        print(f"    Services détectés: {len(result['services'])}")
        
        # Enregistrer pour le reporting
        try:
            from .reporting import add_scan_detail
            add_scan_detail('shodan_results', result)
        except ImportError:
            pass
        
        return result
        
    except ImportError:
        print("[!] ERREUR: Module 'shodan' non installé.")
        print("[!] Installez-le avec: pip install shodan")
        return None
    except Exception as e:
        print(f"[!] ERREUR lors de la recherche Shodan pour {ip}: {str(e)}")
        return None

def search_devices(query: str, limit: int = 10) -> List[Dict]:
    """
    Recherche des appareils IoT via Shodan.
    Retourne une liste d'appareils trouvés.
    """
    if not check_api_key():
        return []
    
    try:
        import shodan
        
        api_key = get_api_key()
        api = shodan.Shodan(api_key)
        
        print(f"[*] Recherche Shodan: '{query}' (limite: {limit})")
        
        # Recherche avec la requête
        search_results = api.search(query, limit=limit)
        
        devices_found = []
        
        for item in search_results['matches']:
            device = {
                'ip': item['ip_str'],
                'port': item.get('port'),
                'service': item.get('product', 'Inconnu'),
                'version': item.get('version', 'Inconnu'),
                'country': item.get('location', {}).get('country_name', 'Inconnu'),
                'org': item.get('org', 'Inconnu'),
                'banner': item.get('data', '')[:100] + '...' if len(item.get('data', '')) > 100 else item.get('data', '')
            }
            devices_found.append(device)
        
        print(f"[+] {len(devices_found)} appareil(s) trouvé(s) via Shodan")
        
        # Enregistrer pour le reporting
        try:
            from .reporting import add_scan_detail
            for device in devices_found:
                add_scan_detail('shodan_results', device)
        except ImportError:
            pass
        
        return devices_found
        
    except ImportError:
        print("[!] ERREUR: Module 'shodan' non installé.")
        print("[!] Installez-le avec: pip install shodan")
        return []
    except Exception as e:
        print(f"[!] ERREUR lors de la recherche Shodan: {str(e)}")
        return []

def run():
    """Fonction de test pour le module Shodan"""
    print("[*] Test du module Shodan...")
    
    # Test avec une IP publique connue (Google DNS)
    test_ip = "8.8.8.8"
    result = get_info_for_ip(test_ip)
    
    if result:
        print(f"[+] Test réussi pour {test_ip}")
    else:
        print(f"[-] Test échoué pour {test_ip}")
    
    # Test de recherche
    search_query = "product:nginx"
    devices = search_devices(search_query, limit=3)
    
    if devices:
        print(f"[+] Recherche réussie: {len(devices)} appareils trouvés")
    else:
        print(f"[-] Recherche échouée pour '{search_query}'") 