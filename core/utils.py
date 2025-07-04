import yaml
import sys
import os
import importlib
import logging

# Configuration du logging
logger = logging.getLogger('iotbreaker')

def log_info(message):
    """Fonction de logging pour les informations"""
    logger.info(message)
    print(f"[+] {message}")

def log_error(message):
    """Fonction de logging pour les erreurs"""
    logger.error(message)
    print(f"[!] ERREUR: {message}")

def log_warning(message):
    """Fonction de logging pour les avertissements"""
    logger.warning(message)
    print(f"[!] AVERTISSEMENT: {message}")

# Import dynamique pour éviter les imports circulaires
def get_module(module_name):
    """Import dynamique d'un module pour éviter les imports circulaires"""
    return importlib.import_module(f'core.{module_name}')

def run_script_yaml(path):
    """
    Exécute un scénario de test à partir d'un fichier YAML.
    
    Le format attendu est:
    ```yaml
    name: Nom du scénario
    description: Description du scénario (optionnel)
    steps:
      - type: discover|analyze|check
        target: IP_CIBLE (optionnel pour discover)
        description: Description de l'étape (optionnel)
    config:
      timeout: 5  # Timeout en secondes
      verbose: true  # Mode verbeux
      safe_mode: true  # Mode sans impact
    """
    
    # Configuration automatique de la clé API Shodan
    try:
        from .shodan_analyzer import set_api_key
        # Utilise uniquement les variables d'environnement pour la sécurité
        shodan_key = os.getenv('SHODAN_API_KEY')
        if shodan_key:
            set_api_key(shodan_key)
            print(f"[+] Clé API Shodan configurée via variable d'environnement")
        else:
            print(f"[!] Clé API Shodan non trouvée. Définissez SHODAN_API_KEY dans vos variables d'environnement")
    except ImportError:
        pass
    if not os.path.exists(path):
        print(f"[!] ERREUR: Le fichier de scénario '{path}' n'existe pas.")
        sys.exit(1)

    print(f"[*] Chargement du scénario : {path}")
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"[!] ERREUR: Format YAML invalide: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] ERREUR: Impossible de lire le fichier: {e}")
        sys.exit(1)

    # Validation du format du scénario
    if not isinstance(data, dict):
        print("[!] ERREUR: Format du scénario invalide. Le fichier YAML doit contenir un dictionnaire.")
        sys.exit(1)
    
    if "steps" not in data or not isinstance(data["steps"], list):
        print("[!] ERREUR: Le scénario doit contenir une liste 'steps'.")
        sys.exit(1)
    
    # Affichage des informations du scénario
    print(f"[+] Exécution du scénario: {data.get('name', 'Sans nom')}")
    if "description" in data:
        print(f"[+] Description: {data['description']}")
    
    # Configuration
    config = data.get("config", {})
    timeout = config.get("timeout", 5)
    verbose = config.get("verbose", False)
    safe_mode = config.get("safe_mode", True)
    should_exploit = config.get("exploit", False)
    if should_exploit:
        print("[!] Mode exploitation activé. Des actions actives seront tentées sur les cibles.")
    print(f"[+] Configuration: timeout={timeout}s, verbose={verbose}, safe_mode={safe_mode}")
    
    # On initialise une liste pour stocker tous les résultats de l'audit
    all_results = []
    
    # Exécution des étapes
    print("\n[*] Début de l'exécution des étapes...")
    
    # Variables pour la découverte automatique
    discovered_devices = []
    auto_discovery_enabled = config.get("auto_discovery", False)
    
    for i, step in enumerate(data.get("steps", []), 1):
        if not isinstance(step, dict) or "type" not in step:
            print(f"[!] AVERTISSEMENT: L'étape {i} est mal formatée, ignorée.")
            continue
        
        step_type = step.get("type")
        target = step.get("target", "")
        description = step.get("description", "")
        
        print(f"\n[*] Étape {i}: {step_type} {target} {description}")
        
        if step_type == "discover":
            discovered_devices = get_module("discover").run()
            if discovered_devices and auto_discovery_enabled:
                print(f"[+] {len(discovered_devices)} appareils découverts pour l'audit automatique")
        elif step_type == "analyze":
            if target == "auto_discovered" and discovered_devices:
                # Analyse automatique de tous les appareils découverts
                analyze_module = get_module("analyze")
                for device in discovered_devices:
                    device_ip = device.get('ip', '')
                    if device_ip:
                        print(f"[*] Analyse automatique de {device_ip}")
                        analyze_module.run(device_ip)
            elif target and target != "auto_discovered":
                analyze_module = get_module("analyze")
                analyze_module.run(target)
            else:
                print("[!] AVERTISSEMENT: Aucune cible spécifiée pour l'analyse.")
        elif step_type == "check":
            if target == "auto_discovered" and discovered_devices:
                # Vérification automatique de tous les appareils découverts
                check_module = get_module("check")
                for device in discovered_devices:
                    device_ip = device.get('ip', '')
                    if device_ip:
                        print(f"[*] Vérification automatique de {device_ip}")
                        results_from_check = check_module.run(device_ip)
                        if results_from_check:
                            # Exploit Telnet si demandé
                            for vuln in results_from_check:
                                if should_exploit and vuln.get('severity') == 'CRITICAL' and vuln.get('module') == 'Telnet':
                                    try:
                                        creds = vuln['description'].split(': ')[-1].split(':')
                                        user, passwd = creds[0], creds[1]
                                        exploit_module = get_module("exploit")
                                        exploit_module.exploit_telnet(device_ip, user, passwd)
                                    except Exception:
                                        print(f"[!] Impossible d'extraire les identifiants pour l'exploit Telnet.")
                                # Exploit MQTT si demandé
                                if should_exploit and 'MQTT' in vuln.get('module', '') and "abonnement à tous les topics" in vuln.get('description', ''):
                                    exploit_module = get_module("exploit")
                                    exploit_module.exploit_mqtt(device_ip)
                            all_results.extend(results_from_check)
            elif target and target != "auto_discovered":
                check_module = get_module("check")
                results_from_check = check_module.run(target)
                if results_from_check:
                    # Exploit Telnet si demandé
                    for vuln in results_from_check:
                        if should_exploit and vuln.get('severity') == 'CRITICAL' and vuln.get('module') == 'Telnet':
                            try:
                                creds = vuln['description'].split(': ')[-1].split(':')
                                user, passwd = creds[0], creds[1]
                                exploit_module = get_module("exploit")
                                exploit_module.exploit_telnet(target, user, passwd)
                            except Exception:
                                print(f"[!] Impossible d'extraire les identifiants pour l'exploit Telnet.")
                        # Exploit MQTT si demandé
                        if should_exploit and 'MQTT' in vuln.get('module', '') and "abonnement à tous les topics" in vuln.get('description', ''):
                            exploit_module = get_module("exploit")
                            exploit_module.exploit_mqtt(target)
                    all_results.extend(results_from_check)
            else:
                print("[!] AVERTISSEMENT: Aucune cible spécifiée pour la vérification.")
        elif step_type == "analyze_firmware":
            firmware_file = step.get("file")
            if not firmware_file:
                print("[!] AVERTISSEMENT: L'étape analyze_firmware nécessite un fichier 'file'.")
                continue
            firmware_analyzer_module = get_module("firmware_analyzer")
            firmware_analyzer_module.analyze_firmware(firmware_file)
        elif step_type == "shodan_lookup":
            target = step.get("target")
            if not target:
                print("[!] AVERTISSEMENT: L'étape shodan_lookup nécessite une cible 'target'.")
                continue
            
            # Gestion de l'IP publique automatique
            if target == "auto_public_ip":
                try:
                    import requests
                    response = requests.get('https://api.ipify.org', timeout=5)
                    target = response.text
                    print(f"[*] IP publique détectée automatiquement: {target}")
                except Exception as e:
                    print(f"[!] Impossible de récupérer l'IP publique: {e}")
                    continue
            
            shodan_analyzer_module = get_module("shodan_analyzer")
            shodan_result = shodan_analyzer_module.get_info_for_ip(target)
            if shodan_result:
                all_results.append(shodan_result)
        elif step_type == "shodan_search":
            query = step.get("query")
            limit = step.get("limit", 10)
            if not query:
                print("[!] AVERTISSEMENT: L'étape shodan_search nécessite une requête 'query'.")
                continue
            shodan_analyzer_module = get_module("shodan_analyzer")
            shodan_analyzer_module.search_devices(query, limit)
        else:
            print(f"[!] AVERTISSEMENT: Type d'étape inconnu : {step_type}")
    
    print("\n[+] Exécution du scénario terminée.")
    
    # Ajout du résumé d'exécution pour le reporting
    try:
        from .reporting import add_execution_summary
        add_execution_summary("Scénario exécuté", data.get('name', 'Sans nom'))
        add_execution_summary("Nombre d'étapes", len(data.get("steps", [])))
        add_execution_summary("Vulnérabilités trouvées", len(all_results))
        add_execution_summary("Mode exploitation", "Activé" if should_exploit else "Désactivé")
        add_execution_summary("Mode sécurisé", "Activé" if safe_mode else "Désactivé")
        add_execution_summary("Timeout configuré", f"{timeout} secondes")
    except ImportError:
        pass
    
    # On appelle les générateurs de rapport
    scenario_title = data.get('name', 'Sans nom')
    reporting_module = get_module("reporting")
    reporting_module.generate_text_report(all_results, scenario_title)
    reporting_module.generate_html_report(all_results, scenario_title)
    reporting_module.generate_pdf_report(all_results, scenario_title) # PDF !

def get_version():
    """Retourne la version actuelle de IoTBreaker"""
    return "0.1.0"

def print_banner():
    """Affiche la bannière IoTBreaker"""
    version = get_version()
    banner = f"""
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║     ██╗ ██████╗ ████████╗██████╗ ██████╗ ███████╗   ║
    ║     ██║██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝   ║
    ║     ██║██║   ██║   ██║   ██████╔╝██████╔╝█████╗     ║
    ║     ██║██║   ██║   ██║   ██╔══██╗██╔══██╗██╔══╝     ║
    ║     ██║╚██████╔╝   ██║   ██████╔╝██║  ██║███████╗   ║
    ║     ╚═╝ ╚═════╝    ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝   ║
    ║                                                      ║
    ║     ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗        ║
    ║     ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝        ║
    ║     ██████╔╝██████╔╝█████╗  ███████║█████╔╝         ║
    ║     ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗         ║
    ║     ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗        ║
    ║     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝        ║
    ║                                                      ║
    ║     Pentest IoT pour Kali Linux - v{version:<10}     ║
    ╚══════════════════════════════════════════════════════╝
    """
    print(banner)
    print("    Développé par: CyberS - https://github.com/servais1983/IoTBreaker\n")