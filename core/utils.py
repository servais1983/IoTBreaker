import yaml
import sys
import os
import importlib
import logging
# Ajout de l'importation pour l'analyseur IA
from .ai_analyzer import get_ai_analysis

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

def run_script_yaml(path, ai_driven_mode=False):
    """
    Exécute un scénario de test à partir d'un fichier YAML.
    
    En mode 'ai_driven_mode', l'IA choisit les prochaines étapes
    en fonction des résultats obtenus.
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
    
    # Variables pour la découverte automatique
    discovered_devices = []
    auto_discovery_enabled = config.get("auto_discovery", False)
    
    # ----- NOUVELLE LOGIQUE POUR LE MODE PILOTÉ PAR L'IA -----
    if ai_driven_mode:
        print("[🧠] Mode d'audit piloté par l'IA activé. L'IA décidera des prochaines actions.")
        
        # L'état de l'audit, que nous fournirons à l'IA
        audit_context = {
            "scenario_name": data.get('name', 'Audit Dynamique'),
            "devices_found": [],
            "vulnerabilities_found": [],
            "history": []
        }

        # On commence par une étape de découverte, qui est toujours nécessaire
        print("\n[*] Étape 1 (forcée): Découverte des appareils...")
        discovered_devices = get_module("discover").run()
        audit_context["devices_found"] = [d['ip'] for d in discovered_devices if 'ip' in d]
        audit_context["history"].append("Découverte réseau effectuée.")

        # Boucle d'audit dynamique pilotée par l'IA
        for i in range(2, 10): # On limite à 10 étapes pour éviter les boucles infinies
            prompt_ai = f"""
            Contexte de l'audit de sécurité IoT en cours :
            - Scénario: {audit_context['scenario_name']}
            - Appareils découverts: {audit_context['devices_found']}
            - Vulnérabilités déjà trouvées: {audit_context['vulnerabilities_found']}
            - Historique des actions: {audit_context['history']}

            En te basant sur ce contexte, quelle est la prochaine étape la plus logique ? Choisis UNE seule action parmi les suivantes :
            - "ANALYZE <IP>" (pour scanner les ports d'un appareil)
            - "CHECK <IP>" (pour chercher des vulnérabilités sur un appareil)
            - "SHODAN_LOOKUP <IP>" (pour obtenir des infos sur une IP publique)
            - "STOP" (si tu estimes que l'audit est terminé ou qu'il n'y a plus rien de pertinent à faire)

            Réponds uniquement avec l'action choisie. Par exemple : "CHECK 192.168.1.50"
            """

            print(f"\n[🧠] L'IA réfléchit à l'étape {i}...")
            next_action = get_ai_analysis(prompt_ai, max_length=64)
            
            print(f"  [+] Décision de l'IA : {next_action}")
            audit_context["history"].append(f"Décision IA: {next_action}")
            
            action_parts = next_action.split()
            command = action_parts[0].lower()
            target = action_parts[1] if len(action_parts) > 1 else None

            if command == "stop":
                print("[+] L'IA a décidé de terminer l'audit.")
                break
            
            if not target:
                print("[!] L'IA n'a pas spécifié de cible. Arrêt de l'audit.")
                break

            # Exécution de l'action choisie par l'IA
            if command == "analyze":
                get_module("analyze").run(target)
            elif command == "check":
                results_from_check = get_module("check").run(target)
                if results_from_check:
                    all_results.extend(results_from_check)
                    audit_context["vulnerabilities_found"].extend(results_from_check)
            elif command == "shodan_lookup":
                shodan_result = get_module("shodan_analyzer").get_info_for_ip(target)
                if shodan_result:
                    all_results.append(shodan_result)
            else:
                print(f"[!] Commande de l'IA inconnue : '{command}'. Arrêt.")
                break
                
    else:
        # ----- LOGIQUE EXISTANTE POUR LE MODE SCRIPTÉ -----
        print("[+] Mode d'audit scripté classique activé.")
        
        # Exécution des étapes
        print("\n[*] Début de l'exécution des étapes...")
        
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
                                all_results.extend(results_from_check)
                elif target and target != "auto_discovered":
                    check_module = get_module("check")
                    results_from_check = check_module.run(target)
                    if results_from_check:
                        all_results.extend(results_from_check)
                else:
                    print("[!] AVERTISSEMENT: Aucune cible spécifiée pour la vérification.")
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
        add_execution_summary("Mode sécurisé", "Activé" if safe_mode else "Désactivé")
        add_execution_summary("Timeout configuré", f"{timeout} secondes")
    except ImportError:
        pass
    
    # On appelle les générateurs de rapport
    scenario_title = data.get('name', 'Sans nom')
    reporting_module = get_module("reporting")
    reporting_module.generate_text_report(all_results, scenario_title)
    reporting_module.generate_html_report(all_results, scenario_title)
    reporting_module.generate_pdf_report(all_results, scenario_title)

def initialize_audit():
    """Initialise un nouveau contexte d'audit."""
    return {
        "devices": {},
        "vulnerabilities": [],
        "history": [],
        "devices_found": []
    }

def run_step(action_string, context):
    """Exécute une seule étape d'audit et met à jour le contexte."""
    parts = action_string.split()
    command = parts[0].lower()
    target = parts[1] if len(parts) > 1 else 'all'
    
    context['history'].append(action_string)

    # COMMANDES DE DÉCOUVERTE
    if command == "discover":
        print("\n[*] Étape : Découverte générale des appareils...")
        discovered_devices = get_module("discover").run()
        for device in discovered_devices:
            ip = device.get('ip')
            if ip:
                context['devices'][ip] = device
        context['devices_found'] = list(context['devices'].keys())
        print(f"[+] {len(context['devices_found'])} appareils sont maintenant dans le contexte.")

    elif command == "discover_cameras":
        print("\n[*] Étape : Recherche spécifique de caméras IP...")
        discovered_devices = get_module("discover").run()
        cameras = [d for d in discovered_devices if 'camera' in d.get('type', '').lower() or 'cam' in d.get('type', '').lower()]
        for device in cameras:
            ip = device.get('ip')
            if ip:
                context['devices'][ip] = device
        context['devices_found'] = list(context['devices'].keys())
        print(f"[+] {len(cameras)} caméras trouvées.")

    elif command == "discover_routers":
        print("\n[*] Étape : Recherche spécifique de routeurs...")
        discovered_devices = get_module("discover").run()
        routers = [d for d in discovered_devices if 'router' in d.get('type', '').lower() or 'gateway' in d.get('type', '').lower()]
        for device in routers:
            ip = device.get('ip')
            if ip:
                context['devices'][ip] = device
        context['devices_found'] = list(context['devices'].keys())
        print(f"[+] {len(routers)} routeurs trouvés.")

    # COMMANDES D'ANALYSE
    elif command == "analyze":
        print(f"\n[*] Étape : Analyse des ports pour '{target}'...")
        targets_to_scan = context['devices'].keys() if target == 'all' else [target]
        for ip in targets_to_scan:
            get_module("analyze").run(ip)

    # COMMANDES DE SÉCURITÉ
    elif command == "check":
        print(f"\n[*] Étape : Vérification des vulnérabilités pour '{target}'...")
        targets_to_scan = context['devices'].keys() if target == 'all' else [target]
        for ip in targets_to_scan:
            results = get_module("check").run(ip)
            if results:
                context['vulnerabilities'].extend(results)
        print(f"[+] {len(context['vulnerabilities'])} vulnérabilité(s) trouvée(s)")

    # COMMANDES DE RAPPORT
    elif command == "report":
        print("\n[*] Étape : Génération du rapport complet...")
        get_module("reporting").generate_html_report(context['vulnerabilities'], "Audit Interactif")

    elif command == "unknown":
        print(f"\n[❓] Je n'ai pas compris votre commande : '{action_string}'")
        print("   Tapez 'help' pour voir toutes les commandes disponibles.")
        print("   Ou reformulez votre demande en langage naturel.")
    
    else:
        print(f"[!] Commande inconnue : {command}")
        print("   Tapez 'help' pour voir toutes les commandes disponibles.")

def get_version():
    """Retourne la version actuelle de IoTBreaker"""
    return "3.0.0"

def print_banner():
    """Affiche la magnifique bannière IoTBreaker corrigée"""
    version = get_version()
    banner = f"""
🤖 IoTBreaker - Outil d'audit de sécurité conversationnel IoT
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║  ██╗ ██████╗ ████████╗    ██████╗ ██████╗ ███████╗      ║
║  ██║██╔═══██╗╚══██╔══╝    ██╔══██╗██╔══██╗██╔════╝      ║
║  ██║██║   ██║   ██║       ██████╔╝██████╔╝█████╗        ║
║  ██║██║   ██║   ██║       ██╔══██╗██╔══██╗██╔══╝        ║
║  ██║╚██████╔╝   ██║       ██████╔╝██║  ██║███████╗      ║
║  ╚═╝ ╚═════╝    ╚═╝       ╚═════╝ ╚═╝  ╚═╝╚══════╝      ║
║                                                          ║
║  ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗ ║
║  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗║
║  ██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝║
║  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗║
║  ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║║
║  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝║
║                                                          ║
║  Outil d'audit de sécurité conversationnel IoT           ║
║  Version {version:<10} - IA Conversationnelle             ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

    🔍 Découverte intelligente    🛡️  Tests de sécurité
    🤖 IA conversationnelle       📊 Rapports automatiques
    🌐 Intégration Shodan          🎯 Exploitation éthique
    """
    print(banner)
    print("    Développé par: CyberS - https://github.com/servais1983/IoTBreaker\n")
