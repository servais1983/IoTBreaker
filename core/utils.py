import yaml
import sys
import os
from core import discover, analyze, check

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
    ```
    """
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
    
    print(f"[+] Configuration: timeout={timeout}s, verbose={verbose}, safe_mode={safe_mode}")
    
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
            discover.run()
        elif step_type == "analyze":
            if not target:
                print("[!] AVERTISSEMENT: L'étape analyze nécessite une cible.")
                continue
            analyze.run(target)
        elif step_type == "check":
            if not target:
                print("[!] AVERTISSEMENT: L'étape check nécessite une cible.")
                continue
            check.run(target)
        else:
            print(f"[!] AVERTISSEMENT: Type d'étape inconnu : {step_type}")
    
    print("\n[+] Exécution du scénario terminée.")

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