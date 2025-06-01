#!/usr/bin/env python3
"""
IoTBreaker - Outil d'audit de sécurité pour les dispositifs IoT
"""

import argparse
import logging
import sys
from core.utils import run_script_yaml

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def print_banner():
    """Affiche la bannière de l'outil"""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║  ██╗ ██████╗ ████████╗██████╗ ██████╗ ██████╗ ███████╗  ║
    ║  ██║██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝  ║
    ║  ██║██║   ██║   ██║   ██████╔╝██████╔╝██████╔╝█████╗    ║
    ║  ██║██║   ██║   ██║   ██╔══██╗██╔══██╗██╔══██╗██╔══╝    ║
    ║  ██║╚██████╔╝   ██║   ██║  ██║██║  ██║██║  ██║███████╗  ║
    ║  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝  ║
    ║                                                          ║
    ║  Outil d'audit de sécurité pour les dispositifs IoT      ║
    ║  Version 1.0.0                                           ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="IoTBreaker - Outil d'audit de sécurité pour les dispositifs IoT")
    parser.add_argument("scenario", help="Chemin vers le fichier de scénario YAML à exécuter")
    parser.add_argument("-v", "--verbose", action="store_true", help="Afficher plus de détails")
    
    args = parser.parse_args()
    
    # Affichage de la bannière
    print_banner()
    
    try:
        # Exécution du scénario
        run_script_yaml(args.scenario)
        print("\n✓ Audit terminé avec succès!")
    except Exception as e:
        print(f"\n✗ Erreur lors de l'exécution: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()