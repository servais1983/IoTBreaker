#!/usr/bin/env python3
"""
IoTBreaker - Outil de pentest IoT pour Kali Linux
https://github.com/servais1983/IoTBreaker

Auteur: CyberS
Version: 0.1.0
"""

import argparse
import sys
from core import discover, analyze, check
from core.utils import run_script_yaml, print_banner, get_version

def main():
    """Fonction principale du programme"""
    # Affichage de la bannière
    print_banner()
    
    # Configuration du parser d'arguments
    parser = argparse.ArgumentParser(
        prog="iotbreaker", 
        description="Pentest IoT CLI - Kali Linux",
        epilog="Exemple: python3 iotbreaker.py discover"
    )
    
    # Ajout des sous-commandes
    subparsers = parser.add_subparsers(dest="command")
    
    # Commande discover
    discover_cmd = subparsers.add_parser(
        "discover", 
        help="Découverte des dispositifs IoT via UPnP, SSDP, mDNS"
    )
    
    # Commande analyze
    analyze_cmd = subparsers.add_parser(
        "analyze",
        help="Analyse des services IoT sur une adresse IP"
    )
    analyze_cmd.add_argument(
        "ip",
        help="Adresse IP cible à analyser"
    )
    
    # Commande check
    check_cmd = subparsers.add_parser(
        "check",
        help="Vérification des vulnérabilités courantes sur une adresse IP"
    )
    check_cmd.add_argument(
        "ip",
        help="Adresse IP cible à vérifier"
    )
    
    # Commande run
    run_cmd = subparsers.add_parser(
        "run",
        help="Exécution d'un scénario YAML automatisé"
    )
    run_cmd.add_argument(
        "file",
        help="Chemin vers le fichier YAML du scénario"
    )
    
    # Commande version
    subparsers.add_parser(
        "version",
        help="Affiche la version actuelle"
    )
    
    # Analyse des arguments
    args = parser.parse_args()
    
    # Exécution de la commande appropriée
    if args.command == "discover":
        discover.run()
    elif args.command == "analyze":
        analyze.run(args.ip)
    elif args.command == "check":
        check.run(args.ip)
    elif args.command == "run":
        run_script_yaml(args.file)
    elif args.command == "version":
        print(f"IoTBreaker version {get_version()}")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()