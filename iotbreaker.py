#!/usr/bin/env python3
"""
IoTBreaker - Outil d'audit de sécurité conversationnel pour les dispositifs IoT
"""

import argparse
import logging
import sys
from core.utils import run_script_yaml, initialize_audit, run_step
try:
    from core.ai_analyzer import get_ai_analysis
except:
    from core.ai_analyzer_simple import get_ai_analysis
from core.knowledge_base import load_knowledge, save_knowledge, get_recent_learnings

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def print_banner():
    """Affiche le magnifique logo ASCII IoTBreaker complet"""
    banner = """
🤖 IoTBreaker - Outil d'audit de sécurité conversationnel IoT
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ██╗ ██████╗ ████████╗    ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗  ║
║  ██║██╔═══██╗╚══██╔══╝    ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝  ║
║  ██║██║   ██║   ██║       ██████╔╝██████╔╝█████╗  ███████║█████╔╝   ║
║  ██║██║   ██║   ██║       ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗   ║
║  ██║╚██████╔╝   ██║       ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗  ║
║  ╚═╝ ╚═════╝    ╚═╝       ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝  ║
║                                                                      ║
║  ███████╗██████╗                                                     ║
║  ██╔════╝██╔══██╗                                                    ║
║  █████╗  ██████╔╝                                                    ║
║  ██╔══╝  ██╔══██╗                                                    ║
║  ███████╗██║  ██║                                                    ║
║  ╚══════╝╚═╝  ╚═╝                                                    ║
║                                                                      ║
║  Outil d'audit de sécurité conversationnel IoT                       ║
║  Version 3.0.0 - IA Conversationnelle                                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

    🔍 Découverte intelligente    🛡️  Tests de sécurité
    🤖 IA conversationnelle       📊 Rapports automatiques
    🌐 Intégration Shodan          🎯 Exploitation éthique
"""
    print(banner)

def interactive_mode():
    """Mode conversationnel interactif avec l'IA."""
    print_banner()
    
    # Initialisation de l'audit et de la mémoire de l'IA
    audit_context = initialize_audit()
    knowledge_base = load_knowledge()

    print("[+] Bienvenue dans le shell interactif d'IoTBreaker.")
    print("    > L'IA est prête. Décrivez votre objectif (ex: 'Lance un scan complet', 'Cherche les caméras vulnérables').")
    print("    > Tapez 'exit' pour quitter.")
    print("    > Tapez 'help' pour voir les commandes disponibles.")
    print("    > Tapez 'status' pour voir l'état actuel de l'audit.")

    while True:
        try:
            user_input = input("\n[Vous]> ").strip()
            
            if not user_input:
                continue
                
            if user_input.lower() == 'exit':
                # Avant de quitter, on demande à l'IA de synthétiser ce qu'elle a appris
                print("[🧠] Synthèse des apprentissages de cette session...")
                learning_prompt = f"""
                Basé sur l'historique de l'audit : {audit_context['history']},
                formule une ou deux règles générales que nous pourrions appliquer dans le futur.
                Par exemple : 'Les appareils de type 'Routeur' sont souvent vulnérables au scan Telnet.'
                Réponds uniquement avec les règles, une par ligne.
                """
                new_learnings = get_ai_analysis(learning_prompt, max_length=256)
                if new_learnings and "non disponible" not in new_learnings:
                    for learning in new_learnings.split('\n'):
                        if learning.strip():
                            knowledge_base['learnings'].append(learning.strip())
                
                save_knowledge(knowledge_base)
                print("[+] Session terminée. Connaissances mises à jour.")
                break

            elif user_input.lower() == 'help':
                print("\n[📖] COMMANDES DISPONIBLES")
                print("=" * 50)
                print("\n🔍 COMMANDES DE DÉCOUVERTE :")
                print("  • 'Lance un scan complet' - Découverte + analyse + vérification")
                print("  • 'Découvre les appareils' - Scan réseau pour trouver les IoT")
                print("  • 'Trouve les caméras' - Recherche spécifique de caméras IP")
                print("  • 'Cherche les routeurs' - Identification des routeurs")
                print("  • 'Détecte les ampoules connectées' - Recherche d'ampoules IoT")
                print("  • 'Trouve les thermostats' - Détection de thermostats intelligents")
                print("  • 'Scan WiFi' - Découverte des réseaux WiFi")
                print("  • 'Scan Bluetooth' - Recherche d'appareils Bluetooth")
                
                print("\n🔬 COMMANDES D'ANALYSE :")
                print("  • 'Analyse tous les appareils' - Analyse complète des ports")
                print("  • 'Analyse cette IP 192.168.1.1' - Analyse d'une IP spécifique")
                print("  • 'Vérifie les ports ouverts' - Scan des ports sur les appareils")
                print("  • 'Analyse les services' - Identification des services actifs")
                print("  • 'Fingerprint les appareils' - Identification des types d'appareils")
                print("  • 'Analyse les bannières' - Extraction des bannières serveur")
                
                print("\n🛡️ COMMANDES DE SÉCURITÉ :")
                print("  • 'Cherche les vulnérabilités' - Test de vulnérabilités")
                print("  • 'Teste les mots de passe par défaut' - Test d'authentification")
                print("  • 'Vérifie les ports Telnet' - Test des ports Telnet")
                print("  • 'Teste les ports SSH' - Vérification SSH")
                print("  • 'Cherche les failles web' - Test des interfaces web")
                print("  • 'Vérifie les configurations faibles' - Audit de configuration")
                print("  • 'Teste les exploits connus' - Tests d'exploitation")
                
                print("\n📊 COMMANDES DE RAPPORT :")
                print("  • 'Génère un rapport' - Création d'un rapport complet")
                print("  • 'Crée un rapport HTML' - Rapport interactif HTML")
                print("  • 'Génère un rapport PDF' - Rapport PDF détaillé")
                print("  • 'Exporte les résultats' - Export des données")
                print("  • 'Affiche les vulnérabilités' - Liste des vulnérabilités trouvées")
                print("  • 'Résumé de l'audit' - Synthèse des résultats")
                
                print("\n🌐 COMMANDES SHODAN :")
                print("  • 'Analyse mon IP publique' - Recherche Shodan de votre IP")
                print("  • 'Cherche des appareils similaires' - Recherche géolocalisée")
                print("  • 'Vérifie ma visibilité externe' - Audit de visibilité")
                
                print("\n🧠 COMMANDES IA :")
                print("  • 'Que penses-tu de ces résultats ?' - Analyse IA des résultats")
                print("  • 'Suggère les prochaines étapes' - Recommandations IA")
                print("  • 'Analyse les risques' - Évaluation des risques par IA")
                print("  • 'Quelles sont tes recommandations ?' - Conseils stratégiques")
                
                print("\n⚙️ COMMANDES SYSTÈME :")
                print("  • 'status' - État actuel de l'audit")
                print("  • 'clear' - Efface l'écran")
                print("  • 'history' - Historique des commandes")
                print("  • 'config' - Configuration actuelle")
                print("  • 'exit' - Quitter le shell")
                
                print("\n💡 EXEMPLES DE COMMANDES NATURELLES :")
                print("  • 'Salut, peux-tu scanner mon réseau ?'")
                print("  • 'Je veux vérifier la sécurité de mes caméras'")
                print("  • 'Y a-t-il des vulnérabilités sur mon routeur ?'")
                print("  • 'Peux-tu analyser cette adresse IP ?'")
                print("  • 'Génère un rapport de sécurité pour mon patron'")
                print("  • 'Que recommandes-tu pour sécuriser mon IoT ?'")
                continue

            elif user_input.lower() == 'status':
                print(f"\n[📊] État de l'audit :")
                print(f"  • Appareils découverts : {len(audit_context['devices_found'])}")
                print(f"  • Vulnérabilités trouvées : {len(audit_context['vulnerabilities'])}")
                print(f"  • Actions effectuées : {len(audit_context['history'])}")
                print(f"  • Connaissances IA : {len(knowledge_base['learnings'])} règles apprises")
                if audit_context['devices_found']:
                    print(f"  • Appareils : {', '.join(audit_context['devices_found'])}")
                if audit_context['vulnerabilities']:
                    print(f"  • Vulnérabilités : {len([v for v in audit_context['vulnerabilities'] if v.get('severity') == 'High'])} critiques")
                continue

            elif user_input.lower() == 'clear':
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
                print("[+] Écran effacé. Continuez votre audit...")
                continue

            elif user_input.lower() == 'history':
                print(f"\n[📜] Historique des commandes ({len(audit_context['history'])} actions) :")
                for i, action in enumerate(audit_context['history'], 1):
                    print(f"  {i}. {action}")
                continue

            elif user_input.lower() == 'config':
                print(f"\n[⚙️] Configuration actuelle :")
                print(f"  • Mode : Conversationnel avec IA")
                print(f"  • Base de connaissances : {len(knowledge_base['learnings'])} règles")
                print(f"  • Contexte d'audit : {len(audit_context['devices'])} appareils")
                print(f"  • Historique : {len(audit_context['history'])} actions")
                continue

            # L'IA interprète la commande de l'utilisateur
            ai_prompt = f"""
            Contexte de l'audit : {len(audit_context['devices_found'])} appareils trouvés.
            Savoirs antérieurs : {get_recent_learnings(knowledge_base, 3)}
            Commande de l'utilisateur : '{user_input}'

            Analyse cette commande et traduis-la en action(s) système. Choisis parmi :

            DÉCOUVERTE :
            - DISCOVER (découverte générale)
            - DISCOVER_CAMERAS (recherche caméras)
            - DISCOVER_ROUTERS (recherche routeurs)
            - DISCOVER_BULBS (recherche ampoules)
            - DISCOVER_THERMOSTATS (recherche thermostats)
            - SCAN_WIFI (scan WiFi)
            - SCAN_BLUETOOTH (scan Bluetooth)

            ANALYSE :
            - ANALYZE <IP|all> (analyse ports)
            - ANALYZE_SERVICES <IP|all> (analyse services)
            - FINGERPRINT <IP|all> (fingerprint)
            - BANNER_GRAB <IP|all> (bannières)

            SÉCURITÉ :
            - CHECK <IP|all> (vulnérabilités générales)
            - CHECK_DEFAULTS <IP|all> (mots de passe par défaut)
            - CHECK_TELNET <IP|all> (ports Telnet)
            - CHECK_SSH <IP|all> (ports SSH)
            - CHECK_WEB <IP|all> (interfaces web)
            - CHECK_CONFIG <IP|all> (configurations)

            RAPPORT :
            - REPORT (rapport complet)
            - REPORT_HTML (rapport HTML)
            - REPORT_PDF (rapport PDF)
            - EXPORT (export données)

            SHODAN :
            - SHODAN_IP (analyse IP publique)
            - SHODAN_SIMILAR (recherche similaire)
            - SHODAN_VISIBILITY (visibilité externe)

            IA :
            - AI_ANALYSIS (analyse IA des résultats)
            - AI_RECOMMENDATIONS (recommandations IA)
            - AI_RISKS (évaluation risques IA)

            Réponds uniquement avec la commande. Exemple : ANALYZE 192.168.1.1
            Si la commande n'est pas claire, réponds : UNKNOWN
            """
            
            print("[🧠] L'IA interprète votre commande...")
            action = get_ai_analysis(ai_prompt, max_length=64)
            print(f"  [+] Action déterminée par l'IA : {action}")

            # Exécution de l'action
            if action:
                run_step(action, audit_context)
            else:
                print("[!] L'IA n'a pas pu déterminer d'action claire.")

        except KeyboardInterrupt:
            print("\n\n[!] Interruption détectée. Tapez 'exit' pour quitter proprement.")
        except Exception as e:
            print(f"[!] Erreur : {e}")

def script_mode():
    """Mode script classique pour la rétro-compatibilité."""
    parser = argparse.ArgumentParser(description="IoTBreaker - Outil d'audit de sécurité pour les dispositifs IoT")
    parser.add_argument("scenario", help="Chemin vers le fichier de scénario YAML à exécuter")
    parser.add_argument("-v", "--verbose", action="store_true", help="Afficher plus de détails")
    parser.add_argument("--ai-driven", action="store_true", help="Activer le mode d'audit piloté par l'IA")
    
    args = parser.parse_args()
    
    # Affichage de la bannière
    print_banner()
    
    try:
        # Exécution du scénario en passant le nouvel argument
        run_script_yaml(args.scenario, args.ai_driven)
        print("\n✓ Audit terminé avec succès!")
    except Exception as e:
        print(f"\n✗ Erreur lors de l'exécution: {str(e)}")
        sys.exit(1)

def main():
    """Fonction principale - Détecte automatiquement le mode à utiliser."""
    if len(sys.argv) > 1 and sys.argv[1] not in ['-h', '--help', '-v', '--verbose', '--ai-driven']:
        # Mode script classique
        script_mode()
    else:
        # Mode conversationnel interactif
        try:
            interactive_mode()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Session interrompue. Au revoir !")
            sys.exit(0)

if __name__ == "__main__":
    main()
