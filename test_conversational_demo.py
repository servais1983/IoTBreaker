#!/usr/bin/env python3
"""
Démonstration du mode conversationnel d'IoTBreaker
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def demo_conversational_mode():
    """Démonstration du mode conversationnel"""
    print("🤖 DÉMONSTRATION DU MODE CONVERSATIONNEL IoTBreaker")
    print("=" * 60)
    
    try:
        from core.utils import initialize_audit, run_step
        from core.knowledge_base import load_knowledge, save_knowledge, get_recent_learnings
        from core.ai_analyzer_simple import get_ai_analysis, get_ai_insights, get_ai_recommendations
        
        # Initialisation
        print("[*] Initialisation de l'audit et de la base de connaissances...")
        audit_context = initialize_audit()
        knowledge_base = load_knowledge()
        
        print(f"[+] Base de connaissances chargée : {len(knowledge_base['learnings'])} règles")
        print(f"[+] Contexte d'audit initialisé : {len(audit_context['devices'])} appareils")
        
        # Simulation d'une session conversationnelle
        print("\n💬 SIMULATION D'UNE SESSION CONVERSATIONNELLE")
        print("-" * 50)
        
        # Commande 1 : Découverte
        print("\n[Vous]> Lance un scan complet")
        action = get_ai_analysis("Lance un scan complet")
        print(f"[🧠] L'IA interprète votre commande...")
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "DISCOVER" in action:
            print("  [+] Simulation : Découverte d'appareils...")
            audit_context['devices']['192.168.1.1'] = {'ip': '192.168.1.1', 'type': 'Routeur'}
            audit_context['devices']['192.168.1.100'] = {'ip': '192.168.1.100', 'type': 'Caméra IP'}
            audit_context['devices_found'] = list(audit_context['devices'].keys())
            audit_context['history'].append("DISCOVER")
            print(f"  [+] Résultat : {len(audit_context['devices_found'])} appareils trouvés")
        
        # Commande 2 : Analyse
        print("\n[Vous]> Analyse tous les appareils")
        action = get_ai_analysis("Analyse tous les appareils")
        print(f"[🧠] L'IA interprète votre commande...")
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "ANALYZE" in action:
            print("  [+] Simulation : Analyse des ports...")
            audit_context['history'].append("ANALYZE all")
            print("  [+] Résultat : Ports 80, 443, 22, 23 analysés sur tous les appareils")
        
        # Commande 3 : Vérification des vulnérabilités
        print("\n[Vous]> Cherche les vulnérabilités")
        action = get_ai_analysis("Cherche les vulnérabilités")
        print(f"[🧠] L'IA interprète votre commande...")
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "CHECK" in action:
            print("  [+] Simulation : Test de vulnérabilités...")
            audit_context['vulnerabilities'].append({
                'ip': '192.168.1.1',
                'type': 'Telnet ouvert',
                'severity': 'High',
                'description': 'Port Telnet accessible sans authentification'
            })
            audit_context['history'].append("CHECK all")
            print(f"  [+] Résultat : {len(audit_context['vulnerabilities'])} vulnérabilités trouvées")
        
        # Commande 4 : Rapport
        print("\n[Vous]> Génère un rapport")
        action = get_ai_analysis("Génère un rapport")
        print(f"[🧠] L'IA interprète votre commande...")
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "REPORT" in action:
            print("  [+] Simulation : Génération du rapport...")
            audit_context['history'].append("REPORT")
            print("  [+] Résultat : Rapport HTML et PDF générés")
        
        # Commande 5 : Analyse IA
        print("\n[Vous]> Que penses-tu de ces résultats ?")
        insights = get_ai_insights(audit_context)
        print(f"[🧠] Analyse IA des résultats :")
        for insight in insights:
            print(f"  [+] {insight}")
        
        # Commande 6 : Recommandations IA
        print("\n[Vous]> Quelles sont tes recommandations ?")
        recommendations = get_ai_recommendations(audit_context)
        print(f"[🧠] Recommandations IA :")
        for rec in recommendations:
            print(f"  [+] {rec}")
        
        # Synthèse des apprentissages
        print("\n[🧠] Synthèse des apprentissages de cette session...")
        new_learning = "Les réseaux domestiques contiennent souvent des routeurs et caméras IoT"
        knowledge_base['learnings'].append(new_learning)
        print(f"  [+] Nouvel apprentissage : {new_learning}")
        
        save_knowledge(knowledge_base)
        
        # Résumé final
        print("\n" + "=" * 60)
        print("📊 RÉSUMÉ DE LA SESSION CONVERSATIONNELLE")
        print("=" * 60)
        print(f"  • Appareils découverts : {len(audit_context['devices_found'])}")
        print(f"  • Vulnérabilités trouvées : {len(audit_context['vulnerabilities'])}")
        print(f"  • Actions effectuées : {len(audit_context['history'])}")
        print(f"  • Connaissances IA : {len(knowledge_base['learnings'])} règles apprises")
        print(f"  • Appareils trouvés : {', '.join(audit_context['devices_found'])}")
        
        if audit_context['vulnerabilities']:
            print("\n  🚨 Vulnérabilités détectées :")
            for vuln in audit_context['vulnerabilities']:
                print(f"    • {vuln['ip']} - {vuln['type']} ({vuln['severity']})")
        
        print("\n🎉 Démonstration terminée !")
        print("   IoTBreaker est maintenant un véritable partenaire d'audit conversationnel.")
        print("   Vous pouvez lancer 'python iotbreaker.py' pour commencer votre session.")
        
    except Exception as e:
        print(f"[!] Erreur lors de la démonstration : {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    demo_conversational_mode() 