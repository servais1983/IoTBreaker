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
        from core.ai_analyzer import get_ai_analysis
        
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
        ai_prompt = """
        Contexte de l'audit : 0 appareils trouvés.
        Savoirs antérieurs : []
        Commande de l'utilisateur : 'Lance un scan complet'

        Traduis cette commande en une action système concrète. Choisis parmi :
        - DISCOVER
        - ANALYZE <IP|all>
        - CHECK <IP|all>
        - REPORT
        
        Réponds uniquement avec la commande. Exemple : ANALYZE 192.168.1.1
        """
        
        print("[🧠] L'IA interprète votre commande...")
        action = get_ai_analysis(ai_prompt, max_length=64)
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "DISCOVER" in action or "non disponible" in action:
            print("  [+] Simulation : Découverte d'appareils...")
            audit_context['devices']['192.168.1.1'] = {'ip': '192.168.1.1', 'type': 'Routeur'}
            audit_context['devices']['192.168.1.100'] = {'ip': '192.168.1.100', 'type': 'Caméra IP'}
            audit_context['devices_found'] = list(audit_context['devices'].keys())
            audit_context['history'].append("DISCOVER")
            print(f"  [+] Résultat : {len(audit_context['devices_found'])} appareils trouvés")
        
        # Commande 2 : Analyse
        print("\n[Vous]> Analyse tous les appareils")
        ai_prompt = f"""
        Contexte de l'audit : {len(audit_context['devices_found'])} appareils trouvés.
        Savoirs antérieurs : {get_recent_learnings(knowledge_base, 3)}
        Commande de l'utilisateur : 'Analyse tous les appareils'

        Traduis cette commande en une action système concrète. Choisis parmi :
        - DISCOVER
        - ANALYZE <IP|all>
        - CHECK <IP|all>
        - REPORT
        
        Réponds uniquement avec la commande. Exemple : ANALYZE 192.168.1.1
        """
        
        print("[🧠] L'IA interprète votre commande...")
        action = get_ai_analysis(ai_prompt, max_length=64)
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "ANALYZE" in action or "non disponible" in action:
            print("  [+] Simulation : Analyse des ports...")
            audit_context['history'].append("ANALYZE all")
            print("  [+] Résultat : Ports 80, 443, 22, 23 analysés sur tous les appareils")
        
        # Commande 3 : Vérification des vulnérabilités
        print("\n[Vous]> Cherche les vulnérabilités")
        ai_prompt = f"""
        Contexte de l'audit : {len(audit_context['devices_found'])} appareils trouvés.
        Savoirs antérieurs : {get_recent_learnings(knowledge_base, 3)}
        Commande de l'utilisateur : 'Cherche les vulnérabilités'

        Traduis cette commande en une action système concrète. Choisis parmi :
        - DISCOVER
        - ANALYZE <IP|all>
        - CHECK <IP|all>
        - REPORT
        
        Réponds uniquement avec la commande. Exemple : ANALYZE 192.168.1.1
        """
        
        print("[🧠] L'IA interprète votre commande...")
        action = get_ai_analysis(ai_prompt, max_length=64)
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "CHECK" in action or "non disponible" in action:
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
        ai_prompt = f"""
        Contexte de l'audit : {len(audit_context['devices_found'])} appareils trouvés, {len(audit_context['vulnerabilities'])} vulnérabilités.
        Savoirs antérieurs : {get_recent_learnings(knowledge_base, 3)}
        Commande de l'utilisateur : 'Génère un rapport'

        Traduis cette commande en une action système concrète. Choisis parmi :
        - DISCOVER
        - ANALYZE <IP|all>
        - CHECK <IP|all>
        - REPORT
        
        Réponds uniquement avec la commande. Exemple : ANALYZE 192.168.1.1
        """
        
        print("[🧠] L'IA interprète votre commande...")
        action = get_ai_analysis(ai_prompt, max_length=64)
        print(f"  [+] Action déterminée par l'IA : {action}")
        
        # Simulation de l'exécution
        if "REPORT" in action or "non disponible" in action:
            print("  [+] Simulation : Génération du rapport...")
            audit_context['history'].append("REPORT")
            print("  [+] Résultat : Rapport HTML et PDF générés")
        
        # Synthèse des apprentissages
        print("\n[🧠] Synthèse des apprentissages de cette session...")
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
                    print(f"  [+] Nouvel apprentissage : {learning.strip()}")
        
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
        
    except Exception as e:
        print(f"[!] Erreur lors de la démonstration : {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    demo_conversational_mode() 