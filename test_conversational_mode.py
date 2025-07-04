#!/usr/bin/env python3
"""
Script de test pour le mode conversationnel d'IoTBreaker
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_knowledge_base():
    """Test de la base de connaissances"""
    print("🧠 Test de la base de connaissances...")
    
    try:
        from core.knowledge_base import load_knowledge, save_knowledge, add_learning, get_recent_learnings
        
        # Test de chargement
        kb = load_knowledge()
        print(f"  [+] Base de connaissances chargée : {len(kb['learnings'])} règles")
        
        # Test d'ajout d'apprentissage
        test_learning = "Les routeurs TP-Link sont souvent vulnérables aux attaques par défaut"
        add_learning(kb, test_learning)
        print(f"  [+] Nouvel apprentissage ajouté : {test_learning}")
        
        # Test de sauvegarde
        save_knowledge(kb)
        print("  [+] Base de connaissances sauvegardée")
        
        # Test de récupération des apprentissages récents
        recent = get_recent_learnings(kb, 3)
        print(f"  [+] Apprentissages récents : {recent}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test de la base de connaissances : {e}")
        return False

def test_audit_context():
    """Test du contexte d'audit"""
    print("\n📊 Test du contexte d'audit...")
    
    try:
        from core.utils import initialize_audit, run_step
        
        # Test d'initialisation
        context = initialize_audit()
        print(f"  [+] Contexte d'audit initialisé : {len(context['devices'])} appareils")
        
        # Test d'ajout d'appareil
        context['devices']['192.168.1.1'] = {'ip': '192.168.1.1', 'type': 'Routeur'}
        context['devices_found'] = list(context['devices'].keys())
        print(f"  [+] Appareil ajouté au contexte : {context['devices_found']}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test du contexte d'audit : {e}")
        return False

def test_ai_interpretation():
    """Test de l'interprétation IA des commandes"""
    print("\n🤖 Test de l'interprétation IA des commandes...")
    
    try:
        from core.ai_analyzer import get_ai_analysis
        
        # Test de différentes commandes
        test_commands = [
            "Lance un scan complet",
            "Cherche les vulnérabilités",
            "Analyse cette IP 192.168.1.1",
            "Génère un rapport"
        ]
        
        for i, command in enumerate(test_commands, 1):
            print(f"  [*] Test {i}: '{command}'")
            
            ai_prompt = f"""
            Contexte de l'audit : 2 appareils trouvés.
            Savoirs antérieurs : ['Les routeurs sont souvent vulnérables']
            Commande de l'utilisateur : '{command}'

            Traduis cette commande en une action système concrète. Choisis parmi :
            - DISCOVER
            - ANALYZE <IP|all>
            - CHECK <IP|all>
            - REPORT
            
            Réponds uniquement avec la commande. Exemple : ANALYZE 192.168.1.1
            """
            
            try:
                action = get_ai_analysis(ai_prompt, max_length=64)
                print(f"    [+] Action IA : {action}")
            except Exception as e:
                print(f"    [!] Erreur IA : {e}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test de l'interprétation IA : {e}")
        return False

def test_conversational_flow():
    """Test du flux conversationnel complet"""
    print("\n💬 Test du flux conversationnel...")
    
    try:
        from core.utils import initialize_audit, run_step
        from core.knowledge_base import load_knowledge, save_knowledge
        from core.ai_analyzer import get_ai_analysis
        
        # Simulation d'une session conversationnelle
        print("  [*] Simulation d'une session d'audit...")
        
        # Initialisation
        context = initialize_audit()
        kb = load_knowledge()
        
        # Commande 1 : Découverte
        print("  [*] Commande utilisateur : 'Lance un scan complet'")
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
        
        action = get_ai_analysis(ai_prompt, max_length=64)
        print(f"    [+] Action IA : {action}")
        
        # Simulation de l'exécution (sans vraiment scanner)
        if "DISCOVER" in action:
            print("    [+] Simulation : Découverte d'appareils...")
            context['devices']['192.168.1.1'] = {'ip': '192.168.1.1', 'type': 'Routeur'}
            context['devices_found'] = list(context['devices'].keys())
            context['history'].append(action)
        
        print(f"    [+] Résultat : {len(context['devices_found'])} appareils trouvés")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test du flux conversationnel : {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🚀 Test du mode conversationnel d'IoTBreaker")
    print("=" * 60)
    
    # Tests
    kb_ok = test_knowledge_base()
    context_ok = test_audit_context()
    ai_ok = test_ai_interpretation()
    flow_ok = test_conversational_flow()
    
    # Résumé
    print("\n" + "=" * 60)
    print("📋 RÉSUMÉ DES TESTS CONVERSATIONNELS")
    print("=" * 60)
    print(f"  🧠 Base de connaissances : {'✅ OK' if kb_ok else '❌ ÉCHEC'}")
    print(f"  📊 Contexte d'audit : {'✅ OK' if context_ok else '❌ ÉCHEC'}")
    print(f"  🤖 Interprétation IA : {'✅ OK' if ai_ok else '❌ ÉCHEC'}")
    print(f"  💬 Flux conversationnel : {'✅ OK' if flow_ok else '❌ ÉCHEC'}")
    
    if kb_ok and context_ok and ai_ok and flow_ok:
        print("\n🎉 Tous les tests conversationnels sont passés !")
        print("   IoTBreaker est maintenant un outil conversationnel :")
        print("   • python iotbreaker.py (lance le mode conversationnel)")
        print("   • Dialoguez avec l'IA en langage naturel")
        print("   • L'IA apprend et s'améliore à chaque session")
        print("   • Mode script toujours disponible pour la rétro-compatibilité")
    else:
        print("\n⚠️  Certains tests conversationnels ont échoué.")
        print("   Vérifiez la configuration de l'IA et les dépendances.")

if __name__ == "__main__":
    main() 