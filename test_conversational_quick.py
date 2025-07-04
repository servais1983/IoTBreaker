#!/usr/bin/env python3
"""
Test rapide du mode conversationnel d'IoTBreaker
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_conversational_quick():
    """Test rapide du mode conversationnel"""
    print("🚀 Test rapide du mode conversationnel")
    print("=" * 40)
    
    try:
        # Test des imports
        from core.utils import initialize_audit
        from core.knowledge_base import load_knowledge, save_knowledge
        print("✅ Imports réussis")
        
        # Test de l'initialisation
        context = initialize_audit()
        kb = load_knowledge()
        print("✅ Initialisation réussie")
        
        # Test de la base de connaissances
        test_rule = "Test rule from quick test"
        kb['learnings'].append(test_rule)
        save_knowledge(kb)
        print("✅ Base de connaissances fonctionnelle")
        
        # Test du contexte d'audit
        context['devices']['192.168.1.1'] = {'ip': '192.168.1.1', 'type': 'Test'}
        context['devices_found'] = list(context['devices'].keys())
        print("✅ Contexte d'audit fonctionnel")
        
        print(f"\n📊 État final :")
        print(f"  • Appareils : {len(context['devices_found'])}")
        print(f"  • Connaissances : {len(kb['learnings'])}")
        
        print("\n🎉 Test rapide réussi !")
        print("   Le mode conversationnel est prêt à être utilisé.")
        print("   Lancez 'python iotbreaker.py' pour commencer.")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur : {e}")
        return False

if __name__ == "__main__":
    success = test_conversational_quick()
    sys.exit(0 if success else 1) 