#!/usr/bin/env python3
"""
Test rapide d'IoTBreaker - Sans scans réseau
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_basic_imports():
    """Test des imports de base"""
    print("🔧 Test des imports de base...")
    
    try:
        # Test des imports de base
        from core.utils import initialize_audit
        from core.knowledge_base import load_knowledge, save_knowledge
        from core.ai_analyzer_simple import get_ai_analysis
        print("  ✅ Imports de base OK")
        
        # Test de l'initialisation
        context = initialize_audit()
        print(f"  ✅ Contexte d'audit initialisé : {len(context['devices'])} appareils")
        
        # Test de la base de connaissances
        kb = load_knowledge()
        print(f"  ✅ Base de connaissances : {len(kb['learnings'])} règles")
        
        # Test de l'IA simple
        result = get_ai_analysis("Lance un scan complet")
        print(f"  ✅ IA simple : {result}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_conversational_mode():
    """Test du mode conversationnel (sans scan)"""
    print("\n💬 Test du mode conversationnel...")
    
    try:
        from core.utils import initialize_audit, run_step
        from core.knowledge_base import load_knowledge
        from core.ai_analyzer_simple import get_ai_analysis
        
        # Test du contexte d'audit
        context = initialize_audit()
        kb = load_knowledge()
        print(f"  ✅ Contexte d'audit : {len(context['devices'])} appareils")
        
        # Test d'interprétation de commande
        command = "Lance un scan complet"
        action = get_ai_analysis(command)
        print(f"  ✅ Commande '{command}' → Action : {action}")
        
        # Test d'une commande d'analyse
        command2 = "Analyse tous les appareils"
        action2 = get_ai_analysis(command2)
        print(f"  ✅ Commande '{command2}' → Action : {action2}")
        
        # Test d'une commande de sécurité
        command3 = "Cherche les vulnérabilités"
        action3 = get_ai_analysis(command3)
        print(f"  ✅ Commande '{command3}' → Action : {action3}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_ai_commands():
    """Test des commandes IA"""
    print("\n🧠 Test des commandes IA...")
    
    try:
        from core.ai_analyzer_simple import get_ai_analysis, get_ai_insights, get_ai_recommendations
        
        # Test des différentes commandes
        commands = [
            "Lance un scan complet",
            "Trouve les caméras",
            "Cherche les routeurs",
            "Analyse tous les appareils",
            "Cherche les vulnérabilités",
            "Génère un rapport",
            "Analyse mon IP publique"
        ]
        
        for cmd in commands:
            result = get_ai_analysis(cmd)
            print(f"  ✅ '{cmd}' → {result}")
        
        # Test des insights
        context = {'devices_found': ['192.168.1.1'], 'vulnerabilities': []}
        insights = get_ai_insights(context)
        print(f"  ✅ Insights : {insights}")
        
        # Test des recommandations
        recommendations = get_ai_recommendations(context)
        print(f"  ✅ Recommandations : {recommendations}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_knowledge_base():
    """Test de la base de connaissances"""
    print("\n📚 Test de la base de connaissances...")
    
    try:
        from core.knowledge_base import load_knowledge, save_knowledge, add_learning, get_recent_learnings
        
        # Test de chargement
        kb = load_knowledge()
        print(f"  ✅ Base chargée : {len(kb['learnings'])} règles")
        
        # Test d'ajout
        add_learning(kb, "Test d'intégration IA rapide")
        save_knowledge(kb)
        print(f"  ✅ Apprentissage ajouté : OK")
        
        # Test de récupération
        recent = get_recent_learnings(kb, 3)
        print(f"  ✅ Apprentissages récents : {len(recent)} règles")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def main():
    """Test principal"""
    print("🚀 TEST RAPIDE D'IoTBreaker")
    print("=" * 50)
    
    # Tests
    basic_ok = test_basic_imports()
    conversational_ok = test_conversational_mode()
    ai_ok = test_ai_commands()
    knowledge_ok = test_knowledge_base()
    
    # Résumé
    print("\n" + "=" * 50)
    print("📋 RÉSUMÉ DES TESTS")
    print("=" * 50)
    print(f"  🔧 Imports de base : {'✅ OK' if basic_ok else '❌ ÉCHEC'}")
    print(f"  💬 Mode conversationnel : {'✅ OK' if conversational_ok else '❌ ÉCHEC'}")
    print(f"  🧠 Commandes IA : {'✅ OK' if ai_ok else '❌ ÉCHEC'}")
    print(f"  📚 Base de connaissances : {'✅ OK' if knowledge_ok else '❌ ÉCHEC'}")
    
    total_tests = 4
    passed_tests = sum([basic_ok, conversational_ok, ai_ok, knowledge_ok])
    
    print(f"\n📊 Résultat global : {passed_tests}/{total_tests} tests réussis")
    
    if passed_tests == total_tests:
        print("\n🎉 IoTBreaker fonctionne correctement !")
        print("   Toutes les fonctionnalités de base sont opérationnelles.")
        print("   L'IA simple fonctionne et peut interpréter les commandes.")
        print("\n   Utilisation :")
        print("   • Mode conversationnel : python iotbreaker.py")
        print("   • Mode script : python iotbreaker.py scripts/audit_iot_rapide.yaml")
        print("   • L'IA peut interpréter vos commandes en langage naturel")
    else:
        print(f"\n⚠️ {total_tests - passed_tests} test(s) ont échoué.")
        print("   Vérifiez les modules et les dépendances.")

if __name__ == "__main__":
    main() 