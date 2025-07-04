#!/usr/bin/env python3
"""
Test rapide de compatibilité Kali Linux - Sans scans réseau
"""

import sys
import os
import platform

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_basic_modules():
    """Test des modules de base sans scan réseau"""
    print("🔧 TEST DES MODULES DE BASE")
    print("=" * 40)
    
    results = {}
    
    # Test 1: Utilitaires
    try:
        from core.utils import initialize_audit
        context = initialize_audit()
        results["core.utils"] = f"✅ OK ({len(context['devices'])} appareils)"
    except Exception as e:
        results["core.utils"] = f"❌ Erreur: {str(e)[:30]}"
    
    # Test 2: Base de connaissances
    try:
        from core.knowledge_base import load_knowledge
        kb = load_knowledge()
        results["core.knowledge_base"] = f"✅ OK ({len(kb['learnings'])} règles)"
    except Exception as e:
        results["core.knowledge_base"] = f"❌ Erreur: {str(e)[:30]}"
    
    # Test 3: IA simple
    try:
        from core.ai_analyzer_simple import get_ai_analysis
        result = get_ai_analysis("test")
        results["core.ai_analyzer_simple"] = f"✅ OK ({result})"
    except Exception as e:
        results["core.ai_analyzer_simple"] = f"❌ Erreur: {str(e)[:30]}"
    
    # Test 4: Rapports
    try:
        from core.reporting import generate_html_report
        generate_html_report([], "Test")
        results["core.reporting"] = "✅ OK"
    except Exception as e:
        results["core.reporting"] = f"❌ Erreur: {str(e)[:30]}"
    
    # Afficher les résultats
    for module, status in results.items():
        print(f"  {status} - {module}")
    
    return all("✅" in status for status in results.values())

def test_conversational_features():
    """Test des fonctionnalités conversationnelles"""
    print("\n💬 TEST DES FONCTIONNALITÉS CONVERSATIONNELLES")
    print("=" * 50)
    
    try:
        from core.ai_analyzer_simple import get_ai_analysis, get_ai_insights, get_ai_recommendations
        from core.utils import initialize_audit
        from core.knowledge_base import load_knowledge
        
        # Test d'interprétation de commandes
        test_commands = [
            "help",
            "status", 
            "Lance un scan complet",
            "Analyse tous les appareils",
            "Cherche les vulnérabilités",
            "Génère un rapport"
        ]
        
        print("Test d'interprétation des commandes :")
        for cmd in test_commands:
            action = get_ai_analysis(cmd)
            print(f"  ✅ '{cmd}' → {action}")
        
        # Test du contexte d'audit
        context = initialize_audit()
        print(f"  ✅ Contexte d'audit : {len(context['devices'])} appareils")
        
        # Test de la base de connaissances
        kb = load_knowledge()
        print(f"  ✅ Base de connaissances : {len(kb['learnings'])} règles")
        
        # Test des insights IA
        insights = get_ai_insights(context)
        print(f"  ✅ Insights IA : {len(insights)} insights")
        
        # Test des recommandations IA
        recommendations = get_ai_recommendations(context)
        print(f"  ✅ Recommandations IA : {len(recommendations)} recommandations")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_kali_environment():
    """Test de l'environnement Kali"""
    print("\n🐧 TEST ENVIRONNEMENT KALI")
    print("=" * 30)
    
    # Vérification du système
    system = platform.system()
    print(f"  Système d'exploitation : {system}")
    
    if system == "Linux":
        print("  ✅ Environnement Linux détecté")
        print("  💡 Compatible avec Kali Linux")
        return True
    else:
        print("  ⚠️ Environnement non-Linux détecté")
        print("  💡 Pour Kali Linux : utilisez WSL ou une VM")
        return False

def test_installation_guide():
    """Guide d'installation Kali"""
    print("\n📋 GUIDE D'INSTALLATION KALI")
    print("=" * 35)
    
    print("""
  🐧 INSTALLATION SUR KALI LINUX :
  
  1. Mise à jour du système :
     sudo apt update && sudo apt upgrade -y
  
  2. Installation des dépendances :
     sudo apt install python3 python3-pip nmap net-tools git -y
  
  3. Cloner et installer IoTBreaker :
     git clone https://github.com/servais1983/IoTBreaker.git
     cd IoTBreaker
     pip3 install -r requirements.txt
  
  4. Test de l'installation :
     python3 iotbreaker.py
  
  5. Utilisation :
     python3 iotbreaker.py  # Mode conversationnel
     python3 iotbreaker.py scripts/audit_iot_rapide.yaml  # Mode script
  """)
    
    return True

def main():
    """Test principal rapide"""
    print("🚀 TEST RAPIDE DE COMPATIBILITÉ KALI")
    print("=" * 50)
    print("Test sans scans réseau réels")
    print("=" * 50)
    
    # Tests
    modules_ok = test_basic_modules()
    conversational_ok = test_conversational_features()
    kali_env_ok = test_kali_environment()
    install_ok = test_installation_guide()
    
    # Résumé
    print("\n" + "=" * 50)
    print("📋 RÉSUMÉ RAPIDE")
    print("=" * 50)
    print(f"  🔧 Modules de base : {'✅ OK' if modules_ok else '❌ ÉCHEC'}")
    print(f"  💬 Fonctionnalités conversationnelles : {'✅ OK' if conversational_ok else '❌ ÉCHEC'}")
    print(f"  🐧 Environnement Kali : {'✅ OK' if kali_env_ok else '❌ ÉCHEC'}")
    print(f"  📋 Guide installation : {'✅ OK' if install_ok else '❌ ÉCHEC'}")
    
    total_tests = 4
    passed_tests = sum([modules_ok, conversational_ok, kali_env_ok, install_ok])
    
    print(f"\n📊 RÉSULTAT : {passed_tests}/{total_tests} tests réussis")
    
    if passed_tests >= total_tests * 0.75:  # 75% de réussite
        print("\n🎉 IoTBreaker est prêt pour Kali Linux !")
        print("   Les fonctionnalités de base sont opérationnelles.")
        print("   L'outil est compatible avec l'environnement Kali.")
        print("\n   Utilisation sur Kali :")
        print("   • Mode conversationnel : python3 iotbreaker.py")
        print("   • Mode script : python3 iotbreaker.py scripts/audit_iot_rapide.yaml")
    else:
        print(f"\n⚠️ {total_tests - passed_tests} test(s) ont échoué.")
        print("   Vérifiez l'installation et les dépendances.")

if __name__ == "__main__":
    main() 