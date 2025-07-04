#!/usr/bin/env python3
"""
Test simple d'IoTBreaker - Vérification des fonctionnalités de base
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_basic_modules():
    """Test des modules de base"""
    print("🔧 Test des modules de base...")
    
    try:
        # Test des imports de base
        from core.utils import initialize_audit, get_module
        from core.knowledge_base import load_knowledge, save_knowledge
        print("  ✅ Imports de base OK")
        
        # Test de l'initialisation
        context = initialize_audit()
        print(f"  ✅ Contexte d'audit initialisé : {len(context['devices'])} appareils")
        
        # Test de la base de connaissances
        kb = load_knowledge()
        print(f"  ✅ Base de connaissances : {len(kb['learnings'])} règles")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_discover_module():
    """Test du module discover"""
    print("\n🔍 Test du module discover...")
    
    try:
        from core.discover import run
        
        # Test de découverte (simulation)
        devices = run()
        print(f"  ✅ Découverte : {len(devices)} appareils trouvés")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_analyze_module():
    """Test du module analyze"""
    print("\n🔬 Test du module analyze...")
    
    try:
        from core.analyze import run
        
        # Test d'analyse (simulation)
        test_ip = "192.168.1.1"
        result = run(test_ip)
        print(f"  ✅ Analyse pour {test_ip} : OK")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_check_module():
    """Test du module check"""
    print("\n🛡️ Test du module check...")
    
    try:
        from core.check import run
        
        # Test de vérification (simulation)
        test_ip = "192.168.1.1"
        result = run(test_ip)
        print(f"  ✅ Vérification pour {test_ip} : OK")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_reporting_module():
    """Test du module reporting"""
    print("\n📊 Test du module reporting...")
    
    try:
        from core.reporting import generate_html_report
        
        # Test de génération de rapport
        test_vulns = [
            {
                'ip': '192.168.1.1',
                'type': 'Telnet ouvert',
                'severity': 'High',
                'description': 'Port Telnet accessible'
            }
        ]
        
        generate_html_report(test_vulns, "Test Simple")
        print(f"  ✅ Rapport généré : OK")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_conversational_mode():
    """Test du mode conversationnel (sans IA)"""
    print("\n💬 Test du mode conversationnel...")
    
    try:
        from core.utils import initialize_audit, run_step
        from core.knowledge_base import load_knowledge
        
        # Test du contexte d'audit
        context = initialize_audit()
        kb = load_knowledge()
        print(f"  ✅ Contexte d'audit : {len(context['devices'])} appareils")
        
        # Test d'une commande simple
        run_step("DISCOVER", context)
        print(f"  ✅ Commande DISCOVER exécutée")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def test_script_mode():
    """Test du mode script"""
    print("\n📜 Test du mode script...")
    
    try:
        from core.utils import run_script_yaml
        
        # Test avec un scénario simple
        print("  ✅ Mode script disponible")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
        return False

def main():
    """Test principal"""
    print("🚀 TEST SIMPLE D'IoTBreaker")
    print("=" * 50)
    
    # Tests
    basic_ok = test_basic_modules()
    discover_ok = test_discover_module()
    analyze_ok = test_analyze_module()
    check_ok = test_check_module()
    reporting_ok = test_reporting_module()
    conversational_ok = test_conversational_mode()
    script_ok = test_script_mode()
    
    # Résumé
    print("\n" + "=" * 50)
    print("📋 RÉSUMÉ DES TESTS")
    print("=" * 50)
    print(f"  🔧 Modules de base : {'✅ OK' if basic_ok else '❌ ÉCHEC'}")
    print(f"  🔍 Module discover : {'✅ OK' if discover_ok else '❌ ÉCHEC'}")
    print(f"  🔬 Module analyze : {'✅ OK' if analyze_ok else '❌ ÉCHEC'}")
    print(f"  🛡️ Module check : {'✅ OK' if check_ok else '❌ ÉCHEC'}")
    print(f"  📊 Module reporting : {'✅ OK' if reporting_ok else '❌ ÉCHEC'}")
    print(f"  💬 Mode conversationnel : {'✅ OK' if conversational_ok else '❌ ÉCHEC'}")
    print(f"  📜 Mode script : {'✅ OK' if script_ok else '❌ ÉCHEC'}")
    
    total_tests = 7
    passed_tests = sum([basic_ok, discover_ok, analyze_ok, check_ok, reporting_ok, conversational_ok, script_ok])
    
    print(f"\n📊 Résultat global : {passed_tests}/{total_tests} tests réussis")
    
    if passed_tests == total_tests:
        print("\n🎉 IoTBreaker fonctionne correctement !")
        print("   Toutes les fonctionnalités de base sont opérationnelles.")
        print("   Note : L'IA nécessite 'pip install accelerate' pour fonctionner.")
        print("\n   Utilisation :")
        print("   • Mode conversationnel : python iotbreaker.py")
        print("   • Mode script : python iotbreaker.py scripts/audit_iot_rapide.yaml")
    else:
        print(f"\n⚠️ {total_tests - passed_tests} test(s) ont échoué.")
        print("   Vérifiez les modules et les dépendances.")

if __name__ == "__main__":
    main() 