#!/usr/bin/env python3
"""
Test complet de l'intégration IA dans IoTBreaker
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_ai_analyzer():
    """Test du module d'analyse IA"""
    print("🧠 Test du module d'analyse IA...")
    
    try:
        from core.ai_analyzer import get_ai_analysis
        
        # Test simple
        result = get_ai_analysis("Test simple", max_length=50)
        print(f"  [+] Test simple : {result}")
        
        # Test d'analyse de vulnérabilité
        vuln_prompt = "Analyse cette vulnérabilité : Port Telnet ouvert sur 192.168.1.1"
        result = get_ai_analysis(vuln_prompt, max_length=100)
        print(f"  [+] Test vulnérabilité : {result}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def test_discover_ai():
    """Test de l'IA dans le module discover"""
    print("\n🔍 Test de l'IA dans le module discover...")
    
    try:
        from core.discover import run
        
        # Test de découverte avec IA
        devices = run()
        print(f"  [+] Découverte : {len(devices)} appareils trouvés")
        
        # Vérification de l'enrichissement IA
        for device in devices:
            if 'ai_analysis' in device:
                print(f"  [+] Enrichissement IA trouvé pour {device.get('ip', 'N/A')}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def test_analyze_ai():
    """Test de l'IA dans le module analyze"""
    print("\n🔬 Test de l'IA dans le module analyze...")
    
    try:
        from core.analyze import run
        
        # Test d'analyse avec IA
        test_ip = "192.168.1.1"
        result = run(test_ip)
        print(f"  [+] Analyse IA pour {test_ip} : OK")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def test_check_ai():
    """Test de l'IA dans le module check"""
    print("\n🛡️ Test de l'IA dans le module check...")
    
    try:
        from core.check import run
        
        # Test de vérification avec IA
        test_ip = "192.168.1.1"
        result = run(test_ip)
        print(f"  [+] Vérification IA pour {test_ip} : OK")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def test_reporting_ai():
    """Test de l'IA dans le module reporting"""
    print("\n📊 Test de l'IA dans le module reporting...")
    
    try:
        from core.reporting import generate_html_report
        
        # Test de génération de rapport avec IA
        test_vulns = [
            {
                'ip': '192.168.1.1',
                'type': 'Telnet ouvert',
                'severity': 'High',
                'description': 'Port Telnet accessible'
            }
        ]
        
        generate_html_report(test_vulns, "Test IA")
        print(f"  [+] Rapport IA généré : OK")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def test_exploit_ai():
    """Test de l'IA dans le module exploit"""
    print("\n💥 Test de l'IA dans le module exploit...")
    
    try:
        from core.exploit import run
        
        # Test d'exploitation avec IA
        test_vuln = {
            'ip': '192.168.1.1',
            'type': 'Telnet ouvert',
            'severity': 'High'
        }
        
        result = run(test_vuln)
        print(f"  [+] Exploitation IA : OK")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def test_conversational_ai():
    """Test de l'IA conversationnelle"""
    print("\n💬 Test de l'IA conversationnelle...")
    
    try:
        from core.utils import initialize_audit, run_step
        from core.knowledge_base import load_knowledge
        from core.ai_analyzer import get_ai_analysis
        
        # Test du contexte d'audit
        context = initialize_audit()
        kb = load_knowledge()
        print(f"  [+] Contexte d'audit : {len(context['devices'])} appareils")
        
        # Test d'interprétation de commande
        ai_prompt = """
        Contexte de l'audit : 0 appareils trouvés.
        Commande de l'utilisateur : 'Lance un scan complet'
        
        Traduis cette commande en action système.
        """
        
        action = get_ai_analysis(ai_prompt, max_length=64)
        print(f"  [+] Interprétation IA : {action}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def test_knowledge_base():
    """Test de la base de connaissances"""
    print("\n📚 Test de la base de connaissances...")
    
    try:
        from core.knowledge_base import load_knowledge, save_knowledge, add_learning
        
        # Test de chargement
        kb = load_knowledge()
        print(f"  [+] Base chargée : {len(kb['learnings'])} règles")
        
        # Test d'ajout
        add_learning(kb, "Test d'intégration IA complète")
        save_knowledge(kb)
        print(f"  [+] Apprentissage ajouté : OK")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur : {e}")
        return False

def main():
    """Test principal de l'intégration IA"""
    print("🤖 TEST COMPLET DE L'INTÉGRATION IA DANS IoTBreaker")
    print("=" * 60)
    
    # Tests
    ai_analyzer_ok = test_ai_analyzer()
    discover_ok = test_discover_ai()
    analyze_ok = test_analyze_ai()
    check_ok = test_check_ai()
    reporting_ok = test_reporting_ai()
    exploit_ok = test_exploit_ai()
    conversational_ok = test_conversational_ai()
    knowledge_ok = test_knowledge_base()
    
    # Résumé
    print("\n" + "=" * 60)
    print("📋 RÉSUMÉ DE L'INTÉGRATION IA")
    print("=" * 60)
    print(f"  🧠 Module d'analyse IA : {'✅ OK' if ai_analyzer_ok else '❌ ÉCHEC'}")
    print(f"  🔍 IA dans discover : {'✅ OK' if discover_ok else '❌ ÉCHEC'}")
    print(f"  🔬 IA dans analyze : {'✅ OK' if analyze_ok else '❌ ÉCHEC'}")
    print(f"  🛡️ IA dans check : {'✅ OK' if check_ok else '❌ ÉCHEC'}")
    print(f"  📊 IA dans reporting : {'✅ OK' if reporting_ok else '❌ ÉCHEC'}")
    print(f"  💥 IA dans exploit : {'✅ OK' if exploit_ok else '❌ ÉCHEC'}")
    print(f"  💬 IA conversationnelle : {'✅ OK' if conversational_ok else '❌ ÉCHEC'}")
    print(f"  📚 Base de connaissances : {'✅ OK' if knowledge_ok else '❌ ÉCHEC'}")
    
    total_tests = 8
    passed_tests = sum([ai_analyzer_ok, discover_ok, analyze_ok, check_ok, reporting_ok, exploit_ok, conversational_ok, knowledge_ok])
    
    print(f"\n📊 Résultat global : {passed_tests}/{total_tests} tests réussis")
    
    if passed_tests == total_tests:
        print("\n🎉 L'IA est parfaitement intégrée dans IoTBreaker !")
        print("   Toutes les fonctionnalités IA sont opérationnelles.")
        print("   Vous pouvez utiliser :")
        print("   • Le mode conversationnel : python iotbreaker.py")
        print("   • Le mode script avec IA : python iotbreaker.py script.yaml --ai-driven")
        print("   • Toutes les commandes IA enrichies")
    else:
        print(f"\n⚠️ {total_tests - passed_tests} test(s) ont échoué.")
        print("   Vérifiez la configuration de l'IA et les dépendances.")

if __name__ == "__main__":
    main() 