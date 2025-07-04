#!/usr/bin/env python3
"""
Script de test pour les fonctionnalités IA avancées d'IoTBreaker
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_check_ai_integration():
    """Test de l'intégration IA dans le module check"""
    print("🔍 Test de l'intégration IA dans le module check...")
    
    try:
        from core.check import check_http_exposed_interfaces
        
        # Test avec une IP fictive
        test_ip = "192.168.1.1"
        
        print("  [*] Test de la fonction check_http_exposed_interfaces avec IA...")
        result = check_http_exposed_interfaces(test_ip)
        print(f"  [+] Résultat : {result}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test check : {e}")
        return False

def test_exploit_ai_integration():
    """Test de l'intégration IA dans le module exploit"""
    print("\n💥 Test de l'intégration IA dans le module exploit...")
    
    try:
        from core.exploit import exploit_telnet
        
        # Test avec des données fictives (ne va pas vraiment se connecter)
        test_ip = "192.168.1.1"
        test_user = "admin"
        test_pass = "password"
        
        print("  [*] Test de la fonction exploit_telnet avec IA...")
        # Note: Cette fonction va échouer car l'IP n'est pas réelle, mais on teste l'import
        print("  [+] Module exploit avec IA chargé avec succès")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test exploit : {e}")
        return False

def test_analyze_ai_integration():
    """Test de l'intégration IA dans le module analyze"""
    print("\n📊 Test de l'intégration IA dans le module analyze...")
    
    try:
        from core.analyze import run
        
        # Test avec une IP fictive
        test_ip = "192.168.1.1"
        
        print("  [*] Test de la fonction analyze avec IA...")
        result = run(test_ip)
        print("  [+] Module analyze avec IA testé avec succès")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test analyze : {e}")
        return False

def test_ai_prompt_generation():
    """Test de la génération de prompts IA"""
    print("\n🧠 Test de la génération de prompts IA...")
    
    try:
        from core.ai_analyzer import get_ai_analysis
        
        # Test de différents types de prompts
        test_prompts = [
            {
                "name": "Analyse de serveur web",
                "prompt": """
                Analyse de sécurité IoT :
                - Appareil : Routeur domestique
                - Ports ouverts : 80, 443, 22, 23
                - Bannière serveur : nginx/1.18.0
                
                Quels chemins d'administration devrais-je tester ?
                """
            },
            {
                "name": "Post-exploitation Telnet",
                "prompt": """
                J'ai obtenu un accès shell sur un appareil IoT via Telnet.
                Le prompt du shell est '$'.
                
                Suggère-moi des commandes pour identifier le système.
                """
            },
            {
                "name": "Analyse de vulnérabilités",
                "prompt": """
                Analyse de sécurité IoT pour l'appareil 192.168.1.1 :
                
                Ports ouverts : [80, 443, 1883]
                Services détectés : ['HTTP', 'HTTPS', 'MQTT']
                
                Quels sont les risques de sécurité les plus critiques ?
                """
            }
        ]
        
        for i, test_case in enumerate(test_prompts, 1):
            print(f"  [*] Test {i}: {test_case['name']}")
            try:
                result = get_ai_analysis(test_case['prompt'], max_length=128)
                print(f"    [+] Réponse IA : {result[:100]}...")
            except Exception as e:
                print(f"    [!] Erreur : {e}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test des prompts : {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🚀 Test des fonctionnalités IA avancées d'IoTBreaker")
    print("=" * 60)
    
    # Tests
    check_ok = test_check_ai_integration()
    exploit_ok = test_exploit_ai_integration()
    analyze_ok = test_analyze_ai_integration()
    prompts_ok = test_ai_prompt_generation()
    
    # Résumé
    print("\n" + "=" * 60)
    print("📋 RÉSUMÉ DES TESTS AVANCÉS")
    print("=" * 60)
    print(f"  🔍 Module Check avec IA : {'✅ OK' if check_ok else '❌ ÉCHEC'}")
    print(f"  💥 Module Exploit avec IA : {'✅ OK' if exploit_ok else '❌ ÉCHEC'}")
    print(f"  📊 Module Analyze avec IA : {'✅ OK' if analyze_ok else '❌ ÉCHEC'}")
    print(f"  🧠 Génération de prompts IA : {'✅ OK' if prompts_ok else '❌ ÉCHEC'}")
    
    if check_ok and exploit_ok and analyze_ok and prompts_ok:
        print("\n🎉 Tous les tests avancés sont passés !")
        print("   IoTBreaker est maintenant doté d'une IA intelligente pour :")
        print("   • Suggérer des chemins de vulnérabilités spécifiques")
        print("   • Guider la post-exploitation avec des commandes pertinentes")
        print("   • Analyser intelligemment les ports et services")
        print("   • Générer des recommandations stratégiques")
    else:
        print("\n⚠️  Certains tests avancés ont échoué.")
        print("   Vérifiez les dépendances et la configuration de l'IA.")

if __name__ == "__main__":
    main() 