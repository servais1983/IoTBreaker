#!/usr/bin/env python3
"""
Script de test pour vérifier l'intégration de l'IA dans IoTBreaker
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
        test_prompt = """
        Analyse de sécurité IoT :
        - Appareil : Routeur domestique
        - Ports ouverts : 80, 443, 22, 23
        - Services : HTTP, HTTPS, SSH, Telnet
        
        Quels sont les risques principaux ?
        """
        
        print("  [*] Test de l'analyse IA...")
        result = get_ai_analysis(test_prompt, max_length=200)
        print(f"  [+] Résultat : {result}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test IA : {e}")
        return False

def test_discover_integration():
    """Test de l'intégration dans le module discover"""
    print("\n🔍 Test de l'intégration dans le module discover...")
    
    try:
        from core.discover import identify_device
        
        # Test avec des données fictives
        test_banners = {
            80: "HTTP/1.1 200 OK\nServer: nginx/1.18.0\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\n"
        }
        test_ports = [80, 443, 22, 23]
        test_ip = "192.168.1.1"
        
        print("  [*] Test de l'identification d'appareil avec IA...")
        result = identify_device(test_banners, test_ip, test_ports)
        print(f"  [+] Résultat : {result}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test discover : {e}")
        return False

def test_reporting_integration():
    """Test de l'intégration dans le module reporting"""
    print("\n📊 Test de l'intégration dans le module reporting...")
    
    try:
        from core.reporting import generate_ai_executive_summary
        
        # Test avec des données fictives
        test_results = [
            {
                'ip': '192.168.1.1',
                'severity': 'HIGH',
                'description': 'Port Telnet ouvert - risque d\'accès non autorisé'
            },
            {
                'ip': '192.168.1.10',
                'severity': 'MEDIUM',
                'description': 'Service HTTP non sécurisé détecté'
            }
        ]
        
        print("  [*] Test de la génération de résumé IA...")
        result = generate_ai_executive_summary(test_results, "Test IA")
        print(f"  [+] Résultat : {result}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test reporting : {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🚀 Test de l'intégration IA dans IoTBreaker")
    print("=" * 50)
    
    # Tests
    ai_ok = test_ai_analyzer()
    discover_ok = test_discover_integration()
    reporting_ok = test_reporting_integration()
    
    # Résumé
    print("\n" + "=" * 50)
    print("📋 RÉSUMÉ DES TESTS")
    print("=" * 50)
    print(f"  🧠 Module IA : {'✅ OK' if ai_ok else '❌ ÉCHEC'}")
    print(f"  🔍 Intégration Discover : {'✅ OK' if discover_ok else '❌ ÉCHEC'}")
    print(f"  📊 Intégration Reporting : {'✅ OK' if reporting_ok else '❌ ÉCHEC'}")
    
    if ai_ok and discover_ok and reporting_ok:
        print("\n🎉 Tous les tests sont passés ! L'intégration IA fonctionne correctement.")
    else:
        print("\n⚠️  Certains tests ont échoué. Vérifiez les dépendances et la configuration.")

if __name__ == "__main__":
    main() 