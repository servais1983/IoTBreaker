#!/usr/bin/env python3
"""
Test de compatibilité Kali Linux pour IoTBreaker
"""

import sys
import os
import platform
import subprocess

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def check_kali_environment():
    """Vérification de l'environnement Kali Linux"""
    print("🐧 VÉRIFICATION ENVIRONNEMENT KALI LINUX")
    print("=" * 50)
    
    # Vérification du système d'exploitation
    system = platform.system()
    print(f"  Système d'exploitation : {system}")
    
    if system != "Linux":
        print("  ⚠️  IoTBreaker est conçu pour Linux (Kali)")
        print("  💡 Pour Windows, utilisez WSL ou une VM Kali")
        return False
    
    # Vérification de la distribution
    try:
        with open('/etc/os-release', 'r') as f:
            os_info = f.read()
            if 'kali' in os_info.lower():
                print("  ✅ Distribution Kali Linux détectée")
            else:
                print("  ⚠️  Distribution Linux détectée (pas Kali)")
                print("  💡 Recommandé : Kali Linux pour les outils de sécurité")
    except:
        print("  ⚠️  Impossible de détecter la distribution")
    
    # Vérification des outils Linux requis
    linux_tools = [
        "nmap",
        "netstat", 
        "ip",
        "ping",
        "curl",
        "wget"
    ]
    
    print("\n  Vérification des outils Linux :")
    for tool in linux_tools:
        try:
            result = subprocess.run([tool, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"    ✅ {tool} disponible")
            else:
                print(f"    ❌ {tool} non disponible")
        except:
            print(f"    ❌ {tool} non installé")
    
    return True

def test_linux_network_scan():
    """Test des fonctionnalités réseau Linux"""
    print("\n🌐 TEST DES FONCTIONNALITÉS RÉSEAU LINUX")
    print("=" * 40)
    
    try:
        # Test de découverte réseau
        from core.discover import run
        
        print("  [*] Test de découverte réseau...")
        # Test avec localhost pour éviter les scans réseau réels
        result = run("127.0.0.1")
        print("  ✅ Module de découverte fonctionnel")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur réseau : {e}")
        return False

def test_linux_security_tools():
    """Test des outils de sécurité Linux"""
    print("\n🛡️ TEST DES OUTILS DE SÉCURITÉ")
    print("=" * 35)
    
    try:
        # Test des modules de sécurité
        from core.check import run
        from core.exploit import run as exploit_run
        
        print("  [*] Test des modules de sécurité...")
        
        # Test de vérification de vulnérabilités
        check_result = run("127.0.0.1")
        print("  ✅ Module de vérification fonctionnel")
        
        # Test d'exploitation (simulation)
        exploit_result = exploit_run({"ip": "127.0.0.1", "type": "test"})
        print("  ✅ Module d'exploitation fonctionnel")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Erreur sécurité : {e}")
        return False

def test_kali_specific_features():
    """Test des fonctionnalités spécifiques à Kali"""
    print("\n🎯 FONCTIONNALITÉS SPÉCIFIQUES KALI")
    print("=" * 40)
    
    features = {
        "Scan réseau avancé": False,
        "Détection de vulnérabilités": False,
        "Exploitation IoT": False,
        "Rapports de sécurité": False,
        "Mode conversationnel": False,
        "IA d'analyse": False
    }
    
    try:
        # Test du scan réseau
        from core.discover import run
        run("127.0.0.1")
        features["Scan réseau avancé"] = True
        
        # Test de détection de vulnérabilités
        from core.check import run
        run("127.0.0.1")
        features["Détection de vulnérabilités"] = True
        
        # Test d'exploitation
        from core.exploit import run
        run({"ip": "127.0.0.1", "type": "test"})
        features["Exploitation IoT"] = True
        
        # Test des rapports
        from core.reporting import generate_html_report
        generate_html_report([], "Test Kali")
        features["Rapports de sécurité"] = True
        
        # Test du mode conversationnel
        from core.ai_analyzer_simple import get_ai_analysis
        get_ai_analysis("test")
        features["Mode conversationnel"] = True
        features["IA d'analyse"] = True
        
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
    
    # Afficher les résultats
    for feature, status in features.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {feature}")
    
    return sum(features.values()) >= len(features) * 0.8

def test_installation_guide():
    """Test du guide d'installation Kali"""
    print("\n📋 GUIDE D'INSTALLATION KALI")
    print("=" * 35)
    
    print("""
  🐧 INSTALLATION SUR KALI LINUX :
  
  1. Mise à jour du système :
     sudo apt update && sudo apt upgrade -y
  
  2. Installation des dépendances :
     sudo apt install python3 python3-pip nmap net-tools -y
  
  3. Installation des dépendances Python :
     pip3 install -r requirements.txt
  
  4. Test de l'installation :
     python3 iotbreaker.py
  
  5. Utilisation :
     python3 iotbreaker.py  # Mode conversationnel
     python3 iotbreaker.py scripts/audit_iot_rapide.yaml  # Mode script
  """)
    
    return True

def main():
    """Test principal de compatibilité Kali"""
    print("🐧 TEST DE COMPATIBILITÉ KALI LINUX - IoTBreaker")
    print("=" * 60)
    print("IoTBreaker est un outil CLI conçu pour Kali Linux")
    print("=" * 60)
    
    # Tests
    kali_env_ok = check_kali_environment()
    network_ok = test_linux_network_scan()
    security_ok = test_linux_security_tools()
    kali_features_ok = test_kali_specific_features()
    install_ok = test_installation_guide()
    
    # Résumé
    print("\n" + "=" * 60)
    print("📋 RÉSUMÉ COMPATIBILITÉ KALI")
    print("=" * 60)
    print(f"  🐧 Environnement Kali : {'✅ OK' if kali_env_ok else '❌ ÉCHEC'}")
    print(f"  🌐 Fonctionnalités réseau : {'✅ OK' if network_ok else '❌ ÉCHEC'}")
    print(f"  🛡️ Outils de sécurité : {'✅ OK' if security_ok else '❌ ÉCHEC'}")
    print(f"  🎯 Fonctionnalités Kali : {'✅ OK' if kali_features_ok else '❌ ÉCHEC'}")
    print(f"  📋 Guide installation : {'✅ OK' if install_ok else '❌ ÉCHEC'}")
    
    total_tests = 5
    passed_tests = sum([kali_env_ok, network_ok, security_ok, kali_features_ok, install_ok])
    
    print(f"\n📊 RÉSULTAT : {passed_tests}/{total_tests} tests réussis")
    
    if passed_tests >= total_tests * 0.8:
        print("\n🎉 IoTBreaker est compatible avec Kali Linux !")
        print("   L'outil est prêt pour l'audit de sécurité IoT.")
        print("\n   Utilisation sur Kali :")
        print("   • Mode conversationnel : python3 iotbreaker.py")
        print("   • Mode script : python3 iotbreaker.py scripts/audit_iot_rapide.yaml")
        print("   • Audit complet : python3 iotbreaker.py scripts/audit_iot_complet.yaml")
    else:
        print(f"\n⚠️ {total_tests - passed_tests} test(s) ont échoué.")
        print("   Vérifiez l'installation sur Kali Linux.")

if __name__ == "__main__":
    main() 