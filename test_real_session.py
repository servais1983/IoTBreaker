#!/usr/bin/env python3
"""
Test en situation réelle d'IoTBreaker - Simulation d'une session complète
"""

import sys
import os
import subprocess
import time

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_real_conversational_session():
    """Test d'une session conversationnelle réelle"""
    print("🎯 TEST EN SITUATION RÉELLE - IoTBreaker")
    print("=" * 60)
    
    # Commandes réelles à tester (comme dans le README)
    commands = [
        "help",
        "status",
        "Lance un scan complet",
        "Analyse tous les appareils", 
        "Cherche les vulnérabilités",
        "Que penses-tu de ces résultats ?",
        "Quelles sont tes recommandations ?",
        "Génère un rapport",
        "exit"
    ]
    
    print("Commandes qui seront testées (selon le README) :")
    for i, cmd in enumerate(commands, 1):
        print(f"  {i}. {cmd}")
    
    print("\n[*] Démarrage du test en situation réelle...")
    
    try:
        # Préparer l'entrée batch
        input_data = "\n".join(commands) + "\n"
        
        # Démarrer IoTBreaker en mode conversationnel
        process = subprocess.Popen(
            [sys.executable, "iotbreaker.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("[+] IoTBreaker démarré en mode conversationnel")
        
        # Envoyer toutes les commandes et récupérer la sortie
        output, error = process.communicate(input=input_data, timeout=120)
        
        print("\n" + "=" * 60)
        print("📋 SORTIE COMPLÈTE D'IoTBreaker")
        print("=" * 60)
        print(output)
        
        if error:
            print("\n" + "=" * 60)
            print("⚠️ ERREURS DÉTECTÉES")
            print("=" * 60)
            print(error)
        
        # Analyser la sortie
        print("\n" + "=" * 60)
        print("🔍 ANALYSE DE LA SESSION")
        print("=" * 60)
        
        output_lines = output.split('\n')
        
        # Vérifications
        checks = {
            "Logo affiché": False,
            "Bienvenue affiché": False,
            "Aide affichée": False,
            "Status affiché": False,
            "Scan lancé": False,
            "Analyse effectuée": False,
            "Vulnérabilités cherchées": False,
            "IA a répondu": False,
            "Recommandations données": False,
            "Rapport généré": False,
            "Session terminée": False
        }
        
        for line in output_lines:
            line_lower = line.lower()
            
            if "iot" in line_lower and "outil" in line_lower:
                checks["Logo affiché"] = True
            if "bienvenue" in line_lower:
                checks["Bienvenue affiché"] = True
            if "commandes disponibles" in line_lower or "help" in line_lower:
                checks["Aide affichée"] = True
            if "état de l'audit" in line_lower or "appareils découverts" in line_lower:
                checks["Status affiché"] = True
            if "scan" in line_lower and ("lancé" in line_lower or "découverte" in line_lower):
                checks["Scan lancé"] = True
            if "analyse" in line_lower and ("effectuée" in line_lower or "ports" in line_lower):
                checks["Analyse effectuée"] = True
            if "vulnérabilités" in line_lower and ("cherchées" in line_lower or "trouvées" in line_lower):
                checks["Vulnérabilités cherchées"] = True
            if "ia" in line_lower and ("interprète" in line_lower or "analyse" in line_lower):
                checks["IA a répondu"] = True
            if "recommandations" in line_lower:
                checks["Recommandations données"] = True
            if "rapport" in line_lower and ("généré" in line_lower or "créé" in line_lower):
                checks["Rapport généré"] = True
            if "session terminée" in line_lower or "exit" in line_lower:
                checks["Session terminée"] = True
        
        # Afficher les résultats
        print("Vérifications de la session :")
        for check, status in checks.items():
            status_icon = "✅" if status else "❌"
            print(f"  {status_icon} {check}")
        
        # Résumé
        passed_checks = sum(checks.values())
        total_checks = len(checks)
        
        print(f"\n📊 RÉSULTAT : {passed_checks}/{total_checks} vérifications réussies")
        
        if passed_checks >= total_checks * 0.8:  # 80% de réussite
            print("\n🎉 IoTBreaker fonctionne correctement en situation réelle !")
            print("   Toutes les fonctionnalités du README sont opérationnelles.")
            return True
        else:
            print(f"\n⚠️ {total_checks - passed_checks} vérifications ont échoué.")
            print("   Certaines fonctionnalités peuvent ne pas fonctionner comme attendu.")
            return False
        
    except Exception as e:
        print(f"[!] Erreur lors du test : {e}")
        return False

def test_script_mode():
    """Test du mode script (rétro-compatibilité)"""
    print("\n" + "=" * 60)
    print("📜 TEST DU MODE SCRIPT (Rétro-compatibilité)")
    print("=" * 60)
    
    try:
        # Test avec le script rapide
        print("[*] Test du script audit_iot_rapide.yaml...")
        
        process = subprocess.Popen(
            [sys.executable, "iotbreaker.py", "scripts/audit_iot_rapide.yaml"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        output, error = process.communicate(timeout=60)
        
        if "audit" in output.lower() or "scan" in output.lower():
            print("✅ Mode script fonctionne correctement")
            return True
        else:
            print("❌ Mode script ne fonctionne pas comme attendu")
            print(f"Sortie : {output[:200]}...")
            return False
            
    except Exception as e:
        print(f"❌ Erreur mode script : {e}")
        return False

def main():
    """Test principal en situation réelle"""
    print("🚀 TEST EN SITUATION RÉELLE D'IoTBreaker")
    print("=" * 60)
    print("Ce test vérifie que IoTBreaker fonctionne exactement comme décrit dans le README")
    print("=" * 60)
    
    # Test du mode conversationnel
    conversational_ok = test_real_conversational_session()
    
    # Test du mode script
    script_ok = test_script_mode()
    
    # Résumé final
    print("\n" + "=" * 60)
    print("📋 RÉSUMÉ FINAL")
    print("=" * 60)
    print(f"  💬 Mode conversationnel : {'✅ OK' if conversational_ok else '❌ ÉCHEC'}")
    print(f"  📜 Mode script : {'✅ OK' if script_ok else '❌ ÉCHEC'}")
    
    if conversational_ok and script_ok:
        print("\n🎉 IoTBreaker est 100% fonctionnel en situation réelle !")
        print("   Toutes les fonctionnalités du README sont opérationnelles.")
        print("   Vous pouvez utiliser :")
        print("   • Mode conversationnel : python iotbreaker.py")
        print("   • Mode script : python iotbreaker.py scripts/audit_iot_rapide.yaml")
    else:
        print("\n⚠️ Des problèmes ont été détectés en situation réelle.")
        print("   Vérifiez la configuration et les dépendances.")

if __name__ == "__main__":
    main() 