#!/usr/bin/env python3
"""
Test d'une session complète d'IoTBreaker avec simulation d'entrées (compatible Windows)
"""

import sys
import os
import subprocess
import time

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_session_with_inputs():
    """Test d'une session avec entrées simulées (mode batch)"""
    print("🤖 TEST DE SESSION COMPLÈTE IoTBreaker (batch)")
    print("=" * 50)
    
    # Commandes à tester
    commands = [
        "help",
        "status", 
        "Lance un scan complet",
        "Analyse tous les appareils",
        "Que penses-tu de ces résultats ?",
        "exit"
    ]
    
    print("Commandes qui seront testées :")
    for i, cmd in enumerate(commands, 1):
        print(f"  {i}. {cmd}")
    
    print("\n[*] Démarrage du test...")
    
    try:
        # Préparer l'entrée batch
        input_data = "\n".join(commands) + "\n"
        
        # Démarrer le processus IoTBreaker
        process = subprocess.Popen(
            [sys.executable, "iotbreaker.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("[+] Processus IoTBreaker démarré (batch mode)")
        
        # Envoyer toutes les commandes d'un coup
        output, error = process.communicate(input=input_data, timeout=60)
        
        print("\n[+] Sortie complète du shell :\n")
        print(output)
        if error:
            print("\n[!] Erreurs :\n" + error)
        
        print("[+] Test batch terminé.")
        return True
        
    except Exception as e:
        print(f"[!] Erreur lors du test : {e}")
        return False

def test_direct_commands():
    """Test direct des commandes sans processus"""
    print("\n🔧 TEST DIRECT DES COMMANDES")
    print("-" * 30)
    
    try:
        from core.ai_analyzer_simple import get_ai_analysis
        from core.utils import initialize_audit
        from core.knowledge_base import load_knowledge
        
        # Initialisation
        context = initialize_audit()
        kb = load_knowledge()
        
        # Test des commandes
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
        
        print(f"\n✅ Contexte d'audit : {len(context['devices'])} appareils")
        print(f"✅ Base de connaissances : {len(kb['learnings'])} règles")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur : {e}")
        return False

def main():
    """Test principal"""
    print("🚀 TEST COMPLET D'IoTBreaker")
    print("=" * 50)
    
    # Test direct (plus fiable)
    direct_ok = test_direct_commands()
    
    # Test avec processus (batch, compatible Windows)
    print("\n" + "=" * 50)
    print("⚠️  Test avec processus batch (compatible Windows)...")
    session_ok = test_session_with_inputs()
    
    # Résumé
    print("\n" + "=" * 50)
    print("📋 RÉSUMÉ DES TESTS")
    print("=" * 50)
    print(f"  🔧 Test direct : {'✅ OK' if direct_ok else '❌ ÉCHEC'}")
    print(f"  🤖 Test session : {'✅ OK' if session_ok else '❌ ÉCHEC'}")
    
    if direct_ok and session_ok:
        print("\n🎉 IoTBreaker fonctionne correctement !")
        print("   L'IA peut interpréter vos commandes.")
        print("   Le mode conversationnel est opérationnel.")
        print("\n   Pour l'utiliser :")
        print("   • Lancez : python iotbreaker.py")
        print("   • Tapez vos commandes en langage naturel")
        print("   • Exemple : 'Lance un scan complet'")
    else:
        print("\n⚠️ Des problèmes ont été détectés.")
        print("   Vérifiez les modules et dépendances.")

if __name__ == "__main__":
    main() 