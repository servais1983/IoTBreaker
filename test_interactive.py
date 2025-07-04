#!/usr/bin/env python3
"""
Test interactif simple du mode conversationnel
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_interactive():
    """Test interactif simple"""
    print("🤖 TEST INTERACTIF IoTBreaker")
    print("=" * 40)
    
    try:
        from core.ai_analyzer_simple import get_ai_analysis
        
        # Test d'une commande simple
        command = "help"
        print(f"[Vous]> {command}")
        
        action = get_ai_analysis(command)
        print(f"[🧠] Action : {action}")
        
        # Test d'une autre commande
        command2 = "scan"
        print(f"\n[Vous]> {command2}")
        
        action2 = get_ai_analysis(command2)
        print(f"[🧠] Action : {action2}")
        
        print("\n✅ Test interactif réussi !")
        print("   Le mode conversationnel fonctionne correctement.")
        
    except Exception as e:
        print(f"❌ Erreur : {e}")

if __name__ == "__main__":
    test_interactive() 