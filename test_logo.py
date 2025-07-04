#!/usr/bin/env python3
"""
Test du nouveau logo IoT
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_logo():
    """Test du nouveau logo"""
    print("🎨 TEST DU NOUVEAU LOGO IoT")
    print("=" * 40)
    
    try:
        from iotbreaker import print_banner
        print_banner()
        print("✅ Logo affiché avec succès !")
        
    except Exception as e:
        print(f"❌ Erreur : {e}")

if __name__ == "__main__":
    test_logo() 