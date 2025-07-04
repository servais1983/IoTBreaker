#!/usr/bin/env python3
"""
Démonstration simple d'utilisation d'IoTBreaker
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def demo_usage():
    """Démonstration d'utilisation"""
    print("🎯 DÉMONSTRATION IoTBreaker - Mode Conversationnel")
    print("=" * 60)
    
    print("""
🤖 IoTBreaker est maintenant un outil d'audit IoT conversationnel !

📋 COMMENT L'UTILISER :

1. Lancez le mode conversationnel :
   python iotbreaker.py

2. Tapez vos commandes en langage naturel :
   > Lance un scan complet
   > Analyse tous les appareils  
   > Cherche les vulnérabilités
   > Génère un rapport
   > Que penses-tu de ces résultats ?
   > Quelles sont tes recommandations ?

3. Commandes de base :
   > help     - Affiche l'aide
   > status   - État de l'audit
   > clear    - Efface l'écran
   > exit     - Quitte le programme

🧠 L'IA comprend vos commandes et les traduit en actions :
""")
    
    try:
        from core.ai_analyzer_simple import get_ai_analysis
        
        # Exemples de commandes
        examples = [
            "Lance un scan complet",
            "Trouve les caméras", 
            "Cherche les routeurs",
            "Analyse tous les appareils",
            "Cherche les vulnérabilités",
            "Génère un rapport",
            "Que penses-tu de ces résultats ?"
        ]
        
        print("📝 Exemples de commandes et leurs actions :")
        for cmd in examples:
            action = get_ai_analysis(cmd)
            print(f"   '{cmd}' → {action}")
        
        print("""
🎉 AVANTAGES DU MODE CONVERSATIONNEL :

✅ Interface naturelle - Parlez comme à un collègue
✅ Apprentissage continu - L'IA mémorise vos préférences  
✅ Commandes intelligentes - Comprend le contexte
✅ Insights automatiques - Analyses et recommandations IA
✅ Rapidité - Plus besoin de scripts complexes

🚀 PRÊT À COMMENCER ?

Lancez maintenant : python iotbreaker.py

Puis tapez : Lance un scan complet

L'IA comprendra et exécutera la découverte d'appareils !
""")
        
    except Exception as e:
        print(f"❌ Erreur : {e}")

if __name__ == "__main__":
    demo_usage() 