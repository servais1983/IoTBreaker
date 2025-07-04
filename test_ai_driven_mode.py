#!/usr/bin/env python3
"""
Script de test pour le mode piloté par l'IA d'IoTBreaker
"""

import sys
import os

# Ajouter le répertoire courant au path pour importer les modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_ai_driven_mode():
    """Test du mode piloté par l'IA"""
    print("🧠 Test du mode piloté par l'IA...")
    
    try:
        from core.utils import run_script_yaml
        
        # Test avec le scénario IA
        scenario_path = "scripts/audit_ai_driven.yaml"
        
        print("  [*] Test du mode piloté par l'IA...")
        print("  [*] Note: Ce test va réellement lancer l'audit IA")
        print("  [*] L'IA va décider des actions à effectuer")
        
        # Lancer le mode IA
        run_script_yaml(scenario_path, ai_driven_mode=True)
        
        print("  [+] Mode IA testé avec succès")
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test du mode IA : {e}")
        return False

def test_ai_decision_logic():
    """Test de la logique de décision de l'IA"""
    print("\n🤖 Test de la logique de décision de l'IA...")
    
    try:
        from core.ai_analyzer import get_ai_analysis
        
        # Test de différents contextes d'audit
        test_contexts = [
            {
                "name": "Contexte avec appareils découverts",
                "prompt": """
                Contexte de l'audit de sécurité IoT en cours :
                - Scénario: Test IA
                - Appareils découverts: ['192.168.1.1', '192.168.1.10']
                - Vulnérabilités déjà trouvées: []
                - Historique des actions: ['Découverte réseau effectuée.']

                En te basant sur ce contexte, quelle est la prochaine étape la plus logique ? Choisis UNE seule action parmi les suivantes :
                - "ANALYZE <IP>" (pour scanner les ports d'un appareil)
                - "CHECK <IP>" (pour chercher des vulnérabilités sur un appareil)
                - "SHODAN_LOOKUP <IP>" (pour obtenir des infos sur une IP publique)
                - "STOP" (si tu estimes que l'audit est terminé ou qu'il n'y a plus rien de pertinent à faire)

                Réponds uniquement avec l'action choisie. Par exemple : "CHECK 192.168.1.50"
                """
            },
            {
                "name": "Contexte avec vulnérabilités trouvées",
                "prompt": """
                Contexte de l'audit de sécurité IoT en cours :
                - Scénario: Test IA
                - Appareils découverts: ['192.168.1.1']
                - Vulnérabilités déjà trouvées: [{'ip': '192.168.1.1', 'severity': 'HIGH', 'description': 'Port Telnet ouvert'}]
                - Historique des actions: ['Découverte réseau effectuée.', 'CHECK 192.168.1.1']

                En te basant sur ce contexte, quelle est la prochaine étape la plus logique ? Choisis UNE seule action parmi les suivantes :
                - "ANALYZE <IP>" (pour scanner les ports d'un appareil)
                - "CHECK <IP>" (pour chercher des vulnérabilités sur un appareil)
                - "SHODAN_LOOKUP <IP>" (pour obtenir des infos sur une IP publique)
                - "STOP" (si tu estimes que l'audit est terminé ou qu'il n'y a plus rien de pertinent à faire)

                Réponds uniquement avec l'action choisie. Par exemple : "CHECK 192.168.1.50"
                """
            }
        ]
        
        for i, context in enumerate(test_contexts, 1):
            print(f"  [*] Test {i}: {context['name']}")
            try:
                decision = get_ai_analysis(context['prompt'], max_length=64)
                print(f"    [+] Décision IA : {decision}")
            except Exception as e:
                print(f"    [!] Erreur : {e}")
        
        return True
        
    except Exception as e:
        print(f"  [!] Erreur lors du test de la logique IA : {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🚀 Test du mode piloté par l'IA d'IoTBreaker")
    print("=" * 60)
    
    # Tests
    ai_mode_ok = test_ai_driven_mode()
    logic_ok = test_ai_decision_logic()
    
    # Résumé
    print("\n" + "=" * 60)
    print("📋 RÉSUMÉ DES TESTS MODE IA")
    print("=" * 60)
    print(f"  🧠 Mode piloté par l'IA : {'✅ OK' if ai_mode_ok else '❌ ÉCHEC'}")
    print(f"  🤖 Logique de décision IA : {'✅ OK' if logic_ok else '❌ ÉCHEC'}")
    
    if ai_mode_ok and logic_ok:
        print("\n🎉 Tous les tests du mode IA sont passés !")
        print("   IoTBreaker peut maintenant fonctionner en mode piloté par l'IA :")
        print("   • python iotbreaker.py scripts/audit_ai_driven.yaml --ai-driven")
        print("   • L'IA décide automatiquement des prochaines actions")
        print("   • Chaque audit est unique et adaptatif")
    else:
        print("\n⚠️  Certains tests du mode IA ont échoué.")
        print("   Vérifiez la configuration de l'IA et les dépendances.")

if __name__ == "__main__":
    main() 