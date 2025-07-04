#!/usr/bin/env python3
"""
Test de validation du logo IoTBreaker et des fonctionnalités de base
"""

import os
import sys

def test_logo_display():
    """Teste l'affichage du magnifique logo IoTBreaker"""
    print("=" * 80)
    print("🎨 TEST DU LOGO IOTBREAKER")
    print("=" * 80)
    
    try:
        # Import des modules principaux
        from core.utils import print_banner, get_version
        from core.ai_analyzer_simple import get_ai_analysis
        
        print("✅ Imports de base : OK")
        
        # Test de l'affichage du logo
        print("\n🎨 Affichage du logo principal :")
        print_banner()
        
        # Test de la version
        version = get_version()
        print(f"✅ Version détectée : {version}")
        
        # Test de l'IA simple
        test_response = get_ai_analysis("test")
        print(f"✅ IA simple fonctionne : {test_response}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors du test du logo : {e}")
        return False

def test_conversational_interface():
    """Teste l'interface conversationnelle sans entrée utilisateur"""
    print("\n=" * 80)
    print("🤖 TEST DE L'INTERFACE CONVERSATIONNELLE")
    print("=" * 80)
    
    try:
        from core.utils import initialize_audit, run_step
        from core.knowledge_base import load_knowledge
        
        # Initialisation du contexte d'audit
        audit_context = initialize_audit()
        knowledge_base = load_knowledge()
        
        print("✅ Contexte d'audit initialisé")
        print(f"✅ Base de connaissances chargée : {len(knowledge_base.get('learnings', []))} règles")
        
        # Test d'une commande simple
        print("\n🧪 Test d'une commande simulée...")
        run_step("DISCOVER", audit_context)
        
        print("✅ Commande exécutée avec succès")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors du test conversationnel : {e}")
        return False

def test_banner_in_main():
    """Teste que le logo s'affiche dans le fichier principal"""
    print("\n=" * 80)
    print("🚀 TEST DU LOGO DANS L'APPLICATION PRINCIPALE")
    print("=" * 80)
    
    try:
        # Import du module principal
        import iotbreaker
        
        print("✅ Module iotbreaker importé")
        
        # Test de la fonction print_banner du module principal
        print("\n🎨 Affichage du logo depuis iotbreaker.py :")
        iotbreaker.print_banner()
        
        print("✅ Logo affiché depuis le module principal")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors du test du module principal : {e}")
        return False

def test_application_startup():
    """Teste que l'application peut démarrer correctement"""
    print("\n=" * 80)
    print("📱 TEST DE DÉMARRAGE DE L'APPLICATION")
    print("=" * 80)
    
    try:
        # Test des fonctions principales
        from iotbreaker import main, interactive_mode, script_mode
        
        print("✅ Fonctions principales importées")
        print("✅ L'application est prête à démarrer")
        
        # Note: On ne lance pas interactive_mode() car cela nécessiterait une entrée utilisateur
        print("📝 Note: Le mode interactif nécessite une entrée utilisateur et n'est pas testé ici")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors du test de démarrage : {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🎨 VALIDATION DU NOUVEAU LOGO IOTBREAKER")
    print("🔍 Test de toutes les fonctionnalités avec le nouveau design")
    print("=" * 80)
    
    tests = [
        ("Logo et fonctions de base", test_logo_display),
        ("Interface conversationnelle", test_conversational_interface),
        ("Logo dans l'application principale", test_banner_in_main),
        ("Démarrage de l'application", test_application_startup)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🧪 Exécution du test : {test_name}")
        try:
            result = test_func()
            results.append(result)
            status = "✅ RÉUSSI" if result else "❌ ÉCHEC"
            print(f"📊 Résultat : {status}")
        except Exception as e:
            print(f"❌ ERREUR CRITIQUE : {e}")
            results.append(False)
    
    # Résumé final
    print("\n" + "=" * 80)
    print("📊 RÉSUMÉ FINAL DES TESTS")
    print("=" * 80)
    
    passed = sum(results)
    total = len(results)
    
    for i, (test_name, _) in enumerate(tests):
        status = "✅ RÉUSSI" if results[i] else "❌ ÉCHEC"
        print(f"  {status} - {test_name}")
    
    print(f"\n📊 Résultat global : {passed}/{total} tests réussis")
    
    if passed == total:
        print("🎉 TOUS LES TESTS SONT RÉUSSIS !")
        print("🚀 IoTBreaker est prêt avec son nouveau logo magnifique !")
        print("💡 Lancez 'python iotbreaker.py' pour voir le logo en action")
    else:
        print("⚠️  Certains tests ont échoué. Vérifiez les erreurs ci-dessus.")
    
    print("\n🔗 Repository : https://github.com/servais1983/IoTBreaker")
    print("👨‍💻 Développé par : CyberS")

if __name__ == "__main__":
    main()
