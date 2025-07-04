#!/bin/bash

echo "🧠 Installation de l'IA pour IoTBreaker"
echo "======================================"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

echo "✅ Python 3 détecté"

# Vérifier pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

echo "✅ pip3 détecté"

# Installer les dépendances IA
echo "📦 Installation des dépendances IA..."
pip3 install torch transformers

if [ $? -eq 0 ]; then
    echo "✅ Dépendances IA installées avec succès"
else
    echo "❌ Erreur lors de l'installation des dépendances IA"
    exit 1
fi

# Tester l'installation
echo "🧪 Test de l'installation IA..."
python3 test_ai_integration.py

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Installation IA terminée avec succès !"
    echo ""
    echo "📋 Prochaines étapes :"
    echo "   1. Lancez IoTBreaker normalement"
    echo "   2. L'IA sera automatiquement activée"
    echo "   3. Le modèle Phi-3 sera téléchargé au premier lancement"
    echo ""
    echo "⚠️  Note : Le téléchargement du modèle peut prendre plusieurs minutes"
    echo "   et nécessite environ 2GB d'espace disque."
else
    echo "❌ Erreur lors du test de l'installation"
    exit 1
fi 