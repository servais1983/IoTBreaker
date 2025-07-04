# Script PowerShell pour installer l'IA sur IoTBreaker

Write-Host "🧠 Installation de l'IA pour IoTBreaker" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Vérifier Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python détecté: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python n'est pas installé. Veuillez l'installer d'abord." -ForegroundColor Red
    exit 1
}

# Vérifier pip
try {
    $pipVersion = pip --version 2>&1
    Write-Host "✅ pip détecté: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ pip n'est pas installé. Veuillez l'installer d'abord." -ForegroundColor Red
    exit 1
}

# Installer les dépendances IA
Write-Host "📦 Installation des dépendances IA..." -ForegroundColor Yellow
try {
    pip install torch transformers
    Write-Host "✅ Dépendances IA installées avec succès" -ForegroundColor Green
} catch {
    Write-Host "❌ Erreur lors de l'installation des dépendances IA" -ForegroundColor Red
    exit 1
}

# Tester l'installation
Write-Host "🧪 Test de l'installation IA..." -ForegroundColor Yellow
try {
    python test_ai_integration.py
    Write-Host ""
    Write-Host "🎉 Installation IA terminée avec succès !" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Prochaines étapes :" -ForegroundColor Cyan
    Write-Host "   1. Lancez IoTBreaker normalement" -ForegroundColor White
    Write-Host "   2. L'IA sera automatiquement activée" -ForegroundColor White
    Write-Host "   3. Le modèle Phi-3 sera téléchargé au premier lancement" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  Note : Le téléchargement du modèle peut prendre plusieurs minutes" -ForegroundColor Yellow
    Write-Host "   et nécessite environ 2GB d'espace disque." -ForegroundColor Yellow
} catch {
    Write-Host "❌ Erreur lors du test de l'installation" -ForegroundColor Red
    exit 1
} 