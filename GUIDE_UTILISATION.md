# 🚀 Guide d'Utilisation IoTBreaker

## 📋 Vue d'ensemble

IoTBreaker est maintenant un **outil d'audit IoT conversationnel** avec intelligence artificielle intégrée. Il peut fonctionner en mode script classique ou en mode conversationnel interactif.

## 🎯 Modes d'utilisation

### 1. Mode Conversationnel (Recommandé)
```bash
python iotbreaker.py
```

**Fonctionnalités :**
- 🧠 **IA conversationnelle** : Parlez en langage naturel
- 📚 **Apprentissage continu** : L'IA mémorise vos préférences
- 🔄 **Commandes naturelles** : "Lance un scan", "Analyse tout", etc.
- 📊 **Rapports intelligents** : Insights et recommandations automatiques

**Exemples de commandes :**
```
> Lance un scan complet
> Trouve les caméras
> Cherche les vulnérabilités
> Génère un rapport
> Que penses-tu de ces résultats ?
> Quelles sont tes recommandations ?
> help
> status
> exit
```

### 2. Mode Script Classique
```bash
# Audit rapide
python iotbreaker.py scripts/audit_iot_rapide.yaml

# Audit complet
python iotbreaker.py scripts/audit_iot_complet.yaml

# Audit portable
python iotbreaker.py scripts/audit_portable_universel.yaml
```

## 🧠 Intelligence Artificielle

### IA Simple (Actuelle)
- ✅ **Fonctionne immédiatement** sans dépendances lourdes
- 🎯 **Interprétation de commandes** en langage naturel
- 📊 **Analyse contextuelle** des résultats
- 💡 **Recommandations automatiques**

### IA Complète (Optionnelle)
Pour activer le modèle Phi-3 complet :
```bash
pip install accelerate
```

## 🛠️ Installation et Configuration

### Dépendances de base
```bash
pip install -r requirements.txt
```

### Dépendances IA (optionnelles)
```bash
pip install accelerate
```

## 📊 Fonctionnalités Principales

### 🔍 Découverte d'appareils
- Scan réseau automatique
- Détection d'appareils IoT
- Identification des types d'appareils

### 🔬 Analyse de sécurité
- Test de ports ouverts
- Vérification de vulnérabilités
- Analyse de firmwares

### 📈 Rapports intelligents
- Génération automatique de rapports
- Insights IA sur les résultats
- Recommandations de sécurité

### 🧠 Apprentissage continu
- Mémorisation des préférences
- Amélioration des analyses
- Adaptation aux environnements

## 🎮 Commandes Conversationnelles

### Commandes de base
- `help` - Affiche l'aide
- `status` - État actuel de l'audit
- `clear` - Efface l'écran
- `exit` - Quitte le programme

### Commandes d'audit
- `Lance un scan complet` - Découverte d'appareils
- `Analyse tous les appareils` - Analyse de sécurité
- `Cherche les vulnérabilités` - Test de vulnérabilités
- `Génère un rapport` - Création de rapport

### Commandes d'analyse IA
- `Que penses-tu de ces résultats ?` - Insights IA
- `Quelles sont tes recommandations ?` - Recommandations
- `Analyse mon réseau` - Analyse complète

## 📁 Structure des fichiers

```
IoTBreaker/
├── iotbreaker.py              # Point d'entrée principal
├── core/
│   ├── ai_analyzer_simple.py  # IA conversationnelle
│   ├── knowledge_base.py      # Base de connaissances
│   ├── utils.py               # Utilitaires
│   ├── discover.py            # Découverte d'appareils
│   ├── analyze.py             # Analyse de sécurité
│   ├── check.py               # Vérification de vulnérabilités
│   └── reporting.py           # Génération de rapports
├── scripts/
│   ├── audit_iot_rapide.yaml  # Audit rapide
│   ├── audit_iot_complet.yaml # Audit complet
│   └── audit_ai_driven.yaml   # Audit piloté par IA
└── wordlists/                 # Dictionnaires d'attaque
```

## 🧪 Tests et Validation

### Test rapide
```bash
python test_iotbreaker_quick.py
```

### Démonstration conversationnelle
```bash
python test_conversational_demo.py
```

### Test interactif
```bash
python test_interactive.py
```

## 🚨 Sécurité et Éthique

### ⚠️ Avertissements
- Utilisez uniquement sur vos propres réseaux
- Respectez les lois locales sur la cybersécurité
- N'effectuez pas d'attaques non autorisées

### 🔒 Bonnes pratiques
- Testez en environnement contrôlé
- Documentez vos audits
- Suivez les recommandations de sécurité

## 🆘 Dépannage

### Problème : L'IA ne se charge pas
**Solution :** L'IA simple fonctionne toujours. Pour l'IA complète :
```bash
pip install accelerate
```

### Problème : Erreur de dépendances
**Solution :**
```bash
pip install -r requirements.txt
```

### Problème : Scan réseau bloqué
**Solution :** Utilisez le mode conversationnel avec des commandes spécifiques

## 📞 Support

### Logs et débogage
- Les erreurs sont affichées dans la console
- Vérifiez les permissions réseau
- Consultez les logs d'erreur

### Amélioration continue
- L'IA apprend de vos sessions
- Les connaissances sont sauvegardées automatiquement
- Les performances s'améliorent avec l'usage

---

**🎉 IoTBreaker est maintenant votre partenaire d'audit IoT intelligent !**

Commencez par : `python iotbreaker.py` 