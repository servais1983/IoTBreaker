# 🤖 IoTBreaker - Outil d'Audit de Sécurité IoT Conversationnel

> **Outil d'audit de sécurité conversationnel avec IA - Dialoguez avec votre partenaire d'audit intelligent qui apprend et s'améliore à chaque session !**

## 🌟 Nouvelles Fonctionnalités

### 🔄 **Mode Portable Universel**
- **Détection automatique** de n'importe quel réseau où vous vous connectez
- **Adaptation intelligente** à tous les environnements réseau
- **Scan automatique** de tous les appareils IoT intelligents
- **Fonctionne partout** : maison, bureau, hôtel, café, etc.

### 🤖 **Détection IoT Intelligente**
- **Google Nest/Chromecast** : Détection automatique via ports 8008/8009
- **Ampoules connectées** : Philips Hue, LIFX, etc.
- **Thermostats intelligents** : Nest, Ecobee, etc.
- **Caméras IP** : Hikvision, Dahua, Foscam, etc.
- **Appareils Bluetooth** : Détection des appareils à proximité
- **Réseaux WiFi** : Découverte des réseaux disponibles
- **Appareils Zigbee** : Détection via dongles USB

### 🌐 **Intégration Shodan Complète**
- **Analyse de votre IP publique** automatique
- **Recherche géolocalisée** d'appareils IoT similaires
- **Détection d'appareils vulnérables** dans votre région
- **Configuration sécurisée** via variables d'environnement

### 🧠 **Intelligence Artificielle Conversationnelle**
- **Modèle Phi-3 local** pour l'analyse intelligente
- **Mode conversationnel interactif** - Dialoguez en langage naturel
- **Apprentissage continu** - L'IA mémorise et s'améliore à chaque session
- **Base de connaissances persistante** - Stockage JSON des apprentissages
- **Interprétation intelligente** des commandes utilisateur
- **Identification avancée** des types d'appareils
- **Analyse des risques** automatique et contextuelle
- **Résumés exécutifs** générés par IA
- **Recommandations stratégiques** personnalisées
- **Tests de vulnérabilités dynamiques** suggérés par l'IA
- **Post-exploitation intelligente** avec commandes ciblées
- **Analyse de ports contextuelle** basée sur les bannières

## 🔍 Aperçu

**IoTBreaker** est un outil CLI révolutionnaire conçu pour :

* 🔍 **Scanner et identifier** tous les appareils IoT sur n'importe quel réseau
* 🤖 **Détecter intelligemment** les appareils IoT modernes (Google Nest, ampoules, etc.)
* 🌐 **Analyser les protocoles** (UPnP, MQTT, CoAP, Telnet, etc.)
* 🛡️ **Détecter les vulnérabilités** courantes et configurations faibles
* 🔄 **S'adapter automatiquement** à n'importe quel environnement réseau
* 📊 **Générer des rapports** détaillés en HTML et PDF
* 🌍 **Intégrer Shodan** pour l'analyse externe

## 📦 Installation

### 🐧 **Installation sur Kali Linux (Recommandé)**

```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Installation des dépendances système
sudo apt install python3 python3-pip nmap net-tools git -y

# Cloner le dépôt
git clone https://github.com/servais1983/IoTBreaker.git
cd IoTBreaker

# Installer les dépendances Python
pip3 install -r requirements.txt

# Test de l'installation
python3 iotbreaker.py

# Test de compatibilité Kali Linux (sans scan réseau)
python3 test_quick_kali.py

### 🖥️ **Installation sur autres systèmes**

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/IoTBreaker.git
cd IoTBreaker

# Créer et activer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
.\venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt

# Configuration de la clé API Shodan (optionnel)
# Copiez le fichier d'exemple et ajoutez votre clé API
cp env.example .env
# Éditez le fichier .env et ajoutez votre clé API Shodan

# Test de l'intégration IA (optionnel)
python test_ai_integration.py

# Test des fonctionnalités IA avancées (optionnel)
python test_ai_advanced.py

# Test du mode piloté par l'IA (optionnel)
python test_ai_driven_mode.py

# Test du mode conversationnel (optionnel)
python test_conversational_mode.py

# Test de compatibilité Kali Linux (sans scan réseau)
python test_quick_kali.py

## 🚀 Utilisation

### 💬 Mode Conversationnel (Recommandé - Nouveau !)

```bash
# Lancez le mode conversationnel interactif
python3 iotbreaker.py  # Sur Kali Linux
# ou
python iotbreaker.py   # Sur autres systèmes

# L'IA vous accueille et vous pouvez dialoguer en langage naturel :
# [Vous]> Lance un scan complet
# [Vous]> Cherche les vulnérabilités sur tous les appareils
# [Vous]> Analyse cette IP 192.168.1.1
# [Vous]> Génère un rapport
# [Vous]> status
# [Vous]> help
# [Vous]> exit
```

**Note importante :** IoTBreaker est conçu pour Kali Linux. Sur Windows, utilisez WSL ou une VM Kali pour une expérience optimale.

### 📜 Mode Script Classique (Rétro-compatibilité)

```bash
# Audit complet qui fonctionne partout
python3 iotbreaker.py scripts/audit_iot_complet.yaml -v  # Sur Kali Linux
# ou
python iotbreaker.py scripts/audit_iot_complet.yaml -v   # Sur autres systèmes

# Audit rapide sans blocage
python3 iotbreaker.py scripts/audit_iot_rapide.yaml -v

# Audit portable universel
python3 iotbreaker.py scripts/audit_portable_universel.yaml -v

# Mode piloté par l'IA
python3 iotbreaker.py scripts/audit_ai_driven.yaml --ai-driven -v
```

### Options disponibles

```bash
python iotbreaker.py -h
```

* `scenario` : Chemin vers le fichier de scénario YAML à exécuter
* `-v, --verbose` : Afficher plus de détails pendant l'exécution

## 📋 Scénarios Disponibles

### 🎯 **Scénarios Principaux**
* `audit_iot_complet.yaml` : **Audit complet portable** avec Shodan intégré
* `audit_iot_rapide.yaml` : **Audit rapide** sans blocage
* `audit_portable_universel.yaml` : **Audit portable universel**
* `audit_ai_driven.yaml` : **Audit piloté par l'IA** - L'IA décide des actions

### 🔧 **Scénarios Spécialisés**
* `audit_avec_shodan.yaml` : Audit avec reconnaissance externe Shodan
* `audit_reseau_reel.yaml` : Audit du réseau local réel
* `test_shodan.yaml` : Test des fonctionnalités Shodan
* `test_exploit.yaml` : Tests d'exploitation (mode avancé)

## 🌟 Fonctionnalités Avancées

### 🔍 **Découverte Intelligente**
- **Scan parallèle** optimisé pour la rapidité
- **Détection multi-protocoles** (IP, WiFi, Bluetooth, Zigbee)
- **Fingerprinting intelligent** des appareils
- **Identification automatique** des types d'appareils

### 🛡️ **Sécurité Avancée**
- **Mode sécurisé** par défaut (pas de tests intrusifs)
- **Validation des entrées** utilisateur
- **Protection contre les attaques** par injection
- **Gestion sécurisée** des connexions réseau

### 🧠 **Fonctionnalités IA Conversationnelles**
- **Mode conversationnel interactif** : Dialoguez avec l'IA en langage naturel
- **Apprentissage continu** : L'IA mémorise et s'améliore à chaque session d'audit
- **Base de connaissances persistante** : Stockage JSON des apprentissages entre les sessions
- **Interprétation intelligente** : L'IA traduit vos commandes en actions techniques
- **Synthèse automatique** : À la fin de chaque session, l'IA extrait des règles générales
- **Tests de vulnérabilités dynamiques** : L'IA suggère des chemins d'administration spécifiques basés sur la bannière du serveur
- **Post-exploitation intelligente** : Une fois l'accès obtenu, l'IA guide avec des commandes pertinentes pour identifier le système et rechercher des secrets
- **Analyse contextuelle** : L'IA analyse les ports ouverts et les bannières pour identifier le type d'appareil et les risques associés
- **Stratégies d'attaque adaptatives** : L'IA adapte les tests en fonction des services détectés
- **Mode piloté par l'IA** : L'IA décide automatiquement des prochaines actions d'audit en fonction des résultats obtenus

### 📊 **Reporting Complet**
- **Rapports HTML** interactifs
- **Rapports PDF** détaillés
- **Rapports texte** pour analyse
- **Génération automatique** avec horodatage

## 📝 Créer un Scénario Personnalisé

Exemple de scénario YAML :

```yaml
name: "Mon scénario personnalisé"
description: "Audit personnalisé de mon réseau IoT"

steps:
  # Découverte automatique
  - type: discover
    description: "Découverte de tous les appareils IoT"
  
  # Analyse automatique
  - type: analyze
    target: auto_discovered
    description: "Analyse de tous les appareils découverts"
  
  # Vérification des vulnérabilités
  - type: check
    target: auto_discovered
    description: "Test de vulnérabilités"
  
  # Recherche Shodan
  - type: shodan_lookup
    target: "auto_public_ip"
    description: "Analyse de mon IP publique"

config:
  timeout: 5
  verbose: true
  safe_mode: true
  portable_mode: true
  shodan_enabled: true
```

## 🧪 Tests et Validation

### Tests de Compatibilité
```bash
# Test rapide de compatibilité Kali Linux (sans scan réseau)
python3 test_quick_kali.py

# Test de l'intégration IA
python3 test_ai_integration.py

# Test du mode conversationnel
python3 test_conversational_mode.py

# Test des fonctionnalités avancées
python3 test_ai_advanced.py
```

### Validation des Modules
- ✅ **Module discover** : Découverte d'appareils
- ✅ **Module analyze** : Analyse des vulnérabilités  
- ✅ **Module check** : Vérifications de sécurité
- ✅ **Module exploit** : Tests d'exploitation
- ✅ **Module reporting** : Génération de rapports
- ✅ **Module IA** : Intelligence artificielle conversationnelle

## 🔧 Configuration Avancée

### Options de Configuration

```yaml
config:
  timeout: 5                    # Timeout des connexions
  verbose: true                 # Mode verbeux
  safe_mode: true              # Mode sécurisé
  network_scan: true           # Scan réseau
  auto_discovery: true         # Découverte automatique
  parallel_scan: true          # Scan parallèle
  bluetooth_scan: true         # Découverte Bluetooth
  wifi_scan: true              # Découverte WiFi
  smart_device_scan: true      # Découverte appareils intelligents
  zigbee_scan: true            # Découverte Zigbee
  shodan_enabled: true         # Intégration Shodan
  portable_mode: true          # Mode portable
  auto_adapt: true             # Adaptation automatique
```

## 🌍 Compatibilité

### ✅ **Systèmes Supportés**
- **Kali Linux** (Recommandé - Distribution de sécurité)
- **Linux** (Ubuntu, Debian, autres distributions)
- **macOS** 10.15+ (avec limitations)
- **Raspberry Pi** (ARM)
- **Windows** (via WSL ou VM Kali)

### 🧠 **Exigences pour l'IA**
- **RAM** : 4GB minimum (8GB recommandé)
- **Espace disque** : 2GB pour le modèle Phi-3
- **GPU** : Optionnel mais recommandé pour les performances
- **Connexion internet** : Requise pour le téléchargement initial du modèle

### 📱 **Réseaux Supportés**
- **WiFi** (2.4GHz et 5GHz)
- **Ethernet** (câblé)
- **Réseaux d'entreprise**
- **Réseaux publics**
- **Réseaux domestiques**

## 🔒 Sécurité et Éthique

### 🛡️ **Mesures de Sécurité**
- Validation des entrées utilisateur
- Protection contre les attaques par injection
- Vérification des chemins de fichiers
- Gestion sécurisée des connexions réseau
- Mode sécurisé par défaut

### ⚖️ **Usage Éthique**
Cet outil est destiné à être utilisé uniquement à des fins de test et d'audit de sécurité légitimes. L'utiliser sur des systèmes sans autorisation explicite est illégal et non éthique.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :

1. 🍴 Fork le projet
2. 🌿 Créer une branche pour votre fonctionnalité
3. 💾 Commiter vos changements
4. 📤 Pousser vers la branche
5. 🔄 Ouvrir une Pull Request

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🆕 Historique des Versions

### v3.0.0 - Version Conversationnelle (Actuelle)
- 💬 **Mode conversationnel interactif** - Dialoguez avec l'IA en langage naturel
- 🧠 **Apprentissage continu** - L'IA mémorise et s'améliore à chaque session
- 📚 **Base de connaissances persistante** - Stockage JSON des apprentissages
- 🤖 **Interprétation intelligente** - L'IA traduit vos commandes en actions
- 🔄 **Synthèse automatique** - Extraction de règles générales à la fin de chaque session
- 📜 **Rétro-compatibilité** - Mode script classique toujours disponible

### v2.0.0 - Version Portable et Intelligente
- ✨ **Mode portable universel** - Fonctionne partout
- 🤖 **Détection IoT intelligente** - Google Nest, ampoules, etc.
- 🌐 **Intégration Shodan complète** - Analyse externe
- 🔄 **Adaptation automatique** aux réseaux
- 📊 **Reporting amélioré** - HTML, PDF, texte

### v1.0.0 - Version Initiale
- 🔍 Découverte basique des appareils IoT
- 🛡️ Tests de vulnérabilités
- 📋 Scénarios YAML
- 📊 Rapports de base

## 📞 Support

Pour toute question ou problème :
- 📧 Ouvrir une issue sur GitHub
- 📖 Consulter la documentation
- 🤝 Contribuer au projet

---

**IoTBreaker** - Votre compagnon de sécurité IoT intelligent et portable ! 🌟
