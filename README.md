# 📡 IoTBreaker CLI - Version Portable et Intelligente

> **Outil d'audit de sécurité automatisé pour les dispositifs IoT - Scannez, analysez et testez la sécurité de votre réseau IoT partout où vous allez !**

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
- **Intelligence artificielle** pour identifier les menaces
- **Configuration sécurisée** via variables d'environnement

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
```

## 🚀 Utilisation

### Audit Complet Portable (Recommandé)

```bash
# Audit complet qui fonctionne partout
python iotbreaker.py scripts/audit_iot_complet.yaml -v
```

### Audit Rapide

```bash
# Audit rapide sans blocage
python iotbreaker.py scripts/audit_iot_rapide.yaml -v
```

### Audit Portable Universel

```bash
# Audit portable universel
python iotbreaker.py scripts/audit_portable_universel.yaml -v
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
- **Windows** 10/11
- **Linux** (Ubuntu, Debian, Kali)
- **macOS** 10.15+
- **Raspberry Pi** (ARM)

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
