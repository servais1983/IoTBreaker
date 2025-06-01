![image](iot.png)


# 📡 IoTBreaker CLI

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2023.1-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

> **Outil d'audit de sécurité automatisé pour les dispositifs IoT - Scannez, analysez et testez la sécurité de votre réseau IoT**

<p align="center">
  <img src="https://raw.githubusercontent.com/servais1983/IoTBreaker/main/docs/logo.png" alt="IoTBreaker Logo" width="300" />
</p>

## 🔍 Aperçu

**IoTBreaker** est un outil CLI conçu pour :

* Scanner et identifier les **appareils IoT sur un réseau local**
* Analyser les **protocoles et services** (UPnP, MQTT, CoAP, Telnet, etc.)
* Détecter les **vulnérabilités courantes** et configurations faibles
* Automatiser les tests via des **scénarios YAML**

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
```

## 🛠️ Utilisation

### Exécuter un scénario d'audit

```bash
python iotbreaker.py scenarios/scan_reseau.yaml
```

### Options disponibles

```bash
python iotbreaker.py -h
```

* `scenario` : Chemin vers le fichier de scénario YAML à exécuter
* `-v, --verbose` : Afficher plus de détails pendant l'exécution

## 📋 Scénarios disponibles

* `scan_reseau.yaml` : Découverte et analyse basique du réseau
* `audit_device.yaml` : Audit complet d'un appareil spécifique
* `check_vuln_web.yaml` : Vérification des vulnérabilités web
* `pentest_mqtt.yaml` : Test de sécurité MQTT
* `full_audit.yaml` : Audit complet multi-cibles

## 📝 Créer un scénario personnalisé

Exemple de scénario YAML :

```yaml
name: Mon scénario personnalisé
steps:
  - type: discover
  - type: analyze
    target: "ALL_DISCOVERED"
  - type: check
    target: "ALL_DISCOVERED"
```

## 🔒 Sécurité

* Validation des entrées utilisateur
* Protection contre les attaques par injection
* Vérification des chemins de fichiers
* Gestion sécurisée des connexions réseau

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## ⚠️ Usage éthique

Cet outil est destiné à être utilisé uniquement à des fins de test et d'audit de sécurité légitimes. L'utiliser sur des systèmes sans autorisation explicite est illégal et non éthique.
