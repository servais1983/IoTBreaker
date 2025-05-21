# 📡 IoTBreaker CLI

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2023.1-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

> **Outil de pentest IoT automatisé pour Kali Linux - Scannez, analysez et testez la sécurité des appareils IoT sur votre réseau**

<p align="center">
  <img src="https://raw.githubusercontent.com/servais1983/IoTBreaker/main/docs/logo.png" alt="IoTBreaker Logo" width="300" />
</p>

## 🔍 Aperçu

**IoTBreaker** est un outil CLI offensif conçu pour :

* Scanner, identifier et analyser les **appareils IoT sur un réseau local**
* Vérifier les **protocoles vulnérables** (UPnP, MQTT, CoAP, Telnet, etc.)
* Détecter les **firmwares faibles**, mots de passe par défaut, backdoors
* Automatiser les tests via des **scénarios YAML**

## 📦 Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/IoTBreaker.git
cd IoTBreaker

# Installer les dépendances
chmod +x install.sh
./install.sh
```

## 🛠️ Commandes disponibles

| Commande | Description |
| ----- | ----- |
| `discover` | Découverte des dispositifs IoT via UPnP, SSDP, mDNS |
| `analyze <IP>` | Scan et fingerprint des services courants (CoAP, MQTT, Telnet, HTTP) |
| `check <IP>` | Recherche de vulnérabilités connues / ports sensibles |
| `run <YAML>` | Exécution d'un scénario YAML automatisé |

## 🚀 Exemples d'utilisation

### Découvrir les appareils IoT sur le réseau

```bash
python3 iotbreaker.py discover
```

### Analyser un appareil spécifique

```bash
python3 iotbreaker.py analyze 192.168.1.50
```

### Vérifier les vulnérabilités d'un appareil

```bash
python3 iotbreaker.py check 192.168.1.50
```

### Exécuter un scénario d'audit complet

```bash
python3 iotbreaker.py run scripts/default_passwords.yaml
```

## 📋 Scénarios personnalisés

Vous pouvez créer des scénarios d'audit personnalisés en YAML :

```yaml
name: Mon scénario personnalisé
steps:
  - type: discover
  - type: analyze
    target: 192.168.1.100
  - type: check
    target: 192.168.1.100
```

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à soumettre des pull requests pour améliorer l'outil.

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier LICENSE pour plus de détails.

## ⚠️ Usage éthique

Cet outil est destiné à être utilisé uniquement à des fins de test et d'audit de sécurité légitimes. L'utiliser sur des systèmes sans autorisation explicite est illégal et non éthique.