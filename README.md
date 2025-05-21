# IoTBreaker CLI

Outil de pentest IoT automatisé pour Kali Linux.

## 📦 Installation

```bash
chmod +x install.sh
./install.sh
```

## 🛠️ Commandes

* `discover` : Recherche de dispositifs via SSDP/mDNS
* `analyze <ip>` : Scan de ports IoT classiques (MQTT, CoAP, Telnet)
* `check <ip>` : Tests de vulnérabilités courantes
* `run <yaml>` : Exécution de scénarios YAML automatisés

## 🚀 Exemple

```bash
python3 iotbreaker.py run scripts/default_passwords.yaml
```