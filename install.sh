#!/bin/bash
echo "[*] Installation de IoTBreaker sur Kali..."

sudo apt update
sudo apt install -y python3 python3-pip gssdp-tools
python3 -m pip install -e ".[dev]"

echo "[+] Installation terminée. Utilisez : python3 iotbreaker.py [commande]"