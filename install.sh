#!/bin/bash
echo "[*] Installation de IoTBreaker sur Kali..."

sudo apt update
sudo apt install -y python3 python3-pip gssdp-tools
pip3 install -r requirements.txt

echo "[+] Installation terminée. Utilisez : python3 iotbreaker.py [commande]"