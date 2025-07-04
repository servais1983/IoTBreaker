import os
import subprocess
import re

def analyze_firmware(firmware_path):
    """
    Orchestre l'analyse d'un fichier de firmware.
    1. Extrait le système de fichiers.
    2. Recherche des secrets dans les fichiers extraits.
    """
    if not os.path.exists(firmware_path):
        print(f"[!] ERREUR: Le fichier de firmware '{firmware_path}' est introuvable.")
        return

    print(f"[*] Démarrage de l'analyse du firmware : {firmware_path}")

    # 1. Extraction avec Binwalk
    output_dir = f"_{firmware_path}.extracted"
    print(f"[*] Tentative d'extraction du système de fichiers avec binwalk vers '{output_dir}'...")
    try:
        subprocess.run(
            ['binwalk', '-eM', '--run-as=root', firmware_path], 
            check=True, capture_output=True, text=True
        )
        print(f"[+] Extraction terminée avec succès.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] ERREUR: L'extraction avec binwalk a échoué. Assurez-vous que binwalk est installé et que vous avez les droits nécessaires.")
        print(f"   Erreur: {e}")
        return

    # 2. Recherche de secrets
    print("[*] Recherche de secrets potentiels dans les fichiers extraits...")
    secrets = find_secrets(output_dir)

    if secrets:
        print(f"[!] {len(secrets)} secret(s) potentiel(s) trouvé(s) dans le firmware :")
        for secret in secrets:
            print(f"  - Fichier: {secret['file']}")
            print(f"    Type   : {secret['type']}")
            print(f"    Secret : {secret['value']}")
    else:
        print("[+] Aucune information sensible évidente n'a été trouvée.")

def find_secrets(directory):
    """Recherche des secrets (mots de passe, clés privées) dans un répertoire."""
    secrets_found = []
    regexes = {
        "Clé privée RSA": r"-----BEGIN RSA PRIVATE KEY-----",
        "Mot de passe (potentiel)": r"(password|pass|pwd)\s*[:=]\s*['\"]?(\w+)['\"]?"
    }
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for name, regex in regexes.items():
                        for match in re.finditer(regex, content, re.IGNORECASE):
                            secrets_found.append({
                                'file': file_path,
                                'type': name,
                                'value': match.group(0)
                            })
            except OSError:
                continue
    return secrets_found 