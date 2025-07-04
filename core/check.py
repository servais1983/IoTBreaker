import socket
import paho.mqtt.client as mqtt
import requests
import time
import os

# Remplacement de telnetlib pour Python 3.13+
class TelnetClient:
    """Classe simple pour remplacer telnetlib"""
    def __init__(self, host, port, timeout=3):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
    
    def read_until(self, expected, timeout=2):
        """Lit jusqu'à ce qu'on trouve le texte attendu"""
        data = b""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                chunk = self.sock.recv(1024)
                if not chunk:
                    break
                data += chunk
                if expected in data:
                    return data
            except socket.timeout:
                break
        return data
    
    def write(self, data):
        """Écrit des données"""
        if isinstance(data, str):
            data = data.encode('ascii')
        self.sock.send(data)
    
    def close(self):
        """Ferme la connexion"""
        self.sock.close()

def load_credentials(file_path):
    """Charge une liste d'identifiants ou de mots de passe depuis un fichier."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # On retire les lignes vides et les espaces superflus
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] ERREUR: Le fichier {file_path} est introuvable.")
        return []
    except Exception as e:
        print(f"[!] ERREUR lors du chargement de {file_path}: {e}")
        return []

def run(ip):
    """
    Module de vérification des vulnérabilités IoT courantes.
    Retourne une liste des vulnérabilités trouvées.
    
    Ce module teste les vulnérabilités suivantes :
    1. Connexion Telnet avec mots de passe par défaut
    2. Authentification MQTT faible ou inexistante
    3. Ports HTTP ouverts avec interfaces d'administration exposées
    4. UPnP mal configuré
    """
    print(f"[*] Vérification de vulnérabilités connues sur {ip}...")
    
    # Liste des vulnérabilités trouvées pour cette IP
    vulns_found = []
    
    # Test 1: Connexion Telnet avec mots de passe par défaut
    telnet_result = check_telnet_default_credentials(ip)
    if telnet_result:
        vulns_found.append(telnet_result)
    
    # Test 2: Authentification MQTT faible
    mqtt_result = check_mqtt_weak_auth(ip)
    if mqtt_result:
        vulns_found.append(mqtt_result)
    
    # Test 3: Interfaces Web exposées
    http_result = check_http_exposed_interfaces(ip)
    if http_result:
        vulns_found.append(http_result)
    
    # Test 4: UPnP mal configuré
    upnp_result = check_upnp_misconfiguration(ip)
    if upnp_result:
        vulns_found.append(upnp_result)
    
    # Enregistrer les détails pour le reporting
    try:
        from .reporting import add_scan_detail
        test_info = {
            'target': ip,
            'module': 'Vulnerability Check',
            'test_type': 'Complete vulnerability assessment',
            'result': f"{len(vulns_found)} vulnerability(ies) found",
            'details': {
                'telnet_tested': True,
                'mqtt_tested': True,
                'http_tested': True,
                'upnp_tested': True,
                'vulnerabilities_found': len(vulns_found)
            }
        }
        add_scan_detail('vulnerability_tests', test_info)
    except ImportError:
        pass
    
    # La fonction run retourne la liste complète
    return vulns_found

def check_telnet_default_credentials(ip, user_file='wordlists/users.txt', pass_file='wordlists/passwords.txt'):
    """Teste la connexion Telnet avec des listes de mots de passe externes."""
    print("[+] Test de connexion Telnet avec des listes de mots de passe...")

    # Chargement des listes
    usernames = load_credentials(user_file)
    passwords = load_credentials(pass_file)

    if not usernames or not passwords:
        print("[!] AVERTISSEMENT: Listes d'identifiants ou de mots de passe vides ou non trouvées. Test annulé.")
        return None

    try:
        # On vérifie d'abord si le port 23 est bien ouvert
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout réduit à 1 seconde
        if sock.connect_ex((ip, 23)) != 0:
            # print("[-] Port Telnet 23 fermé.") # On peut décommenter pour le mode verbeux
            sock.close()
            return None
        sock.close()

        print(f"[*] Test de {len(usernames)} utilisateurs × {len(passwords)} mots de passe = {len(usernames) * len(passwords)} combinaisons...")

        # Test de toutes les combinaisons
        for user in usernames:
            for password in passwords:
                try:
                    tn = TelnetClient(ip, 23, timeout=3)
                    tn.read_until(b"login: ", timeout=2)
                    tn.write(user + "\n")
                    # Certains services demandent le mot de passe, d'autres non
                    if password:
                        tn.read_until(b"Password: ", timeout=2)
                        tn.write(password + "\n")

                    # On attend un prompt qui indique une connexion réussie
                    response = tn.read_until(b"$", timeout=2)
                    if b"$" in response or b"#" in response or b">" in response:
                        desc = f"Connexion Telnet acceptée avec les identifiants : {user}:{password}"
                        print(f"[!] VULNÉRABILITÉ TROUVÉE: {desc}")
                        tn.close()
                        # On retourne le dictionnaire standardisé
                        return {
                            'ip': ip,
                            'module': 'Telnet',
                            'severity': 'CRITICAL',
                            'description': desc
                        }
                    tn.close()
                except Exception:
                    # On ignore les erreurs de connexion pour passer à la suite
                    pass
        print("[-] Aucun identifiant par défaut n'a fonctionné pour Telnet.")
        return None
    except Exception:
        return None

def check_mqtt_weak_auth(ip):
    """Teste l'authentification MQTT faible et les abonnements non restreints."""
    print("[+] Test de MQTT sans authentification et avec des topics 'wildcard'...")

    # Variable globale pour suivre le succès de l'abonnement
    global subscription_successful
    subscription_successful = False

    def on_connect(client, userdata, flags, rc):
        """Callback pour la connexion."""
        if rc == 0:
            # Une fois connecté, on tente de s'abonner au topic wildcard '#'
            client.subscribe("#")
        else:
            # La connexion a échoué, inutile d'aller plus loin
            client.disconnect()

    def on_subscribe(client, userdata, mid, granted_qos):
        """Callback pour l'abonnement."""
        # Si granted_qos n'est pas un code d'erreur, l'abonnement a réussi
        if granted_qos and granted_qos[0] < 128:
            global subscription_successful
            subscription_successful = True
        client.disconnect()

    try:
        # Vérification que le port MQTT est ouvert
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 1883))
        sock.close()
        
        if result != 0:
            return None

        client = mqtt.Client("iotbreaker_test")
        client.on_connect = on_connect
        client.on_subscribe = on_subscribe

        # On tente de se connecter au port 1883 avec un timeout court
        client.connect(ip, 1883, 3)  # Timeout de connexion réduit à 3 secondes
        # loop_start() lance un thread pour gérer les callbacks
        client.loop_start()
        # On attend 1.5 secondes pour laisser le temps aux callbacks de s'exécuter
        time.sleep(1.5)
        client.loop_stop()

        if subscription_successful:
            desc = "Le serveur MQTT autorise les connexions anonymes ET l'abonnement à tous les topics ('#')."
            print(f"[!] VULNÉRABILITÉ CRITIQUE TROUVÉE: {desc}")
            return {
                'ip': ip,
                'module': 'MQTT',
                'severity': 'CRITICAL',
                'description': desc
            }
        elif client.is_connected():
            desc = "Le serveur MQTT autorise les connexions anonymes, mais l'abonnement à '#' a peut-être échoué."
            print(f"[!] VULNÉRABILITÉ TROUVÉE: {desc}")
            return {
                'ip': ip,
                'module': 'MQTT',
                'severity': 'HIGH',
                'description': desc
            }
        else:
            # Si on n'est même pas connecté, il n'y a pas de vulnérabilité
            return None

    except Exception as e:
        # print(f"[-] Erreur lors du test MQTT: {e}") # Pour le debug
        return None

def check_http_exposed_interfaces(ip, path_file='wordlists/web_paths.txt'):
    """Teste les interfaces web exposées en utilisant une liste de chemins."""
    print("[+] Test des interfaces Web exposées...")

    # Chargement de la liste des chemins
    paths = load_credentials(path_file) # On peut réutiliser notre fonction `load_credentials`

    if not paths:
        print("[!] AVERTISSEMENT: La liste de chemins web est vide ou non trouvée. Test annulé.")
        return None

    # Limitation du nombre de chemins à tester pour éviter les blocages
    max_paths = 20  # On limite à 20 chemins au lieu de tous les 73
    if len(paths) > max_paths:
        print(f"[*] Limitation à {max_paths} chemins web sur {len(paths)} disponibles pour éviter les blocages...")
        paths = paths[:max_paths]

    print(f"[*] Test de {len(paths)} chemins web sur HTTP et HTTPS...")

    # On teste d'abord HTTP, puis HTTPS si nécessaire
    for protocol in ['http', 'https']:
        print(f"[*] Test sur {protocol.upper()}...")
        
        for i, path in enumerate(paths, 1):
            # Affichage du progrès
            if i % 5 == 0:
                print(f"[*] Progrès: {i}/{len(paths)} chemins testés...")
            
            # On s'assure que le chemin commence bien par un /
            if not path.startswith('/'):
                path = '/' + path
            
            url = f"{protocol}://{ip}{path}"
            try:
                # Timeout très court pour éviter les blocages
                response = requests.get(url, timeout=2, verify=False, allow_redirects=False)

                # On vérifie si la page contient un formulaire de connexion
                has_form = '<form' in response.text.lower()
                has_password_field = 'type="password"' in response.text.lower()

                if response.status_code == 200 and has_form and has_password_field:
                    server_header = response.headers.get('Server', 'N/A')
                    desc = f"Interface d'administration potentielle trouvée à {url} (Serveur: {server_header})"
                    print(f"[!] VULNÉRABILITÉ TROUVÉE: {desc}")
                    return {
                        'ip': ip,
                        'module': 'HTTP',
                        'severity': 'HIGH',
                        'description': desc
                    }

            except requests.exceptions.Timeout:
                # Timeout spécifique - on continue
                continue
            except requests.exceptions.RequestException:
                # On ignore les autres erreurs de connexion
                continue
    
    print("[-] Aucune interface d'administration web évidente n'a été trouvée.")
    return None

def check_upnp_misconfiguration(ip):
    """Teste les mauvaises configurations UPnP en envoyant une vraie requête de découverte."""
    print("[+] Test de configurations UPnP incorrectes (recherche de passerelles exposées)...")
    
    # Message de découverte M-SEARCH pour les passerelles Internet (le service le plus critique)
    msearch_query = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n'
        'MX: 1\r\n'
        '\r\n'
    ).encode('utf-8')

    try:
        # Création d'un socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(2)
        
        # Envoi de la requête à l'adresse IP spécifique de la cible sur le port 1900
        sock.sendto(msearch_query, (ip, 1900))
        
        # Attente d'une réponse
        data, addr = sock.recvfrom(1024)
        sock.close()

        # Si on reçoit une réponse de la bonne IP, c'est que le service est actif
        if data and addr[0] == ip:
            desc = f"Le service UPnP (InternetGatewayDevice) est actif et répond aux requêtes sur {ip}. Il pourrait être exploitable."
            print(f"[!] VULNÉRABILITÉ POTENTIELLE TROUVÉE: {desc}")
            return {
                'ip': ip,
                'module': 'UPnP',
                'severity': 'MEDIUM',
                'description': desc
            }
            
        return None

    except socket.timeout:
        # Pas de réponse, le service n'est probablement pas actif ou ne répond pas à cette requête
        print("[-] Aucune réponse UPnP reçue.")
        return None
    except Exception as e:
        # print(f"[-] Erreur lors du test UPnP: {e}") # Pour le debug
        return None