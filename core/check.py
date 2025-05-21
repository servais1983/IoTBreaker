import socket
import telnetlib
import paho.mqtt.client as mqtt
import requests
import time

def run(ip):
    """
    Module de vérification des vulnérabilités IoT courantes.
    
    Ce module teste les vulnérabilités suivantes :
    1. Connexion Telnet avec mots de passe par défaut
    2. Authentification MQTT faible ou inexistante
    3. Ports HTTP ouverts avec interfaces d'administration exposées
    4. UPnP mal configuré
    """
    print(f"[*] Vérification de vulnérabilités connues sur {ip}...")
    
    # Liste des vulnérabilités trouvées
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
    
    # Résumé des résultats
    if vulns_found:
        print("\n[!] Résumé des vulnérabilités trouvées :")
        for i, vuln in enumerate(vulns_found, 1):
            print(f"  {i}. {vuln}")
    else:
        print("[+] Aucune vulnérabilité commune n'a été détectée.")

def check_telnet_default_credentials(ip):
    """Teste la connexion Telnet avec des mots de passe par défaut"""
    print("[+] Test de connexion Telnet sans mot de passe ou avec mots de passe par défaut...")
    
    # Liste des combinaisons utilisateur/mot de passe par défaut courantes
    default_credentials = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', ''),
        ('root', 'root'),
        ('root', ''),
        ('user', 'user'),
    ]
    
    try:
        # Vérification que le port Telnet est ouvert
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, 23))
        sock.close()
        
        if result != 0:
            return None
        
        # Test des identifiants par défaut
        for username, password in default_credentials:
            try:
                tn = telnetlib.Telnet(ip, timeout=3)
                tn.read_until(b"login: ", timeout=2)
                tn.write(username.encode('ascii') + b"\n")
                tn.read_until(b"Password: ", timeout=2)
                tn.write(password.encode('ascii') + b"\n")
                
                # Vérification de l'accès
                response = tn.read_until(b"$", timeout=2)
                if b"$" in response or b"#" in response or b">" in response:
                    print(f"[!] VULNÉRABILITÉ TROUVÉE: Connexion Telnet réussie avec {username}:{password}")
                    return f"Connexion Telnet acceptée avec identifiants par défaut ({username}:{password})"
                tn.close()
            except:
                pass
                
        return None
    except:
        return None

def check_mqtt_weak_auth(ip):
    """Teste l'authentification MQTT faible ou inexistante"""
    print("[+] Test de MQTT sans authentification...")
    
    try:
        # Vérification que le port MQTT est ouvert
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, 1883))
        sock.close()
        
        if result != 0:
            return None
        
        # Essai de connexion MQTT sans authentification
        client = mqtt.Client("iotbreaker_test")
        client.connect(ip, 1883, 5)
        client.loop_start()
        time.sleep(1)
        client.loop_stop()
        
        print(f"[!] VULNÉRABILITÉ TROUVÉE: Connexion MQTT sans authentification")
        return "MQTT accepte des connexions sans authentification"
    except:
        return None

def check_http_exposed_interfaces(ip):
    """Teste les interfaces web exposées"""
    print("[+] Test des interfaces Web exposées...")
    
    # Chemins d'administration courants
    admin_paths = [
        '/admin', 
        '/admin.php',
        '/login.php',
        '/management',
        '/manager/html',
        '/console',
        '/dashboard',
        '/device'
    ]
    
    try:
        for path in admin_paths:
            try:
                response = requests.get(f"http://{ip}{path}", timeout=2)
                if response.status_code == 200:
                    if 'login' in response.text.lower() or 'admin' in response.text.lower() or 'password' in response.text.lower():
                        print(f"[!] VULNÉRABILITÉ TROUVÉE: Interface d'administration exposée à http://{ip}{path}")
                        return f"Interface d'administration exposée à http://{ip}{path}"
            except:
                pass
        
        return None
    except:
        return None

def check_upnp_misconfiguration(ip):
    """Teste les mauvaises configurations UPnP"""
    print("[+] Test de configurations UPnP incorrectes...")
    
    try:
        # Vérification que le port UPnP est ouvert
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, 1900))
        sock.close()
        
        if result != 0:
            return None
        
        # Simulation simplifiée du test (démo)
        print("[!] VULNÉRABILITÉ POTENTIELLE: Port UPnP 1900 ouvert, possible exposition aux attaques.")
        return "Port UPnP exposé (1900) - Susceptible aux attaques de redirection de port"
    except:
        return None