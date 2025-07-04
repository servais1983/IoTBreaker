# 🤖 Mode Conversationnel IoTBreaker

## Vue d'ensemble

Le mode conversationnel d'IoTBreaker transforme l'outil d'audit en un véritable partenaire d'intelligence artificielle avec lequel vous pouvez dialoguer en langage naturel. L'IA comprend vos objectifs, exécute les actions appropriées et apprend de chaque session pour s'améliorer continuellement.

## 🚀 Lancement

```bash
# Lancez le mode conversationnel
python iotbreaker.py

# L'IA vous accueille et vous pouvez commencer à dialoguer
```

## 💬 Commandes Disponibles

### Commandes en Langage Naturel

Vous pouvez utiliser des expressions naturelles comme :

- **"Lance un scan complet"** → Découverte + analyse + vérification
- **"Cherche les vulnérabilités"** → Test de vulnérabilités sur les appareils trouvés
- **"Analyse cette IP 192.168.1.1"** → Analyse détaillée d'une IP spécifique
- **"Génère un rapport"** → Création d'un rapport d'audit
- **"Trouve les caméras"** → Recherche spécifique d'appareils de type caméra
- **"Vérifie les ports ouverts"** → Analyse des ports sur les appareils découverts

### Commandes Système

- **`help`** - Affiche l'aide et les commandes disponibles
- **`status`** - Affiche l'état actuel de l'audit
- **`exit`** - Quitte le mode conversationnel

## 🧠 Fonctionnalités IA

### Interprétation Intelligente

L'IA analyse votre commande et la traduit en action technique :

```
[Vous]> Lance un scan complet
[🧠] L'IA interprète votre commande...
  [+] Action déterminée par l'IA : DISCOVER
```

### Apprentissage Continu

À la fin de chaque session, l'IA extrait des règles générales :

```
[🧠] Synthèse des apprentissages de cette session...
  [+] Nouvel apprentissage : Les routeurs TP-Link sont souvent vulnérables aux attaques par défaut
  [+] Nouvel apprentissage : Les caméras IP ont souvent des ports 80 et 443 ouverts
```

### Base de Connaissances Persistante

Les apprentissages sont stockés dans `ai_knowledge_base.json` et réutilisés dans les sessions suivantes.

## 📊 Exemple de Session

```
🤖 IoTBreaker - Outil d'audit de sécurité conversationnel IoT
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║  ██╗ ██████╗ ████████╗██████╗ ██████╗ ██████╗ ███████╗  ║
║  ██║██╔═══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝  ║
║  ██║██║   ██║   ██║   ██████╔╝██████╔╝██████╔╝█████╗    ║
║  ██║██║   ██║   ██║   ██╔══██╗██╔══██╗██╔══██╗██╔══╝    ║
║  ██║╚██████╔╝   ██║   ██║  ██║██║  ██║██║  ██║███████╗  ║
║  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝  ║
║                                                          ║
║  Outil d'audit de sécurité conversationnel IoT           ║
║  Version 3.0.0 - IA Conversationnelle                    ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

[+] Bienvenue dans le shell interactif d'IoTBreaker.
    > L'IA est prête. Décrivez votre objectif (ex: 'Lance un scan complet', 'Cherche les caméras vulnérables').
    > Tapez 'exit' pour quitter.
    > Tapez 'help' pour voir les commandes disponibles.
    > Tapez 'status' pour voir l'état actuel de l'audit.

[Vous]> Lance un scan complet
[🧠] L'IA interprète votre commande...
  [+] Action déterminée par l'IA : DISCOVER

[*] Étape : Découverte des appareils...
[+] 3 appareils sont maintenant dans le contexte.

[Vous]> Cherche les vulnérabilités
[🧠] L'IA interprète votre commande...
  [+] Action déterminée par l'IA : CHECK all

[*] Étape : Vérification des vulnérabilités pour 'all'...
[+] 2 vulnérabilités trouvées

[Vous]> status
[📊] État de l'audit :
  • Appareils découverts : 3
  • Vulnérabilités trouvées : 2
  • Actions effectuées : 2
  • Connaissances IA : 5 règles apprises

[Vous]> Génère un rapport
[🧠] L'IA interprète votre commande...
  [+] Action déterminée par l'IA : REPORT

[*] Étape : Génération du rapport...
[+] Rapport généré avec succès

[Vous]> exit
[🧠] Synthèse des apprentissages de cette session...
  [+] Nouvel apprentissage : Les réseaux domestiques contiennent souvent 3-5 appareils IoT
  [+] Nouvel apprentissage : Les vulnérabilités Telnet sont fréquentes sur les routeurs
[+] Session terminée. Connaissances mises à jour.
```

## 🔧 Configuration

### Base de Connaissances

Le fichier `ai_knowledge_base.json` contient les apprentissages de l'IA :

```json
{
  "learnings": [
    "Les routeurs TP-Link sont souvent vulnérables aux attaques par défaut",
    "Les caméras IP ont souvent des ports 80 et 443 ouverts",
    "Les réseaux domestiques contiennent souvent 3-5 appareils IoT"
  ]
}
```

### Personnalisation

Vous pouvez modifier le comportement de l'IA en éditant les prompts dans `core/ai_analyzer.py`.

## 🧪 Tests

### Test Rapide

```bash
python test_conversational_quick.py
```

### Test Complet

```bash
python test_conversational_mode.py
```

### Démonstration

```bash
python demo_conversational_mode.py
```

## 🔄 Rétro-compatibilité

Le mode conversationnel est entièrement compatible avec le mode script classique :

```bash
# Mode conversationnel (nouveau)
python iotbreaker.py

# Mode script classique (toujours disponible)
python iotbreaker.py scripts/audit_iot_complet.yaml -v
```

## 🚨 Dépannage

### Erreur "EOF when reading a line"

Cette erreur apparaît quand on essaie d'alimenter le mode conversationnel avec `echo`. Le mode conversationnel nécessite une entrée interactive.

**Solution :** Utilisez directement `python iotbreaker.py` sans redirection.

### IA non disponible

Si l'IA n'est pas chargée, l'outil fonctionne en mode dégradé avec des actions par défaut.

**Solution :** Installez les dépendances IA :
```bash
pip install accelerate
```

### Base de connaissances corrompue

Si le fichier `ai_knowledge_base.json` est corrompu, il sera automatiquement recréé.

## 🎯 Avantages du Mode Conversationnel

1. **Interface naturelle** - Dialoguez en langage naturel
2. **Apprentissage continu** - L'IA s'améliore à chaque session
3. **Flexibilité** - Adaptez l'audit selon vos besoins
4. **Mémoire persistante** - Les apprentissages sont conservés
5. **Rétro-compatibilité** - Mode script toujours disponible

## 🔮 Évolutions Futures

- **Reconnaissance vocale** - Commandes vocales
- **Interface graphique** - GUI conversationnelle
- **Intégration multi-modèles** - Support d'autres modèles IA
- **Collaboration** - Partage de connaissances entre utilisateurs
- **Automatisation avancée** - Scripts générés automatiquement par l'IA 