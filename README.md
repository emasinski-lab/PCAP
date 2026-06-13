# PCAP - Analyse Approfondie de Flux Réseau Entrant

Projet d'analyse **ultra-détaillée** de fichiers PCAP pour le trafic entrant, avec extraction maximale d'informations pour éviter d'utiliser Wireshark manuellement.

## 📋 Description

Ce projet fournit une suite d'outils pour **analyser automatiquement** les fichiers PCAP avec un focus sur :

- ✅ **Identification des applications** (HTTP, HTTPS, DNS, SSH, SMTP, etc.)
- ✅ **Extraction des variables** (emails, numéros de téléphone, IDs, tokens, etc.)
- ✅ **Classification par écosystème** (Android, iOS, Web, IoT, VoIP, etc.)
- ✅ **Détection des supports** (email, SMS, VoIP, messagerie instantanée)
- ✅ **Analyse de sécurité** (patterns suspects, credentials, API keys)
- ✅ **Statistiques complètes** (protocoles, ports, conversations, etc.)

**Tout cela sans avoir à ouvrir Wireshark et faire des filtres manuellement !**

## 🛠️ Prérequis

- Python 3.9.14 (comme demandé)
- Scapy (seule dépendance requise)

```bash
pip install scapy
```

## 📁 Structure du projet

```
PCAP/
├── LANCER.py                     # 🎯 Script principal de lancement
├── README.md                     # 📖 Documentation
├── requirements.txt              # 📦 Dépendances (Scapy uniquement)
├── Brutes/                       # 📥 Dossier pour les fichiers PCAP à analyser
│   └── *.pcap                    # Placez vos fichiers PCAP ici
├── Sortie/                       # 📤 Dossier pour les résultats
│   └── *.txt, *.json             # Rapports et statistiques générés
├── Error/                        # ⚠️ Dossier pour les logs d'erreurs
│   └── error.log                # Log des erreurs d'analyse
└── scripts/
    ├── analyze_pcap.py            # 🔍 Moteur d'analyse avancée
    └── utils.py                   # 🛠️ Utilitaires (filtrage, extraction, etc.)
```

## 🚀 Utilisation

### 1. Préparation

Placez vos fichiers PCAP dans le dossier **`Brutes/`** :

```bash
# Exemple :
PCAP/
├── Brutes/
│   ├── capture1.pcap
│   ├── capture2.pcap
│   └── capture3.pcapng
├── Sortie/
└── Error/
```

### 2. Lancement de l'analyse

#### Mode interactif (par défaut)
```bash
# Lance le mode interactif : affiche la liste des fichiers et demande à l'utilisateur de choisir
python LANCER.py

Exemple de sortie:
```
======================================================================
FICHIERS PCAP DISPONIBLES DANS 'Brutes/'
======================================================================
  1. capture1.pcap (12.50 Mo)
  2. capture2.pcap (8.30 Mo)
  3. test_multiapps.pcap (5.20 Mo)

  0. Traiter TOUS les fichiers
  q. Quitter
======================================================================

Votre choix (numéro, 0 pour tous, q pour quitter) :
```

#### Traiter tous les fichiers
```bash
# Traite tous les fichiers sans demander confirmation
python LANCER.py --all
```

#### Analyser un fichier spécifique
```bash
# Analyse un fichier spécifique par son nom
python LANCER.py Brutes/capture1.pcap
```

#### Analyse approfondie (extraction de données)
```bash
# Avec extraction de toutes les données (emails, téléphones, IDs, etc.)
python LANCER.py --deep
python LANCER.py --all --deep

# Sur un fichier spécifique avec extraction
python LANCER.py Brutes/capture1.pcap --deep
```

#### Sauvegarde dans différents formats
```bash
# Sauvegarde au format JSON (pour intégration avec d'autres outils)
python LANCER.py --json
python LANCER.py --all --json

# Sauvegarde dans tous les formats (texte + JSON)
python LANCER.py --all-formats
python LANCER.py --all --all-formats

# Combinaison : analyse approfondie + tous les formats
python LANCER.py --deep --all-formats
python LANCER.py --all --deep --all-formats
```

### 3. Afficher l'aide

```bash
python LANCER.py --help
```

### 4. Vérifier les erreurs

```bash
# Afficher les erreurs enregistrées
cat Error/error.log

# Vider le log des erreurs
> Error/error.log
```

## 📊 Fonctionnalités d'analyse

### 🎯 Identification des Applications

Le système identifie automatiquement **plus de 30 types d'applications** :

| Catégorie | Applications | Ports |
|----------|-------------|-------|
| **Web** | HTTP, HTTPS, HTTP-ALT, HTTPS-ALT | 80, 443, 8080, 8443 |
| **DNS** | DNS, mDNS | 53, 5353 |
| **Email** | SMTP, SMTPS, POP3, POP3S, IMAP, IMAPS | 25, 465, 587, 110, 995, 143, 993 |
| **Messagerie** | XMPP, XMPPS, SIP, SIPS | 5222, 5223, 5060, 5061 |
| **Bases de données** | MySQL, PostgreSQL, MongoDB, Redis | 3306, 5432, 27017, 6379 |
| **Accès distant** | SSH, Telnet, RDP, VNC | 22, 23, 3389, 5900 |
| **Transfert de fichiers** | FTP, TFTP | 21, 20, 69 |
| **Cloud** | Docker, Kubernetes | 2375, 2376, 8000 |
| **IoT** | MQTT, MQTTS, SNMP | 1883, 8883, 161, 162 |
| **VoIP** | SIP, SIPS, RTP, RTCP | 5060, 5061, 16384, 16385 |
| **Jeux** | Minecraft, Steam | 25565, 27000 |
| **Autres** | NTP, DHCP, NetBIOS, SMB | 123, 67, 68, 137-139, 445 |

### 🌍 Classification par Écosystème

Détection automatique des écosystèmes basés sur les User-Agents et les ports :

- **Android** (appareils mobiles Android)
- **iOS** (iPhone, iPad, iPod)
- **Windows** (Windows, Win64, Win32)
- **macOS** (Macintosh, Mac OS X)
- **Linux** (Linux, Ubuntu, Debian)
- **Web** (navigateurs : Chrome, Firefox, Safari, Edge, Opera)
- **IoT** (ESP8266, ESP32, Raspberry Pi, Arduino)
- **Bot** (Googlebot, Bingbot, Slurp, Spider)
- **API** (clients Python, Java, Go, curl)
- **Mobile-Messaging** (XMPP, etc.)
- **VoIP** (SIP, RTP)

### 🔍 Extraction de Données

Avec l'option `--deep`, le système extrait automatiquement :

#### 1. **Identifiants Personnels**
- 📧 **Emails** : `user@example.com`
- 📱 **Numéros de téléphone** : `+33123456789`, `0123456789`
- 🌐 **URLs** : `https://example.com/api`

#### 2. **Identifiants Techniques**
- 🔑 **UUIDs** : `550e8400-e29b-41d4-a716-446655440000`
- 🎫 **Session IDs** : `session=abc123...`, `sid=xyz789...`
- 📱 **Device IDs** : `device_id=ABC123`, `imei=123456789012345`
- 👤 **User IDs** : `user_id=12345`, `uid=john_doe`

#### 3. **Sécurité et Authentification**
- 🔐 **API Keys** : `api_key=sk_live_abc123...`
- 🛡️ **JWT Tokens** : `eyJhbGciOiJIUzI1NiIs...`
- 🔑 **Credentials** : `username:admin`, `password:secret123`
- 🍪 **Cookies** : `sessionid=abc123; user_token=xyz`

#### 4. **Données Structurées**
- 📦 **JSON Objects** : `{"key": "value"}`
- 🔤 **Base64 Strings** : `dGVzdA==`
- 🌐 **IP Addresses** : `192.168.1.1`

### 📈 Statistiques Complètes

- **Paquets totaux, entrants, sortants**
- **Répartition par protocole** (TCP, UDP, ICMP)
- **Top adresses sources et destinations**
- **Top ports et applications**
- **Conversations réseau** (flux entre IP:port)
- **User-Agents** (navigateurs, applications)
- **Domaines DNS** les plus interrogés
- **Endpoints HTTP** les plus fréquents
- **Statistiques de taille des paquets**

### 🚨 Analyse de Sécurité

Détection automatique de :

- **Port Scanning** : Beaucoup de ports différents ciblés
- **Connexions massives** : Beaucoup de connexions depuis une seule IP
- **Ping Flood** : Trafic ICMP excessif
- **Ports suspects** : Trafic sur SSH, Telnet, RDP, etc.
- **SYN Flood** : Beaucoup de paquets SYN sans ACK
- **Credentials en clair** : Détection de mots de passe dans le payload
- **API Keys exposées** : Détection de clés API dans le trafic
- **JWT Tokens** : Détection de tokens JWT

## 📄 Formats de Sortie

### 1. Rapport Texte (`.txt`)

**Contenu :**
- Résumé de l'analyse
- Statistiques détaillées
- Applications détectées
- Écosystèmes identifiés
- Données extraites (si `--deep`)
- Analyse de sécurité

**Exemple :**
```
======================================================================
RAPPORT D'ANALYSE PCAP - DÉTAILLÉ
======================================================================

Fichier: Brutes/capture1.pcap
Durée: 60.00 secondes
Début: 2024-01-15 10:30:00
Fin: 2024-01-15 10:31:00

Paquets totaux: 1542
Paquets entrants: 892 (57.8%)
Paquets sortants: 650 (42.2%)

Protocoles:
  TCP: 1200 (77.8%)
  UDP: 300 (19.5%)
  ICMP: 42 (2.7%)

Applications détectées:
  HTTPS: 750
  HTTP: 450
  DNS: 300
  SSH: 42

Écosystèmes détectés:
  Web: 1200
  Android: 300
  iOS: 150

======================================================================
DONNÉES EXTRAITES
======================================================================

EMAILS (5):
  1. user1@example.com
  2. user2@gmail.com
  ...

PHONE NUMBERS (3):
  1. +33123456789
  2. 0123456789
  ...

USER IDS (10):
  1. user_id=12345
  2. uid=john_doe
  ...
```

### 2. JSON (`.json`)

**Contenu :** Toutes les données au format structuré pour intégration avec d'autres outils.

**Exemple :**
```json
{
  "filename": "Brutes/capture1.pcap",
  "start_time": 1705315800.0,
  "end_time": 1705315860.0,
  "duration": 60.0,
  "stats": {
    "total_packets": 1542,
    "incoming_packets": 892,
    "applications": {
      "HTTPS": 750,
      "HTTP": 450,
      "DNS": 300
    },
    "ecosystems": {
      "Web": 1200,
      "Android": 300
    }
  },
  "extracted_data": {
    "emails": ["user1@example.com", "user2@gmail.com"],
    "phone_numbers": ["+33123456789", "0123456789"],
    "user_ids": ["user_id=12345", "uid=john_doe"],
    "credentials": ["username:admin", "password:secret123"],
    "api_keys": ["api_key=sk_live_abc123"],
    "jwt_tokens": ["eyJhbGciOiJIUzI1NiIs..."]
  }
}
```

## 🎯 Cas d'Usage Pratiques

### 1. Analyse de routine

```bash
# Analyser tous les nouveaux fichiers PCAP
python LANCER.py

# Vérifier les résultats dans Sortie/
ls -la Sortie/
```

### 2. Investigation de sécurité

```bash
# Analyse approfondie avec extraction de toutes les données
python LANCER.py --deep --all-formats

# Rechercher des informations sensibles
cat Sortie/*rapport*.txt | grep -i "credential\|password\|api_key\|jwt"
```

### 3. Monitoring d'applications spécifiques

```bash
# Analyser uniquement le trafic vers une application
python LANCER.py Brutes/api_traffic.pcap --deep

# Vérifier les endpoints HTTP
cat Sortie/*rapport*.txt | grep -A 10 "Endpoints HTTP"
```

### 4. Analyse par écosystème

```bash
# Analyser et filtrer par écosystème
python LANCER.py --deep

# Extraire les informations sur les écosystèmes
cat Sortie/*rapport*.txt | grep -A 20 "Écosystèmes détectés"
```

### 5. Automatisation

```bash
# Script pour analyser automatiquement les nouveaux fichiers
#!/bin/bash
while true; do
    python LANCER.py --deep --all-formats
    sleep 3600  # Attendre 1 heure
    clear
    echo "Nouvelle analyse démarrée à $(date)"
done
```

## 🔧 Personnalisation

### 1. Ajouter de nouvelles applications

Modifiez le dictionnaire `APPLICATION_PORTS` dans `scripts/analyze_pcap.py` :

```python
APPLICATION_PORTS = {
    # ... existant ...
    8081: 'My-Custom-App',
    9000: 'Portainer',
    # Ajoutez vos applications ici
}
```

### 2. Ajouter de nouveaux patterns d'extraction

Modifiez le dictionnaire `PATTERNS` dans `scripts/analyze_pcap.py` :

```python
PATTERNS = {
    # ... existant ...
    'custom_ids': re.compile(r'custom[_-]?id[=:"]?([a-zA-Z0-9_-]{8,})'),
    'serial_numbers': re.compile(r'(serial|sn)[=:"]?([a-zA-Z0-9-]{10,})'),
    # Ajoutez vos patterns ici
}
```

### 3. Ajouter de nouveaux écosystèmes

Modifiez le dictionnaire `ECOSYSTEM_PATTERNS` dans `scripts/analyze_pcap.py` :

```python
ECOSYSTEM_PATTERNS = {
    # ... existant ...
    'Custom-App': [r'MyApp/', r'Custom-Client'],
    # Ajoutez vos écosystèmes ici
}
```

## 📚 Documentation Scapy

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Scapy GitHub](https://github.com/secdev/scapy)

## 🤝 Contribution

1. Fork le projet
2. Crée une branche pour votre fonctionnalité
3. Commit vos changements
4. Push vers la branche
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT.

---

## 🎉 Résumé des Avantages

✅ **100% compatible Python 3.9.14**  
✅ **Scapy uniquement** (aucune autre dépendance)  
✅ **Pas besoin d'ouvrir Wireshark**  
✅ **Extraction automatique de toutes les informations**  
✅ **Identification des applications et écosystèmes**  
✅ **Détection des données sensibles**  
✅ **Analyse de sécurité intégrée**  
✅ **Rapports détaillés en texte et JSON**  
✅ **Traitement par lots** (tous les fichiers dans Brutes/)  
✅ **Personnalisable** (applications, patterns, écosystèmes)  

**Ce projet vous permet d'analyser vos fichiers PCAP de manière exhaustive sans avoir à utiliser Wireshark manuellement !** 🚀
