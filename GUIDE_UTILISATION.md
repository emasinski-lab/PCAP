# 📖 **GUIDE COMPLET D'UTILISATION - PCAP Analyzer**

*Analyseur avancé de flux réseau entrant avec extraction maximale d'informations*

---

## 📌 **TABLE DES MATIÈRES**

1. [📥 INSTALLATION ET CONFIGURATION](#-installation-et-configuration)
2. [🚀 UTILISATION DE BASE](#-utilisation-de-base)
3. [🔍 UTILISATION AVANCÉE](#-utilisation-avancée)
4. [📊 INTERPRÉTATION DES RÉSULTATS](#-interprétation-des-résultats)
5. [🎯 CAS D'USAGE CONCRETS](#-cas-dusage-concrets)
6. [⚠️ DÉPANNAGE](#-dépannage)
7. [📚 ANNEXES](#-annexes)

---

## 📥 **INSTALLATION ET CONFIGURATION**

### **Prérequis**

| Élément | Version requise | Vérification |
|---------|-----------------|--------------|
| Python | 3.9.x | `python --version` |
| Scapy | ≥ 2.4.0 | `pip show scapy` |
| Système d'exploitation | Windows/Linux/macOS | - |

### **Installation**

#### **1. Cloner le dépôt**
```bash
# Si tu utilises git
git clone https://github.com/emasinski-lab/PCAP.git
cd PCAP

# Sinon, copie simplement le dossier PCAP sur ton machine
```

#### **2. Installer les dépendances**
```bash
# Créer un environnement virtuel (recommandé)
python -m venv venv

# Activer l'environnement
# Sur Windows:
venv\Scripts\activate
# Sur Linux/macOS:
source venv/bin/activate

# Installer Scapy
pip install scapy>=2.4.0
```

#### **3. Vérifier l'installation**
```bash
# Lancer le script de vérification
python LANCER.py --help

# Tu devrais voir:
# ======================================================================
# VERIFICATION DES DEPENDANCES
# ======================================================================
# ✓ Python: version 3.9.x
# ✓ Scapy: version X.X.X
# ======================================================================
```

### **Structure des dossiers**

```
PCAP/
├── LANCER.py              # 🎯 Script principal de lancement
├── README.md              # 📖 Documentation technique
├── GUIDE_UTILISATION.md   # 📖 Ce guide (à convertir en Word)
├── requirements.txt       # 📦 Dépendances
├── Brutes/                # 📥 Dossier pour les fichiers PCAP à analyser
│   └── *.pcap             # Placez vos fichiers ici
├── Sortie/                # 📤 Dossier pour les résultats
│   ├── *.txt              # Rapports texte
│   └── *.json             # Statistiques JSON
├── Error/                 # ⚠️ Dossier pour les logs d'erreurs
│   └── error.log          # Log des erreurs (rotation automatique)
└── scripts/
    ├── analyze_pcap.py     # 🔍 Moteur d'analyse avancée
    └── utils.py            # 🛠️ Utilitaires
```

### **Configuration (optionnelle)**

Tu peux modifier les paramètres dans le fichier `LANCER.py` :

```python
# Taille maximale des fichiers à analyser (en Mo) - 0 = pas de limite
MAX_FILE_SIZE_MB = 0

# Configuration de la rotation des logs
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 Mo
LOG_BACKUP_COUNT = 5  # Nombre de fichiers de backup
```

---

## 🚀 **UTILISATION DE BASE**

### **1. Préparation des fichiers**

Place tes fichiers PCAP dans le dossier **`Brutes/`** :

```bash
# Exemple :
PCAP/
├── Brutes/
│   ├── capture_20240601.pcap
│   ├── traffic_web.pcap
│   └── scan_network.pcapng
└── Sortie/
```

**Formats supportés** : `.pcap`, `.pcapng`, `.cap`

### **2. Lancement de l'analyse**

#### **Mode interactif (recommandé)**
```bash
python LANCER.py
```

**Le script affiche :**
```
======================================================================
FICHIERS PCAP DISPONIBLES DANS 'Brutes/'
======================================================================
  1. capture_20240601.pcap (12.50 Mo)
  2. traffic_web.pcap (8.30 Mo)
  3. scan_network.pcapng (5.20 Mo)

  0. Traiter TOUS les fichiers
  q. Quitter
======================================================================

Votre choix (numéro, 0 pour tous, q pour quitter) :
```

**Options :**
- **1, 2, 3...** → Traite le fichier correspondant
- **0** → Traite **tous** les fichiers
- **q** → Quitte le script

#### **Traiter tous les fichiers**
```bash
python LANCER.py --all
```

#### **Analyser un fichier spécifique**
```bash
python LANCER.py Brutes/capture_20240601.pcap
```

### **3. Options d'analyse**

| Option | Description | Exemple |
|--------|-------------|---------|
| `--all` | Traite tous les fichiers | `python LANCER.py --all` |
| `--deep` | Analyse approfondie (extraction de données) | `python LANCER.py --deep` |
| `--json` | Sauvegarde au format JSON | `python LANCER.py --json` |
| `--all-formats` | Sauvegarde en TXT + JSON | `python LANCER.py --all-formats` |

**Combinaisons possibles :**
```bash
# Analyse approfondie de tous les fichiers
python LANCER.py --all --deep

# Analyse approfondie avec tous les formats
python LANCER.py --all --deep --all-formats

# Analyse d'un fichier spécifique avec extraction
python LANCER.py Brutes/traffic_web.pcap --deep
```

### **4. Vérification des résultats**

Les résultats sont sauvegardés dans **`Sortie/`** :

```bash
# Lister les résultats
ls -la Sortie/

# Lire un rapport texte
cat Sortie/capture_20240601_rapport_20240614_103000.txt

# Lire un rapport JSON
cat Sortie/capture_20240601_stats_20240614_103000.json
```

### **5. Vérification des erreurs**

Les erreurs sont enregistrées dans **`Error/error.log`** :

```bash
# Afficher les erreurs
cat Error/error.log

# Vider le log
> Error/error.log
```

---

## 🔍 **UTILISATION AVANCÉE**

### **1. Analyse approfondie (`--deep`)**

L'option `--deep` active l'**extraction de données** depuis les payloads des paquets :

**Données extraites :**
- 📧 **Emails** : `user@example.com`
- 📱 **Numéros de téléphone** : `+33123456789`
- 🌐 **URLs** : `https://api.example.com`
- 🔑 **UUIDs** : `550e8400-e29b-41d4-a716-446655440000`
- 🎫 **Session IDs** : `session=abc123...`
- 📱 **Device IDs** : `device_id=ABC123`
- 👤 **User IDs** : `user_id=12345`
- 🔐 **API Keys** : `api_key=sk_live_...`
- 🛡️ **JWT Tokens** : `eyJhbGciOiJIUzI1NiIs...`
- 🔑 **Credentials** : `username:admin, password:...`
- 🍪 **Cookies** : `sessionid=abc123`

**Exemple de sortie avec `--deep` :**
```
======================================================================
DONNÉES EXTRAITES
======================================================================

EMAILS (5):
  1. user1@example.com
  2. admin@company.com
  3. support@service.fr
  ...

PHONE NUMBERS (2):
  1. +33123456789
  2. 0123456789

USER IDS (10):
  1. user_id=12345
  2. uid=john_doe
  ...

CREDENTIALS (3):
  1. username:admin
  2. password:secret123
  3. api_key:abc123
```

### **2. Identification des applications**

Le script identifie automatiquement **plus de 30 types d'applications** :

| Catégorie | Applications | Ports |
|----------|-------------|-------|
| **Web** | HTTP, HTTPS, HTTP-ALT, HTTPS-ALT | 80, 443, 8080, 8443 |
| **DNS** | DNS, mDNS | 53, 5353 |
| **Email** | SMTP, SMTPS, POP3, POP3S, IMAP, IMAPS | 25, 465, 587, 110, 995, 143, 993 |
| **Messagerie** | XMPP, XMPPS, SIP, SIPS | 5222, 5223, 5060, 5061 |
| **Bases de données** | MySQL, PostgreSQL, MongoDB, Redis | 3306, 5432, 27017, 6379 |
| **Accès distant** | SSH, Telnet, RDP, VNC | 22, 23, 3389, 5900 |
| **Transfert** | FTP, TFTP | 21, 20, 69 |
| **Cloud** | Docker, Kubernetes | 2375, 2376, 8000 |
| **IoT** | MQTT, MQTTS, SNMP | 1883, 8883, 161, 162 |
| **VoIP** | SIP, SIPS, RTP, RTCP | 5060, 5061, 16384, 16385 |

### **3. Classification par écosystème**

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

### **4. Analyse de sécurité**

Détection automatique de :

- **Port Scanning** : Beaucoup de connexions sur différents ports
- **Connexions massives** : Beaucoup de connexions depuis une seule IP
- **Ping Flood** : Trafic ICMP excessif
- **Ports suspects** : Trafic sur SSH, Telnet, RDP, etc.
- **SYN Flood** : Beaucoup de paquets SYN sans ACK
- **Credentials en clair** : Détection de mots de passe dans le payload
- **API Keys exposées** : Détection de clés API dans le trafic
- **JWT Tokens** : Détection de tokens JWT

**Exemple de sortie :**
```
Analyse de sécurité:
  [ALERTE] Possible port scanning: 55 ports differents cibles
  [ALERTE] Trafic sur port suspect 22 (SSH): 42 paquets
  [ALERTE] 3 credentials potentiels detectes dans le payload
```

### **5. Statistiques détaillées**

Le script génère des statistiques complètes :

- **Paquets totaux, entrants, sortants**
- **Répartition par protocole** (TCP, UDP, ICMP)
- **Top adresses sources et destinations**
- **Top ports et applications**
- **Conversations réseau** (flux entre IP:port)
- **User-Agents** (navigateurs, applications)
- **Domaines DNS** les plus interrogés
- **Endpoints HTTP** les plus fréquents
- **Statistiques de taille des paquets**

---

## 📊 **INTERPRÉTATION DES RÉSULTATS**

### **1. Rapport Texte (`*_rapport_*.txt`)**

#### **Structure du rapport**
```
======================================================================
RAPPORT D'ANALYSE PCAP - DETAILLE
======================================================================

Fichier: Brutes/capture1.pcap
Duree: 60.00 secondes
Debut: 2024-06-14 10:30:00
Fin: 2024-06-14 10:31:00

Paquets totaux: 1542
Paquets entrants: 892 (57.8%)
Paquets sortants: 650 (42.2%)

Protocoles:
  TCP: 1200 (77.8%)
  UDP: 300 (19.5%)
  ICMP: 42 (2.7%)

Applications:
  HTTPS: 750
  HTTP: 450
  DNS: 300

Ecosystemes:
  Web: 1200
  Android: 300
  iOS: 150

Top 10 adresses sources:
  192.168.1.1: 450 (29.2%)
  10.0.0.1: 320 (20.7%)
  ...

Top 10 ports destinations:
  443 (HTTPS): 750
  80 (HTTP): 450
  53 (DNS): 300
  ...

======================================================================
DONNEES EXTRAITES
======================================================================

EMAILS (5):
  1. user1@example.com
  2. user2@gmail.com
  ...
```

#### **Comment interpréter**

| Section | Signification | Action recommandée |
|---------|---------------|-------------------|
| **Paquets totaux** | Nombre total de paquets capturés | Vérifier que c'est cohérent avec la durée |
| **Paquets entrants** | % de trafic destiné à ta machine | Un ratio > 50% est normal pour un serveur |
| **Protocoles** | Répartition TCP/UDP/ICMP | Un trafic UDP élevé peut indiquer du DNS ou VoIP |
| **Applications** | Services détectés | Vérifier les applications inattendues |
| **Écosystèmes** | Types de clients | Identifier les plateformes utilisées |
| **Adresses sources** | Top des IP émettrices | Vérifier les IP inconnues |
| **Ports destinations** | Services ciblés | Vérifier les ports suspects (22, 3389, etc.) |
| **Données extraites** | Informations sensibles | **À vérifier en priorité** |

### **2. Rapport JSON (`*_stats_*.json`)**

Le rapport JSON contient **toutes les données brutes** au format structuré :

```json
{
  "filename": "Brutes/capture1.pcap",
  "start_time": 1718365800.0,
  "end_time": 1718365860.0,
  "duration": 60.0,
  "stats": {
    "total_packets": 1542,
    "incoming_packets": 892,
    "outgoing_packets": 650,
    "protocols": {
      "TCP": 1200,
      "UDP": 300,
      "ICMP": 42
    },
    "applications": {
      "HTTPS": 750,
      "HTTP": 450,
      "DNS": 300
    },
    "ecosystems": {
      "Web": 1200,
      "Android": 300
    },
    "sources": {
      "192.168.1.1": 450,
      "10.0.0.1": 320
    },
    "dest_ports": {
      "443": 750,
      "80": 450
    }
  },
  "extracted_data": {
    "emails": ["user1@example.com", "user2@gmail.com"],
    "phone_numbers": ["+33123456789"],
    "user_ids": ["user_id=12345"],
    "credentials": ["username:admin"],
    "api_keys": ["api_key=abc123"],
    "jwt_tokens": ["eyJhbGciOiJIUzI1NiIs..."]
  }
}
```

**Utilisation du JSON :**
- **Intégration avec d'autres outils** (Splunk, ELK, etc.)
- **Analyse automatisée** avec des scripts Python
- **Visualisation** avec des outils comme Grafana

### **3. Log des erreurs (`Error/error.log`)**

**Format :**
```
2024-06-14 10:30:00,123 - ERROR - Erreur lors de l'analyse de Brutes/bad_file.pcap: Fichier corrompu
2024-06-14 10:31:00,456 - ERROR - Fichier introuvable: Brutes/missing.pcap
```

**Rotation automatique :**
- **Taille max par fichier** : 10 Mo
- **Nombre de backups** : 5 fichiers (`error.log`, `error.log.1`, `error.log.2`, etc.)

---

## 🎯 **CAS D'USAGE CONCRETS**

### **Cas 1 : Surveillance réseau de routine**

**Objectif** : Analyser le trafic réseau quotidien pour détecter des anomalies.

**Commande :**
```bash
# Analyser tous les fichiers du jour
python LANCER.py --all --deep --all-formats
```

**Résultats attendus :**
- Détection des applications utilisées
- Identification des écosystèmes (Android, iOS, Web, etc.)
- Extraction des données sensibles (si présentes)
- Détection des patterns suspects

**Actions recommandées :**
1. Vérifier les **alertes de sécurité** dans le rapport
2. Examiner les **données extraites** (emails, IDs, etc.)
3. Analyser les **adresses sources inconnues**

---

### **Cas 2 : Investigation de sécurité**

**Objectif** : Analyser un fichier PCAP suspect pour identifier une attaque.

**Commande :**
```bash
# Analyse approfondie d'un fichier suspect
python LANCER.py Brutes/suspicious_traffic.pcap --deep --all-formats
```

**Points à vérifier :**
1. **Alertes de sécurité** : Port scanning, brute-force, etc.
2. **Données extraites** : Credentials, API keys, tokens
3. **Adresses sources** : IP inconnues ou suspectes
4. **Ports destinations** : Ports suspects (22, 23, 3389, etc.)
5. **Applications détectées** : Services inattendus

**Exemple de résultats suspects :**
```
[ALERTE] Possible port scanning: 55 ports differents cibles
[ALERTE] 3 credentials potentiels detectes dans le payload
[ALERTE] Trafic sur port suspect 22 (SSH): 42 paquets
```

---

### **Cas 3 : Monitoring d'un service spécifique**

**Objectif** : Analyser le trafic vers un service web (port 80/443).

**Commande :**
```bash
# Filtrer et analyser le trafic web
python LANCER.py Brutes/web_traffic.pcap --deep
```

**Points à vérifier :**
1. **Endpoints HTTP** : URLs les plus fréquentes
2. **User-Agents** : Types de clients (navigateurs, bots, etc.)
3. **Données extraites** : Emails, IDs, tokens dans les requêtes
4. **Écosystèmes** : Plateformes des clients (Android, iOS, Web)

---

### **Cas 4 : Analyse des performances**

**Objectif** : Analyser les performances d'une application.

**Commande :**
```bash
python LANCER.py Brutes/performance_test.pcap
```

**Points à vérifier :**
1. **Statistiques de taille des paquets** : Min, Max, Moyenne
2. **Répartition des protocoles** : TCP vs UDP
3. **Top ports destinations** : Services les plus utilisés
4. **Conversations réseau** : Flux entre clients et serveurs

---

### **Cas 5 : Automatisation avec cron**

**Objectif** : Analyser automatiquement les nouveaux fichiers PCAP.

**Commande (Linux/macOS) :**
```bash
# Éditer la crontab
crontab -e

# Ajouter une entrée pour analyser tous les jours à 2h
0 2 * * * /chemin/vers/PCAP/venv/bin/python /chemin/vers/PCAP/LANCER.py --all --deep --all-formats >> /chemin/vers/PCAP/Error/automation.log 2>&1
```

**Commande (Windows) :**
```batch
@echo off
cd C:\chemin\vers\PCAP
python LANCER.py --all --deep --all-formats >> Error\automation.log 2>&1
```

**Planification avec Task Scheduler :**
1. Créer une tâche planifiée
2. Déclencheur : Tous les jours à 2h
3. Action : `python LANCER.py --all --deep --all-formats`
4. Dossier de travail : `C:\chemin\vers\PCAP`

---

## ⚠️ **DÉPANNAGE**

### **Problèmes courants et solutions**

| Problème | Cause | Solution |
|----------|-------|----------|
| `ModuleNotFoundError: No module named 'scapy'` | Scapy non installé | `pip install scapy` |
| `UnicodeEncodeError` | Caractères exotiques | Utiliser `--deep` pour la translittération |
| `No libpcap provider available` | Libpcap non disponible | Scapy fonctionne sans libpcap (mode limité) |
| `File not found` | Fichier PCAP introuvable | Vérifier le chemin dans `Brutes/` |
| `Permission denied` | Droits insuffisants | `chmod +x LANCER.py` (Linux) |
| `MemoryError` | Fichier trop gros | Augmenter `MAX_FILE_SIZE_MB` ou diviser le PCAP |

### **Vérification de l'environnement**

```bash
# Vérifier Python
python --version

# Vérifier Scapy
python -c "import scapy; print(scapy.__version__)"

# Vérifier les dossiers
ls -la PCAP/Brutes/  # Linux/macOS
dir PCAP\Brutes\   # Windows
```

### **Test de fonctionnement**

```bash
# Tester avec un petit fichier PCAP
python LANCER.py --help

# Tester l'analyse
python LANCER.py --all
```

### **Réinitialisation**

Si le script ne fonctionne pas :

```bash
# Supprimer les fichiers temporaires
rm -rf PCAP/Sortie/* PCAP/Error/*

# Réinstaller les dépendances
pip uninstall scapy -y
pip install scapy
```

---

## 📚 **ANNEXES**

### **A. Format des fichiers PCAP**

| Format | Extension | Description |
|--------|-----------|-------------|
| PCAP | `.pcap` | Format standard (libpcap) |
| PCAP-NG | `.pcapng` | Format nouvelle génération |
| CAP | `.cap` | Format alternatif |

**Compatibilité :**
- ✅ Tous les formats sont supportés par Scapy
- ✅ Pas de différence de traitement entre les formats

### **B. Limites connues**

| Limite | Description | Solution |
|--------|-------------|----------|
| Taille des fichiers | Les très gros fichiers (>1 Go) peuvent consommer beaucoup de mémoire | Diviser le PCAP avec `editcap` |
| Temps d'analyse | L'analyse approfondie (`--deep`) est plus lente | Utiliser sans `--deep` pour une analyse rapide |
| Caractères exotiques | Certains caractères peuvent ne pas être translittérés | Vérifier les rapports générés |

### **C. Outils complémentaires**

| Outil | Description | Lien |
|-------|-------------|------|
| Wireshark | Analyse manuelle des PCAP | [wireshark.org](https://www.wireshark.org/) |
| TShark | Version CLI de Wireshark | Inclus avec Wireshark |
| tcpdump | Capture de paquets | [tcpdump.org](https://www.tcpdump.org/) |
| Scapy | Manipulation de paquets | [scapy.net](https://scapy.net/) |

### **D. Commandes utiles**

**Diviser un gros fichier PCAP :**
```bash
# Avec editcap (fournis avec Wireshark)
editcap -c 1000 big_file.pcap split_file.pcap

# Avec tcpdump
tcpdump -r big_file.pcap -c 1000 -w split_file.pcap
```

**Filtrer un fichier PCAP :**
```bash
# Garder seulement le trafic HTTP
tcpdump -r input.pcap -w http_only.pcap 'tcp port 80 or tcp port 443'

# Garder seulement le trafic entrant
tcpdump -r input.pcap -w incoming.pcap 'dst host YOUR_IP'
```

**Convertir un PCAP :**
```bash
# Convertir en PCAP-NG
editcap -F pcapng input.pcap output.pcapng

# Convertir en PCAP
editcap -F pcap input.pcapng output.pcap
```

### **E. Glossaire**

| Terme | Définition |
|-------|------------|
| **PCAP** | Packet Capture - Format de fichier pour stocker des paquets réseau |
| **Payload** | Données utiles transportées par un paquet (hors en-têtes) |
| **TCP** | Transmission Control Protocol - Protocole de transport fiable |
| **UDP** | User Datagram Protocol - Protocole de transport non fiable |
| **ICMP** | Internet Control Message Protocol - Protocole de contrôle (ping) |
| **DNS** | Domain Name System - Protocole de résolution de noms |
| **HTTP** | HyperText Transfer Protocol - Protocole du web |
| **HTTPS** | HTTP Secure - HTTP avec chiffrement TLS |
| **TLS/SSL** | Transport Layer Security - Protocole de chiffrement |
| **SYN** | Flag TCP pour initier une connexion |
| **ACK** | Flag TCP pour accuser réception |
| **User-Agent** | En-tête HTTP identifiant le client |
| **Écosystème** | Plateforme ou environnement (Android, iOS, Web, etc.) |

---

## 🎉 **CONCLUSION**

Ce guide t'a fourni toutes les informations nécessaires pour :

✅ **Installer et configurer** le PCAP Analyzer
✅ **Comprendre les différents modes d'utilisation**
✅ **Interpréter les résultats** des analyses
✅ **Appliquer le bon cas d'usage** selon tes besoins
✅ **Résoudre les problèmes courants**

**Pour aller plus loin :**
- Consulte le **README.md** pour les détails techniques
- Explore le code source pour comprendre les algorithmes d'analyse
- Contribue au projet en ajoutant de nouvelles fonctionnalités

**Bonnes analyses !** 🚀

---

*Documentation générée pour PCAP Analyzer - Version 1.0*
*Dernière mise à jour : 2024-06-14*
