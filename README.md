# PCAP - Analyse de flux réseau entrant

Projet d'analyse de trafic réseau entrant utilisant **Scapy** et **Python 3.9.14**.

## 📋 Description

Ce projet fournit une suite d'outils pour capturer, analyser et interpréter des fichiers PCAP, avec un focus particulier sur le **trafic entrant** (incoming traffic).

## 🛠️ Prérequis

- Python 3.9.14
- Scapy (seul dépendance requise)

```bash
pip install scapy
```

## 📁 Structure du projet

```
PCAP/
├── scripts/                  # Scripts principaux
│   ├── capture_incoming.py  # Capture de trafic entrant en temps réel
│   ├── analyze_pcap.py      # Analyse avancée de fichiers PCAP
│   └── utils.py             # Utilitaires (filtrage, fusion, etc.)
├── data/                    # Dossier pour les fichiers PCAP
├── results/                 # Dossier pour les rapports et résultats
└── README.md
```

## 🚀 Utilisation

### 1. Capture de trafic entrant en temps réel

```bash
# Capture sur une interface spécifique pendant 60 secondes
python scripts/capture_incoming.py eth0 60 capture.pcap

# Avec des options détaillées
python scripts/capture_incoming.py -i wlan0 -t 30 -o incoming.pcap

# Lister les interfaces disponibles
python scripts/capture_incoming.py --list-interfaces
```

**Options:**
- `-i, --interface`: Interface réseau (eth0, wlan0, etc.)
- `-t, --timeout`: Durée de capture en secondes (par défaut: 60)
- `-o, --output`: Fichier de sortie PCAP
- `--list-interfaces`: Affiche les interfaces disponibles

### 2. Analyse de fichiers PCAP existants

```bash
# Analyse complète
python scripts/analyze_pcap.py capture.pcap

# Analyse du trafic entrant uniquement
python scripts/analyze_pcap.py -f capture.pcap --incoming-only

# Sauvegarder un rapport texte
python scripts/analyze_pcap.py -f capture.pcap -o rapport.txt

# Sauvegarder les statistiques au format JSON
python scripts/analyze_pcap.py -f capture.pcap --json stats.json
```

**Options:**
- `-f, --file`: Fichier PCAP à analyser
- `-o, --output`: Fichier de sortie pour le rapport
- `--json`: Fichier de sortie pour les statistiques JSON
- `--incoming-only`: Afficher uniquement l'analyse du trafic entrant

### 3. Utilitaires

```bash
# Filtrer les paquets entrants
python scripts/utils.py filter-incoming input.pcap output.pcap

# Extraire les conversations individuelles
python scripts/utils.py extract-conversations input.pcap conversations/

# Obtenir des statistiques rapides
python scripts/utils.py stats input.pcap

# Fusionner plusieurs fichiers PCAP
python scripts/utils.py merge output.pcap input1.pcap input2.pcap
```

## 📊 Fonctionnalités d'analyse

### Analyse du trafic entrant

Le système identifie le trafic entrant en utilisant plusieurs méthodes :

1. **Flags TCP**: 
   - SYN sans ACK = Nouvelle connexion entrante
   - ACK sans SYN = Réponse à une connexion sortante (donc entrant)
   - Données avec PSH ou ACK

2. **Protocoles UDP/ICMP**:
   - Réponses DNS, DHCP, NTP
   - Réponses ICMP (Echo Reply)

3. **Ports serveurs**:
   - Trafic destiné aux ports serveurs courants (80, 443, 53, etc.)

### Statistiques générées

- **Générales**: Nombre total de paquets, durée, débit
- **Par protocole**: TCP, UDP, ICMP, autres
- **Par adresse**: Top sources et destinations
- **Par port**: Ports les plus ciblés
- **Conversations**: Flux entre paires source:port -> destination:port
- **HTTP**: Endpoints les plus fréquents
- **DNS**: Domaines les plus interrogés
- **Sécurité**: Détection de patterns suspects

### Détection de patterns suspects

Le système détecte automatiquement :
- Port scanning (beaucoup de ports différents ciblés)
- Connexions massives depuis une seule IP
- Trafic ICMP excessif (ping flood)
- Trafic sur des ports suspects (SSH, Telnet, etc.)
- SYN flood (beaucoup de paquets SYN sans ACK)

## 📈 Exemple de sortie

```
======================================================================
RÉSUMÉ DE L'ANALYSE PCAP
======================================================================
Fichier: capture.pcap
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

Top 10 adresses sources:
  192.168.1.1: 450 (29.2%)
  10.0.0.1: 320 (20.7%)
  ...

Top 10 ports destinations:
  80: 450
  443: 320
  53: 120
  ...

======================================================================
ANALYSE DU TRAFIC ENTRANT
======================================================================
Nombre de paquets entrants: 892

Protocoles entrants:
  TCP: 750 (84.1%)
  UDP: 120 (13.5%)
  ICMP: 22 (2.4%)

Top 10 sources de trafic entrant:
  192.168.1.1: 320 (35.9%)
  10.0.0.1: 250 (28.0%)
  ...

Analyse de sécurité:
  Aucun pattern suspect détecté
```

## 🎯 Cas d'usage

### 1. Surveillance réseau
```bash
# Capture continue avec sauvegarde automatique
while true; do
    python scripts/capture_incoming.py eth0 300 capture_$(date +%Y%m%d_%H%M%S).pcap
    sleep 60
done
```

### 2. Analyse de sécurité
```bash
# Analyser un fichier suspect
python scripts/analyze_pcap.py suspicious.pcap --incoming-only

# Extraire uniquement le trafic entrant pour analyse approfondie
python scripts/utils.py filter-incoming suspicious.pcap incoming_only.pcap
python scripts/analyze_pcap.py incoming_only.pcap
```

### 3. Monitoring de services
```bash
# Capturer le trafic vers un port spécifique (ex: 80)
# Puis filtrer et analyser
python scripts/capture_incoming.py eth0 60 web_traffic.pcap
python scripts/analyze_pcap.py web_traffic.pcap --incoming-only
```

## 📝 Format des rapports

### Rapport texte
Contient toutes les statistiques au format lisible, idéal pour un rapport rapide.

### JSON
Contient toutes les données brutes au format structuré, idéal pour :
- Intégration avec d'autres outils
- Visualisation avec des outils comme Grafana
- Analyse automatisée

Exemple de structure JSON :
```json
{
  "filename": "capture.pcap",
  "start_time": 1705315800.0,
  "end_time": 1705315860.0,
  "duration": 60.0,
  "stats": {
    "total_packets": 1542,
    "incoming_packets": 892,
    "protocols": {
      "TCP": 1200,
      "UDP": 300,
      "ICMP": 42
    },
    "sources": {
      "192.168.1.1": 450,
      "10.0.0.1": 320
    },
    "dest_ports": {
      "80": 450,
      "443": 320
    }
  }
}
```

## 🔧 Personnalisation

### Modifier la détection de trafic entrant

Dans `capture_incoming.py` et `analyze_pcap.py`, la méthode `is_incoming()` peut être modifiée pour adapter la détection à votre environnement spécifique.

### Ajouter de nouveaux protocoles

Pour analyser d'autres protocoles (ex: DNS, HTTP), ajoutez les imports et la logique d'analyse correspondante.

## 📚 Documentation Scapy

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Scapy GitHub](https://github.com/secdev/scapy)

## 🤝 Contribution

1. Fork le projet
2. Crée une branche pour votre fonctionnalité (`git checkout -b feature/nouvelle-fonctionnalité`)
3. Commit vos changements (`git commit -m 'Ajout de nouvelle fonctionnalité'`)
4. Push vers la branche (`git push origin feature/nouvelle-fonctionnalité`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENCE pour plus de détails.

---

**Note**: Ce projet est conçu pour fonctionner avec Python 3.9.14 et Scapy uniquement, comme demandé. Aucune autre dépendance n'est requise.
