#!/usr/bin/env python3
"""
Script d'analyse AVANCÉE de fichiers PCAP pour le trafic entrant
Utilise Scapy pour analyser les fichiers PCAP existants avec extraction maximale d'informations

Usage:
    python analyze_pcap.py fichier.pcap
    python analyze_pcap.py -f fichier.pcap -o rapport.txt --deep
"""

import sys
import os
import re
from datetime import datetime
from collections import defaultdict, Counter
import argparse
import json
import base64

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    try:
        from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
        from scapy.layers.tls.record import TLSRecord
        TLS_AVAILABLE = True
    except ImportError:
        TLS_AVAILABLE = False
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Erreur: Scapy non disponible - {e}")
    sys.exit(1)


# Patterns pour l'extraction d'informations
PATTERNS = {
    # Emails
    'emails': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    
    # Numéros de téléphone (format international)
    'phone_numbers': re.compile(r'(\+\d{1,3}[- .]?)?(\d{2,4}[- .]?){2,4}\d{2,4}'),
    
    # URLs
    'urls': re.compile(r'(https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s]*)?'),
    
    # UUIDs
    'uuids': re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    
    # Session IDs (format courant)
    'session_ids': re.compile(r'(session[id]?|sid|token)[=:"]?([a-zA-Z0-9_-]{20,})'),
    
    # Device IDs
    'device_ids': re.compile(r'(device[id]?|imei|imsi|mac)[=:"]?([a-zA-Z0-9:_-]{10,})'),
    
    # User IDs
    'user_ids': re.compile(r'(user[id]?|uid|username)[=:"]?([a-zA-Z0-9_-]{3,})'),
    
    # API Keys (format courant)
    'api_keys': re.compile(r'(api[_-]?key|apikey)[=:"]?([a-zA-Z0-9_-]{20,})'),
    
    # JWT Tokens
    'jwt_tokens': re.compile(r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+'),
    
    # Base64 strings (potentiellement intéressantes)
    'base64_strings': re.compile(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    
    # JSON objects
    'json_objects': re.compile(r'\{[^{}]*\}'),
    
    # IP addresses
    'ip_addresses': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    
    # User Agents
    'user_agents': re.compile(r'(Android|iPhone|iPad|iOS|Windows|Macintosh|Linux|Chrome|Firefox|Safari|Edge)'),
}

# Ports des applications courantes
APPLICATION_PORTS = {
    # Web
    80: 'HTTP',
    443: 'HTTPS',
    8080: 'HTTP-ALT',
    8443: 'HTTPS-ALT',
    
    # DNS
    53: 'DNS',
    5353: 'mDNS',
    
    # Email
    25: 'SMTP',
    465: 'SMTPS',
    587: 'SMTP-SUBMISSION',
    110: 'POP3',
    995: 'POP3S',
    143: 'IMAP',
    993: 'IMAPS',
    
    # Messagerie
    5222: 'XMPP',
    5223: 'XMPPS',
    5060: 'SIP',
    5061: 'SIPS',
    
    # Bases de données
    3306: 'MySQL',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    
    # Remote Access
    22: 'SSH',
    23: 'Telnet',
    3389: 'RDP',
    5900: 'VNC',
    
    # Fichiers
    21: 'FTP',
    20: 'FTP-DATA',
    69: 'TFTP',
    
    # Cloud
    2375: 'Docker',
    2376: 'Docker',
    8000: 'Kubernetes',
    
    # IoT
    1883: 'MQTT',
    8883: 'MQTTS',
    161: 'SNMP',
    162: 'SNMP-TRAP',
    
    # VoIP
    5060: 'SIP',
    5061: 'SIPS',
    16384: 'RTP',
    16385: 'RTCP',
    
    # Jeux
    25565: 'Minecraft',
    27000: 'Steam',
    
    # Autres
    123: 'NTP',
    67: 'DHCP-Server',
    68: 'DHCP-Client',
    137: 'NetBIOS',
    138: 'NetBIOS',
    139: 'NetBIOS',
    445: 'SMB',
}

# User Agents des écosystèmes
ECOSYSTEM_PATTERNS = {
    'Android': [r'Android', r'Dalvik', r'SM-A', r'SM-N', r'Pixel'],
    'iOS': [r'iPhone', r'iPad', r'iPod', r'iOS', r'CFNetwork'],
    'Windows': [r'Windows', r'Win64', r'Win32'],
    'macOS': [r'Macintosh', r'Mac OS X', r'Mac_PowerPC'],
    'Linux': [r'Linux', r'X11', r'Ubuntu', r'Debian'],
    'Web': [r'Chrome', r'Firefox', r'Safari', r'Edge', r'Opera'],
    'IoT': [r'ESP8266', r'ESP32', r'Raspberry', r'Arduino'],
    'Bot': [r'Googlebot', r'Bingbot', r'Slurp', r'Bot', r'Spider'],
    'API': [r'Python-urllib', r'Java', r'Go-http-client', r'curl'],
}


class PCAPAnalyzer:
    """Classe pour analyser les fichiers PCAP avec extraction maximale d'informations"""
    
    def __init__(self, pcap_file=None, deep_analysis=False):
        self.pcap_file = pcap_file
        self.deep_analysis = deep_analysis
        self.packets = []
        self.incoming_packets = []
        self.stats = {
            'total_packets': 0,
            'incoming_packets': 0,
            'outgoing_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_requests': 0,
            'http_responses': 0,
            'https_requests': 0,
            'dns_queries': 0,
            'dns_responses': 0,
            'tls_handshakes': 0,
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'source_ports': defaultdict(int),
            'dest_ports': defaultdict(int),
            'protocols': defaultdict(int),
            'applications': defaultdict(int),
            'conversations': defaultdict(lambda: {'packets': 0, 'bytes': 0, 'app': None}),
            'http_endpoints': defaultdict(int),
            'dns_domains': defaultdict(int),
            'tcp_flags': defaultdict(int),
            'packet_sizes': [],
            'timestamps': [],
            'user_agents': defaultdict(int),
            'ecosystems': defaultdict(int),
        }
        
        # Données extraites
        self.extracted_data = {
            'emails': set(),
            'phone_numbers': set(),
            'urls': set(),
            'uuids': set(),
            'session_ids': set(),
            'device_ids': set(),
            'user_ids': set(),
            'api_keys': set(),
            'jwt_tokens': set(),
            'base64_strings': set(),
            'json_objects': set(),
            'credentials': set(),
            'cookies': set(),
        }
        
        self.start_time = None
        self.end_time = None
    
    def is_incoming(self, packet):
        """
        Détermine si un paquet est entrant
        """
        if not packet.haslayer(IP):
            return False
        
        ip = packet[IP]
        
        # Méthode basée sur les flags TCP pour identifier le trafic entrant
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # SYN sans ACK = nouvelle connexion entrante
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                return True
            # ACK sans SYN = réponse à une connexion sortante (donc entrant)
            if tcp.flags & 0x10 and not (tcp.flags & 0x02):
                return True
            # Données avec PSH ou ACK
            if tcp.flags & 0x18:
                return True
        
        # Pour UDP et ICMP, on considère comme entrant si c'est une réponse
        # ou si le port source est bien connu (serveur)
        if packet.haslayer(UDP):
            udp = packet[UDP]
            # Ports serveurs courants
            server_ports = [53, 67, 68, 123, 137, 138, 139, 161, 162, 443, 80, 5060, 5061]
            if udp.dport in server_ports:
                return True
        
        if packet.haslayer(ICMP):
            # Les réponses ICMP (echo reply) sont entrantes
            if packet[ICMP].type == 0:  # Echo Reply
                return True
        
        return False
    
    def is_outgoing(self, packet):
        """
        Détermine si un paquet est sortant
        """
        if not packet.haslayer(IP):
            return False
        
        ip = packet[IP]
        
        # Méthode basée sur les flags TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # SYN avec ACK = réponse à une connexion entrante (donc sortant)
            if tcp.flags & 0x12:  # SYN-ACK
                return True
            # SYN seul = nouvelle connexion sortante
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                return False  # C'est entrant
        
        # Pour UDP, ports clients courants
        if packet.haslayer(UDP):
            udp = packet[UDP]
            client_ports = [53, 67, 68, 123]  # DNS, DHCP, NTP
            if udp.sport in client_ports:
                return True
        
        if packet.haslayer(ICMP):
            # Les requêtes ICMP (echo request) sont sortantes
            if packet[ICMP].type == 8:  # Echo Request
                return True
        
        return False
    
    def get_application_name(self, port, packet):
        """Identifie le nom de l'application basée sur le port et le paquet"""
        # Vérifier dans les ports connus
        if port in APPLICATION_PORTS:
            return APPLICATION_PORTS[port]
        
        # Détection basée sur le contenu
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            return 'HTTP'
        
        if packet.haslayer(DNS):
            return 'DNS'
        
        if packet.haslayer(TLSClientHello) or packet.haslayer(TLSServerHello):
            return 'TLS/SSL'
        
        if packet.haslayer(ICMP):
            return 'ICMP'
        
        return 'UNKNOWN'
    
    def detect_ecosystem(self, packet):
        """Détecte l'écosystème basé sur le User-Agent et autres indicateurs"""
        ecosystems = []
        
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            if http.User_Agent:
                user_agent = http.User_Agent.decode('utf-8', errors='ignore')
                for ecosystem, patterns in ECOSYSTEM_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, user_agent, re.IGNORECASE):
                            ecosystems.append(ecosystem)
                            break
        
        # Détection basée sur les ports
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == 5222 or tcp.dport == 5223:
                ecosystems.append('Mobile-Messaging')
            if tcp.dport == 5060 or tcp.dport == 5061:
                ecosystems.append('VoIP')
        
        if packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.dport == 1883 or udp.dport == 8883:
                ecosystems.append('IoT')
        
        return ecosystems if ecosystems else ['Unknown']
    
    def extract_payload_data(self, packet):
        """Extrait les données utiles du payload du paquet"""
        if not self.deep_analysis:
            return
        
        try:
            # Obtenir le payload
            payload = None
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                if tcp.payload:
                    payload = bytes(tcp.payload)
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                if udp.payload:
                    payload = bytes(udp.payload)
            
            if not payload:
                return
            
            # Convertir en string
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except:
                payload_str = str(payload)
            
            # Extraire avec les patterns
            for pattern_name, pattern in PATTERNS.items():
                matches = pattern.findall(payload_str)
                for match in matches:
                    if isinstance(match, tuple):
                        # Pour les patterns avec groupes
                        for m in match:
                            if m and len(m) > 3:
                                if pattern_name == 'phone_numbers':
                                    # Nettoyer le numéro de téléphone
                                    clean_phone = re.sub(r'[^\d+]', '', m)
                                    if len(clean_phone) >= 7:
                                        self.extracted_data[pattern_name].add(clean_phone)
                                elif pattern_name == 'session_ids':
                                    if len(m) > 1:
                                        self.extracted_data[pattern_name].add(m)
                                elif pattern_name == 'device_ids':
                                    if len(m) > 1:
                                        self.extracted_data[pattern_name].add(m)
                                elif pattern_name == 'user_ids':
                                    if len(m) > 1:
                                        self.extracted_data[pattern_name].add(m)
                                elif pattern_name == 'api_keys':
                                    if len(m) > 1:
                                        self.extracted_data[pattern_name].add(m)
                                else:
                                    self.extracted_data[pattern_name].add(m)
                    else:
                        if match and len(match) > 3:
                            self.extracted_data[pattern_name].add(match)
            
            # Extraction spécifique pour les credentials
            self.extract_credentials(payload_str)
            
            # Extraction des cookies
            self.extract_cookies(payload_str)
            
        except Exception as e:
            # Ne pas bloquer l'analyse à cause d'une erreur sur un paquet
            pass
    
    def extract_credentials(self, payload_str):
        """Extrait les credentials (username/password) du payload"""
        # Patterns pour les credentials
        cred_patterns = [
            r'(username|user|login|email)[=:"]?([^&"]+)',
            r'(password|pass|pwd)[=:"]?([^&"]+)',
            r'(auth|authorization)[=:"]?(Basic\s+[a-zA-Z0-9+/=]+|Bearer\s+[a-zA-Z0-9.-]+)',
            r'"(username|user|login|email)"\s*:\s*"([^"]+)"',
            r'"(password|pass|pwd)"\s*:\s*"([^"]+)"',
        ]
        
        for pattern in cred_patterns:
            matches = re.findall(pattern, payload_str, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    field, value = match[0].lower(), match[1]
                    if value and len(value) > 1:
                        self.extracted_data['credentials'].add(f"{field}:{value}")
    
    def extract_cookies(self, payload_str):
        """Extrait les cookies du payload"""
        cookie_patterns = [
            r'Cookie:\s*([^\r\n]+)',
            r'Set-Cookie:\s*([^\r\n]+)',
            r'(cookie|session)[=:"]?([a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)',
        ]
        
        for pattern in cookie_patterns:
            matches = re.findall(pattern, payload_str, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    for m in match:
                        if m and len(m) > 5:
                            self.extracted_data['cookies'].add(m)
                else:
                    if match and len(match) > 5:
                        self.extracted_data['cookies'].add(match)
    
    def analyze_packet(self, packet):
        """Analyse un paquet et met à jour les statistiques"""
        self.stats['total_packets'] += 1
        
        # Déterminer la direction
        is_in = self.is_incoming(packet)
        is_out = self.is_outgoing(packet)
        
        if is_in:
            self.stats['incoming_packets'] += 1
            self.incoming_packets.append(packet)
        elif is_out:
            self.stats['outgoing_packets'] += 1
        
        # Analyse IP
        if packet.haslayer(IP):
            ip = packet[IP]
            self.stats['ip_packets'] += 1
            
            # Statistiques par protocole
            proto = ip.proto
            if proto == 6:  # TCP
                self.stats['tcp_packets'] += 1
                self.stats['protocols']['TCP'] += 1
            elif proto == 17:  # UDP
                self.stats['udp_packets'] += 1
                self.stats['protocols']['UDP'] += 1
            elif proto == 1:  # ICMP
                self.stats['icmp_packets'] += 1
                self.stats['protocols']['ICMP'] += 1
            else:
                self.stats['protocols'][f'OTHER_{proto}'] += 1
            
            # Statistiques par adresse
            self.stats['sources'][ip.src] += 1
            self.stats['destinations'][ip.dst] += 1
            
            # Taille du paquet
            packet_size = len(packet)
            self.stats['packet_sizes'].append(packet_size)
            
            # Timestamp
            if packet.time:
                self.stats['timestamps'].append(packet.time)
        
        # Analyse TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            self.stats['source_ports'][tcp.sport] += 1
            self.stats['dest_ports'][tcp.dport] += 1
            
            # Flags TCP
            flags = tcp.flags
            self.stats['tcp_flags'][self.tcp_flags_to_string(flags)] += 1
            
            # Détecter TLS/SSL
            if tcp.dport == 443 or tcp.sport == 443:
                if packet.haslayer(TLSClientHello) or packet.haslayer(TLSServerHello):
                    self.stats['https_requests'] += 1
                    self.stats['applications']['HTTPS'] += 1
                else:
                    self.stats['applications']['HTTPS'] += 1
            
            # Conversations TCP
            if packet.haslayer(IP):
                ip = packet[IP]
                conv_key = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
                
                # Détecter l'application
                app_name = self.get_application_name(tcp.dport, packet)
                self.stats['applications'][app_name] += 1
                
                # Détecter l'écosystème
                ecosystems = self.detect_ecosystem(packet)
                for eco in ecosystems:
                    self.stats['ecosystems'][eco] += 1
                
                self.stats['conversations'][conv_key]['packets'] += 1
                self.stats['conversations'][conv_key]['bytes'] += len(tcp.payload) if tcp.payload else 0
                self.stats['conversations'][conv_key]['app'] = app_name
        
        # Analyse UDP
        if packet.haslayer(UDP):
            udp = packet[UDP]
            self.stats['source_ports'][udp.sport] += 1
            self.stats['dest_ports'][udp.dport] += 1
            
            # Détecter l'application
            app_name = self.get_application_name(udp.dport, packet)
            self.stats['applications'][app_name] += 1
            
            # DNS
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0:  # Query
                    self.stats['dns_queries'] += 1
                    if dns.qd:
                        for q in dns.qd:
                            if q.qname:
                                domain = q.qname.decode('utf-8', errors='ignore')
                                self.stats['dns_domains'][domain] += 1
                else:  # Response
                    self.stats['dns_responses'] += 1
                    if dns.an:
                        for ans in dns.an:
                            if ans.rdata:
                                domain = ans.rrname.decode('utf-8', errors='ignore')
                                self.stats['dns_domains'][domain] += 1
        
        # Analyse HTTP
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            self.stats['http_requests'] += 1
            self.stats['applications']['HTTP'] += 1
            
            if http.Host:
                host = http.Host.decode('utf-8', errors='ignore')
                self.stats['http_endpoints'][host] += 1
            
            if http.Path:
                path = http.Path.decode('utf-8', errors='ignore')
                endpoint = f"{http.Host.decode('utf-8', errors='ignore') if http.Host else 'unknown'}{path}"
                self.stats['http_endpoints'][endpoint] += 1
            
            # User-Agent
            if http.User_Agent:
                ua = http.User_Agent.decode('utf-8', errors='ignore')
                self.stats['user_agents'][ua] += 1
                
                # Détecter l'écosystème
                ecosystems = self.detect_ecosystem(packet)
                for eco in ecosystems:
                    self.stats['ecosystems'][eco] += 1
        
        if packet.haslayer(HTTPResponse):
            self.stats['http_responses'] += 1
        
        # Extraction des données du payload (analyse approfondie)
        if self.deep_analysis:
            self.extract_payload_data(packet)
    
    def tcp_flags_to_string(self, flags):
        """Convertit les flags TCP en chaîne lisible"""
        flag_names = {
            0x01: 'FIN',
            0x02: 'SYN', 
            0x04: 'RST',
            0x08: 'PSH',
            0x10: 'ACK',
            0x20: 'URG',
            0x40: 'ECE',
            0x80: 'CWR'
        }
        result = []
        for mask, name in flag_names.items():
            if flags & mask:
                result.append(name)
        return ",".join(result) if result else "NONE"
    
    def load_pcap(self, filename):
        """Charge un fichier PCAP"""
        try:
            self.packets = rdpcap(filename)
            self.pcap_file = filename
            print(f"Fichier chargé: {filename}")
            print(f"Nombre de paquets: {len(self.packets)}")
            return True
        except Exception as e:
            print(f"Erreur lors du chargement du fichier: {e}")
            return False
    
    def analyze(self):
        """Analyse tous les paquets"""
        if not self.packets:
            print("Aucun paquet à analyser")
            return False
        
        print(f"Analyse de {len(self.packets)} paquets...")
        if self.deep_analysis:
            print("Mode d'analyse approfondie activé")
        
        # Trouver les timestamps min et max
        timestamps = [p.time for p in self.packets if p.time]
        if timestamps:
            self.start_time = min(timestamps)
            self.end_time = max(timestamps)
        
        # Analyser chaque paquet
        for i, packet in enumerate(self.packets):
            self.analyze_packet(packet)
            if self.deep_analysis and i % 100 == 0:
                print(f"  Traité {i}/{len(self.packets)} paquets...")
        
        print("Analyse terminée")
        return True
    
    def print_summary(self):
        """Affiche un résumé de l'analyse"""
        print("\n" + "="*70)
        print("RÉSUMÉ DE L'ANALYSE PCAP")
        print("="*70)
        
        print(f"Fichier: {self.pcap_file}")
        
        if self.start_time and self.end_time:
            duration = self.end_time - self.start_time
            print(f"Durée: {duration:.2f} secondes")
            print(f"Début: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Fin: {datetime.fromtimestamp(self.end_time).strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\nPaquets totaux: {self.stats['total_packets']}")
        print(f"Paquets entrants: {self.stats['incoming_packets']} ({self.stats['incoming_packets']/self.stats['total_packets']*100:.1f}%)")
        print(f"Paquets sortants: {self.stats['outgoing_packets']} ({self.stats['outgoing_packets']/self.stats['total_packets']*100:.1f}%)")
        
        print(f"\nProtocoles:")
        for proto, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.stats['ip_packets'] * 100) if self.stats['ip_packets'] > 0 else 0
            print(f"  {proto}: {count} ({percentage:.1f}%)")
        
        print(f"\nApplications détectées:")
        for app, count in sorted(self.stats['applications'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {app}: {count}")
        
        print(f"\nÉcosystèmes détectés:")
        for eco, count in sorted(self.stats['ecosystems'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {eco}: {count}")
        
        print(f"\nTop 10 adresses sources:")
        for ip, count in sorted(self.stats['sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
            print(f"  {ip}: {count} ({percentage:.1f}%)")
        
        print(f"\nTop 10 adresses destinations:")
        for ip, count in sorted(self.stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
            print(f"  {ip}: {count} ({percentage:.1f}%)")
        
        print(f"\nTop 10 ports destinations:")
        for port, count in sorted(self.stats['dest_ports'].items(), key=lambda x: x[1], reverse=True)[:10]:
            app_name = APPLICATION_PORTS.get(port, 'UNKNOWN')
            print(f"  {port} ({app_name}): {count}")
        
        if self.stats['tcp_flags']:
            print(f"\nRépartition des flags TCP:")
            for flags, count in sorted(self.stats['tcp_flags'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {flags}: {count}")
        
        if self.stats['http_endpoints']:
            print(f"\nEndpoints HTTP les plus fréquents:")
            for endpoint, count in sorted(self.stats['http_endpoints'].items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {endpoint}: {count}")
        
        if self.stats['dns_domains']:
            print(f"\nDomaines DNS les plus fréquents:")
            for domain, count in sorted(self.stats['dns_domains'].items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {domain}: {count}")
        
        if self.stats['user_agents']:
            print(f"\nTop User-Agents:")
            for ua, count in sorted(self.stats['user_agents'].items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {ua[:60]}...: {count}")
        
        # Statistiques de taille de paquets
        if self.stats['packet_sizes']:
            sizes = self.stats['packet_sizes']
            print(f"\nStatistiques de taille des paquets:")
            print(f"  Min: {min(sizes)} octets")
            print(f"  Max: {max(sizes)} octets")
            print(f"  Moyenne: {sum(sizes)/len(sizes):.1f} octets")
            print(f"  Médiane: {sorted(sizes)[len(sizes)//2]} octets")
        
        # Top conversations
        if self.stats['conversations']:
            print(f"\nTop 10 conversations (par nombre de paquets):")
            for conv, data in sorted(self.stats['conversations'].items(), 
                                    key=lambda x: x[1]['packets'], 
                                    reverse=True)[:10]:
                app = data['app'] if data['app'] else 'UNKNOWN'
                print(f"  {conv} [{app}]: {data['packets']} paquets, {data['bytes']} octets")
    
    def print_incoming_analysis(self):
        """Affiche une analyse spécifique du trafic entrant"""
        print("\n" + "="*70)
        print("ANALYSE DU TRAFIC ENTRANT")
        print("="*70)
        
        if not self.incoming_packets:
            print("Aucun paquet entrant détecté")
            return
        
        print(f"Nombre de paquets entrants: {self.stats['incoming_packets']}")
        
        # Statistiques par protocole pour le trafic entrant
        incoming_protocols = defaultdict(int)
        incoming_sources = defaultdict(int)
        incoming_ports = defaultdict(int)
        incoming_apps = defaultdict(int)
        
        for packet in self.incoming_packets:
            if packet.haslayer(IP):
                ip = packet[IP]
                proto = ip.proto
                if proto == 6:
                    incoming_protocols['TCP'] += 1
                elif proto == 17:
                    incoming_protocols['UDP'] += 1
                elif proto == 1:
                    incoming_protocols['ICMP'] += 1
                else:
                    incoming_protocols[f'OTHER_{proto}'] += 1
                
                incoming_sources[ip.src] += 1
                
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    incoming_ports[tcp.dport] += 1
                    app_name = self.get_application_name(tcp.dport, packet)
                    incoming_apps[app_name] += 1
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    incoming_ports[udp.dport] += 1
                    app_name = self.get_application_name(udp.dport, packet)
                    incoming_apps[app_name] += 1
        
        print(f"\nProtocoles entrants:")
        for proto, count in sorted(incoming_protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.stats['incoming_packets'] * 100) if self.stats['incoming_packets'] > 0 else 0
            print(f"  {proto}: {count} ({percentage:.1f}%)")
        
        print(f"\nApplications entrantes:")
        for app, count in sorted(incoming_apps.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.stats['incoming_packets'] * 100) if self.stats['incoming_packets'] > 0 else 0
            print(f"  {app}: {count} ({percentage:.1f}%)")
        
        print(f"\nTop 10 sources de trafic entrant:")
        for ip, count in sorted(incoming_sources.items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['incoming_packets'] * 100) if self.stats['incoming_packets'] > 0 else 0
            print(f"  {ip}: {count} ({percentage:.1f}%)")
        
        print(f"\nTop 10 ports destinations pour le trafic entrant:")
        for port, count in sorted(incoming_ports.items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['incoming_packets'] * 100) if self.stats['incoming_packets'] > 0 else 0
            app_name = APPLICATION_PORTS.get(port, 'UNKNOWN')
            print(f"  {port} ({app_name}): {count} ({percentage:.1f}%)")
        
        # Détection de patterns suspects
        print(f"\nAnalyse de sécurité:")
        self.detect_suspicious_patterns()
    
    def print_extracted_data(self):
        """Affiche les données extraites du payload"""
        if not self.deep_analysis:
            print("\nActivez le mode d'analyse approfondie (--deep) pour voir les données extraites")
            return
        
        print("\n" + "="*70)
        print("DONNÉES EXTRAITES DU PAYLOAD")
        print("="*70)
        
        has_data = False
        
        for data_type, data_set in self.extracted_data.items():
            if data_set:
                has_data = True
                print(f"\n{data_type.upper().replace('_', ' ')} ({len(data_set)}):")
                for i, item in enumerate(sorted(data_set)[:20]):  # Limiter à 20 par type
                    print(f"  {i+1}. {item}")
                if len(data_set) > 20:
                    print(f"  ... et {len(data_set) - 20} de plus")
        
        if not has_data:
            print("Aucune donnée intéressante extraite du payload")
    
    def detect_suspicious_patterns(self):
        """Détecte les patterns suspects dans le trafic entrant"""
        suspicious_findings = []
        
        # 1. Port scanning (beaucoup de connexions sur différents ports)
        if len(self.stats['dest_ports']) > 20:
            unique_ports = len(self.stats['dest_ports'])
            if unique_ports > 50:
                suspicious_findings.append(f"⚠️  Possible port scanning: {unique_ports} ports différents ciblés")
        
        # 2. Beaucoup de connexions depuis une seule IP
        if self.stats['sources']:
            max_connections = max(self.stats['sources'].values())
            if max_connections > 1000:
                suspicious_ip = max(self.stats['sources'].items(), key=lambda x: x[1])[0]
                suspicious_findings.append(f"⚠️  Beaucoup de connexions depuis {suspicious_ip}: {max_connections} paquets")
        
        # 3. Trafic ICMP excessif (ping flood)
        if self.stats['icmp_packets'] > 100:
            percentage = (self.stats['icmp_packets'] / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
            if percentage > 10:
                suspicious_findings.append(f"⚠️  Trafic ICMP élevé: {self.stats['icmp_packets']} paquets ({percentage:.1f}%)")
        
        # 4. Trafic sur des ports suspects
        suspicious_ports = [22, 23, 21, 3389, 5900, 4444, 6667]
        for port in suspicious_ports:
            if port in self.stats['dest_ports']:
                suspicious_findings.append(f"⚠️  Trafic sur port suspect {port} ({APPLICATION_PORTS.get(port, 'UNKNOWN')}): {self.stats['dest_ports'][port]} paquets")
        
        # 5. Beaucoup de SYN sans ACK (SYN flood)
        if 'SYN' in self.stats['tcp_flags']:
            syn_count = self.stats['tcp_flags']['SYN']
            if syn_count > 100:
                percentage = (syn_count / sum(self.stats['tcp_flags'].values()) * 100) if self.stats['tcp_flags'] else 0
                if percentage > 30:
                    suspicious_findings.append(f"⚠️  Beaucoup de paquets SYN: {syn_count} ({percentage:.1f}%)")
        
        # 6. Détection de credentials dans le trafic
        if self.deep_analysis and self.extracted_data['credentials']:
            suspicious_findings.append(f"⚠️  {len(self.extracted_data['credentials'])} credentials potentiels détectés dans le payload")
        
        # 7. Détection d'API keys
        if self.deep_analysis and self.extracted_data['api_keys']:
            suspicious_findings.append(f"⚠️  {len(self.extracted_data['api_keys'])} API keys potentielles détectées")
        
        # 8. Détection de JWT tokens
        if self.deep_analysis and self.extracted_data['jwt_tokens']:
            suspicious_findings.append(f"⚠️  {len(self.extracted_data['jwt_tokens'])} JWT tokens détectés")
        
        if suspicious_findings:
            for finding in suspicious_findings:
                print(f"  {finding}")
        else:
            print("  Aucun pattern suspect détecté")
    
    def save_report(self, filename):
        """Sauvegarde un rapport d'analyse dans un fichier"""
        try:
            with open(filename, 'w') as f:
                f.write("="*70 + "\n")
                f.write("RAPPORT D'ANALYSE PCAP - DÉTAILLÉ\n")
                f.write("="*70 + "\n\n")
                
                f.write(f"Fichier: {self.pcap_file}\n")
                if self.start_time and self.end_time:
                    duration = self.end_time - self.start_time
                    f.write(f"Durée: {duration:.2f} secondes\n")
                    f.write(f"Début: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Fin: {datetime.fromtimestamp(self.end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                f.write(f"\nPaquets totaux: {self.stats['total_packets']}\n")
                f.write(f"Paquets entrants: {self.stats['incoming_packets']}\n")
                f.write(f"Paquets sortants: {self.stats['outgoing_packets']}\n")
                
                f.write(f"\nProtocoles:\n")
                for proto, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {proto}: {count}\n")
                
                f.write(f"\nApplications:\n")
                for app, count in sorted(self.stats['applications'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {app}: {count}\n")
                
                f.write(f"\nÉcosystèmes:\n")
                for eco, count in sorted(self.stats['ecosystems'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {eco}: {count}\n")
                
                f.write(f"\nTop 10 adresses sources:\n")
                for ip, count in sorted(self.stats['sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {ip}: {count}\n")
                
                f.write(f"\nTop 10 adresses destinations:\n")
                for ip, count in sorted(self.stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {ip}: {count}\n")
                
                f.write(f"\nTop 10 ports destinations:\n")
                for port, count in sorted(self.stats['dest_ports'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    app_name = APPLICATION_PORTS.get(port, 'UNKNOWN')
                    f.write(f"  {port} ({app_name}): {count}\n")
                
                if self.stats['http_endpoints']:
                    f.write(f"\nEndpoints HTTP:\n")
                    for endpoint, count in sorted(self.stats['http_endpoints'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(f"  {endpoint}: {count}\n")
                
                if self.stats['dns_domains']:
                    f.write(f"\nDomaines DNS:\n")
                    for domain, count in sorted(self.stats['dns_domains'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(f"  {domain}: {count}\n")
                
                if self.stats['user_agents']:
                    f.write(f"\nUser-Agents:\n")
                    for ua, count in sorted(self.stats['user_agents'].items(), key=lambda x: x[1], reverse=True)[:5]:
                        f.write(f"  {ua[:100]}: {count}\n")
                
                # Données extraites
                if self.deep_analysis:
                    f.write(f"\n" + "="*70 + "\n")
                    f.write("DONNÉES EXTRAITES\n")
                    f.write("="*70 + "\n\n")
                    
                    for data_type, data_set in self.extracted_data.items():
                        if data_set:
                            f.write(f"\n{data_type.upper().replace('_', ' ')}:\n")
                            for item in sorted(data_set)[:20]:
                                f.write(f"  - {item}\n")
                            if len(data_set) > 20:
                                f.write(f"  ... et {len(data_set) - 20} de plus\n")
            
            print(f"Rapport sauvegardé dans: {filename}")
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde du rapport: {e}")
            return False
    
    def save_json(self, filename):
        """Sauvegarde les statistiques au format JSON"""
        try:
            # Convertir defaultdict en dict standard pour la sérialisation
            stats_dict = {}
            for key, value in self.stats.items():
                if isinstance(value, defaultdict):
                    stats_dict[key] = dict(value)
                else:
                    stats_dict[key] = value
            
            # Convertir les sets en listes
            extracted_dict = {}
            for key, value in self.extracted_data.items():
                extracted_dict[key] = list(value)
            
            data = {
                'filename': self.pcap_file,
                'start_time': self.start_time,
                'end_time': self.end_time,
                'duration': (self.end_time - self.start_time) if self.start_time and self.end_time else None,
                'stats': stats_dict,
                'extracted_data': extracted_dict,
                'deep_analysis': self.deep_analysis
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"Statistiques sauvegardées au format JSON: {filename}")
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde JSON: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Analyse avancée de fichiers PCAP avec extraction maximale d\'informations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python analyze_pcap.py capture.pcap
  python analyze_pcap.py -f capture.pcap -o rapport.txt
  python analyze_pcap.py -f capture.pcap --deep --json output.json
  python analyze_pcap.py --incoming-only --deep capture.pcap
        """
    )
    
    parser.add_argument(
        'file',
        nargs='?',
        help='Fichier PCAP à analyser'
    )
    
    parser.add_argument(
        '-f', '--file',
        dest='input_file',
        help='Fichier PCAP à analyser'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Fichier de sortie pour le rapport'
    )
    
    parser.add_argument(
        '--json',
        help='Sauvegarder les statistiques au format JSON'
    )
    
    parser.add_argument(
        '--incoming-only',
        action='store_true',
        help='Afficher uniquement l\'analyse du trafic entrant'
    )
    
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Activer l\'analyse approfondie (extraction de données du payload)'
    )
    
    parser.add_argument(
        '--no-payload',
        action='store_true',
        help='Désactiver l\'extraction du payload (plus rapide)'
    )
    
    args = parser.parse_args()
    
    # Gestion des arguments
    input_file = args.input_file or args.file
    deep_analysis = args.deep and not args.no_payload
    
    if not input_file:
        print("Erreur: Veuillez spécifier un fichier PCAP à analyser")
        parser.print_help()
        return 1
    
    if not os.path.exists(input_file):
        print(f"Erreur: Le fichier {input_file} n'existe pas")
        return 1
    
    # Créer l'analyseur
    analyzer = PCAPAnalyzer(deep_analysis=deep_analysis)
    
    # Charger le fichier
    if not analyzer.load_pcap(input_file):
        return 1
    
    # Analyser
    if not analyzer.analyze():
        return 1
    
    # Afficher les résultats
    if args.incoming_only:
        analyzer.print_incoming_analysis()
        if deep_analysis:
            analyzer.print_extracted_data()
    else:
        analyzer.print_summary()
        analyzer.print_incoming_analysis()
        if deep_analysis:
            analyzer.print_extracted_data()
    
    # Sauvegarder les résultats
    if args.output:
        analyzer.save_report(args.output)
    
    if args.json:
        analyzer.save_json(args.json)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
