#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import unicodedata
from datetime import datetime
from collections import defaultdict, Counter
import argparse
import json
import base64
import hashlib
from html import escape as html_escape

# Forcer l'encodage UTF-8 pour la sortie console (surtout sous Windows)
# Désactiver colorama qui peut causer des problèmes d'encodage
import os
os.environ['COLORAMA'] = '0'  # Désactiver colorama

if sys.platform == 'win32':
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

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
    
    # Détection MPLS
    try:
        from scapy.layers.mpls import MPLS
        MPLS_AVAILABLE = True
    except ImportError:
        MPLS_AVAILABLE = False
        # Valeurs de protocole MPLS pour détection manuelle
        MPLS_PROTOCOLS = {0x8847: 'MPLS', 0x8848: 'MPLS_MCAST'}
    
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Erreur: Scapy non disponible - {e}")
    sys.exit(1)


# ============================================================================
# PATTERNS POUR L'EXTRACTION D'INFORMATIONS
# ============================================================================

# Patterns pour l'extraction d'informations
PATTERNS = {
    # Emails
    'emails': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE),
    
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

# ============================================================================
# PATTERNS POUR LA DÉTECTION DES DONNÉES SENSIBLES
# ============================================================================

CREDIT_CARD_PATTERNS = {
    'Visa': re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),
    'MasterCard': re.compile(r'\b5[1-5][0-9]{14}\b'),
    'Amex': re.compile(r'\b3[47][0-9]{13}\b'),
    'Discover': re.compile(r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'),
}

SSN_PATTERN = re.compile(r'\b[0-9]{3}-?[0-9]{2}-?[0-9]{4}\b')
NIRA_PATTERN = re.compile(r'\b[0-9]{13}\b')
PASSPORT_PATTERNS = [
    re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'),
    re.compile(r'\b[0-9]{8,9}\b'),
]

# ============================================================================
# PATTERNS POUR LA DÉTECTION DES ATTAQUES
# ============================================================================

SQLI_PATTERNS = [
    re.compile(r"('|\"|`|\b)(?:OR|AND)\s+('|\"|`|\b)", re.IGNORECASE),
    re.compile(r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*\b(?:FROM|INTO|TABLE)\b', re.IGNORECASE),
    re.compile(r'\b(?:EXEC|EXECUTE|DECLARE)\b', re.IGNORECASE),
    re.compile(r'\b(?:1=1|OR\s+1=1|AND\s+1=1)\b', re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'on\w+\s*=\s*["\']?\s*javascript:', re.IGNORECASE),
    re.compile(r'\b(?:alert|eval|document\.cookie)\s*\([^)]*\)', re.IGNORECASE),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r'[;|&`$><]\s*(?:ls|cat|echo|whoami|wget|curl|nc|sh|bash)', re.IGNORECASE),
    re.compile(r'\b(?:system|exec|popen)\s*\([^)]*\)', re.IGNORECASE),
]

# ============================================================================
# SIGNATURES POUR LA DÉTECTION DES PROTOCOLES APPLICATIFS
# ============================================================================

HTTP2_MAGIC = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
WEBSOCKET_PATTERN = re.compile(r'Sec-WebSocket-Key:\s*[a-zA-Z0-9+/=]+', re.IGNORECASE)
GRPC_CONTENT_TYPE = b'application/grpc'

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
        
        # TCP Stream Reassembly
        self.tcp_streams = defaultdict(list)
        self.reassembled_streams = defaultdict(bytes)
        
        # Advanced analysis results
        self.attack_findings = []
        self.sensitive_data_findings = []
        self.protocol_detections = defaultdict(int)
        self.temporal_analysis = {}
        
        # MPLS specific
        self.mpls_packets = 0
        self.mpls_labels = defaultdict(int)
        self.mpls_warnings = []
    
    def reassemble_tcp_streams(self):
        """Reassemble TCP streams from packets"""
        if not self.packets:
            return
        
        for packet in self.packets:
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                continue
            
            ip = packet[IP]
            tcp = packet[TCP]
            endpoints = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))
            stream_key = (endpoints[0][0], endpoints[0][1], endpoints[1][0], endpoints[1][1])
            
            payload = bytes(tcp.payload) if tcp.payload else b''
            seq_num = tcp.seq
            
            self.tcp_streams[stream_key].append({
                'seq': seq_num,
                'payload': payload,
                'flags': tcp.flags,
                'time': packet.time if hasattr(packet, 'time') else None
            })
        
        for stream_key, packets in self.tcp_streams.items():
            packets.sort(key=lambda x: x['seq'])
            reassembled = b''.join(pkt['payload'] for pkt in packets)
            self.reassembled_streams[stream_key] = reassembled
    
    def detect_application_protocols(self):
        """Detect advanced application protocols"""
        for stream_key, data in self.reassembled_streams.items():
            if data.startswith(HTTP2_MAGIC):
                self.protocol_detections['HTTP/2'] += 1
            elif WEBSOCKET_PATTERN.search(data.decode('utf-8', errors='ignore')):
                self.protocol_detections['WebSocket'] += 1
            elif GRPC_CONTENT_TYPE in data:
                self.protocol_detections['gRPC'] += 1
    
    def perform_temporal_analysis(self):
        """Perform advanced temporal analysis"""
        if not self.stats['timestamps'] or len(self.stats['timestamps']) < 2:
            return
        
        timestamps = sorted(self.stats['timestamps'])
        duration = timestamps[-1] - timestamps[0]
        if duration <= 0:
            duration = 1
        
        pps = len(timestamps) / duration
        total_bytes = sum(self.stats['packet_sizes'])
        throughput = total_bytes / duration
        
        self.temporal_analysis = {
            'duration': duration,
            'packets_per_second': pps,
            'throughput_bytes_per_second': throughput,
            'total_bytes': total_bytes,
            'average_packet_size': total_bytes / len(timestamps) if timestamps else 0,
        }
    
    def luhn_check(self, card_number):
        """Validate credit card number using Luhn algorithm"""
        card_number = re.sub(r'[^0-9]', '', card_number)
        if not card_number.isdigit():
            return False
        
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        
        return checksum % 10 == 0
    
    def detect_sensitive_data(self, payload_str):
        """Detect sensitive data in payload"""
        findings = []
        
        for card_type, pattern in CREDIT_CARD_PATTERNS.items():
            for match in pattern.findall(payload_str):
                if self.luhn_check(match):
                    findings.append({'type': 'Credit Card', 'subtype': card_type, 'value': match, 'severity': 'HIGH'})
        
        for match in SSN_PATTERN.findall(payload_str):
            findings.append({'type': 'SSN', 'value': match, 'severity': 'HIGH'})
        
        for match in NIRA_PATTERN.findall(payload_str):
            findings.append({'type': 'NIRA', 'value': match, 'severity': 'HIGH'})
        
        for pattern in PASSPORT_PATTERNS:
            for match in pattern.findall(payload_str):
                findings.append({'type': 'Passport', 'value': match, 'severity': 'MEDIUM'})
        
        return findings
    
    def detect_attacks(self, payload_str):
        """Detect attack patterns in payload"""
        findings = []
        
        for pattern in SQLI_PATTERNS:
            for match in pattern.findall(payload_str):
                if isinstance(match, tuple):
                    match = ' '.join([m for m in match if m])
                if match:
                    findings.append({'type': 'SQL Injection', 'pattern': str(pattern.pattern)[:50], 'value': match[:100], 'severity': 'CRITICAL'})
        
        for pattern in XSS_PATTERNS:
            for match in pattern.findall(payload_str):
                if isinstance(match, tuple):
                    match = ' '.join([m for m in match if m])
                if match:
                    findings.append({'type': 'XSS', 'pattern': str(pattern.pattern)[:50], 'value': match[:100], 'severity': 'HIGH'})
        
        for pattern in COMMAND_INJECTION_PATTERNS:
            for match in pattern.findall(payload_str):
                if isinstance(match, tuple):
                    match = ' '.join([m for m in match if m])
                if match:
                    findings.append({'type': 'Command Injection', 'pattern': str(pattern.pattern)[:50], 'value': match[:100], 'severity': 'CRITICAL'})
        
        return findings
    
    def detect_mpls(self, packet):
        """Détecte et analyse les paquets MPLS"""
        is_mpls = False
        label = None
        
        # Méthode 1: Utiliser la couche MPLS si disponible
        if MPLS_AVAILABLE and packet.haslayer(MPLS):
            is_mpls = True
            mpls_layer = packet[MPLS]
            label = mpls_layer.label
            self.mpls_labels[label] += 1
            
            # Essayer d'extraire l'IP originale si MPLS est décapsulé
            if packet.haslayer(IP):
                ip = packet[IP]
                return True, label, ip.src, ip.dst
            
            return True, label, None, None
        
        # Méthode 2: Détection manuelle via Ether type
        if packet.haslayer(Ether):
            ether = packet[Ether]
            ethertype = ether.type
            if ethertype in MPLS_PROTOCOLS:
                is_mpls = True
                # Essayer de trouver l'IP après MPLS
                if packet.haslayer(IP):
                    ip = packet[IP]
                    return True, ethertype, ip.src, ip.dst
                return True, ethertype, None, None
        
        # Méthode 3: Détection via protocole IP
        if packet.haslayer(IP):
            ip = packet[IP]
            if ip.proto == 0x8847 or ip.proto == 0x8848:
                is_mpls = True
                return True, ip.proto, None, None
        
        return False, None, None, None
    
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
            
            # Détection des données sensibles
            sensitive_findings = self.detect_sensitive_data(payload_str)
            self.sensitive_data_findings.extend(sensitive_findings)
            
            # Détection des attaques
            attack_findings = self.detect_attacks(payload_str)
            self.attack_findings.extend(attack_findings)
            
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
        
        # Détection MPLS
        is_mpls, mpls_label, mpls_src, mpls_dst = self.detect_mpls(packet)
        if is_mpls:
            self.mpls_packets += 1
            if mpls_label:
                self.mpls_labels[mpls_label] += 1
            
            # Ajouter un avertissement si c'est la première fois qu'on voit MPLS
            if self.mpls_packets == 1:
                self.mpls_warnings.append(
                    "[ALERTE] Trafic MPLS détecté - L'analyse des adresses IP et ports peut être limitée. "
                    "Pour une analyse complète, capturez les paquets APRES la décapsulation MPLS (sur le PE ou CE router)."
                )
            
            # Si on a pu extraire des adresses IP malgré MPLS
            if mpls_src and mpls_dst:
                self.stats['sources'][mpls_src] += 1
                self.stats['destinations'][mpls_dst] += 1
        
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
            # Essayer avec conf.use_pcap = False si libpcap n'est pas disponible
            try:
                from scapy.config import conf
                conf.use_pcap = False
                self.packets = rdpcap(filename)
                self.pcap_file = filename
                print(f"Fichier chargé (mode sans libpcap): {filename}")
                print(f"Nombre de paquets: {len(self.packets)}")
                return True
            except Exception as e2:
                print(f"Erreur lors du chargement du fichier: {e2}")
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
        timestamps = []
        for p in self.packets:
            if hasattr(p, 'time') and p.time is not None:
                try:
                    # Convertir en float si c'est un EDecimal ou autre type
                    ts = float(p.time)
                    timestamps.append(ts)
                except (TypeError, ValueError):
                    # Ignorer les timestamps invalides
                    continue
        
        if timestamps:
            self.start_time = min(timestamps)
            self.end_time = max(timestamps)
        
        # Analyser chaque paquet
        for i, packet in enumerate(self.packets):
            self.analyze_packet(packet)
            if self.deep_analysis and i % 100 == 0:
                print(f"  Traité {i}/{len(self.packets)} paquets...")
        
        # Advanced analysis (Phase 2)
        if self.deep_analysis:
            # TCP Stream Reassembly
            self.reassemble_tcp_streams()
            
            # Application protocol detection
            self.detect_application_protocols()
            
            # Temporal analysis
            self.perform_temporal_analysis()
        
        print("Analyse terminée")
        return True
    
    def print_summary(self):
        """Affiche un résumé de l'analyse"""
        print("\n" + "="*70)
        print("RÉSUMÉ DE L'ANALYSE PCAP")
        print("="*70)
        
        print(f"Fichier: {self.pcap_file}")
        
        if self.start_time and self.end_time:
            try:
                duration = float(self.end_time) - float(self.start_time)
                print(f"Durée: {duration:.2f} secondes")
                print(f"Début: {datetime.fromtimestamp(float(self.start_time)).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Fin: {datetime.fromtimestamp(float(self.end_time)).strftime('%Y-%m-%d %H:%M:%S')}")
            except (TypeError, ValueError):
                print("Durée: Inconnue")
        
        # Statistiques MPLS
        if self.mpls_packets > 0:
            print(f"\n[MPLS] Paquets MPLS détectés: {self.mpls_packets} ({self.mpls_packets/self.stats['total_packets']*100:.1f}%)")
            if self.mpls_labels:
                print("[MPLS] Labels détectés:")
                for label, count in sorted(self.mpls_labels.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  Label {label}: {count} paquets")
            for warning in self.mpls_warnings:
                print(f"\n{warning}")
        
        print(f"\nPaquets totaux: {self.stats['total_packets']}")
        if self.stats['total_packets'] > 0:
            incoming_pct = (self.stats['incoming_packets'] / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
            outgoing_pct = (self.stats['outgoing_packets'] / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
            print(f"Paquets entrants: {self.stats['incoming_packets']} ({incoming_pct:.1f}%)")
            print(f"Paquets sortants: {self.stats['outgoing_packets']} ({outgoing_pct:.1f}%)")
        else:
            print(f"Paquets entrants: {self.stats['incoming_packets']}")
            print(f"Paquets sortants: {self.stats['outgoing_packets']}")
        
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
        
        # 1. Port scanning (beaucoup de connexions sur differents ports)
        if len(self.stats['dest_ports']) > 20:
            unique_ports = len(self.stats['dest_ports'])
            if unique_ports > 50:
                suspicious_findings.append(f"[ALERTE] Possible port scanning: {unique_ports} ports differents cibles")
        
        # 2. Beaucoup de connexions depuis une seule IP
        if self.stats['sources']:
            max_connections = max(self.stats['sources'].values())
            if max_connections > 1000:
                suspicious_ip = max(self.stats['sources'].items(), key=lambda x: x[1])[0]
                suspicious_findings.append(f"[ALERTE] Beaucoup de connexions depuis {suspicious_ip}: {max_connections} paquets")
        
        # 3. Trafic ICMP excessif (ping flood)
        if self.stats['icmp_packets'] > 100:
            percentage = (self.stats['icmp_packets'] / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
            if percentage > 10:
                suspicious_findings.append(f"[ALERTE] Trafic ICMP eleve: {self.stats['icmp_packets']} paquets ({percentage:.1f} pct)")
        
        # 4. Trafic sur des ports suspects
        suspicious_ports = [22, 23, 21, 3389, 5900, 4444, 6667]
        for port in suspicious_ports:
            if port in self.stats['dest_ports']:
                suspicious_findings.append(f"[ALERTE] Trafic sur port suspect {port} ({APPLICATION_PORTS.get(port, 'UNKNOWN')}): {self.stats['dest_ports'][port]} paquets")
        
        # 5. Beaucoup de SYN sans ACK (SYN flood)
        if 'SYN' in self.stats['tcp_flags']:
            syn_count = self.stats['tcp_flags']['SYN']
            if syn_count > 100:
                percentage = (syn_count / sum(self.stats['tcp_flags'].values()) * 100) if self.stats['tcp_flags'] else 0
                if percentage > 30:
                    suspicious_findings.append(f"[ALERTE] Beaucoup de paquets SYN: {syn_count} ({percentage:.1f} pct)")
        
        # 6. Detection de credentials dans le trafic
        if self.deep_analysis and self.extracted_data['credentials']:
            suspicious_findings.append(f"[ALERTE] {len(self.extracted_data['credentials'])} credentials potentiels detectes dans le payload")
        
        # 7. Detection d'API keys
        if self.deep_analysis and self.extracted_data['api_keys']:
            suspicious_findings.append(f"[ALERTE] {len(self.extracted_data['api_keys'])} API keys potentielles detectees")
        
        # 8. Detection de JWT tokens
        if self.deep_analysis and self.extracted_data['jwt_tokens']:
            suspicious_findings.append(f"[ALERTE] {len(self.extracted_data['jwt_tokens'])} JWT tokens detectes")
        
        if suspicious_findings:
            for finding in suspicious_findings:
                print(f"  {finding}")
        else:
            print("  Aucun pattern suspect détecté")
    
    def clean_string(self, text):
        """
        Translittère une chaîne de caractères pour convertir les caractères exotiques 
        (hébreu, arabe, farsi, chinois, etc.) en leur équivalent ASCII le plus proche.
        
        Exemples:
            "例子" -> "li ju" (chinois)
            "سلام" -> "slam" (arabe)  
            "فارسى" -> "farsy" (farsi)
            "test\u05fb" -> "test" (hébreu)
        """
        if not isinstance(text, str):
            text = str(text)
        
        # Dictionnaire de translittération pour les caractères courants
        translit_map = {
            # Hébreu
            '\u05d0': 'a', '\u05d1': 'b', '\u05d2': 'g', '\u05d3': 'd', '\u05d4': 'h',
            '\u05d5': 'v', '\u05d6': 'z', '\u05d7': 'h', '\u05d8': 't', '\u05d9': 'y',
            '\u05da': 'k', '\u05db': 'kh', '\u05dc': 'l', '\u05dd': 'm', '\u05de': 'm',
            '\u05df': 'n', '\u05e0': 'n', '\u05e1': 's', '\u05e2': 'a', '\u05e3': 'f',
            '\u05e4': 'p', '\u05e5': 'p', '\u05e6': 'ts', '\u05e7': 'k', '\u05e8': 'r',
            '\u05e9': 'sh', '\u05ea': 't',
            # Maqaf hébreu (tiret)
            '\u05fb': '-',
            # Autres caractères hébreux
            '\u05f3': '/', '\u05f4': '/',
            
            # Arabe (simplifié)
            '\u0627': 'a', '\u0628': 'b', '\u062a': 't', '\u062b': 'th', '\u062c': 'j',
            '\u062d': 'h', '\u062e': 'kh', '\u062f': 'd', '\u0630': 'th', '\u0631': 'r',
            '\u0632': 'z', '\u0633': 's', '\u0634': 'sh', '\u0635': 's', '\u0636': 'd',
            '\u0637': 't', '\u0638': 'z', '\u0639': 'e', '\u063a': 'gh', '\u0641': 'f',
            '\u0642': 'q', '\u0643': 'k', '\u0644': 'l', '\u0645': 'm', '\u0646': 'n',
            '\u0647': 'h', '\u0648': 'w', '\u0649': 'y',
            
            # Farsi/Persan (simplifié)
            '\u067e': 'p', '\u067f': 'ch', '\u0680': 'zh', '\u06a9': 'g', '\u06af': 'g',
            '\u06be': 'h', '\u06cc': 'y',
            
            # Chinois (pinyin simplifié pour les caractères courants)
            '\u4e2d': 'zhong', '\u56fd': 'guo', '\u4e00': 'yi', '\u4e8c': 'er',
            '\u4e09': 'san', '\u56db': 'si', '\u4e94': 'wu', '\u516d': 'liu',
            '\u4e03': 'qi', '\u516b': 'ba', '\u4e07': 'wan',
        }
        
        result = []
        for char in text:
            # Vérifier si le caractère est ASCII
            if ord(char) < 128:
                result.append(char)
            else:
                # Essayer de trouver une translittération
                if char in translit_map:
                    result.append(translit_map[char])
                else:
                    # Pour les autres caractères, essayer de les décomposer
                    try:
                        # Normalisation NFKD pour séparer les caractères accentués
                        import unicodedata
                        normalized = unicodedata.normalize('NFKD', char)
                        # Garder seulement les parties ASCII
                        ascii_parts = [c for c in normalized if ord(c) < 128]
                        if ascii_parts:
                            result.extend(ascii_parts)
                        # Sinon, ignorer
                    except:
                        # Si tout échoue, ignorer le caractère
                        pass
        
        return ''.join(result)
    
    def save_report(self, filename):
        """Sauvegarde un rapport d'analyse dans un fichier"""
        try:
            # Forcer l'encodage UTF-8 et ignorer les erreurs
            # Appliquer clean_string à TOUT ce qui est écrit
            with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(self.clean_string("="*70 + "\n"))
                f.write(self.clean_string("RAPPORT D'ANALYSE PCAP - DETAILLE\n"))
                f.write(self.clean_string("="*70 + "\n\n"))
                
                if self.start_time and self.end_time:
                    try:
                        duration = self.end_time - self.start_time
                        f.write(self.clean_string(f"Duree: {duration:.2f} secondes\n"))
                        f.write(self.clean_string(f"Debut: {datetime.fromtimestamp(float(self.start_time)).strftime('%Y-%m-%d %H:%M:%S')}\n"))
                        f.write(self.clean_string(f"Fin: {datetime.fromtimestamp(float(self.end_time)).strftime('%Y-%m-%d %H:%M:%S')}\n"))
                    except (TypeError, ValueError):
                        f.write(self.clean_string("Duree: Inconnue\n"))
                
                f.write(self.clean_string(f"\nPaquets totaux: {self.stats['total_packets']}\n"))
                f.write(self.clean_string(f"Paquets entrants: {self.stats['incoming_packets']}\n"))
                f.write(self.clean_string(f"Paquets sortants: {self.stats['outgoing_packets']}\n"))
                
                f.write(self.clean_string(f"\nProtocoles:\n"))
                for proto, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                    f.write(self.clean_string(f"  {proto}: {count}\n"))
                
                f.write(self.clean_string(f"\nApplications:\n"))
                for app, count in sorted(self.stats['applications'].items(), key=lambda x: x[1], reverse=True):
                    f.write(self.clean_string(f"  {app}: {count}\n"))
                
                f.write(self.clean_string(f"\nEcosystemes:\n"))
                for eco, count in sorted(self.stats['ecosystems'].items(), key=lambda x: x[1], reverse=True):
                    f.write(self.clean_string(f"  {eco}: {count}\n"))
                
                f.write(self.clean_string(f"\nTop 10 adresses sources:\n"))
                for ip, count in sorted(self.stats['sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(self.clean_string(f"  {ip}: {count}\n"))
                
                f.write(self.clean_string(f"\nTop 10 adresses destinations:\n"))
                for ip, count in sorted(self.stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(self.clean_string(f"  {ip}: {count}\n"))
                
                f.write(self.clean_string(f"\nTop 10 ports destinations:\n"))
                for port, count in sorted(self.stats['dest_ports'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    app_name = APPLICATION_PORTS.get(port, 'UNKNOWN')
                    f.write(self.clean_string(f"  {port} ({app_name}): {count}\n"))
                
                if self.stats['http_endpoints']:
                    f.write(self.clean_string(f"\nEndpoints HTTP:\n"))
                    for endpoint, count in sorted(self.stats['http_endpoints'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(self.clean_string(f"  {endpoint}: {count}\n"))
                
                if self.stats['dns_domains']:
                    f.write(self.clean_string(f"\nDomaines DNS:\n"))
                    for domain, count in sorted(self.stats['dns_domains'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(self.clean_string(f"  {domain}: {count}\n"))
                
                if self.stats['user_agents']:
                    f.write(self.clean_string(f"\nUser-Agents:\n"))
                    for ua, count in sorted(self.stats['user_agents'].items(), key=lambda x: x[1], reverse=True)[:5]:
                        f.write(self.clean_string(f"  {ua[:100]}: {count}\n"))
                
                # Donnees extraites
                if self.deep_analysis:
                    f.write(self.clean_string(f"\n{'='*70}\n"))
                    f.write(self.clean_string("DONNEES EXTRAITES\n"))
                    f.write(self.clean_string(f"{'='*70}\n\n"))
                    
                    for data_type, data_set in self.extracted_data.items():
                        if data_set:
                            f.write(self.clean_string(f"\n{data_type.upper().replace('_', ' ')}:\n"))
                            for item in sorted(data_set)[:20]:
                                f.write(self.clean_string(f"  - {item}\n"))
                            if len(data_set) > 20:
                                f.write(self.clean_string(f"  ... et {len(data_set) - 20} de plus\n"))
            
            print(f"Rapport sauvegardé dans: {filename}")
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde du rapport: {e}")
            return False
    
    def save_json(self, filename):
        """Sauvegarde les statistiques au format JSON"""
        try:
            # Convertir defaultdict en dict standard pour la sérialisation
            # et nettoyer les clés et valeurs
            stats_dict = {}
            for key, value in self.stats.items():
                clean_key = self.clean_string(str(key))
                if isinstance(value, defaultdict):
                    stats_dict[clean_key] = {self.clean_string(str(k)): v for k, v in value.items()}
                elif isinstance(value, dict):
                    stats_dict[clean_key] = {self.clean_string(str(k)): v for k, v in value.items()}
                else:
                    stats_dict[clean_key] = value
            
            # Convertir les sets en listes et nettoyer les caractères
            extracted_dict = {}
            for key, value in self.extracted_data.items():
                extracted_dict[key] = [self.clean_string(item) for item in value]
            
            try:
                duration = (self.end_time - self.start_time) if self.start_time and self.end_time else None
            except (TypeError, ValueError):
                duration = None
            
            data = {
                'filename': self.pcap_file,
                'start_time': float(self.start_time) if self.start_time else None,
                'end_time': float(self.end_time) if self.end_time else None,
                'duration': duration,
                'stats': stats_dict,
                'extracted_data': extracted_dict,
                'deep_analysis': self.deep_analysis,
                'mpls_stats': {
                    'mpls_packets': self.mpls_packets,
                    'mpls_labels': dict(self.mpls_labels),
                    'mpls_warnings': self.mpls_warnings
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"Statistiques sauvegardées au format JSON: {filename}")
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde JSON: {e}")
            return False
    
    def save_html(self, filename):
        """Sauvegarde un rapport HTML complet"""
        try:
            html = []
            html.append('<!DOCTYPE html>')
            html.append('<html lang="fr">')
            html.append('<head>')
            html.append('<meta charset="UTF-8">')
            html.append('<title>Rapport d\'Analyse PCAP</title>')
            html.append('<style>')
            html.append('body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; background: #f5f5f5; }')
            html.append('.container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }')
            html.append('h1 { border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }')
            html.append('h2 { border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }')
            html.append('table { width: 100%; border-collapse: collapse; margin: 10px 0; }')
            html.append('th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }')
            html.append('th { background-color: #4CAF50; color: white; }')
            html.append('.stat-box { display: inline-block; width: 200px; padding: 15px; margin: 10px; background: #e8f5e9; border-radius: 5px; text-align: center; }')
            html.append('.stat-value { font-size: 24px; font-weight: bold; color: #4CAF50; }')
            html.append('.severity-critical { background: #ffebee; color: #d32f2f; padding: 5px 10px; border-radius: 3px; font-weight: bold; }')
            html.append('.severity-high { background: #fff3e0; color: #f57c00; padding: 5px 10px; border-radius: 3px; font-weight: bold; }')
            html.append('.severity-medium { background: #e8f5e9; color: #388e3c; padding: 5px 10px; border-radius: 3px; font-weight: bold; }')
            html.append('</style>')
            html.append('</head>')
            html.append('<body>')
            html.append('<div class="container">')
            
            html.append(f'<h1>Rapport d\'Analyse PCAP</h1>')
            html.append(f'<p><strong>Fichier:</strong> {html_escape(self.pcap_file)}</p>')
            
            if self.start_time and self.end_time:
                try:
                    duration = self.end_time - self.start_time
                    html.append(f'<p><strong>Durée:</strong> {duration:.2f} secondes</p>')
                    html.append(f'<p><strong>Début:</strong> {datetime.fromtimestamp(float(self.start_time)).strftime("%Y-%m-%d %H:%M:%S")}</p>')
                    html.append(f'<p><strong>Fin:</strong> {datetime.fromtimestamp(float(self.end_time)).strftime("%Y-%m-%d %H:%M:%S")}</p>')
                except:
                    pass
            
            # Summary Statistics
            html.append('<h2>Statistiques Générales</h2>')
            html.append('<div>')
            html.append(f'<div class="stat-box"><div class="stat-value">{self.stats["total_packets"]}</div><div>Paquets Totaux</div></div>')
            html.append(f'<div class="stat-box"><div class="stat-value">{self.stats["incoming_packets"]}</div><div>Paquets Entrants</div></div>')
            html.append(f'<div class="stat-box"><div class="stat-value">{self.stats["outgoing_packets"]}</div><div>Paquets Sortants</div></div>')
            html.append('</div>')
            
            # Protocols
            html.append('<h2>Protocoles</h2>')
            html.append('<table>')
            html.append('<tr><th>Protocole</th><th>Nombre</th><th>Pourcentage</th></tr>')
            for proto, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.stats['ip_packets'] * 100) if self.stats['ip_packets'] > 0 else 0
                html.append(f'<tr><td>{html_escape(proto)}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>')
            html.append('</table>')
            
            # Applications
            html.append('<h2>Applications Détectées</h2>')
            html.append('<table>')
            html.append('<tr><th>Application</th><th>Nombre</th></tr>')
            for app, count in sorted(self.stats['applications'].items(), key=lambda x: x[1], reverse=True):
                html.append(f'<tr><td>{html_escape(app)}</td><td>{count}</td></tr>')
            html.append('</table>')
            
            # Advanced Protocols
            if self.protocol_detections:
                html.append('<h2>Protocoles Applicatifs Avancés</h2>')
                html.append('<table>')
                html.append('<tr><th>Protocole</th><th>Nombre</th></tr>')
                for proto, count in sorted(self.protocol_detections.items(), key=lambda x: x[1], reverse=True):
                    html.append(f'<tr><td>{html_escape(proto)}</td><td>{count}</td></tr>')
                html.append('</table>')
            
            # Temporal Analysis
            if self.temporal_analysis:
                html.append('<h2>Analyse Temporelle</h2>')
                html.append('<table>')
                html.append('<tr><th>Métrique</th><th>Valeur</th></tr>')
                for key, value in self.temporal_analysis.items():
                    if isinstance(value, float):
                        html.append(f'<tr><td>{html_escape(str(key))}</td><td>{value:.2f}</td></tr>')
                    else:
                        html.append(f'<tr><td>{html_escape(str(key))}</td><td>{html_escape(str(value))}</td></tr>')
                html.append('</table>')
            
            # MPLS Statistics
            if self.mpls_packets > 0:
                html.append('<h2>Statistiques MPLS</h2>')
                html.append('<div class="section">')
                html.append(f'<p><strong>Paquets MPLS:</strong> {self.mpls_packets} ({self.mpls_packets/self.stats["total_packets"]*100:.1f}%)</p>')
                if self.mpls_labels:
                    html.append('<table>')
                    html.append('<tr><th>Label MPLS</th><th>Nombre de paquets</th></tr>')
                    for label, count in sorted(self.mpls_labels.items(), key=lambda x: x[1], reverse=True)[:10]:
                        html.append(f'<tr><td>{label}</td><td>{count}</td></tr>')
                    html.append('</table>')
                for warning in self.mpls_warnings:
                    html.append(f'<p style="color: #d32f2f; font-weight: bold;">{html_escape(warning)}</p>')
                html.append('</div>')
            
            # Attack Findings
            if self.attack_findings:
                html.append('<h2>Détections d\'Attaques</h2>')
                html.append('<table>')
                html.append('<tr><th>Type</th><th>Valeur</th><th>Sévérité</th></tr>')
                for finding in self.attack_findings:
                    severity_class = f'severity-{finding["severity"].lower()}'
                    html.append(f'<tr><td>{html_escape(finding["type"])}</td><td>{html_escape(finding["value"][:100])}</td><td><span class="{severity_class}">{html_escape(finding["severity"])}</span></td></tr>')
                html.append('</table>')
            
            # Sensitive Data Findings
            if self.sensitive_data_findings:
                html.append('<h2>Données Sensibles Détectées</h2>')
                html.append('<table>')
                html.append('<tr><th>Type</th><th>Valeur</th><th>Sévérité</th></tr>')
                for finding in self.sensitive_data_findings:
                    severity_class = f'severity-{finding["severity"].lower()}'
                    html.append(f'<tr><td>{html_escape(finding["type"])}</td><td>{html_escape(finding["value"])}</td><td><span class="{severity_class}">{html_escape(finding["severity"])}</span></td></tr>')
                html.append('</table>')
            
            # Extracted Data
            if self.deep_analysis and any(self.extracted_data.values()):
                html.append('<h2>Données Extraites</h2>')
                for data_type, data_set in self.extracted_data.items():
                    if data_set:
                        html.append(f'<h3>{html_escape(data_type.upper().replace("_", " "))}</h3>')
                        html.append('<ul>')
                        for item in sorted(data_set)[:20]:
                            html.append(f'<li>{html_escape(str(item))}</li>')
                        if len(data_set) > 20:
                            html.append(f'<li><em>... et {len(data_set) - 20} de plus</em></li>')
                        html.append('</ul>')
            
            html.append('<p><em>Rapport généré par PCAP Analyzer - ' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '</em></p>')
            html.append('</div>')
            html.append('</body>')
            html.append('</html>')
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            
            print(f"Rapport HTML sauvegardé: {filename}")
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde HTML: {e}")
            return False
    
    def save_cef(self, filename):
        """Sauvegarde les événements au format CEF"""
        try:
            cef_events = []
            cef_version = "0"
            device_vendor = "PCAP Analyzer"
            device_product = "Network Traffic Analyzer"
            device_version = "1.0"
            
            # Attack findings
            for i, finding in enumerate(self.attack_findings):
                signature_id = f"ATTACK-{i+1:04d}"
                name = finding['type']
                severity = self.cef_severity_to_num(finding['severity'])
                extension = {
                    'rt': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    'msg': self.clean_string(finding['value'][:200]),
                }
                event = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{self.format_cef_extension(extension)}"
                cef_events.append(event)
            
            # Sensitive data findings
            for i, finding in enumerate(self.sensitive_data_findings):
                signature_id = f"SENSITIVE-{i+1:04d}"
                name = finding['type']
                severity = self.cef_severity_to_num(finding['severity'])
                extension = {
                    'rt': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    'dataType': self.clean_string(finding.get('subtype', finding['type'])),
                    'dataValue': self.clean_string(finding['value']),
                }
                event = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{self.format_cef_extension(extension)}"
                cef_events.append(event)
            
            # MPLS Detection
            if self.mpls_packets > 0:
                signature_id = "MPLS-0001"
                name = "MPLS Traffic Detected"
                severity = "4"  # Medium
                extension = {
                    'rt': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    'mplsPackets': str(self.mpls_packets),
                    'mplsPercentage': f"{self.mpls_packets/self.stats['total_packets']*100:.1f}",
                    'msg': 'MPLS traffic detected - analysis may be limited',
                }
                event = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{self.format_cef_extension(extension)}"
                cef_events.append(event)
            
            # Summary
            if self.stats['total_packets'] > 0:
                signature_id = "SUMMARY-0001"
                name = "Network Traffic Summary"
                severity = "1"
                extension = {
                    'rt': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    'totalPackets': str(self.stats['total_packets']),
                    'incomingPackets': str(self.stats['incoming_packets']),
                    'outgoingPackets': str(self.stats['outgoing_packets']),
                    'mplsPackets': str(self.mpls_packets),
                }
                event = f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{self.format_cef_extension(extension)}"
                cef_events.append(event)
            
            with open(filename, 'w', encoding='utf-8') as f:
                for event in cef_events:
                    f.write(event + '\n')
            
            print(f"Événements CEF sauvegardés: {filename} ({len(cef_events)} événements)")
            return True
        except Exception as e:
            print(f"Erreur lors de la sauvegarde CEF: {e}")
            return False
    
    def cef_severity_to_num(self, severity):
        """Convertit la sévérité en nombre CEF"""
        severity_map = {'CRITICAL': '10', 'HIGH': '7', 'MEDIUM': '4', 'LOW': '1'}
        return severity_map.get(severity.upper(), '1')
    
    def format_cef_extension(self, extension_dict):
        """Formate le champ d'extension CEF"""
        return ' '.join(f"{k}={v}" for k, v in extension_dict.items())


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
    
    parser.add_argument(
        '--html',
        help='Sauvegarder le rapport au format HTML'
    )
    
    parser.add_argument(
        '--cef',
        help='Sauvegarder les événements au format CEF'
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
    
    if args.html:
        analyzer.save_html(args.html)
    
    if args.cef:
        analyzer.save_cef(args.cef)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
