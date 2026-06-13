#!/usr/bin/env python3
"""
Script d'analyse avancée de fichiers PCAP pour le trafic entrant
Utilise Scapy pour analyser les fichiers PCAP existants

Usage:
    python analyze_pcap.py fichier.pcap
    python analyze_pcap.py -f fichier.pcap -o rapport.txt
"""

import sys
import os
from datetime import datetime
from collections import defaultdict, Counter
import argparse
import json

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Erreur: Scapy non disponible - {e}")
    sys.exit(1)


class PCAPAnalyzer:
    """Classe pour analyser les fichiers PCAP"""
    
    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
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
            'dns_queries': 0,
            'dns_responses': 0,
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'source_ports': defaultdict(int),
            'dest_ports': defaultdict(int),
            'protocols': defaultdict(int),
            'conversations': defaultdict(lambda: {'packets': 0, 'bytes': 0}),
            'http_endpoints': defaultdict(int),
            'dns_domains': defaultdict(int),
            'tcp_flags': defaultdict(int),
            'packet_sizes': [],
            'timestamps': []
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
            server_ports = [53, 67, 68, 123, 137, 138, 139, 161, 162, 443, 80]
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
            # ACK seul = accusé de réception sortant
            if tcp.flags & 0x10 and not (tcp.flags & 0x02):
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
            
            # Conversations (paires source->destination)
            conv_key = f"{ip.src}:{ip.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else '*'} -> {ip.dst}:{ip.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else '*'}"
            
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
            
            # Conversations TCP
            if packet.haslayer(IP):
                ip = packet[IP]
                conv_key = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
                self.stats['conversations'][conv_key]['packets'] += 1
                self.stats['conversations'][conv_key]['bytes'] += len(tcp.payload) if tcp.payload else 0
        
        # Analyse UDP
        if packet.haslayer(UDP):
            udp = packet[UDP]
            self.stats['source_ports'][udp.sport] += 1
            self.stats['dest_ports'][udp.dport] += 1
            
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
            if http.Host:
                self.stats['http_endpoints'][http.Host.decode('utf-8', errors='ignore')] += 1
            if http.Path:
                path = http.Path.decode('utf-8', errors='ignore')
                endpoint = f"{http.Host.decode('utf-8', errors='ignore') if http.Host else 'unknown'}{path}"
                self.stats['http_endpoints'][endpoint] += 1
        
        if packet.haslayer(HTTPResponse):
            self.stats['http_responses'] += 1
    
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
        
        # Trouver les timestamps min et max
        timestamps = [p.time for p in self.packets if p.time]
        if timestamps:
            self.start_time = min(timestamps)
            self.end_time = max(timestamps)
        
        # Analyser chaque paquet
        for packet in self.packets:
            self.analyze_packet(packet)
        
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
            print(f"  {port}: {count}")
        
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
                print(f"  {conv}: {data['packets']} paquets, {data['bytes']} octets")
    
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
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    incoming_ports[udp.dport] += 1
        
        print(f"\nProtocoles entrants:")
        for proto, count in sorted(incoming_protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.stats['incoming_packets'] * 100) if self.stats['incoming_packets'] > 0 else 0
            print(f"  {proto}: {count} ({percentage:.1f}%)")
        
        print(f"\nTop 10 sources de trafic entrant:")
        for ip, count in sorted(incoming_sources.items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['incoming_packets'] * 100) if self.stats['incoming_packets'] > 0 else 0
            print(f"  {ip}: {count} ({percentage:.1f}%)")
        
        print(f"\nTop 10 ports destinations pour le trafic entrant:")
        for port, count in sorted(incoming_ports.items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['incoming_packets'] * 100) if self.stats['incoming_packets'] > 0 else 0
            print(f"  {port}: {count} ({percentage:.1f}%)")
        
        # Détection de patterns suspects
        print(f"\nAnalyse de sécurité:")
        self.detect_suspicious_patterns()
    
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
                suspicious_findings.append(f"⚠️  Trafic sur port suspect {port}: {self.stats['dest_ports'][port]} paquets")
        
        # 5. Beaucoup de SYN sans ACK (SYN flood)
        if 'SYN' in self.stats['tcp_flags']:
            syn_count = self.stats['tcp_flags']['SYN']
            if syn_count > 100:
                percentage = (syn_count / sum(self.stats['tcp_flags'].values()) * 100) if self.stats['tcp_flags'] else 0
                if percentage > 30:
                    suspicious_findings.append(f"⚠️  Beaucoup de paquets SYN: {syn_count} ({percentage:.1f}%)")
        
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
                f.write("RAPPORT D'ANALYSE PCAP\n")
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
                
                f.write(f"\nTop 10 adresses sources:\n")
                for ip, count in sorted(self.stats['sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {ip}: {count}\n")
                
                f.write(f"\nTop 10 adresses destinations:\n")
                for ip, count in sorted(self.stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {ip}: {count}\n")
                
                f.write(f"\nTop 10 ports destinations:\n")
                for port, count in sorted(self.stats['dest_ports'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {port}: {count}\n")
                
                if self.stats['http_endpoints']:
                    f.write(f"\nEndpoints HTTP:\n")
                    for endpoint, count in sorted(self.stats['http_endpoints'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(f"  {endpoint}: {count}\n")
                
                if self.stats['dns_domains']:
                    f.write(f"\nDomaines DNS:\n")
                    for domain, count in sorted(self.stats['dns_domains'].items(), key=lambda x: x[1], reverse=True)[:10]:
                        f.write(f"  {domain}: {count}\n")
            
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
            
            data = {
                'filename': self.pcap_file,
                'start_time': self.start_time,
                'end_time': self.end_time,
                'duration': (self.end_time - self.start_time) if self.start_time and self.end_time else None,
                'stats': stats_dict
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
        description='Analyse avancée de fichiers PCAP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python analyze_pcap.py capture.pcap
  python analyze_pcap.py -f capture.pcap -o rapport.txt
  python analyze_pcap.py --json output.json capture.pcap
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
    
    args = parser.parse_args()
    
    # Gestion des arguments
    input_file = args.input_file or args.file
    
    if not input_file:
        print("Erreur: Veuillez spécifier un fichier PCAP à analyser")
        parser.print_help()
        return 1
    
    if not os.path.exists(input_file):
        print(f"Erreur: Le fichier {input_file} n'existe pas")
        return 1
    
    # Créer l'analyseur
    analyzer = PCAPAnalyzer()
    
    # Charger le fichier
    if not analyzer.load_pcap(input_file):
        return 1
    
    # Analyser
    if not analyzer.analyze():
        return 1
    
    # Afficher les résultats
    if args.incoming_only:
        analyzer.print_incoming_analysis()
    else:
        analyzer.print_summary()
        analyzer.print_incoming_analysis()
    
    # Sauvegarder les résultats
    if args.output:
        analyzer.save_report(args.output)
    
    if args.json:
        analyzer.save_json(args.json)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())