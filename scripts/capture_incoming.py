#!/usr/bin/env python3
"""
Script de capture de trafic réseau ENTRANT en temps réel
Utilise Scapy pour capturer et analyser les paquets entrants

Usage:
    python capture_incoming.py [interface] [durée_en_secondes] [fichier_de_sortie]
    python capture_incoming.py eth0 60 capture_incoming.pcap
"""

import sys
import time
from datetime import datetime
from collections import defaultdict
import argparse

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Erreur: Scapy non disponible - {e}")
    sys.exit(1)


class IncomingTrafficCapture:
    """Classe pour capturer et analyser le trafic entrant"""
    
    def __init__(self, interface=None, timeout=60, output_file=None):
        self.interface = interface
        self.timeout = timeout
        self.output_file = output_file
        self.packets = []
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'ports': defaultdict(int),
            'protocols': defaultdict(int)
        }
        self.start_time = None
        self.end_time = None
    
    def is_incoming(self, packet):
        """
        Détermine si un paquet est entrant (destiné à notre machine)
        """
        if not packet.haslayer(IP):
            return False
        
        # Pour simplifier, on considère comme entrant tout paquet 
        # qui a une adresse IP de destination dans notre réseau local
        # ou qui est destiné à notre machine
        
        # Méthode 1: Vérifier si c'est une réponse à une connexion sortante
        # (SYN-ACK, ACK sans SYN, etc.)
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # Paquet entrant: SYN (nouvelle connexion entrante) ou ACK sans SYN
            if tcp.flags & 0x02 and not (tcp.flags & 0x12):  # SYN sans ACK
                return True
            # Réponses à nos connexions sortantes
            if tcp.flags & 0x10 and not (tcp.flags & 0x02):  # ACK sans SYN
                return True
            # Données entrantes
            if tcp.flags & 0x18:  # PSH ou ACK
                return True
        
        # Méthode 2: Pour UDP et ICMP, considérer comme entrant
        # si la source est externe
        if packet.haslayer(UDP) or packet.haslayer(ICMP):
            return True
        
        # Méthode 3: Basée sur l'interface (si spécifiée)
        # Si on capture sur une interface spécifique, tout est considéré comme entrant
        if self.interface:
            return True
        
        return False
    
    def analyze_packet(self, packet):
        """Analyse un paquet et met à jour les statistiques"""
        self.stats['total_packets'] += 1
        
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
                self.stats['other_packets'] += 1
                self.stats['protocols'][f'OTHER_{proto}'] += 1
            
            # Statistiques par adresse source et destination
            self.stats['sources'][ip.src] += 1
            self.stats['destinations'][ip.dst] += 1
            
            # Statistiques par port (si TCP ou UDP)
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                self.stats['ports'][tcp.dport] += 1
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                self.stats['ports'][udp.dport] += 1
    
    def packet_handler(self, packet):
        """Callback pour traiter chaque paquet capturé"""
        if self.is_incoming(packet):
            self.analyze_packet(packet)
            self.packets.append(packet)
            
            # Affichage en temps réel
            self.display_packet_info(packet)
    
    def display_packet_info(self, packet):
        """Affiche les informations du paquet"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        info_parts = [f"[{timestamp}]"]
        
        if packet.haslayer(Ether):
            ether = packet[Ether]
            info_parts.append(f"ETH: {ether.src} -> {ether.dst}")
        
        if packet.haslayer(IP):
            ip = packet[IP]
            info_parts.append(f"IP: {ip.src} -> {ip.dst}")
            info_parts.append(f"Proto: {ip.proto}")
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info_parts.append(f"TCP: {tcp.sport} -> {tcp.dport}")
                info_parts.append(f"Flags: {self.tcp_flags_to_string(tcp.flags)}")
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info_parts.append(f"UDP: {udp.sport} -> {udp.dport}")
            elif packet.haslayer(ICMP):
                info_parts.append("ICMP")
        
        print(" | ".join(info_parts))
    
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
    
    def print_statistics(self):
        """Affiche les statistiques de capture"""
        print("\n" + "="*60)
        print("STATISTIQUES DE CAPTURE")
        print("="*60)
        
        duration = self.end_time - self.start_time if self.start_time and self.end_time else 0
        
        print(f"Durée de capture: {duration:.2f} secondes")
        print(f"Paquets totaux: {self.stats['total_packets']}")
        print(f"Paquets IP: {self.stats['ip_packets']}")
        print(f"Paquets TCP: {self.stats['tcp_packets']}")
        print(f"Paquets UDP: {self.stats['udp_packets']}")
        print(f"Paquets ICMP: {self.stats['icmp_packets']}")
        print(f"Autres paquets: {self.stats['other_packets']}")
        
        print(f"\nProtocoles:")
        for proto, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {proto}: {count}")
        
        print(f"\nTop 10 adresses sources:")
        for ip, count in sorted(self.stats['sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count}")
        
        print(f"\nTop 10 adresses destinations:")
        for ip, count in sorted(self.stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count}")
        
        print(f"\nTop 10 ports destinations:")
        for port, count in sorted(self.stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {port}: {count}")
    
    def save_to_pcap(self):
        """Sauvegarde les paquets capturés dans un fichier PCAP"""
        if self.output_file and self.packets:
            try:
                wrpcap(self.output_file, self.packets)
                print(f"\nPaquets sauvegardés dans: {self.output_file}")
            except Exception as e:
                print(f"Erreur lors de la sauvegarde: {e}")
    
    def capture(self):
        """Lance la capture du trafic"""
        print(f"Début de la capture sur interface: {self.interface or 'toutes'}")
        print(f"Durée: {self.timeout} secondes")
        print("Appuyez sur Ctrl+C pour arrêter...")
        print("-"*60)
        
        self.start_time = time.time()
        
        try:
            # Capture en mode promiscuous
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                timeout=self.timeout,
                store=0  # On ne stocke pas dans sniff, on utilise notre propre liste
            )
        except KeyboardInterrupt:
            print("\nCapture arrêtée par l'utilisateur")
        except Exception as e:
            print(f"Erreur lors de la capture: {e}")
        
        self.end_time = time.time()
        
        # Afficher les statistiques
        self.print_statistics()
        
        # Sauvegarder dans un fichier PCAP
        self.save_to_pcap()
        
        return self.packets, self.stats


def main():
    parser = argparse.ArgumentParser(
        description='Capture et analyse du trafic réseau entrant',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python capture_incoming.py eth0 60 capture.pcap
  python capture_incoming.py -i wlan0 -t 30 -o incoming.pcap
  python capture_incoming.py --list-interfaces
        """
    )
    
    parser.add_argument(
        'interface', 
        nargs='?', 
        default=None,
        help='Interface réseau à capturer (ex: eth0, wlan0)'
    )
    
    parser.add_argument(
        'duration', 
        nargs='?', 
        type=int,
        default=60,
        help='Durée de capture en secondes (par défaut: 60)'
    )
    
    parser.add_argument(
        'output', 
        nargs='?', 
        default=None,
        help='Fichier de sortie PCAP (ex: capture.pcap)'
    )
    
    parser.add_argument(
        '-i', '--interface',
        dest='interface_arg',
        help='Interface réseau à capturer'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=60,
        help='Durée de capture en secondes'
    )
    
    parser.add_argument(
        '-o', '--output',
        dest='output_arg',
        help='Fichier de sortie PCAP'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='Lister les interfaces réseau disponibles'
    )
    
    args = parser.parse_args()
    
    # Gestion des arguments positionnels et optionnels
    interface = args.interface_arg or args.interface
    duration = args.timeout or args.duration
    output = args.output_arg or args.output
    
    if args.list_interfaces:
        print("Interfaces réseau disponibles:")
        try:
            interfaces = get_if_list()
            for iface in interfaces:
                print(f"  - {iface}")
        except Exception as e:
            print(f"Erreur: {e}")
        return
    
    # Créer le captureur
    capture = IncomingTrafficCapture(
        interface=interface,
        timeout=duration,
        output_file=output
    )
    
    # Lancer la capture
    packets, stats = capture.capture()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())