#!/usr/bin/env python3
"""
Utilitaires pour la manipulation de fichiers PCAP
"""

import sys
import os
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"Erreur: Scapy non disponible - {e}")
    sys.exit(1)


def filter_incoming_packets(pcap_file, output_file):
    """
    Filtre les paquets entrants d'un fichier PCAP et les sauvegarde dans un nouveau fichier
    """
    try:
        packets = rdpcap(pcap_file)
        incoming_packets = []
        
        print(f"Filtrage de {len(packets)} paquets...")
        
        for packet in packets:
            if is_incoming(packet):
                incoming_packets.append(packet)
        
        wrpcap(output_file, incoming_packets)
        print(f"{len(incoming_packets)} paquets entrants sauvegardés dans {output_file}")
        return True
    except Exception as e:
        print(f"Erreur: {e}")
        return False


def is_incoming(packet):
    """Détermine si un paquet est entrant"""
    if not packet.haslayer(IP):
        return False
    
    ip = packet[IP]
    
    # Méthode basée sur les flags TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        # SYN sans ACK = nouvelle connexion entrante
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            return True
        # ACK sans SYN = réponse à une connexion sortante
        if tcp.flags & 0x10 and not (tcp.flags & 0x02):
            return True
        # Données avec PSH ou ACK
        if tcp.flags & 0x18:
            return True
    
    # Pour UDP et ICMP
    if packet.haslayer(UDP) or packet.haslayer(ICMP):
        return True
    
    return False


def extract_conversations(pcap_file, output_dir="conversations"):
    """
    Extrait les conversations individuelles d'un fichier PCAP
    Chaque conversation est sauvegardée dans un fichier séparé
    """
    try:
        packets = rdpcap(pcap_file)
        conversations = defaultdict(list)
        
        print(f"Extraction des conversations de {len(packets)} paquets...")
        
        for packet in packets:
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                ip = packet[IP]
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    conv_key = f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
                else:
                    udp = packet[UDP]
                    conv_key = f"{ip.src}:{udp.sport}-{ip.dst}:{udp.dport}"
                
                conversations[conv_key].append(packet)
        
        # Créer le répertoire de sortie
        os.makedirs(output_dir, exist_ok=True)
        
        # Sauvegarder chaque conversation
        for conv_key, conv_packets in conversations.items():
            safe_key = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in conv_key)
            output_file = os.path.join(output_dir, f"{safe_key}.pcap")
            wrpcap(output_file, conv_packets)
            print(f"  Conversation {conv_key}: {len(conv_packets)} paquets -> {output_file}")
        
        print(f"{len(conversations)} conversations extraites dans {output_dir}")
        return True
    except Exception as e:
        print(f"Erreur: {e}")
        return False


def get_packet_statistics(pcap_file):
    """
    Retourne des statistiques rapides sur un fichier PCAP
    """
    try:
        packets = rdpcap(pcap_file)
        stats = {
            'total': len(packets),
            'ip': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'sources': defaultdict(int),
            'destinations': defaultdict(int)
        }
        
        for packet in packets:
            if packet.haslayer(IP):
                stats['ip'] += 1
                ip = packet[IP]
                stats['sources'][ip.src] += 1
                stats['destinations'][ip.dst] += 1
                
                if packet.haslayer(TCP):
                    stats['tcp'] += 1
                elif packet.haslayer(UDP):
                    stats['udp'] += 1
                elif packet.haslayer(ICMP):
                    stats['icmp'] += 1
        
        return stats
    except Exception as e:
        print(f"Erreur: {e}")
        return None


def merge_pcap_files(input_files, output_file):
    """
    Fusionne plusieurs fichiers PCAP en un seul
    """
    try:
        all_packets = []
        
        for input_file in input_files:
            packets = rdpcap(input_file)
            all_packets.extend(packets)
            print(f"Chargé {len(packets)} paquets de {input_file}")
        
        wrpcap(output_file, all_packets)
        print(f"Fusion terminée: {len(all_packets)} paquets sauvegardés dans {output_file}")
        return True
    except Exception as e:
        print(f"Erreur: {e}")
        return False


def main():
    print("Utilitaires PCAP avec Scapy")
    print("="*50)
    print("Commandes disponibles:")
    print("  filter-incoming <input.pcap> <output.pcap>")
    print("  extract-conversations <input.pcap> [output_dir]")
    print("  stats <input.pcap>")
    print("  merge <output.pcap> <input1.pcap> [input2.pcap] ...")
    
    if len(sys.argv) < 2:
        return 0
    
    command = sys.argv[1]
    
    if command == "filter-incoming":
        if len(sys.argv) < 4:
            print("Usage: filter-incoming <input.pcap> <output.pcap>")
            return 1
        filter_incoming_packets(sys.argv[2], sys.argv[3])
    
    elif command == "extract-conversations":
        output_dir = sys.argv[3] if len(sys.argv) > 3 else "conversations"
        extract_conversations(sys.argv[2], output_dir)
    
    elif command == "stats":
        if len(sys.argv) < 3:
            print("Usage: stats <input.pcap>")
            return 1
        stats = get_packet_statistics(sys.argv[2])
        if stats:
            print(f"Statistiques pour {sys.argv[2]}:")
            print(f"  Paquets totaux: {stats['total']}")
            print(f"  Paquets IP: {stats['ip']}")
            print(f"  Paquets TCP: {stats['tcp']}")
            print(f"  Paquets UDP: {stats['udp']}")
            print(f"  Paquets ICMP: {stats['icmp']}")
            print(f"  Adresses sources uniques: {len(stats['sources'])}")
            print(f"  Adresses destinations uniques: {len(stats['destinations'])}")
    
    elif command == "merge":
        if len(sys.argv) < 4:
            print("Usage: merge <output.pcap> <input1.pcap> [input2.pcap] ...")
            return 1
        merge_pcap_files(sys.argv[3:], sys.argv[2])
    
    else:
        print(f"Commande inconnue: {command}")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())