#!/usr/bin/env python3
"""
Script de test pour vérifier le bon fonctionnement des outils PCAP
"""

import sys
import os
import tempfile
import subprocess
from pathlib import Path


def test_imports():
    """Teste que tous les imports fonctionnent"""
    print("Test des imports...")
    
    try:
        import scapy.all as scapy
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import Ether
        print("✓ Tous les imports Scapy fonctionnent")
        return True
    except ImportError as e:
        print(f"✗ Erreur d'import: {e}")
        return False


def test_capture_script():
    """Teste le script de capture"""
    print("\nTest du script capture_incoming.py...")
    
    # Tester l'aide
    result = subprocess.run(
        [sys.executable, "scripts/capture_incoming.py", "--help"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 and "Capture et analyse du trafic réseau entrant" in result.stdout:
        print("✓ Script capture_incoming.py: aide fonctionnelle")
        return True
    else:
        print(f"✗ Script capture_incoming.py: {result.stderr}")
        return False


def test_analyze_script():
    """Teste le script d'analyse"""
    print("\nTest du script analyze_pcap.py...")
    
    # Tester l'aide
    result = subprocess.run(
        [sys.executable, "scripts/analyze_pcap.py", "--help"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 and "Analyse avancée de fichiers PCAP" in result.stdout:
        print("✓ Script analyze_pcap.py: aide fonctionnelle")
        return True
    else:
        print(f"✗ Script analyze_pcap.py: {result.stderr}")
        return False


def test_utils_script():
    """Teste le script d'utilitaires"""
    print("\nTest du script utils.py...")
    
    # Tester l'aide
    result = subprocess.run(
        [sys.executable, "scripts/utils.py"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 and "Utilitaires PCAP" in result.stdout:
        print("✓ Script utils.py: aide fonctionnelle")
        return True
    else:
        print(f"✗ Script utils.py: {result.stderr}")
        return False


def test_pcap_creation():
    """Teste la création d'un fichier PCAP de test"""
    print("\nTest de création d'un fichier PCAP de test...")
    
    try:
        import scapy.all as scapy
        from scapy.layers.inet import IP, TCP
        
        # Créer un paquet simple
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80)
        
        # Sauvegarder dans un fichier temporaire
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_file = f.name
        
        scapy.wrpcap(temp_file, [packet])
        
        # Vérifier que le fichier existe et est lisible
        if os.path.exists(temp_file):
            packets = scapy.rdpcap(temp_file)
            if len(packets) == 1:
                print(f"✓ Fichier PCAP de test créé: {temp_file}")
                os.unlink(temp_file)
                return True
            else:
                print(f"✗ Fichier PCAP invalide: {len(packets)} paquets au lieu de 1")
                os.unlink(temp_file)
                return False
        else:
            print(f"✗ Fichier PCAP non créé")
            return False
            
    except Exception as e:
        print(f"✗ Erreur lors de la création du PCAP: {e}")
        return False


def test_analyze_with_test_file():
    """Teste l'analyse avec un fichier PCAP de test"""
    print("\nTest d'analyse avec un fichier PCAP de test...")
    
    try:
        import scapy.all as scapy
        from scapy.layers.inet import IP, TCP, UDP
        
        # Créer quelques paquets de test
        packets = [
            IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=1234, dport=80, flags="S"),
            IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=1234, flags="SA"),
            IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=5345, dport=53),
            IP(src="8.8.8.8", dst="192.168.1.1") / UDP(sport=53, dport=5345),
        ]
        
        # Sauvegarder dans un fichier temporaire
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_file = f.name
        
        scapy.wrpcap(temp_file, packets)
        
        # Analyser avec notre script
        result = subprocess.run(
            [sys.executable, "scripts/analyze_pcap.py", temp_file],
            capture_output=True,
            text=True
        )
        
        os.unlink(temp_file)
        
        if result.returncode == 0:
            print("✓ Analyse du fichier PCAP de test réussie")
            return True
        else:
            print(f"✗ Analyse échouée: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"✗ Erreur lors du test d'analyse: {e}")
        return False


def main():
    """Exécute tous les tests"""
    print("="*60)
    print("TESTS DES OUTILS PCAP")
    print("="*60)
    
    tests = [
        test_imports,
        test_capture_script,
        test_analyze_script,
        test_utils_script,
        test_pcap_creation,
        test_analyze_with_test_file,
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "="*60)
    print("RÉSULTATS DES TESTS")
    print("="*60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Tests réussis: {passed}/{total}")
    
    if passed == total:
        print("✓ Tous les tests ont réussi!")
        return 0
    else:
        print(f"✗ {total - passed} test(s) échoué(s)")
        return 1


if __name__ == '__main__':
    sys.exit(main())