#!/usr/bin/env python3
"""
Script de lancement principal pour l'analyse des fichiers PCAP

Ce script permet de lancer toutes les analyses sur les fichiers PCAP
présents dans le dossier 'Brutes/' et sauvegarde les résultats dans 'Sortie/'
Les erreurs sont enregistrées dans 'Error/error.log'

Usage:
    python LANCER.py                    # Demande à l'utilisateur quel fichier traiter
    python LANCER.py --all             # Traite tous les fichiers PCAP
    python LANCER.py fichier.pcap       # Analyse un fichier spécifique
    python LANCER.py --deep             # Analyse approfondie avec extraction de données
    python LANCER.py --json             # Sauvegarde au format JSON
    python LANCER.py --all-formats      # Sauvegarde dans tous les formats
"""

import sys
import os
import argparse
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path


# ============================================================================
# CONFIGURATION
# ============================================================================

# Chemins des dossiers
BRUTES_DIR = "Brutes"
SORTIE_DIR = "Sortie"
ERROR_DIR = "Error"
SCRIPTS_DIR = "scripts"

# Fichier de log des erreurs
ERROR_LOG = os.path.join(ERROR_DIR, "error.log")

# Extensions de fichiers PCAP
PCAP_EXTENSIONS = ['.pcap', '.pcapng', '.cap']

# Taille maximale des fichiers à analyser (en Mo) - 0 = pas de limite
MAX_FILE_SIZE_MB = 0

# Configuration de la rotation des logs
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 Mo
LOG_BACKUP_COUNT = 5  # Nombre de fichiers de backup


# ============================================================================
# VÉRIFICATION DES DÉPENDANCES
# ============================================================================

def check_dependencies():
    """Vérifie que toutes les dépendances requises sont installées"""
    print("="*70)
    print("VERIFICATION DES DEPENDANCES")
    print("="*70)
    
    all_ok = True
    
    # Vérifier Scapy
    try:
        import scapy
        print(f"✓ Scapy: version {scapy.__version__}")
    except ImportError:
        print("✗ Scapy: NON INSTALLE")
        print("  Solution: pip install scapy")
        all_ok = False
    
    # Vérifier Python version
    if sys.version_info < (3, 9):
        print(f"✗ Python: version {sys.version_info.major}.{sys.version_info.minor} (requis: 3.9+)")
        all_ok = False
    else:
        print(f"✓ Python: version {sys.version_info.major}.{sys.version_info.minor}")
    
    print("="*70)
    
    if not all_ok:
        print("\n⚠️  Des dependances manquent. Installez-les avant de continuer.")
        return False
    
    return True


def setup_logging():
    """Configure le logging des erreurs avec rotation des fichiers"""
    # Créer le dossier Error s'il n'existe pas
    if not os.path.exists(ERROR_DIR):
        os.makedirs(ERROR_DIR)
    
    # Configurer le logger
    logger = logging.getLogger('PCAP_Analyzer')
    logger.setLevel(logging.ERROR)
    
    # Handler pour le fichier de log avec rotation
    # Max 10 Mo par fichier, garde 5 anciens fichiers
    file_handler = RotatingFileHandler(
        ERROR_LOG,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.ERROR)
    
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Ajouter le handler
    logger.addHandler(file_handler)
    
    return logger


def log_error(logger, message, exc_info=None):
    """Enregistre une erreur dans le log"""
    if exc_info:
        logger.error(message, exc_info=exc_info)
    else:
        logger.error(message)


def get_pcap_files(directory):
    """Récupère la liste des fichiers PCAP dans un dossier"""
    pcap_files = []
    
    if not os.path.exists(directory):
        print(f"Dossier '{directory}' introuvable")
        return pcap_files
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.lower().endswith(ext) for ext in PCAP_EXTENSIONS):
                pcap_files.append(os.path.join(root, file))
    
    return sorted(pcap_files)


def ensure_directories():
    """Vérifie que les dossiers nécessaires existent"""
    for directory in [BRUTES_DIR, SORTIE_DIR, ERROR_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Dossier '{directory}' créé")


def get_output_filename(input_file, suffix="", extension=".txt"):
    """Génère un nom de fichier de sortie basé sur le fichier d'entrée"""
    # Obtenir le nom du fichier sans extension
    filename = os.path.basename(input_file)
    name_without_ext = os.path.splitext(filename)[0]
    
    # Ajouter un suffixe si fourni
    if suffix:
        name_without_ext += f"_{suffix}"
    
    # Créer le chemin complet
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{name_without_ext}_{timestamp}{extension}"
    
    return os.path.join(SORTIE_DIR, output_filename)


def display_file_list(pcap_files):
    """Affiche la liste des fichiers PCAP avec numérotation"""
    print(f"\n{'='*70}")
    print("FICHIERS PCAP DISPONIBLES DANS 'Brutes/'")
    print(f"{'='*70}")
    
    for i, pcap_file in enumerate(pcap_files, 1):
        filename = os.path.basename(pcap_file)
        size = os.path.getsize(pcap_file)
        size_mb = size / (1024 * 1024)
        print(f"  {i}. {filename} ({size_mb:.2f} Mo)")
    
    print(f"\n  0. Traiter TOUS les fichiers")
    print(f"  q. Quitter")
    print(f"{'='*70}")


def get_user_choice(pcap_files):
    """Demande à l'utilisateur de choisir un fichier ou tous les fichiers"""
    while True:
        try:
            choice = input("\nVotre choix (numéro, 0 pour tous, q pour quitter) : ").strip().lower()
            
            if choice == 'q':
                return None
            elif choice == '0':
                return pcap_files  # Tous les fichiers
            elif choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(pcap_files):
                    return [pcap_files[index]]  # Un seul fichier
                else:
                    print(f"Numéro invalide. Veuillez choisir entre 1 et {len(pcap_files)}")
            else:
                print("Choix invalide. Veuillez entrer un numéro, 0, ou q.")
        except (ValueError, IndexError):
            print("Entrée invalide. Veuillez réessayer.")


def run_analysis(input_file, deep_analysis=False, output_format="txt", logger=None):
    """Exécute l'analyse sur un fichier PCAP"""
    print(f"\n{'='*70}")
    print(f"Analyse du fichier: {input_file}")
    print(f"{'='*70}")
    
    # Préparer les arguments
    args = [
        sys.executable,
        os.path.join(SCRIPTS_DIR, "analyze_pcap.py"),
        "-f", input_file,
    ]
    
    if deep_analysis:
        args.append("--deep")
    
    # Déterminer le fichier de sortie
    if output_format == "txt":
        output_file = get_output_filename(input_file, "rapport", ".txt")
        args.extend(["-o", output_file])
    elif output_format == "json":
        output_file = get_output_filename(input_file, "stats", ".json")
        args.extend(["--json", output_file])
    elif output_format == "all":
        # Sauvegarder dans les deux formats
        txt_file = get_output_filename(input_file, "rapport", ".txt")
        json_file = get_output_filename(input_file, "stats", ".json")
        args.extend(["-o", txt_file, "--json", json_file])
    
    # Exécuter la commande
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Afficher la sortie
        print(result.stdout)
        if result.stderr:
            print("Avertissements:", result.stderr)
        
        print(f"✓ Analyse terminée pour {input_file}")
        if output_format != "none":
            print(f"  Résultats sauvegardés dans: {SORTIE_DIR}/")
        
        return True
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Erreur lors de l'analyse de {input_file}: {e.stderr}"
        print(f"✗ {error_msg}")
        if logger:
            log_error(logger, error_msg)
        return False
    except Exception as e:
        error_msg = f"Erreur inattendue lors de l'analyse de {input_file}: {str(e)}"
        print(f"✗ {error_msg}")
        if logger:
            log_error(logger, error_msg, exc_info=True)
        return False


def analyze_files(file_list, deep_analysis=False, output_format="txt", logger=None):
    """Analyse une liste de fichiers PCAP"""
    if not file_list:
        print("Aucun fichier à analyser")
        return False
    
    success_count = 0
    for pcap_file in file_list:
        if run_analysis(pcap_file, deep_analysis, output_format, logger):
            success_count += 1
    
    print(f"\n{'='*70}")
    print(f"Analyse terminée: {success_count}/{len(file_list)} fichiers traités avec succès")
    print(f"{'='*70}")
    
    # Enregistrer un résumé dans le log
    if logger:
        logger.info(f"Analyse terminée: {success_count}/{len(file_list)} fichiers traités")
    
    return success_count == len(file_list)


def interactive_mode(deep_analysis=False, output_format="txt", logger=None):
    """Mode interactif : demande à l'utilisateur de choisir"""
    pcap_files = get_pcap_files(BRUTES_DIR)
    
    if not pcap_files:
        error_msg = f"Aucun fichier PCAP trouvé dans {BRUTES_DIR}/"
        print(error_msg)
        if logger:
            log_error(logger, error_msg)
        return False
    
    # Afficher la liste des fichiers
    display_file_list(pcap_files)
    
    # Demander le choix de l'utilisateur
    selected_files = get_user_choice(pcap_files)
    
    if selected_files is None:
        print("Analyse annulée par l'utilisateur")
        return True
    
    # Analyser les fichiers sélectionnés
    return analyze_files(selected_files, deep_analysis, output_format, logger)


def analyze_single_file(filepath, deep_analysis=False, output_format="txt", logger=None):
    """Analyse un fichier PCAP unique"""
    if not os.path.exists(filepath):
        error_msg = f"Fichier introuvable: {filepath}"
        print(f"✗ {error_msg}")
        if logger:
            log_error(logger, error_msg)
        return False
    
    return run_analysis(filepath, deep_analysis, output_format, logger)


def analyze_all_files(deep_analysis=False, output_format="txt", logger=None):
    """Analyse tous les fichiers PCAP dans le dossier Brutes"""
    pcap_files = get_pcap_files(BRUTES_DIR)
    
    if not pcap_files:
        error_msg = f"Aucun fichier PCAP trouvé dans {BRUTES_DIR}/"
        print(error_msg)
        if logger:
            log_error(logger, error_msg)
        return False
    
    print(f"Trouvé {len(pcap_files)} fichier(s) PCAP dans {BRUTES_DIR}/")
    
    return analyze_files(pcap_files, deep_analysis, output_format, logger)


def show_help():
    """Affiche l'aide détaillée"""
    print("""
================================================================================
SCRIPT DE LANCEMENT POUR L'ANALYSE PCAP
================================================================================

Ce script permet d'analyser les fichiers PCAP présents dans le dossier 'Brutes/'
et sauvegarde les résultats dans 'Sortie/'. Les erreurs sont enregistrées dans 'Error/'

DOSSIERS:
  Brutes/   - Contient les fichiers PCAP à analyser
  Sortie/   - Contiendra les rapports et résultats
  Error/    - Contiendra les logs d'erreurs (error.log)

USAGE:
  1. Mode interactif (par défaut) :
     python LANCER.py
     -> Demande à l'utilisateur de choisir un fichier ou tous

  2. Analyse de tous les fichiers PCAP dans Brutes/:
     python LANCER.py --all

  3. Analyse d'un fichier spécifique:
     python LANCER.py mon_fichier.pcap

  4. Analyse approfondie (extraction de données du payload):
     python LANCER.py --deep
     python LANCER.py --all --deep

  5. Sauvegarde au format JSON:
     python LANCER.py --json
     python LANCER.py --all --json

  6. Sauvegarde dans tous les formats (texte + JSON):
     python LANCER.py --all-formats

  7. Combinaison d'options:
     python LANCER.py --all --deep --all-formats

OPTIONS:
  --all           Traite tous les fichiers PCAP (sans demander)
  --deep          Active l'analyse approfondie (extraction de données)
  --json          Sauvegarde les résultats au format JSON
  --all-formats   Sauvegarde dans tous les formats disponibles
  --help, -h      Affiche cette aide

EXEMPLES COMPLETS:
  # Mode interactif (choix utilisateur)
  python LANCER.py

  # Traiter tous les fichiers
  python LANCER.py --all

  # Analyse approfondie de tous les fichiers
  python LANCER.py --all --deep --all-formats

  # Analyse d'un fichier spécifique
  python LANCER.py Brutes/capture1.pcap --deep

  # Vérifier les erreurs
  cat Error/error.log

NOTES:
  - Les fichiers PCAP doivent être dans le dossier 'Brutes/'
  - Les résultats seront sauvegardés dans 'Sortie/'
  - Les erreurs seront enregistrées dans 'Error/error.log'
  - L'analyse approfondie (--deep) est plus lente mais extrait plus d'informations
  - Les formats supportés: .pcap, .pcapng, .cap

ANALYSE INCLUSE:
  ✓ Détection du trafic entrant vs sortant
  ✓ Identification des applications (HTTP, HTTPS, DNS, SSH, etc.)
  ✓ Classification par écosystème (Android, iOS, Web, IoT, etc.)
  ✓ Extraction de données (emails, téléphones, IDs, tokens, etc.)
  ✓ Détection de patterns suspects
  ✓ Statistiques détaillées
  ✓ Analyse de sécurité

================================================================================
    """)


def main():
    parser = argparse.ArgumentParser(
        description='Lance l\'analyse des fichiers PCAP',
        add_help=False
    )
    
    parser.add_argument(
        'file',
        nargs='?',
        help='Fichier PCAP spécifique à analyser (optionnel)'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Traite tous les fichiers PCAP sans demander'
    )
    
    parser.add_argument(
        '--deep',
        action='store_true',
        help='Active l\'analyse approfondie avec extraction de données'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Sauvegarde les résultats au format JSON'
    )
    
    parser.add_argument(
        '--all-formats',
        action='store_true',
        help='Sauvegarde dans tous les formats (texte + JSON)'
    )
    
    parser.add_argument(
        '--help', '-h',
        action='store_true',
        help='Affiche l\'aide'
    )
    
    args = parser.parse_args()
    
    # Afficher l'aide si demandé
    if args.help:
        show_help()
        return 0
    
    # Configurer le logging
    logger = setup_logging()
    
    # Vérifier que les dossiers existent
    ensure_directories()
    
    # Déterminer le format de sortie
    output_format = "none"
    if args.all_formats:
        output_format = "all"
    elif args.json:
        output_format = "json"
    else:
        output_format = "txt"
    
    # Enregistrer le début de l'analyse
    logger.info(f"Début de l'analyse - Options: all={args.all}, deep={args.deep}, format={output_format}")
    
    # Analyser
    if args.file:
        # Analyse d'un fichier spécifique
        if not analyze_single_file(args.file, args.deep, output_format, logger):
            logger.error(f"Échec de l'analyse du fichier: {args.file}")
            return 1
    elif args.all:
        # Analyse de tous les fichiers dans Brutes/
        if not analyze_all_files(args.deep, output_format, logger):
            logger.error("Échec de l'analyse par lots")
            return 1
    else:
        # Mode interactif : demander à l'utilisateur
        if not interactive_mode(args.deep, output_format, logger):
            logger.error("Échec de l'analyse interactive")
            return 1
    
    # Enregistrer la fin de l'analyse
    logger.info("Analyse terminée avec succès")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
