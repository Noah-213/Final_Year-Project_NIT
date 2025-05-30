import os
import shutil
import re
import json
from typing import List, Dict

# --- Configuration ---
BASE_PATH = "/home/Tarek/Documents/Atrdf_Dataset"
MODSEC_LOG_NATIVE = "/var/log/modsec_audit.log"
MODSEC_LOG_LOCAL = os.path.join(BASE_PATH, "modsec_audit.log")
MODSEC_JSON_PATH = os.path.join(BASE_PATH, "modsec_audit.json")

# Regex précompilées
RE_TIMESTAMP = re.compile(r'^\[([^]]+)\]')
RE_UNIQUE_ID = re.compile(r'\b(\d+\.\d+)\b')
RE_URI = re.compile(r'\[uri\s+"([^"]+)"\]')
RE_HOST = re.compile(r'\[hostname\s+"([^"]+)"\]')
RE_ALERT_FIELDS = {
    'id': re.compile(r'\[id\s+"([^"]+)"\]'),
    'msg': re.compile(r'\[msg\s+"([^"]+)"\]'),
    'severity': re.compile(r'\[severity\s+"([^"]+)"\]'),
    'ref': re.compile(r'\[ref\s+"([^"]*)"\]')
}
RE_TAGS = re.compile(r'\[tag\s+"([^"]+)"\]')
RE_REQ_ID = re.compile(r'X-Req-ID:([A-Za-z0-9\-]+)')

class Transaction:
    """Représente une transaction complète avec ses alertes"""
    def __init__(self):
        self.unique_id: str = None
        self.primary_key: str = None  # <-- Ajouté ici
        self.timestamp: str = None
        self.uri: str = None
        self.host: str = None
        self.alerts: List[Dict] = []
    
    def is_valid(self) -> bool:
        """Valide les champs obligatoires"""
        return all([
            self.unique_id,
            self.timestamp,
            self.uri,
            self.host
        ])
    
    def to_dict(self) -> Dict:
        """Formatte pour la sérialisation JSON"""
        return {
            'request_id': self.unique_id,
            'primary_key': self.primary_key,  # <-- Ajouté ici
            'timestamp': self.timestamp,
            'uri': self.uri,
            'host': self.host,
            'alerts': self.alerts
        }

def reset_or_create(filepath: str) -> None:
    """Réinitialise un fichier"""
    open(filepath, 'w').close()

def safe_copy_log(src: str, dst: str) -> bool:
    """Copie sécurisée du fichier log"""
    try:
        shutil.copy2(src, dst)
        return True
    except Exception as e:
        print(f"[ERREUR] Copie impossible : {e}")
        return False

def parse_alert_line(line: str) -> Dict:
    """Extrait les informations d'une ligne d'alerte"""
    alert = {}
    for field, pattern in RE_ALERT_FIELDS.items():
        match = pattern.search(line)
        if match:
            alert[field] = match.group(1)
    tags = RE_TAGS.findall(line)
    if tags:
        alert['tags'] = tags
    return alert if alert.get('id') and alert.get('msg') else None

def process_transaction_line(line: str, transaction: Transaction) -> None:
    """Traite une ligne de transaction"""
    # Timestamp
    if not transaction.timestamp:
        ts_match = RE_TIMESTAMP.match(line)
        if ts_match:
            transaction.timestamp = ts_match.group(1)
    # Unique ID
    if not transaction.unique_id:
        uid_match = RE_UNIQUE_ID.search(line)
        if uid_match:
            transaction.unique_id = uid_match.group(1)
    # Backup pour unique_id
    if 'unique_id "' in line and not transaction.unique_id:
        uid_match = re.search(r'unique_id\s+"([^"]+)"', line)
        if uid_match:
            transaction.unique_id = uid_match.group(1)
    # URI et Host
    uri_match = RE_URI.search(line)
    if uri_match:
        transaction.uri = uri_match.group(1)
    host_match = RE_HOST.search(line)
    if host_match:
        transaction.host = host_match.group(1)
    # Extraction X-Req-ID (primary_key)
    reqid_match = RE_REQ_ID.search(line)
    if reqid_match:
        transaction.primary_key = reqid_match.group(1)
    # Alertes
    if line.startswith('ModSecurity:'):
        alert = parse_alert_line(line)
        if alert:
            transaction.alerts.append(alert)

def extract_modsec_transactions(log_path: str) -> List[Dict]:
    """Extrait et groupe les alertes par transaction"""
    transactions = {}
    current_transaction = None
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw_line in f:
            line = raw_line.strip()
            # Début/fin de transaction
            if line.startswith('---'):
                parts = line.split('---')
                if len(parts) > 2:
                    section = parts[2]
                    if section == 'A--':
                        current_transaction = Transaction()
                    elif section == 'Z--' and current_transaction:
                        if current_transaction.is_valid():
                            transactions[current_transaction.unique_id] = current_transaction
                        current_transaction = None
                continue
            if current_transaction:
                process_transaction_line(line, current_transaction)
    return [t.to_dict() for t in transactions.values() if t.alerts]

def main():
    # Initialisation
    os.makedirs(BASE_PATH, exist_ok=True)
    # Nettoyage des fichiers
    for path in [MODSEC_LOG_LOCAL, MODSEC_JSON_PATH]:
        reset_or_create(path)
    # Copie du log
    if not safe_copy_log(MODSEC_LOG_NATIVE, MODSEC_LOG_LOCAL):
        exit(1)
    # Traitement
    transactions = extract_modsec_transactions(MODSEC_LOG_LOCAL)
    if transactions:
        with open(MODSEC_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(transactions, f, indent=2, ensure_ascii=False)
        print(f"[SUCCÈS] {len(transactions)} transactions sauvegardées")
    else:
        print("[ERREUR] Aucune transaction valide trouvée. Vérifiez :")
        print(f"- Que le fichier source contient des données : {MODSEC_LOG_NATIVE}")
        print("- Les permissions d'accès aux fichiers")
        print("- La configuration de ModSecurity")

if __name__ == "__main__":
    main()

