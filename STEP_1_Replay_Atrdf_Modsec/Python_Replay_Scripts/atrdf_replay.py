import os
import json
import requests
from tqdm import tqdm
from urllib.parse import urlparse, urlunparse

# === CONFIG ===
BASE_PATH = "/home/Tarek/Documents/Atrdf_Dataset"
ATRDF_PATH = os.path.join(BASE_PATH, "atrdf.json")
LOG_NATIVE_PATH = "/var/log/modsec_audit.log"
LOG_PARSED_PATH = os.path.join(BASE_PATH, "modsec_audit.json")

# === ÉTAPE 1 : s'assurer que le dossier existe ===
os.makedirs(BASE_PATH, exist_ok=True)

# === ÉTAPE 2 : réinitialiser le log natif ===
open(LOG_NATIVE_PATH, "w").close()
print(f"[INFO] Log natif réinitialisé : {LOG_NATIVE_PATH}")

# === ÉTAPE 3 : charger les requêtes ===
with open(ATRDF_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

# === ÉTAPE 4 : envoyer les requêtes (tout traiter, sans limite) ===
for entry in tqdm(data, total=len(data)):
    req = entry['request']
    method = req['method']
    url = req['url']

    # Force destination sur port 80 (localhost)
    parsed = urlparse(url)
    new_netloc = '127.0.0.1'
    url = urlunparse(parsed._replace(netloc=new_netloc, scheme='http'))

    headers = req['headers'].copy()
    body = req.get('body', '')

    # 👉 Prend le champ primary_key tel quel
    headers['X-Req-ID'] = entry["primary_key"]
    headers = {k: v for k, v in headers.items() if k.lower() != 'set-cookie'}

    try:
        if method.upper() == "POST":
            requests.post(url, headers=headers, data=body, timeout=5, verify=False)
        elif method.upper() == "GET":
            requests.get(url, headers=headers, timeout=5, verify=False)
        else:
            print(f"Skip (unsupported method): {method} @ {url}")
    except Exception as e:
        print(f"Erreur requête {entry['primary_key']} ({url}): {e}")

print("[INFO] Replay terminé !")

