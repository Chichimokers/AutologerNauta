import requests
from bs4 import BeautifulSoup
from ping3 import ping
import urllib3
import time
import threading
import signal
import sys
import json
import os
from getpass import getpass
from colorama import init, Fore, Style

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_url = "https://secure.etecsa.net:8443"
session_file = "session.json"

session = None
ATTRIBUTE_UUID = None
remaining_seconds = 0
login_data = None
USERNAME = None
PASSWORD = None

def log(msg, color=Fore.WHITE):
    print(color + f"[LOG] {time.strftime('%H:%M:%S')} - {msg}")

def is_host_up(host):
    result = ping(host, timeout=1)
    return result is not None

def save_credentials(username, password):
    with open(session_file, "w") as f:
        json.dump({"username": username, "password": password}, f)

def load_credentials():
    if os.path.exists(session_file):
        with open(session_file, "r") as f:
            creds = json.load(f)
            return creds.get("username"), creds.get("password")
    return None, None

def prompt_credentials():
    print(Fore.YELLOW + "🔐 Ingresa tus credenciales de acceso:")
    username = input("Usuario NAUTA: ")
    password = getpass("Contraseña: ")
    save = input("¿Deseas guardar las credenciales para futuros inicios? (s/n): ").lower()
    if save == 's':
        save_credentials(username, password)
    return username, password

def scrape_login_data(sess):
    url = f"{base_url}/"
    response = sess.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    return {name: (soup.find("input", {"name": name})["value"] if soup.find("input", {"name": name}) else "") for name in
            ["CSRFHW", "loggerId", "wlanuserip", "ssid", "wlanacname", "wlanmac"]}

def login_etecsa(username, password, data, sess):
    post_url = f"{base_url}/LoginServlet"
    payload = {
        "wlanuserip": data["wlanuserip"],
        "wlanacname": data["wlanacname"],
        "wlanmac": data["wlanmac"],
        "firsturl": "notFound.jsp",
        "ssid": data["ssid"],
        "gotopage": "/nauta_etecsa/LoginURL/pc_login.jsp",
        "successpage": "/nauta_etecsa/OnlineURL/pc_index.jsp",
        "loggerId": data["loggerId"],
        "lang": "es_ES",
        "username": username,
        "password": password,
        "CSRFHW": data["CSRFHW"]
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0",
        "Referer": f"{base_url}/",
    }

    return sess.post(post_url, data=payload, headers=headers, verify=False)

def extract_attribute_uuid(sess):
    online_url = f"{base_url}/web/online.do?CSRFHW={login_data['CSRFHW']}"
    resp = sess.get(online_url, verify=False)
    soup = BeautifulSoup(resp.text, 'html.parser')
    input_tag = soup.find("input", {"name": "ATTRIBUTE_UUID"})
    if input_tag and input_tag.has_attr("value"):
        return input_tag["value"]
    import re
    match = re.search(r'ATTRIBUTE_UUID=([A-F0-9]+)', resp.text)
    if match:
        return match.group(1)
    log("No se encontró ATTRIBUTE_UUID en la página online.", Fore.RED)
    return None

def get_available_time(sess, data):
    global remaining_seconds
    url = f"{base_url}/EtecsaQueryServlet"
    payload = {
        "op": "getLeftTime",
        "ATTRIBUTE_UUID": ATTRIBUTE_UUID,
        "CSRFHW": data["CSRFHW"],
        "wlanuserip": data["wlanuserip"],
        "ssid": data["ssid"],
        "loggerId": data["loggerId"],
        "domain": "",
        "username": USERNAME,
        "wlanacname": data["wlanacname"],
        "wlanmac": data["wlanmac"],
    }

    res = sess.post(url, data=payload, verify=False)
    time_str = res.text.strip()
    log(f"⏳ Tiempo disponible: {time_str}", Fore.CYAN)

    try:
        h, m, s = map(int, time_str.split(':'))
        remaining_seconds = h*3600 + m*60 + s
    except Exception as e:
        log(f"Error al convertir tiempo: {e}", Fore.RED)
        remaining_seconds = 0

def countdown():
    global remaining_seconds
    while remaining_seconds > 0:
        h, m, s = remaining_seconds // 3600, (remaining_seconds % 3600) // 60, remaining_seconds % 60
        print(f"\r{Fore.MAGENTA}⏱ Tiempo restante: {h:02}:{m:02}:{s:02} ", end="", flush=True)
        time.sleep(1)
        remaining_seconds -= 1
    print(f"\n{Fore.YELLOW}[LOG] Tiempo agotado.")

def logout(sess, data):
    url = f"{base_url}/LogoutServlet"
    payload = {
        "ATTRIBUTE_UUID": ATTRIBUTE_UUID,
        "CSRFHW": data["CSRFHW"],
        "wlanuserip": data["wlanuserip"],
        "ssid": data["ssid"],
        "loggerId": data["loggerId"],
        "username": USERNAME,
        "wlanacname": data["wlanacname"],
        "wlanmac": data["wlanmac"],
        "remove": "1"
    }
    sess.post(url, data=payload, verify=False)
    log("🚪 Sesión cerrada correctamente.", Fore.GREEN)

def signal_handler(sig, frame):
    global session, ATTRIBUTE_UUID, login_data
    log('🚨 Interrupción detectada. Cerrando sesión...', Fore.YELLOW)
    if session and ATTRIBUTE_UUID and login_data:
        logout(session, login_data)
    sys.exit(0)

def main_loop():
    global ATTRIBUTE_UUID, session, remaining_seconds, login_data, USERNAME, PASSWORD
    signal.signal(signal.SIGINT, signal_handler)

    USERNAME, PASSWORD = load_credentials()
    if not USERNAME or not PASSWORD:
        USERNAME, PASSWORD = prompt_credentials()

    while True:
        try:
            log("🌐 Verificando conectividad...", Fore.WHITE)
            if not is_host_up("10.24.22.55"):
                log("10.24.22.55 no responde.", Fore.RED)
            elif not is_host_up("10.180.0.30"):
                log("10.180.0.30 no responde.", Fore.RED)
            elif is_host_up("cubadebate.cu"):
                log("🌍 Acceso a Internet disponible.", Fore.GREEN)
            else:
                log("🌐 No hay conexión externa. Intentando login...", Fore.YELLOW)
                session = requests.Session()
                login_data = scrape_login_data(session)
                log("Datos obtenidos desde portal...", Fore.BLUE)

                response = login_etecsa(USERNAME, PASSWORD, login_data, session)
                if "OnlineURL" in response.text:
                    log("✅ Login exitoso.", Fore.GREEN)
                    ATTRIBUTE_UUID = extract_attribute_uuid(session)
                    if ATTRIBUTE_UUID:
                        log(f"UUID de sesión: {ATTRIBUTE_UUID}", Fore.CYAN)
                        get_available_time(session, login_data)
                        t = threading.Thread(target=countdown, daemon=True)
                        t.start()
                    else:
                        log("UUID no obtenido. No se iniciará contador.", Fore.RED)
                else:
                    log("❌ Fallo de login. Verifica tus credenciales.", Fore.RED)
        except Exception as e:
            log(f"❌ Error inesperado: {e}", Fore.RED)

        time.sleep(10)

if __name__ == "__main__":
    main_loop()
