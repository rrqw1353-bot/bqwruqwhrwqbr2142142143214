
# -*- coding: utf-8 -*-
import sys
import os
import jwt
import datetime
import win32crypt
import time
import vdf
import zlib
import shutil
import subprocess
import psutil
import winreg
import stat
import logging
import random
import string
import json
import base64
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import QApplication, QMessageBox
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Sabit input (username----token)
FIXED_INPUT = "zlucassousa----eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5ODI2MTgwNjgzNSIsICJhdWQiOiBbICJjbGllbnQiLCAid2ViIiwgInJlbmV3IiwgImRlcml2ZSIgXSwgImV4cCI6IDE3NzM3NTg5MTUsICJuYmYiOiAxNzQ3MDc0ODgzLCAiaWF0IjogMTc1NTcxNDg4MywgImp0aSI6ICIwMDE5XzI2Q0U5RDNFXzdDQjg3IiwgIm9hdCI6IDE3NTU3MTQ4ODMsICJwZXIiOiAxLCAiaXBfc3ViamVjdCI6ICIxNjguMTk1LjE1Mi4yMzgiLCAiaXBfY29uZmlybWVyIjogIjE2OC4xOTUuMTUyLjIzOCIgfQ.VseMBfI9_DGS6bsqIpAg63dBtPVO1EA9iIdxljd9E_lbraGl2m0a96vnWwFDt1iRdCgp_LSnpamsqz3iMJuPCg"

def random_string(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def parse_eya(eya):
    token_arr = eya.split('.')
    if len(token_arr) != 3:
        return None
    padding = len(token_arr[1]) % 4
    if padding != 0:
        token_arr[1] += '=' * (4 - padding)
    return base64.b64decode(token_arr[1]).decode('utf-8')

def doLogin(account_name,token):
    if '@' in account_name:
        account_name = account_name.split('@')[0]
    crc32_account_name = compute_crc32(account_name) + "1"
    json_data = json.loads(parse_eya(token))
    if not json_data:
        return False, "Invalid token!"
    steam_id = json_data['sub']
    mtbf = ''.join(random.choices(string.digits, k=9))
    jwt = steam_encrypt(token, account_name)
    path = get_steam_install_path()
    local_vdf_path = get_local_vdf_path()
    if os.path.exists(local_vdf_path):
        os.remove(local_vdf_path)
    try:
        os.makedirs(os.path.join(path, 'config'), exist_ok=True)
    except FileExistsError:
        pass
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Valve\\Steam', 0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, 'AutoLoginUser', 0, winreg.REG_SZ, account_name)
    winreg.CloseKey(key)
    
    # Mevcut config.vdf'yi oku ve parse et
    config_path = os.path.join(path, 'config', 'config.vdf')
    existing_config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                existing_config = vdf.loads(f.read())
        except Exception:
            existing_config = {}
    
    # Mevcut config'i temel al, yeni hesabı ekle
    config = existing_config.get('InstallConfigStore', {})
    software = config.get('Software', {})
    valve = software.get('Valve', {})
    steam = valve.get('Steam', {})
    
    # Accounts bölümünü güncelle
    accounts = steam.get('Accounts', {})
    accounts[account_name] = {'SteamID': steam_id}
    steam['Accounts'] = accounts
    
    # Diğer mevcut alanları koru
    steam['MTBF'] = mtbf  # Yeni MTBF'yi güncelle
    steam['CellIDServerOverride'] = steam.get('CellIDServerOverride', '170')
    # Diğer sabit alanları ekle/güncelle
    steam['AutoUpdateWindowEnabled'] = steam.get('AutoUpdateWindowEnabled', '0')
    steam['ipv6check_http_state'] = steam.get('ipv6check_http_state', 'bad')
    steam['ipv6check_udp_state'] = steam.get('ipv6check_udp_state', 'bad')
    
    # ShaderCacheManager vb. mevcutsa koru
    if 'ShaderCacheManager' not in steam:
        steam['ShaderCacheManager'] = {
            "HasCurrentBucket": "1",
            "CurrentBucketGPU": "b4799b250d4196b0;36174e7cc31a08f9",
            "CurrentBucketDriver": "W2:c18b09d9c69329b41cdbbf3de627bc9f;W2:ee32edf67d134b7cc2ec0cdecbd00037"
        }
    
    steam['RecentWebSocket443Failures'] = steam.get('RecentWebSocket443Failures', '')
    steam['RecentWebSocketNon443Failures'] = steam.get('RecentWebSocketNon443Failures', '')
    steam['RecentUDPFailures'] = steam.get('RecentUDPFailures', '')
    steam['RecentTCPFailures'] = steam.get('RecentTCPFailures', '')
    steam['cip'] = steam.get('cip', "02000000507a6c24d6e96c6b00004021a356")
    steam['SurveyDate'] = steam.get('SurveyDate', "2017-10-22")
    steam['SurveyDateVersion'] = steam.get('SurveyDateVersion', "-1724767764117155760")
    steam['SurveyDateType'] = steam.get('SurveyDateType', "3")
    steam['Rate'] = steam.get('Rate', "30000")
    
    valve['Steam'] = steam
    software['Valve'] = valve
    config['Software'] = software
    install_config_store = {'InstallConfigStore': config}
    
    # Diğer bölümleri koru (SDL_GamepadBind, streaming, Music vb.)
    if 'SDL_GamepadBind' not in install_config_store:
        install_config_store['SDL_GamepadBind'] = {
            "03000000de280000ff11000001000000,Steam Virtual Gamepad": "a:b0,b:b1,back:b6,dpdown:h0.4,dpleft:h0.8,dpright:h0.2,dpup:h0.1,leftshoulder:b4,leftstick:b8,lefttrigger:+a2,leftx:a0,lefty:a1,rightshoulder:b5,rightstick:b9,righttrigger:-a2,rightx:a3,righty:a4,start:b7,x:b2,y:b3,platform:Windows",
            "03000000de280000ff11000000000000,Steam Virtual Gamepad": "a:b0,b:b1,back:b6,dpdown:h0.4,dpleft:h0.8,dpright:h0.2,dpup:h0.1,leftshoulder:b4,leftstick:b8,lefttrigger:+a2,leftx:a0,lefty:a1,rightshoulder:b5,rightstick:b9,righttrigger:-a2,rightx:a3,righty:a4,start:b7,x:b2,y:b3",
            "03000000de280000ff11000000007701,Steam Virtual Gamepad": "a:b0,b:b1,x:b2,y:b3,back:b6,start:b7,leftstick:b8,rightstick:b9,leftshoulder:b4,rightshoulder:b5,dpup:b10,dpdown:b12,dpleft:b13,dpright:b11,leftx:a1,lefty:a0~,rightx:a3,righty:a2~,lefttrigger:a4,righttrigger:a5,"
        }
    if 'streaming' not in install_config_store:
        install_config_store['streaming'] = {"ClientID": "-6167702798309564492"}
    if 'Music' not in install_config_store:
        install_config_store['Music'] = {
            "LocalLibrary": {
                "Directories": {
                    "0": "0200000013500d50b7e96d1b621bcb56f5a12ce5e0651b4c3b3a50a59063d16c7d6fc334d903be2347030590f9d63c5a09370ac77bcfc6c945d0b348b91a586438e4162d56e494c9c73173ae",
                    "1": "0200000013500d50b7e96d1b621bcb56f2a12ce3e76508523b7812f4c237ec51786ff63aac72a1212b7416a2f0d71b7039302dcc2ebca3bb45d2c02bd87645623d8a784832e49cc1a01779a2209be04c"
                }
            }
        }
    
    config_vdf = vdf.dumps(install_config_store)
    
    # Mevcut loginusers.vdf'yi oku ve parse et
    loginusers_path = os.path.join(path, 'config', 'loginusers.vdf')
    existing_loginusers = {}
    if os.path.exists(loginusers_path):
        try:
            with open(loginusers_path, 'r', encoding='utf-8') as f:
                existing_loginusers = vdf.loads(f.read())
        except Exception:
            existing_loginusers = {}
    
    users = existing_loginusers.get('users', {})
    random_persona = random_string(8)
    users[steam_id] = {
        "AccountName": account_name,
        "PersonaName": random_persona,
        "RememberPassword": "1",
        "WantsOfflineMode": "0",
        "SkipOfflineModeWarning": "0",
        "AllowAutoLogin": "1",
        "MostRecent": "1",
        "Timestamp": str(int(time.time()))
    }
    existing_loginusers['users'] = users
    login_users_vdf = vdf.dumps(existing_loginusers)
    
    # Config.vdf yaz
    remove_readonly(os.remove, config_path, None)
    with open(config_path, 'w', encoding='utf-8') as f:
        f.write(config_vdf)
    
    # Loginusers.vdf yaz
    remove_readonly(os.remove, loginusers_path, None)
    with open(loginusers_path, 'w', encoding='utf-8') as f:
        f.write(login_users_vdf)
    
    # Local.vdf oluştur/güncelle
    local = build_local(crc32_account_name, jwt)
    local_vdf_path = get_local_vdf_path()
    if os.path.exists(local_vdf_path):
        remove_readonly(os.remove, local_vdf_path, None)
    with open(local_vdf_path, 'w', encoding='utf-8') as f:
        f.write(local)
    
    subprocess.Popen(os.path.join(path, 'steam.exe'), shell=True)
    return True, "Logged in."

def get_pid(process_name):
    for process in psutil.process_iter():
        if process.name() == process_name:
            return process.pid
    return 0

def read_registry_value(key_path, value_name):
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
    value, _ = winreg.QueryValueEx(key, value_name)
    winreg.CloseKey(key)
    if isinstance(value, bytes):
        value = value.decode('utf-8')
    return value

def get_steam_install_path():
    steam_pid = get_pid('steam.exe')
    if steam_pid != 0:
        process = psutil.Process(steam_pid)
        steam_path = process.exe()
        subprocess.run('taskkill /f /im steam.exe', shell=True)
        subprocess.run('taskkill /f /im steamwebhelper.exe', shell=True)
        time.sleep(2)
    else:
        steam_path = read_registry_value('Software\\Classes\\steam\\Shell\\Open\\Command', '').replace('"', '')
        steam_path = steam_path[:len(steam_path) - 6]
    return steam_path[:len(steam_path) - 9]

def compute_crc32(data):
    crc32_value = zlib.crc32(data.encode('utf-8'))
    return f'{crc32_value:08x}'.lstrip('0')

def steam_encrypt(token, account_name):
    data_to_encrypt = token.encode('utf-8')
    byte_string = b'B\x00O\x00b\x00f\x00u\x00s\x00c\x00a\x00t\x00e\x00B\x00u\x00f\x00f\x00e\x00r\x00\x00\x00'
    encrypted_data = win32crypt.CryptProtectData(data_to_encrypt, byte_string.decode('utf-8'), account_name.encode('utf-8'), None, None, 17)
    return encrypted_data.hex()

def build_local(crc32, jwt):
    local = {
        "MachineUserConfigStore": {
            "Software": {
                "Valve": {
                    "Steam": {
                        "ConnectCache": {
                            crc32: jwt
                        }
                    }
                }
            }
        }
    }
    return vdf.dumps(local)

def get_local_vdf_path():
    app_data_path = os.getenv('localappdata')
    if app_data_path is None:
        logger.error("Failed to get localappdata environment variable.")
    return os.path.join(app_data_path, 'Steam', 'local.vdf')

def remove_readonly(func, path, excinfo):
    if os.path.exists(path):
        try:
            os.chmod(path, stat.S_IWRITE)
        except Exception:
            pass
        func(path)

def get_current_jwt_from_local_vdf():
    try:
        username = get_current_account()
        if not username:
            print("Kullanıcı adı alınamadı.")
            return None

        # crc32(account) + '1' şeklinde anahtar
        crc_key = compute_crc32(username) + "1"

        local_vdf_path = get_local_vdf_path()
        if not os.path.exists(local_vdf_path):
            print("local.vdf bulunamadı.")
            return None

        with open(local_vdf_path, 'r', encoding='utf-8', errors='ignore') as f:
            vdf_text = f.read()

        # vdf dosyasını parse et
        try:
            data = vdf.loads(vdf_text)
        except Exception as e:
            print(f"VDF parse hatası: {e}")
            return None

        # Veriye ulaş
        try:
            connect_cache = data['MachineUserConfigStore']['Software']['Valve']['Steam']['ConnectCache']
        except KeyError:
            print("ConnectCache bulunamadı.")
            return None

        # Belirli anahtarı al
        jwt_encrypted_hex = connect_cache.get(crc_key)
        if not jwt_encrypted_hex:
            print(f"{crc_key} anahtarı ConnectCache içinde yok.")
            return None

        # Hex -> bytes
        try:
            encrypted_bytes = bytes.fromhex(jwt_encrypted_hex)
        except ValueError:
            print("Hex decoding başarısız.")
            return None

        # CryptUnprotectData kullanarak çöz
        try:
            desc, decrypted = win32crypt.CryptUnprotectData(encrypted_bytes, None, username.encode('utf-8'), None, None, 0)
            return decrypted.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Token çözme hatası: {e}")
            return None

    except Exception as e:
        print(f"Hata oluştu: {e}")
        return None

def reset_steam():
    path = get_steam_install_path()
    for directory in [os.path.join(path, 'userdata'), os.path.join(path, 'config')]:
        if os.path.exists(directory):
            shutil.rmtree(directory, onerror=remove_readonly)
    local_vdf_path = get_local_vdf_path()
    if os.path.exists(local_vdf_path):
        os.remove(local_vdf_path)
    subprocess.Popen(os.path.join(path, 'steam.exe'), shell=True)


def get_current_account():
    try:
        registry_path = r"SOFTWARE\Valve\Steam"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path) as key:
            value, value_type = winreg.QueryValueEx(key, "AutoLoginUser")
            return value
    except FileNotFoundError:
        print("Registry key or value not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def kill_steam():
    steam_pid = get_pid('steam.exe')
    if steam_pid != 0:
        process = psutil.Process(steam_pid)
        steam_path = process.exe()
        subprocess.run('taskkill /f /im steam.exe', shell=True)
        subprocess.run('taskkill /f /im steamwebhelper.exe', shell=True)
        time.sleep(2)

def saveCurrentAccounts():
    try:
        username = get_current_account()
        vdf_path = get_local_vdf_path()
        path = get_steam_install_path()
    
        save_path = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData/Local")) / 'WbDI8NbcA' / 'config'
        save_path.mkdir(parents=True, exist_ok=True)
        file_path = save_path / "saved_user.txt"
        if os.path.exists(file_path):
            file_path.unlink() 
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(username or '')
        try:
            shutil.copyfile(os.path.join(path, 'config', 'config.vdf'), save_path / 'config.vdf')
        except Exception as e: 
            print(e)
        try:
            shutil.copyfile(os.path.join(path, 'config', 'loginusers.vdf'), save_path / 'loginusers.vdf')
        except Exception as e: 
            print(e)
        try:
            shutil.copyfile(vdf_path, save_path / 'local.vdf')
        except Exception as e: 
            print(e)
    except Exception as e:
        print(e)
     
def restoreSavedAccounts():
    kill_steam()
    try:
        vdf_path = get_local_vdf_path()
        path = get_steam_install_path()
    
        save_path = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData/Local")) / 'WbDI8NbcA' / 'config'
        file_path = save_path / "saved_user.txt"
        if not file_path.exists():
            raise FileNotFoundError("Saved user file not found.")
        with open(file_path,'r',encoding='utf-8',errors='ignore') as f:
            username = f.readline().strip()
        try:
            shutil.copyfile(save_path / 'config.vdf', os.path.join(path, 'config', 'config.vdf'))
        except Exception as e: 
            print(e)
        try:
            shutil.copyfile(save_path / 'loginusers.vdf', os.path.join(path, 'config', 'loginusers.vdf'))
        except Exception as e: 
            print(e)
        try:
            shutil.copyfile(save_path / 'local.vdf', vdf_path)
        except Exception as e: 
            print(e)
    except Exception as e:
        print(e)
        
def start_steam():
    path = get_steam_install_path()
    subprocess.Popen(os.path.join(path, 'steam.exe'), shell=True)

if __name__ == "__main__":
    # Konsolu gizle (Windows için)
    if sys.platform.startswith('win'):
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    app = QApplication(sys.argv)
    
    parts = FIXED_INPUT.split("----", 1)
    if len(parts) != 2:
        QMessageBox.warning(None, "Error", "Invalid input format. Expected username----token.")
        sys.exit(1)

    username = parts[0].strip()
    token_plain = parts[1].strip().replace(" ", "")

    if not token_plain:
        QMessageBox.warning(None, "Error", "Token is required.")
        sys.exit(1)

    try:
        success, msg = doLogin(username, token_plain)
        if success:
            QMessageBox.information(None, "Success", msg)
            sys.exit(0)
        else:
            QMessageBox.warning(None, "Error", msg)
            sys.exit(1)
    except Exception as e:
        QMessageBox.warning(None, "Error", f"Login failed: {str(e)}")

        sys.exit(1)




