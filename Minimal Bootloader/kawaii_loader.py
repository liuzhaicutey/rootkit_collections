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

# Get the directory of the executable or script
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    DIR = os.path.dirname(sys.executable)
else:
    # Running as script
    DIR = os.path.dirname(os.path.abspath(__file__))

# Enable console output for frozen executable
if getattr(sys, 'frozen', False):
    # Allocate console for exe if it doesn't have one
    kernel32 = ctypes.windll.kernel32
    kernel32.AllocConsole()
    sys.stdout = open('CONOUT
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
    """Print to console and log file"""
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
    """Request admin privileges and restart"""
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
            # Restart with admin privileges
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
            
        log_print(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        
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
    log_print("Detecting system boot mode (UEFI or Legacy BIOS)...")
    
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
                log_print("UEFI System Partition (ESP) found.")
                return "UEFI"
    
    if os.environ.get('firmware_type') == 'UEFI':
        log_print("Environment variable indicates UEFI.")
        return "UEFI"
        
    log_print("UEFI System Partition not found. Assuming Legacy BIOS mode.")
    return "BIOS"


def find_free_drive_letter():
    """Find an available drive letter"""
    import string
    used_drives = [d.upper() for d in [chr(x) + ':' for x in range(65, 91)] if os.path.exists(chr(x) + ':')]
    
    # Prefer letters from S to Z (less likely to be used)
    for letter in string.ascii_uppercase[::-1]:
        if letter not in ['A', 'B', 'C'] and letter + ':' not in used_drives:
            return letter
    
    raise Exception("No free drive letters available!")


def mount_partition(is_uefi):
    if is_uefi:
        log_print("Searching for EFI System Partition...")
        target_search = "FAT32"
        target_error = "EFI System Partition (ESP) volume not found."
    else:
        log_print("Searching for the Active System Partition...")
        target_search = "Active"
        target_error = "Active/System Partition not found. Legacy boot requires an active partition."

    tmp = os.path.join(DIR, 'tmp_list.txt')
    vol = None
    existing_letter = None
    
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
                # Check if it already has a drive letter
                letter_match = re.search(r'\s+([A-Z])\s+', line)
                if letter_match:
                    existing_letter = letter_match.group(1)
                    log_print(f"Volume {vol} already has drive letter {existing_letter}:")
                break
            
    if not vol:
        raise Exception(target_error)
    
    # If it already has a letter, use that
    if existing_letter:
        drive_path = f"{existing_letter}:\\"
        log_print(f"Using existing drive letter: {existing_letter}:")
        return drive_path
    
    # Find a free drive letter
    free_letter = find_free_drive_letter()
    log_print(f"Found volume: {vol}. Mounting as letter {free_letter}:")
    
    tmp_mount = os.path.join(DIR, 'tmp_mount.txt')
    content = f"select volume {vol}\nassign letter={free_letter}\nexit\n"
    
    try:
        with open(tmp_mount, 'w') as f: 
            f.write(content)
        run_cmd(["diskpart", "/s", tmp_mount])
    finally:
        if os.path.exists(tmp_mount): 
            os.remove(tmp_mount)
            
    time.sleep(2)
    drive_path = f"{free_letter}:\\"
    if not os.path.isdir(drive_path):
        raise Exception(f"Failed to mount partition as {free_letter}:. Check if the letter is already in use.")

    return drive_path


def umount(d):
    log_print(f"Unmounting volume {d}...")
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
            log_print(f"Volume {d} unmounted successfully.")
        else:
            log_print(f"Could not find volume number for drive {d} to unmount.")
            
    except Exception as e:
        log_print(f"Warning: Failed to unmount drive {d}. Manual removal might be necessary. Error: {e}")
    finally:
        if os.path.exists(tmp): 
            os.remove(tmp)
        if os.path.exists(list_vol):
            os.remove(list_vol)


def uefi_cert():
    log_print(f"Generating, installing, and exporting certificate '{UEFI_CERT_NAME}'...")
    
    script = f"""
$ErrorActionPreference='Stop'

Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object {{$_.Subject -like "CN={UEFI_CERT_NAME}"}} | Remove-Item -Force
if (Test-Path "{UEFI_TEMP_PFX}") {{ Remove-Item "{UEFI_TEMP_PFX}" -Force }}

$cert = New-SelfSignedCertificate -DnsName "{UEFI_CERT_NAME}" -CertStoreLocation "Cert:\\CurrentUser\\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5) -Type CodeSigning -HashAlgorithm SHA256

$p = "{UEFI_CERT_FILE}"
Export-Certificate -Cert $cert -FilePath $p -Force -Type CERT

if (Test-Path $p) {{
    Import-Certificate -FilePath $p -CertStoreLocation "Cert:\\LocalMachine\\Root"
    Write-Host "Certificate imported successfully to Root store."
}} else {{
    throw "Certificate file not found after export."
}}

$cert | Export-PfxCertificate -FilePath "{UEFI_TEMP_PFX}" -Password (ConvertTo-SecureString -String "{UEFI_PFX_PASSWORD}" -Force -AsPlainText)
Write-Host "Private key exported to PFX successfully."
"""
    try:
        with open(UEFI_TEMP_PS1, "w", encoding="utf-8") as f:
            f.write(script)
            
        run_cmd(f"powershell -ExecutionPolicy Bypass -File \"{UEFI_TEMP_PS1}\"", shell=True)
        log_print("Certificate successfully generated, imported, and PFX exported.")
        
    except Exception as e:
        log_print(f"Certificate management failed: {e}")
        raise
    finally:
        if os.path.exists(UEFI_TEMP_PS1):
            os.remove(UEFI_TEMP_PS1)


def uefi_load_private_key_from_pfx(pfx_path, password):
    log_print(f"Loading private key from PFX: {pfx_path}...")
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
    
    log_print(f"--- Starting Custom Secure Signing Process for '{UEFI_BOOT_BINARY}' ---")

    if not os.path.exists(bl_src):
        raise FileNotFoundError(f"Binary file '{bl_src}' missing in script directory.")

    try:
        with open(bl_src, 'rb') as f:
            raw_binary_data = f.read()
            
        binary_size = len(raw_binary_data)
        log_print(f"Raw binary size: {binary_size} bytes")

        signature = private_key.sign(
            raw_binary_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        log_print(f"Digital Signature Size: {len(signature)} bytes")

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
        log_print(f"Secure Header Size: {len(secure_header)} bytes")
        
        with open(secure_img_path, 'wb') as f:
            f.write(secure_header)
            f.write(raw_binary_data)
        
        log_print(f"✅ Successfully created secure image: {UEFI_SECURE_IMAGE_NAME}")
        
    except Exception as e:
        log_print(f"Binary signing failed: {e}")
        raise


def uefi_boot(private_key):
    log_print("\n--- Starting UEFI Bootloader Installation ---")
    
    uefi_custom_sign(private_key)
    
    bl_src = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)
    
    d = None
    try:
        d = mount_partition(True)
        
        base_dir = os.path.join(d, UEFI_EFI_PATH.strip('\\'))
        dest_path = os.path.join(base_dir, UEFI_BOOT_BINARY)
        
        log_print(f"Copying '{UEFI_SECURE_IMAGE_NAME}' to '{dest_path}'...")
        os.makedirs(base_dir, exist_ok=True)
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        log_print("Bootloader copied successfully.")
        
        bcd_path = os.path.join(UEFI_EFI_PATH, UEFI_BOOT_BINARY).replace("/", "\\")
        
        log_print(f"Creating new BCD entry: '{UEFI_BOOT_NAME}'...")
        
        # For custom UEFI bootloaders, we need to create a firmware boot entry
        # First, let's try creating it with /create /firmware
        try:
            out = run_cmd(["bcdedit", "/create", "/d", UEFI_BOOT_NAME, "/application", "bootapp"])
            log_print(f"bcdedit output:\n{out}")
        except Exception as e:
            log_print(f"Failed with bootapp, trying alternative method: {e}")
            # Alternative: create with firmware flag
            out = run_cmd(["bcdedit", "/create", "{guid}", "/d", UEFI_BOOT_NAME])
        
        # Try multiple GUID patterns
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
                log_print(f"Successfully extracted GUID: {g}")
                break
        
        if not g:
            log_print(f"ERROR - Could not find GUID in output.")
            log_print(f"Output lines:")
            for i, line in enumerate(out.splitlines(), 1):
                log_print(f"  Line {i}: {repr(line)}")
            raise Exception(f"Failed to extract GUID from bcdedit output")
        
        log_print(f"New BCD Entry GUID: {g}")
        
        # Configure the boot entry
        log_print("Configuring boot entry...")
        run_cmd(["bcdedit", "/set", g, "device", f"partition={d}"])
        run_cmd(["bcdedit", "/set", g, "path", bcd_path])
        
        # Set this entry as the DEFAULT boot option
        log_print("Setting as default boot entry...")
        try:
            run_cmd(["bcdedit", "/default", g])
            log_print("✅ Set as default boot entry")
        except Exception as e:
            log_print(f"Warning: Could not set as default: {e}")
        
        # Add to display order as first option
        log_print("Adding to boot display order...")
        try:
            run_cmd(["bcdedit", "/displayorder", g, "/addfirst"])
            log_print("✅ Added to display order as first option")
        except Exception as e:
            log_print(f"Warning: Could not add to display order: {e}")
        
        # Set boot timeout
        log_print("Setting boot menu timeout...")
        try:
            run_cmd(["bcdedit", "/timeout", "10"])
            log_print("✅ Boot timeout set to 10 seconds")
        except Exception as e:
            log_print(f"Warning: Could not set timeout: {e}")
        
        log_print("\n" + "="*60)
        log_print("BCD Configuration Complete!")
        log_print("="*60)
        
        log_print("BCD entry created and set as first in display order.")
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Success", f"UEFI Bootloader '{UEFI_BOOT_NAME}' installed successfully!\n\nREMEMBER TO ENROLL '{UEFI_CERT_FILE}'!")
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
    log_print("\n--- Starting Legacy BIOS Boot Installation ---")
    
    bl_src = os.path.join(DIR, BIOS_BOOT_BINARY)
    
    d = None
    try:
        d = mount_partition(False)
        
        dest_path = os.path.join(d, BIOS_DEST_BOOT_NAME)
        
        log_print(f"Copying '{BIOS_BOOT_BINARY}' to '{dest_path}'...")
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        log_print(f"Custom boot binary copied successfully as '{BIOS_DEST_BOOT_NAME}'.")
        
        log_print(f"Writing Legacy Windows Boot Sector to the partition {d}")
        run_cmd(["bootsect", "/nt60", f"{d}", "/force"])
        
        log_print("✅ Legacy Boot configuration complete.")
        
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

    log_print(f"Script started from: {DIR}")
    log_print(f"Running as frozen executable: {getattr(sys, 'frozen', False)}")

    boot_mode = detect_boot_mode()
    
    if boot_mode == "UEFI":
        binary_path = os.path.join(DIR, UEFI_BOOT_BINARY)
        if not os.path.exists(binary_path):
            log_print(f"Creating dummy UEFI binary: {binary_path} (10 KB)")
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
        
        private_key = None
        
        try:
            uefi_cert()
            private_key = uefi_load_private_key_from_pfx(UEFI_TEMP_PFX, UEFI_PFX_PASSWORD)
            uefi_boot(private_key)
            
        finally:
            if os.path.exists(UEFI_TEMP_PFX):
                os.remove(UEFI_TEMP_PFX)
                log_print(f"Cleaned up sensitive temporary PFX file: {UEFI_TEMP_PFX}")
                
        log_print(f"Script finished. **IMPORTANT:** Retained '{UEFI_CERT_FILE}' for manual UEFI key enrollment.")

    elif boot_mode == "BIOS":
        binary_path = os.path.join(DIR, BIOS_BOOT_BINARY)
        if not os.path.exists(binary_path):
            log_print(f"Creating dummy BIOS binary: {binary_path} (10 KB)")
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
                
        legacy_boot()
        
        log_print("Script finished. The active partition is now set to boot the custom binary.")
        
    else:
        raise Exception("Could not reliably determine the system boot mode.")


def main():
    log_print("="*60)
    log_print("BOOTLOADER INSTALLER STARTING")
    log_print("="*60)
    
    try:
        # Check admin first
        request_admin()
        
        # Run installer
        main_installer()
        
        log_print("\n--- Self-Destruct Sequence Initiated ---")
        target = os.path.abspath(__file__) if not getattr(sys, 'frozen', False) else sys.executable
        bat = os.path.join(DIR, "delete_me.bat")
        
        image_to_delete_secure = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)
        image_to_delete_uefi = os.path.join(DIR, UEFI_BOOT_BINARY)
        image_to_delete_bios = os.path.join(DIR, BIOS_BOOT_BINARY)
        
        with open(bat, 'w') as f:
            f.write('@echo off\n')
            f.write(f'ping 127.0.0.1 -n 5 >nul\n')
            f.write(f'del "{target}" /f /q\n')
            
            f.write(f'if exist "{image_to_delete_secure}" del "{image_to_delete_secure}" /f /q\n')
            f.write(f'if exist "{image_to_delete_uefi}" del "{image_to_delete_uefi}" /f /q\n')
            f.write(f'if exist "{image_to_delete_bios}" del "{image_to_delete_bios}" /f /q\n')

            f.write(f'del "%~f0" /f /q\n')
        
        log_print("\n✅ Installation completed successfully!")
        log_print(f"Log file saved to: {LOG_FILE}")
        log_print("\nPress any key to exit...")
        
        try:
            input()
        except:
            time.sleep(5)
            
        subprocess.Popen([bat], shell=True, creationflags=subprocess.DETACHED_PROCESS)
        sys.exit(0)

    except Exception as e:
        log_print(f"\n{'='*60}")
        log_print(f"FATAL ERROR: {e}")
        log_print(f"{'='*60}")
        log_print(traceback.format_exc())
        log_print(f"\nLog file saved to: {LOG_FILE}")
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", f"A critical error occurred:\n\n{e}\n\nCheck {LOG_FILE} for details.")
            root.destroy()
        except:
            pass
        
        log_print("\nPress any key to exit...")
        try:
            input()
        except:
            time.sleep(10)
        
        sys.exit(1)


if __name__ == "__main__":
    main(), 'w')
    sys.stderr = open('CONOUT
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
    """Print to console and log file"""
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
    """Request admin privileges and restart"""
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
            # Restart with admin privileges
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
            
        log_print(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        
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
    log_print("Detecting system boot mode (UEFI or Legacy BIOS)...")
    
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
                log_print("UEFI System Partition (ESP) found.")
                return "UEFI"
    
    if os.environ.get('firmware_type') == 'UEFI':
        log_print("Environment variable indicates UEFI.")
        return "UEFI"
        
    log_print("UEFI System Partition not found. Assuming Legacy BIOS mode.")
    return "BIOS"


def find_free_drive_letter():
    """Find an available drive letter"""
    import string
    used_drives = [d.upper() for d in [chr(x) + ':' for x in range(65, 91)] if os.path.exists(chr(x) + ':')]
    
    # Prefer letters from S to Z (less likely to be used)
    for letter in string.ascii_uppercase[::-1]:
        if letter not in ['A', 'B', 'C'] and letter + ':' not in used_drives:
            return letter
    
    raise Exception("No free drive letters available!")


def mount_partition(is_uefi):
    if is_uefi:
        log_print("Searching for EFI System Partition...")
        target_search = "FAT32"
        target_error = "EFI System Partition (ESP) volume not found."
    else:
        log_print("Searching for the Active System Partition...")
        target_search = "Active"
        target_error = "Active/System Partition not found. Legacy boot requires an active partition."

    tmp = os.path.join(DIR, 'tmp_list.txt')
    vol = None
    existing_letter = None
    
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
                # Check if it already has a drive letter
                letter_match = re.search(r'\s+([A-Z])\s+', line)
                if letter_match:
                    existing_letter = letter_match.group(1)
                    log_print(f"Volume {vol} already has drive letter {existing_letter}:")
                break
            
    if not vol:
        raise Exception(target_error)
    
    # If it already has a letter, use that
    if existing_letter:
        drive_path = f"{existing_letter}:\\"
        log_print(f"Using existing drive letter: {existing_letter}:")
        return drive_path
    
    # Find a free drive letter
    free_letter = find_free_drive_letter()
    log_print(f"Found volume: {vol}. Mounting as letter {free_letter}:")
    
    tmp_mount = os.path.join(DIR, 'tmp_mount.txt')
    content = f"select volume {vol}\nassign letter={free_letter}\nexit\n"
    
    try:
        with open(tmp_mount, 'w') as f: 
            f.write(content)
        run_cmd(["diskpart", "/s", tmp_mount])
    finally:
        if os.path.exists(tmp_mount): 
            os.remove(tmp_mount)
            
    time.sleep(2)
    drive_path = f"{free_letter}:\\"
    if not os.path.isdir(drive_path):
        raise Exception(f"Failed to mount partition as {free_letter}:. Check if the letter is already in use.")

    return drive_path


def umount(d):
    log_print(f"Unmounting volume {d}...")
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
            log_print(f"Volume {d} unmounted successfully.")
        else:
            log_print(f"Could not find volume number for drive {d} to unmount.")
            
    except Exception as e:
        log_print(f"Warning: Failed to unmount drive {d}. Manual removal might be necessary. Error: {e}")
    finally:
        if os.path.exists(tmp): 
            os.remove(tmp)
        if os.path.exists(list_vol):
            os.remove(list_vol)


def uefi_cert():
    log_print(f"Generating, installing, and exporting certificate '{UEFI_CERT_NAME}'...")
    
    script = f"""
$ErrorActionPreference='Stop'

Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object {{$_.Subject -like "CN={UEFI_CERT_NAME}"}} | Remove-Item -Force
if (Test-Path "{UEFI_TEMP_PFX}") {{ Remove-Item "{UEFI_TEMP_PFX}" -Force }}

$cert = New-SelfSignedCertificate -DnsName "{UEFI_CERT_NAME}" -CertStoreLocation "Cert:\\CurrentUser\\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5) -Type CodeSigning -HashAlgorithm SHA256

$p = "{UEFI_CERT_FILE}"
Export-Certificate -Cert $cert -FilePath $p -Force -Type CERT

if (Test-Path $p) {{
    Import-Certificate -FilePath $p -CertStoreLocation "Cert:\\LocalMachine\\Root"
    Write-Host "Certificate imported successfully to Root store."
}} else {{
    throw "Certificate file not found after export."
}}

$cert | Export-PfxCertificate -FilePath "{UEFI_TEMP_PFX}" -Password (ConvertTo-SecureString -String "{UEFI_PFX_PASSWORD}" -Force -AsPlainText)
Write-Host "Private key exported to PFX successfully."
"""
    try:
        with open(UEFI_TEMP_PS1, "w", encoding="utf-8") as f:
            f.write(script)
            
        run_cmd(f"powershell -ExecutionPolicy Bypass -File \"{UEFI_TEMP_PS1}\"", shell=True)
        log_print("Certificate successfully generated, imported, and PFX exported.")
        
    except Exception as e:
        log_print(f"Certificate management failed: {e}")
        raise
    finally:
        if os.path.exists(UEFI_TEMP_PS1):
            os.remove(UEFI_TEMP_PS1)


def uefi_load_private_key_from_pfx(pfx_path, password):
    log_print(f"Loading private key from PFX: {pfx_path}...")
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
    
    log_print(f"--- Starting Custom Secure Signing Process for '{UEFI_BOOT_BINARY}' ---")

    if not os.path.exists(bl_src):
        raise FileNotFoundError(f"Binary file '{bl_src}' missing in script directory.")

    try:
        with open(bl_src, 'rb') as f:
            raw_binary_data = f.read()
            
        binary_size = len(raw_binary_data)
        log_print(f"Raw binary size: {binary_size} bytes")

        signature = private_key.sign(
            raw_binary_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        log_print(f"Digital Signature Size: {len(signature)} bytes")

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
        log_print(f"Secure Header Size: {len(secure_header)} bytes")
        
        with open(secure_img_path, 'wb') as f:
            f.write(secure_header)
            f.write(raw_binary_data)
        
        log_print(f"✅ Successfully created secure image: {UEFI_SECURE_IMAGE_NAME}")
        
    except Exception as e:
        log_print(f"Binary signing failed: {e}")
        raise


def uefi_boot(private_key):
    log_print("\n--- Starting UEFI Bootloader Installation ---")
    
    uefi_custom_sign(private_key)
    
    bl_src = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)
    
    d = None
    try:
        d = mount_partition(True)
        
        base_dir = os.path.join(d, UEFI_EFI_PATH.strip('\\'))
        dest_path = os.path.join(base_dir, UEFI_BOOT_BINARY)
        
        log_print(f"Copying '{UEFI_SECURE_IMAGE_NAME}' to '{dest_path}'...")
        os.makedirs(base_dir, exist_ok=True)
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        log_print("Bootloader copied successfully.")
        
        bcd_path = os.path.join(UEFI_EFI_PATH, UEFI_BOOT_BINARY).replace("/", "\\")
        
        log_print(f"Creating new BCD entry: '{UEFI_BOOT_NAME}'...")
        # Create a firmware boot entry (for UEFI custom bootloaders)
        out = run_cmd(["bcdedit", "/create", "/d", UEFI_BOOT_NAME, "/application", "bootapp"])
        
        # Debug output
        log_print(f"bcdedit output:\n{out}")
        
        # Try multiple GUID patterns
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
                log_print(f"Successfully extracted GUID: {g}")
                break
        
        if not g:
            log_print(f"ERROR - Could not find GUID in output.")
            log_print(f"Output lines:")
            for i, line in enumerate(out.splitlines(), 1):
                log_print(f"  Line {i}: {repr(line)}")
            raise Exception(f"Failed to extract GUID from bcdedit output")
        
        log_print(f"New BCD Entry GUID: {g}")
        
        # Configure the boot entry
        run_cmd(["bcdedit", "/set", g, "device", f"partition={d}"])
        run_cmd(["bcdedit", "/set", g, "path", bcd_path])
        
        # Add to firmware boot sequence
        run_cmd(["bcdedit", "/set", "{fwbootmgr}", "displayorder", g, "/addfirst"])
        run_cmd(["bcdedit", "/timeout", "10"])
        
        log_print("BCD entry created and set as first in display order.")
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Success", f"UEFI Bootloader '{UEFI_BOOT_NAME}' installed successfully!\n\nREMEMBER TO ENROLL '{UEFI_CERT_FILE}'!")
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
    log_print("\n--- Starting Legacy BIOS Boot Installation ---")
    
    bl_src = os.path.join(DIR, BIOS_BOOT_BINARY)
    
    d = None
    try:
        d = mount_partition(False)
        
        dest_path = os.path.join(d, BIOS_DEST_BOOT_NAME)
        
        log_print(f"Copying '{BIOS_BOOT_BINARY}' to '{dest_path}'...")
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        log_print(f"Custom boot binary copied successfully as '{BIOS_DEST_BOOT_NAME}'.")
        
        log_print(f"Writing Legacy Windows Boot Sector to the partition {d}")
        run_cmd(["bootsect", "/nt60", f"{d}", "/force"])
        
        log_print("✅ Legacy Boot configuration complete.")
        
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

    log_print(f"Script started from: {DIR}")
    log_print(f"Running as frozen executable: {getattr(sys, 'frozen', False)}")

    boot_mode = detect_boot_mode()
    
    if boot_mode == "UEFI":
        binary_path = os.path.join(DIR, UEFI_BOOT_BINARY)
        if not os.path.exists(binary_path):
            log_print(f"Creating dummy UEFI binary: {binary_path} (10 KB)")
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
        
        private_key = None
        
        try:
            uefi_cert()
            private_key = uefi_load_private_key_from_pfx(UEFI_TEMP_PFX, UEFI_PFX_PASSWORD)
            uefi_boot(private_key)
            
        finally:
            if os.path.exists(UEFI_TEMP_PFX):
                os.remove(UEFI_TEMP_PFX)
                log_print(f"Cleaned up sensitive temporary PFX file: {UEFI_TEMP_PFX}")
                
        log_print(f"Script finished. **IMPORTANT:** Retained '{UEFI_CERT_FILE}' for manual UEFI key enrollment.")

    elif boot_mode == "BIOS":
        binary_path = os.path.join(DIR, BIOS_BOOT_BINARY)
        if not os.path.exists(binary_path):
            log_print(f"Creating dummy BIOS binary: {binary_path} (10 KB)")
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
                
        legacy_boot()
        
        log_print("Script finished. The active partition is now set to boot the custom binary.")
        
    else:
        raise Exception("Could not reliably determine the system boot mode.")


def main():
    log_print("="*60)
    log_print("BOOTLOADER INSTALLER STARTING")
    log_print("="*60)
    
    try:
        # Check admin first
        request_admin()
        
        # Run installer
        main_installer()
        
        log_print("\n--- Self-Destruct Sequence Initiated ---")
        target = os.path.abspath(__file__) if not getattr(sys, 'frozen', False) else sys.executable
        bat = os.path.join(DIR, "delete_me.bat")
        
        image_to_delete_secure = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)
        image_to_delete_uefi = os.path.join(DIR, UEFI_BOOT_BINARY)
        image_to_delete_bios = os.path.join(DIR, BIOS_BOOT_BINARY)
        
        with open(bat, 'w') as f:
            f.write('@echo off\n')
            f.write(f'ping 127.0.0.1 -n 5 >nul\n')
            f.write(f'del "{target}" /f /q\n')
            
            f.write(f'if exist "{image_to_delete_secure}" del "{image_to_delete_secure}" /f /q\n')
            f.write(f'if exist "{image_to_delete_uefi}" del "{image_to_delete_uefi}" /f /q\n')
            f.write(f'if exist "{image_to_delete_bios}" del "{image_to_delete_bios}" /f /q\n')

            f.write(f'del "%~f0" /f /q\n')
        
        log_print("\n✅ Installation completed successfully!")
        log_print(f"Log file saved to: {LOG_FILE}")
        log_print("\nPress any key to exit...")
        
        try:
            input()
        except:
            time.sleep(5)
            
        subprocess.Popen([bat], shell=True, creationflags=subprocess.DETACHED_PROCESS)
        sys.exit(0)

    except Exception as e:
        log_print(f"\n{'='*60}")
        log_print(f"FATAL ERROR: {e}")
        log_print(f"{'='*60}")
        log_print(traceback.format_exc())
        log_print(f"\nLog file saved to: {LOG_FILE}")
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", f"A critical error occurred:\n\n{e}\n\nCheck {LOG_FILE} for details.")
            root.destroy()
        except:
            pass
        
        log_print("\nPress any key to exit...")
        try:
            input()
        except:
            time.sleep(10)
        
        sys.exit(1)


if __name__ == "__main__":
    main(), 'w')

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
    """Print to console and log file"""
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
    """Request admin privileges and restart"""
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
            # Restart with admin privileges
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
            
        log_print(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        
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
    log_print("Detecting system boot mode (UEFI or Legacy BIOS)...")
    
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
                log_print("UEFI System Partition (ESP) found.")
                return "UEFI"
    
    if os.environ.get('firmware_type') == 'UEFI':
        log_print("Environment variable indicates UEFI.")
        return "UEFI"
        
    log_print("UEFI System Partition not found. Assuming Legacy BIOS mode.")
    return "BIOS"


def find_free_drive_letter():
    """Find an available drive letter"""
    import string
    used_drives = [d.upper() for d in [chr(x) + ':' for x in range(65, 91)] if os.path.exists(chr(x) + ':')]
    
    # Prefer letters from S to Z (less likely to be used)
    for letter in string.ascii_uppercase[::-1]:
        if letter not in ['A', 'B', 'C'] and letter + ':' not in used_drives:
            return letter
    
    raise Exception("No free drive letters available!")


def mount_partition(is_uefi):
    if is_uefi:
        log_print("Searching for EFI System Partition...")
        target_search = "FAT32"
        target_error = "EFI System Partition (ESP) volume not found."
    else:
        log_print("Searching for the Active System Partition...")
        target_search = "Active"
        target_error = "Active/System Partition not found. Legacy boot requires an active partition."

    tmp = os.path.join(DIR, 'tmp_list.txt')
    vol = None
    existing_letter = None
    
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
                # Check if it already has a drive letter
                letter_match = re.search(r'\s+([A-Z])\s+', line)
                if letter_match:
                    existing_letter = letter_match.group(1)
                    log_print(f"Volume {vol} already has drive letter {existing_letter}:")
                break
            
    if not vol:
        raise Exception(target_error)
    
    # If it already has a letter, use that
    if existing_letter:
        drive_path = f"{existing_letter}:\\"
        log_print(f"Using existing drive letter: {existing_letter}:")
        return drive_path
    
    # Find a free drive letter
    free_letter = find_free_drive_letter()
    log_print(f"Found volume: {vol}. Mounting as letter {free_letter}:")
    
    tmp_mount = os.path.join(DIR, 'tmp_mount.txt')
    content = f"select volume {vol}\nassign letter={free_letter}\nexit\n"
    
    try:
        with open(tmp_mount, 'w') as f: 
            f.write(content)
        run_cmd(["diskpart", "/s", tmp_mount])
    finally:
        if os.path.exists(tmp_mount): 
            os.remove(tmp_mount)
            
    time.sleep(2)
    drive_path = f"{free_letter}:\\"
    if not os.path.isdir(drive_path):
        raise Exception(f"Failed to mount partition as {free_letter}:. Check if the letter is already in use.")

    return drive_path


def umount(d):
    log_print(f"Unmounting volume {d}...")
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
            log_print(f"Volume {d} unmounted successfully.")
        else:
            log_print(f"Could not find volume number for drive {d} to unmount.")
            
    except Exception as e:
        log_print(f"Warning: Failed to unmount drive {d}. Manual removal might be necessary. Error: {e}")
    finally:
        if os.path.exists(tmp): 
            os.remove(tmp)
        if os.path.exists(list_vol):
            os.remove(list_vol)


def uefi_cert():
    log_print(f"Generating, installing, and exporting certificate '{UEFI_CERT_NAME}'...")
    
    script = f"""
$ErrorActionPreference='Stop'

Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object {{$_.Subject -like "CN={UEFI_CERT_NAME}"}} | Remove-Item -Force
if (Test-Path "{UEFI_TEMP_PFX}") {{ Remove-Item "{UEFI_TEMP_PFX}" -Force }}

$cert = New-SelfSignedCertificate -DnsName "{UEFI_CERT_NAME}" -CertStoreLocation "Cert:\\CurrentUser\\My" -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5) -Type CodeSigning -HashAlgorithm SHA256

$p = "{UEFI_CERT_FILE}"
Export-Certificate -Cert $cert -FilePath $p -Force -Type CERT

if (Test-Path $p) {{
    Import-Certificate -FilePath $p -CertStoreLocation "Cert:\\LocalMachine\\Root"
    Write-Host "Certificate imported successfully to Root store."
}} else {{
    throw "Certificate file not found after export."
}}

$cert | Export-PfxCertificate -FilePath "{UEFI_TEMP_PFX}" -Password (ConvertTo-SecureString -String "{UEFI_PFX_PASSWORD}" -Force -AsPlainText)
Write-Host "Private key exported to PFX successfully."
"""
    try:
        with open(UEFI_TEMP_PS1, "w", encoding="utf-8") as f:
            f.write(script)
            
        run_cmd(f"powershell -ExecutionPolicy Bypass -File \"{UEFI_TEMP_PS1}\"", shell=True)
        log_print("Certificate successfully generated, imported, and PFX exported.")
        
    except Exception as e:
        log_print(f"Certificate management failed: {e}")
        raise
    finally:
        if os.path.exists(UEFI_TEMP_PS1):
            os.remove(UEFI_TEMP_PS1)


def uefi_load_private_key_from_pfx(pfx_path, password):
    log_print(f"Loading private key from PFX: {pfx_path}...")
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
    
    log_print(f"--- Starting Custom Secure Signing Process for '{UEFI_BOOT_BINARY}' ---")

    if not os.path.exists(bl_src):
        raise FileNotFoundError(f"Binary file '{bl_src}' missing in script directory.")

    try:
        with open(bl_src, 'rb') as f:
            raw_binary_data = f.read()
            
        binary_size = len(raw_binary_data)
        log_print(f"Raw binary size: {binary_size} bytes")

        signature = private_key.sign(
            raw_binary_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        log_print(f"Digital Signature Size: {len(signature)} bytes")

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
        log_print(f"Secure Header Size: {len(secure_header)} bytes")
        
        with open(secure_img_path, 'wb') as f:
            f.write(secure_header)
            f.write(raw_binary_data)
        
        log_print(f"✅ Successfully created secure image: {UEFI_SECURE_IMAGE_NAME}")
        
    except Exception as e:
        log_print(f"Binary signing failed: {e}")
        raise


def uefi_boot(private_key):
    log_print("\n--- Starting UEFI Bootloader Installation ---")
    
    uefi_custom_sign(private_key)
    
    bl_src = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)
    
    d = None
    try:
        d = mount_partition(True)
        
        base_dir = os.path.join(d, UEFI_EFI_PATH.strip('\\'))
        dest_path = os.path.join(base_dir, UEFI_BOOT_BINARY)
        
        log_print(f"Copying '{UEFI_SECURE_IMAGE_NAME}' to '{dest_path}'...")
        os.makedirs(base_dir, exist_ok=True)
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        log_print("Bootloader copied successfully.")
        
        bcd_path = os.path.join(UEFI_EFI_PATH, UEFI_BOOT_BINARY).replace("/", "\\")
        
        log_print(f"Creating new BCD entry: '{UEFI_BOOT_NAME}'...")
        # Create a firmware boot entry (for UEFI custom bootloaders)
        out = run_cmd(["bcdedit", "/create", "/d", UEFI_BOOT_NAME, "/application", "bootapp"])
        
        # Debug output
        log_print(f"bcdedit output:\n{out}")
        
        # Try multiple GUID patterns
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
                log_print(f"Successfully extracted GUID: {g}")
                break
        
        if not g:
            log_print(f"ERROR - Could not find GUID in output.")
            log_print(f"Output lines:")
            for i, line in enumerate(out.splitlines(), 1):
                log_print(f"  Line {i}: {repr(line)}")
            raise Exception(f"Failed to extract GUID from bcdedit output")
        
        log_print(f"New BCD Entry GUID: {g}")
        
        # Configure the boot entry
        run_cmd(["bcdedit", "/set", g, "device", f"partition={d}"])
        run_cmd(["bcdedit", "/set", g, "path", bcd_path])
        
        # Add to firmware boot sequence
        run_cmd(["bcdedit", "/set", "{fwbootmgr}", "displayorder", g, "/addfirst"])
        run_cmd(["bcdedit", "/timeout", "10"])
        
        log_print("BCD entry created and set as first in display order.")
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showinfo("Success", f"UEFI Bootloader '{UEFI_BOOT_NAME}' installed successfully!\n\nREMEMBER TO ENROLL '{UEFI_CERT_FILE}'!")
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
    log_print("\n--- Starting Legacy BIOS Boot Installation ---")
    
    bl_src = os.path.join(DIR, BIOS_BOOT_BINARY)
    
    d = None
    try:
        d = mount_partition(False)
        
        dest_path = os.path.join(d, BIOS_DEST_BOOT_NAME)
        
        log_print(f"Copying '{BIOS_BOOT_BINARY}' to '{dest_path}'...")
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        log_print(f"Custom boot binary copied successfully as '{BIOS_DEST_BOOT_NAME}'.")
        
        log_print(f"Writing Legacy Windows Boot Sector to the partition {d}")
        run_cmd(["bootsect", "/nt60", f"{d}", "/force"])
        
        log_print("✅ Legacy Boot configuration complete.")
        
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

    log_print(f"Script started from: {DIR}")
    log_print(f"Running as frozen executable: {getattr(sys, 'frozen', False)}")

    boot_mode = detect_boot_mode()
    
    if boot_mode == "UEFI":
        binary_path = os.path.join(DIR, UEFI_BOOT_BINARY)
        if not os.path.exists(binary_path):
            log_print(f"Creating dummy UEFI binary: {binary_path} (10 KB)")
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
        
        private_key = None
        
        try:
            uefi_cert()
            private_key = uefi_load_private_key_from_pfx(UEFI_TEMP_PFX, UEFI_PFX_PASSWORD)
            uefi_boot(private_key)
            
        finally:
            if os.path.exists(UEFI_TEMP_PFX):
                os.remove(UEFI_TEMP_PFX)
                log_print(f"Cleaned up sensitive temporary PFX file: {UEFI_TEMP_PFX}")
                
        log_print(f"Script finished. **IMPORTANT:** Retained '{UEFI_CERT_FILE}' for manual UEFI key enrollment.")

    elif boot_mode == "BIOS":
        binary_path = os.path.join(DIR, BIOS_BOOT_BINARY)
        if not os.path.exists(binary_path):
            log_print(f"Creating dummy BIOS binary: {binary_path} (10 KB)")
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
                
        legacy_boot()
        
        log_print("Script finished. The active partition is now set to boot the custom binary.")
        
    else:
        raise Exception("Could not reliably determine the system boot mode.")


def main():
    log_print("="*60)
    log_print("BOOTLOADER INSTALLER STARTING")
    log_print("="*60)
    
    try:
        # Check admin first
        request_admin()
        
        # Run installer
        main_installer()
        
        log_print("\n--- Self-Destruct Sequence Initiated ---")
        target = os.path.abspath(__file__) if not getattr(sys, 'frozen', False) else sys.executable
        bat = os.path.join(DIR, "delete_me.bat")
        
        image_to_delete_secure = os.path.join(DIR, UEFI_SECURE_IMAGE_NAME)
        image_to_delete_uefi = os.path.join(DIR, UEFI_BOOT_BINARY)
        image_to_delete_bios = os.path.join(DIR, BIOS_BOOT_BINARY)
        
        with open(bat, 'w') as f:
            f.write('@echo off\n')
            f.write(f'ping 127.0.0.1 -n 5 >nul\n')
            f.write(f'del "{target}" /f /q\n')
            
            f.write(f'if exist "{image_to_delete_secure}" del "{image_to_delete_secure}" /f /q\n')
            f.write(f'if exist "{image_to_delete_uefi}" del "{image_to_delete_uefi}" /f /q\n')
            f.write(f'if exist "{image_to_delete_bios}" del "{image_to_delete_bios}" /f /q\n')

            f.write(f'del "%~f0" /f /q\n')
        
        log_print("\n✅ Installation completed successfully!")
        log_print(f"Log file saved to: {LOG_FILE}")
        log_print("\nPress any key to exit...")
        
        try:
            input()
        except:
            time.sleep(5)
            
        subprocess.Popen([bat], shell=True, creationflags=subprocess.DETACHED_PROCESS)
        sys.exit(0)

    except Exception as e:
        log_print(f"\n{'='*60}")
        log_print(f"FATAL ERROR: {e}")
        log_print(f"{'='*60}")
        log_print(traceback.format_exc())
        log_print(f"\nLog file saved to: {LOG_FILE}")
        
        try:
            root = Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", f"A critical error occurred:\n\n{e}\n\nCheck {LOG_FILE} for details.")
            root.destroy()
        except:
            pass
        
        log_print("\nPress any key to exit...")
        try:
            input()
        except:
            time.sleep(10)
        
        sys.exit(1)


if __name__ == "__main__":
    main()
