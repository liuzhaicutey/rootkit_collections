import ctypes
import sys
import os
import subprocess
import time
import re
import platform
import struct
import traceback

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

UEFI_BOOT_BINARY = "BOOTX64.efi"
UEFI_EFI_PATH = r"\EFI\BOOT"
UEFI_BOOT_NAME = "Shaacidyne"

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
        log_print("Admin Rights Required: Script will attempt to restart as administrator.")
        
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
            f.write("exit\n")
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

    content = f"select volume {vol}\nassign\nexit\n"
    
    assigned_drive_letter = None
    
    try:
        with open(tmp_mount, 'w') as f:
            f.write(content)

        run_cmd(["diskpart", "/s", tmp_mount])
        

        with open(tmp, 'w') as f:
            f.write("list volume\n")
            f.write("exit\n")
        out_list = run_cmd(["diskpart", "/s", tmp])
        

        for line in out_list.splitlines():

            pattern = rf"^\s*Volume\s*{re.escape(vol)}\s+([A-Z])\s+"

            m = re.search(pattern, line)
            
            if m:

                assigned_drive_letter = m.group(1)
                break

        if not assigned_drive_letter:

            log_print(f"DEBUG: Failed to parse drive letter for Volume {vol}. DiskPart output:\n{out_list}")
            raise Exception("DiskPart assigned a letter but could not detect which one.")
        
    finally:
        if os.path.exists(tmp_mount):
            os.remove(tmp_mount)
        if os.path.exists(tmp):
            os.remove(tmp)
            
    time.sleep(2)

    drive_path = f"{assigned_drive_letter}:\\"
    if not os.path.isdir(drive_path):
        raise Exception(f"Failed to mount partition as {assigned_drive_letter}:. Check if the drive is not accessible.")

    return drive_path


def umount(d):

    tmp = os.path.join(DIR, 'tmp_umount.txt')
    list_vol = os.path.join(DIR, 'list_vol.txt')
    

    drive_letter = d.strip(':').strip('\\')
    
    try:
        with open(list_vol, 'w') as f:
            f.write("list volume\n")
            f.write("exit\n")
            
        out = run_cmd(["diskpart", "/s", list_vol])
        vol = None
        

        for line in out.splitlines():

            pattern = rf"^\s*Volume\s*\d*\s*{re.escape(drive_letter)}\s+"

            m = re.search(pattern, line)

            if m:

                m_vol = re.search(r'Volume\s+(\d+)', line)
                if m_vol:
                    vol = m_vol.group(1)
                    break

            
        if vol:

            content = f"select volume {vol}\nremove letter={drive_letter}\nexit\n"
            with open(tmp, 'w') as f:
                f.write(content)
            run_cmd(["diskpart", "/s", tmp])
        else:
            log_print(f"Warning: Volume for letter {drive_letter} was not found for unmounting.")
            
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
        out = run_cmd(["reg", "query", f"HKEY_LOCAL_MACHINE\\{key_path}", "/v", "UEFISecureBootEnabled"])
        
        if "0x1" in out:
            return True
        else:
            return False
            
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        log_print(f"Warning: Could not reliably determine Secure Boot status: {e}")
        return False


def get_esp_location():

    log_print("Attempting to determine Disk and Partition number for the ESP.")
    

    tmp_disk_list = os.path.join(DIR, 'tmp_disk_list.txt')
    disk_num = None

    try:

        with open(tmp_disk_list, 'w') as f:
            f.write("list disk\n")
            f.write("exit\n")
        
        out_disk = run_cmd(["diskpart", "/s", tmp_disk_list])
        log_print("DiskPart list disk output retrieved successfully.")
        

        for line in out_disk.splitlines():

            if "GPT" in line:
                m = re.search(r'Disk\s+(\d+)', line)
                if m:
                    disk_num = m.group(1)
                    log_print(f"Detected GPT Disk: {disk_num}")
                    break
        
        if not disk_num:

             disk_num = "0"
             log_print("WARNING: Could not find GPT disk, falling back to disk 0.")

    except Exception as e:
        log_print(f"ERROR: Failed to run DiskPart 'list disk' command. Error: {e}")
        raise
    finally:
        if os.path.exists(tmp_disk_list):
            os.remove(tmp_disk_list)
            

    tmp_part = os.path.join(DIR, 'tmp_part.txt')
    part_num = None
    
    try:

        with open(tmp_part, 'w') as f:
            f.write(f"select disk {disk_num}\n")
            f.write("list partition\n")
            f.write("exit\n")
        
        out_part = run_cmd(["diskpart", "/s", tmp_part])
    finally:
        if os.path.exists(tmp_part):
            os.remove(tmp_part)
            

    for line in out_part.splitlines():
        if "System" in line and re.search(r'Partition\s+(\d+)', line, re.IGNORECASE):
            m = re.search(r'Partition\s+(\d+)', line, re.IGNORECASE)
            if m:
                part_num = m.group(1)
                log_print(f"Found ESP on Disk {disk_num}, Partition {part_num}.")
                return disk_num, part_num
    
    raise Exception("Could not reliably find the Disk and Partition number for the EFI System Partition.")


def uefi_boot():
    secure_boot_on = check_secure_boot_status()
    
    dest_name = UEFI_BOOT_BINARY
    bl_src = os.path.join(DIR, UEFI_BOOT_BINARY)

    if secure_boot_on:
        log_print(f"UEFI Bootloader '{UEFI_BOOT_NAME}' installation running.")
        log_print(f"!! WARNING: SECURE BOOT IS ON !! (Installed unsigned binary. Booting may fail unless Secure Boot is OFF or custom keys are enrolled.)")
        boot_instructions = f"To boot: Restart and access your BIOS/UEFI boot menu (usually F12, F8, or ESC) and select '{UEFI_BOOT_NAME}' or 'UEFI Boot'."
    else:
        log_print(f"UEFI Bootloader '{UEFI_BOOT_NAME}' installation running.")
        log_print(f"(Secure Boot is OFF, installed unsigned binary.)")
        boot_instructions = f"To boot: Restart and access your BIOS/UEFI boot menu (usually F12, F8, or ESC) and select '{UEFI_BOOT_NAME}' or 'UEFI Boot'."

    d = None
    try:
        
        d = mount_partition(True)

        disk_num = part_num = None
        try:
            disk_num, part_num = get_esp_location()
            log_print(f"ESP physical location: disk {disk_num}, partition {part_num}")
        except Exception as e:
            log_print(f"Could not determine physical disk/partition: {e}")

        base_dir = os.path.join(d, UEFI_EFI_PATH.strip('\\'))
        dest_path = os.path.join(base_dir, dest_name)
        
        os.makedirs(base_dir, exist_ok=True)
        
        run_cmd(f"copy /Y \"{bl_src}\" \"{dest_path}\"", shell=True)
        
        if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
            raise Exception(f"Copy failed. Destination file '{dest_path}' not found or is empty.")
        

        bcd_path = os.path.join(UEFI_EFI_PATH, dest_name).replace("/", "\\")
        if not bcd_path.startswith("\\"):
            bcd_path = "\\" + bcd_path.lstrip("\\")
        
        boot_configured = False
        created_guid = None


        drive, _ = os.path.splitdrive(d)
        if not drive:
            raise Exception(f"Could not determine mounted drive letter from '{d}'")
        partition_device = f"partition={drive}"
        log_print(f"Using device string for bcdedit/device: {partition_device}")
        log_print(f"Using bcd path: {bcd_path}")

        try:

            out = run_cmd(["bcdedit", "/create", "/d", UEFI_BOOT_NAME, "/application", "bootapp"])
            log_print(f"bcdedit /create output: {out.strip()}")
            

            patterns = [
                r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}',
                r'\{[0-9a-fA-F-]{36}\}',
            ]
            
            for pattern in patterns:
                m = re.search(pattern, out)
                if m:
                    created_guid = m.group(0)
                    break
            
            if created_guid:

                created_guid = created_guid.strip()
                if not (created_guid.startswith("{") and created_guid.endswith("}")):
                    created_guid = "{" + created_guid.strip("{}") + "}"
                

                try:
                    out1 = run_cmd(["bcdedit", "/set", created_guid, "device", partition_device])
                    log_print(f"bcdedit set device output: {out1.strip()}")
                except Exception as e:
                    log_print(f"Failed to set device using '{partition_device}': {e}")

                    if disk_num is not None and part_num is not None:
                        phys_device = f"disk={disk_num} partition={part_num}"
                        out_fallback = run_cmd(["bcdedit", "/set", created_guid, "device", phys_device])
                        log_print(f"bcdedit set device (fallback) output: {out_fallback.strip()}")
                    else:
                        raise
                
                out2 = run_cmd(["bcdedit", "/set", created_guid, "path", bcd_path])
                log_print(f"bcdedit set path output: {out2.strip()}")
                

                try:
                    out3 = run_cmd(["bcdedit", "/set", "{fwbootmgr}", "displayorder", created_guid, "/addfirst"])
                    log_print(f"bcdedit set fwbootmgr displayorder output: {out3.strip()}")
                except Exception as e:
                    log_print(f"Warning: Could not add entry to fwbootmgr displayorder: {e}")
                
                try:
                    out4 = run_cmd(["bcdedit", "/default", created_guid])
                    log_print(f"bcdedit default output: {out4.strip()}")
                except Exception as e:
                    log_print(f"Warning: Could not set default to the new entry: {e}")

                boot_configured = True
            else:
                log_print(f"Could not extract GUID from bcdedit create output. Continuing to ensure boot via bootmgr.")
            
        except Exception as e:
            log_print(f"Method 1 (create bootapp entry) had an error: {e}")


        try:
            run_cmd(["bcdedit", "/timeout", "0"])
            log_print("Set boot timeout to 0 (instant boot, no delay)")
        except Exception as e:
            log_print(f"Could not set boot timeout to 0: {e}")
        
        try:
            run_cmd(["bcdedit", "/set", "{fwbootmgr}", "timeout", "0"])
            log_print("Set firmware boot manager timeout to 0")
        except Exception as e:
            log_print(f"Note: Could not set fwbootmgr timeout: {e}")


        try:
            bootmgr_enum = run_cmd(["bcdedit", "/enum", "{bootmgr}"])
            log_print(f"Current {{bootmgr}} settings:\n{bootmgr_enum.strip()}")

            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write("\n--- BOOTMGR BACKUP ---\n")
                f.write(bootmgr_enum + "\n")
        except Exception as e:
            log_print(f"Warning: Could not read original {{bootmgr}} settings: {e}")

        forced_bootmgr_ok = False
        try:

            out_bdev = run_cmd(["bcdedit", "/set", "{bootmgr}", "device", partition_device])
            log_print(f"bcdedit set {{bootmgr}} device output: {out_bdev.strip()}")

            out_bpath = run_cmd(["bcdedit", "/set", "{bootmgr}", "path", bcd_path])
            log_print(f"bcdedit set {{bootmgr}} path output: {out_bpath.strip()}")
            forced_bootmgr_ok = True
            log_print("Successfully pointed {bootmgr} at the custom EFI binary.")

        except Exception as e:
            log_print(f"Failed to force {{bootmgr}} to our binary: {e}")
            forced_bootmgr_ok = False

        if boot_configured or forced_bootmgr_ok:
            boot_instructions = "Your bootloader will launch INSTANTLY on restart with NO timeout (Windows Boot Manager now points to it)."
        else:
            log_print("WARNING: Could not automatically configure boot order or override Windows Boot Manager.")
            log_print("You may need to manually set the firmware boot priority or restore {bootmgr} manually.")
            boot_instructions += "\n\nNOTE: Automatic boot configuration failed. You must manually set boot priority in BIOS/UEFI settings."

        log_print(f"Bootloader installed to: {dest_path}")
        if boot_configured:
            log_print(f"Boot entry GUID: {created_guid}")
            log_print(f"Configuration: Created BCD boot entry and attempted to set fwbootmgr displayorder")
        if forced_bootmgr_ok:
            log_print("Configuration: {bootmgr} device/path pointed to the installed EFI file (forced).")
            log_print("If you wish to restore the previous Windows Boot Manager behavior, check the installer_log.txt for the backed up {bootmgr} output and run appropriate bcdedit commands to restore device/path.")
        
        log_print("--- UEFI INSTALLATION SUCCESS ---")
        log_print(f"Summary: {boot_instructions}")

    except Exception as e:
        log_print(f"\n--- UEFI Installation Failed ---")
        log_print(f"Error: {e}")
        log_print(traceback.format_exc())
        log_print(f"Error: UEFI Installation failed: {e}")
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
        
        log_print("--- LEGACY BIOS INSTALLATION SUCCESS ---")
        log_print("Custom boot binary installed and VBR updated for Legacy BIOS boot.")

    except Exception as e:
        log_print(f"\n--- BIOS Installation Failed ---")
        log_print(f"Error: {e}")
        log_print(traceback.format_exc())
        log_print(f"Error: BIOS Installation failed: {e}")
        raise
    finally:
        if d:
            umount(d)


def main_installer():
    if platform.system() != "Windows":
        raise OSError(f"This script is designed for Windows, not {platform.system()}.")

    boot_mode = detect_boot_mode()
    log_print(f"Detected Boot Mode: {boot_mode}")
    
    if boot_mode == "UEFI":
        binary_path = os.path.join(DIR, UEFI_BOOT_BINARY)
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"FATAL: Missing required unsigned UEFI binary: '{UEFI_BOOT_BINARY}'. Please place it here.")
        
        try:
            uefi_boot()
            
        finally:
            pass
            
    elif boot_mode == "BIOS":
        binary_path = os.path.join(DIR, BIOS_BOOT_BINARY)
        if not os.path.exists(binary_path):
            log_print(f"WARNING: Missing required BIOS binary: '{BIOS_BOOT_BINARY}'. Creating dummy file (10KB).")
            with open(binary_path, 'wb') as f:
                f.write(os.urandom(10240))
            
        legacy_boot()
        
    else:
        raise Exception("Could not reliably determine the system boot mode.")


def display_fatal_error(error_msg):
    log_print(f"\nFATAL ERROR DISPLAY: {error_msg}")
    pass


def main():
    try:
        request_admin()
        main_installer()

        log_print("Installation completed. The system will now restart immediately.")
        
        subprocess.run(["shutdown", "/r", "/f", "/t", "0"], check=True)

    except Exception as e:
        log_print(f"\nFATAL ERROR: {e}")
        log_print(traceback.format_exc())
        display_fatal_error(str(e))


        
if __name__ == "__main__":
    main()
