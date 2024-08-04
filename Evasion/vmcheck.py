import os
import subprocess

def check_processes(process_names):
    """Check if any of the specified processes are running."""
    for proc in process_names:
        try:
            output = subprocess.check_output(f'tasklist | findstr {proc}', shell=True)
            if proc in str(output):
                return True
        except subprocess.CalledProcessError:
            continue
    return False

def check_files(files):
    """Check if any of the specified files exist."""
    for file in files:
        if os.path.exists(file):
            return True
    return False

def check_registry_keys(keys):
    """Check if any of the specified registry keys exist."""
    try:
        import winreg
    except ImportError:
        return False  # Only applicable on Windows

    for key in keys:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
            return True
        except FileNotFoundError:
            continue
    return False

def is_vm():
    # Check for known VM processes
    vm_processes = [
        'VBoxService.exe',   # VirtualBox
        'vmtoolsd.exe',      # VMware
        'vboxtray.exe',      # VirtualBox Guest Additions
        'vmwaretray.exe',    # VMware Tools
    ]
    if check_processes(vm_processes):
        return True

    # Check for known VM files
    vm_files = [
        'C:\\Windows\\System32\\drivers\\VBoxMouse.sys',   # VirtualBox
        'C:\\Windows\\System32\\drivers\\vmhgfs.sys',      # VMware
    ]
    if check_files(vm_files):
        return True

    # Check for known VM registry keys (Windows-specific)
    vm_registry_keys = [
        r'SOFTWARE\\Oracle\\VirtualBox Guest Additions',
        r'SYSTEM\\CurrentControlSet\\Services\\VBoxGuest',
        r'SYSTEM\\CurrentControlSet\\Services\\vmtools',
    ]
    if check_registry_keys(vm_registry_keys):
        return True

    return False

def main():
    if is_vm():
        print("Running in a virtual machine environment")
    else:
        print("Not running in a virtual machine environment")

if __name__ == "__main__":
    main()
