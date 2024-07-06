import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
import os
import psutil
from colorama import init, Fore, Style
import msvcrt

def select_file(file_type):
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    if file_type == "DLL":
        file_path = filedialog.askopenfilename(
            title="Select a DLL file to inject",
            filetypes=(("DLL Files", "*.dll"), ("All Files", "*.*"))
        )
    elif file_type == "EXE":
        file_path = filedialog.askopenfilename(
            title="Select an EXE file",
            filetypes=(("EXE Files", "*.exe"), ("All Files", "*.*"))
        )
    else:
        file_path = None

    if file_path and os.path.isfile(file_path):
        return file_path
    else:
        messagebox.showerror("Error", f"No valid {file_type} file selected")
        return None

def inject_dll(process_id, dll_path):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    dll_path_bytes = dll_path.encode('utf-8')

    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
    if not process_handle:
        raise Exception(f"Could not open process: {ctypes.GetLastError()}")

    arg_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, len(dll_path_bytes), 0x3000, 0x40)
    if not arg_address:
        raise Exception(f"Could not allocate memory in process: {ctypes.GetLastError()}")

    written = ctypes.c_int(0)
    if not ctypes.windll.kernel32.WriteProcessMemory(process_handle, arg_address, dll_path_bytes, len(dll_path_bytes), ctypes.byref(written)):
        raise Exception(f"Could not write to process memory: {ctypes.GetLastError()}")

    kernel32_handle = ctypes.windll.kernel32.GetModuleHandleA(b'kernel32.dll')
    load_library_a_address = ctypes.windll.kernel32.GetProcAddress(kernel32_handle, b'LoadLibraryA')

    thread_id = ctypes.c_ulong(0)
    if not ctypes.windll.kernel32.CreateRemoteThread(process_handle, None, 0, load_library_a_address, arg_address, 0, ctypes.byref(thread_id)):
        raise Exception(f"Could not create remote thread: {ctypes.GetLastError()}")

    ctypes.windll.kernel32.CloseHandle(process_handle)

def select_process():
    root = tk.Tk()
    root.withdraw()

    messagebox.showinfo("Select Process", "Select the process from the list in the terminal")
    for proc in psutil.process_iter(['pid', 'name']):
        print(f"PID: {proc.info['pid']} - Name: {proc.info['name']}")

    pid = int(input("Enter the PID of the process to inject into: "))
    if psutil.pid_exists(pid):
        return pid
    else:
        messagebox.showerror("Error", "Invalid PID selected")
        return None

if __name__ == "__main__":
    init()
    print(Fore.BLUE + Style.BRIGHT + "by Uro" + Style.RESET_ALL)
    print("Press any key to continue...")
    msvcrt.getch()  # Wait for a key press

    dll_path = select_file("DLL")
    if not dll_path:
        input("Press Enter to exit...")
        exit()

    process_id = select_process()
    if not process_id:
        input("Press Enter to exit...")
        exit()

    try:
        inject_dll(process_id, dll_path)
        messagebox.showinfo("Success", "DLL injected successfully")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    
    input("Press Enter to exit...")
