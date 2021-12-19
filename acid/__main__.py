from ctypes import *
import ctypes.util
import injector
import psutil
import sys


def find_dll():    
    dll = ctypes.util.find_library(f'python{sys.version_info.major}{sys.version_info.minor}.dll')
    parent_folder = dll.split('\\')[-2]
    if not sys.maxsize.bit_length() > 32:
        dll = dll.replace(parent_folder, parent_folder+'-32')
    return dll.encode()

def get_process_by_name(name):
    for pid in psutil.pids():
        try:
            process = psutil.Process(pid)
            if process is not None and psutil.pid_exists(pid):
                if process.name() == name:
                    return pid
        except psutil.AccessDenied as e:
            pass
    return None

pid = get_process_by_name('Notepad.exe')
dll = find_dll()
injector.inject(pid, dll)
