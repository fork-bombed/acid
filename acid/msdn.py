from ctypes import *
from ctypes import wintypes
from typing import Callable

kernel32 = windll.kernel32
SIZE_T = c_size_t
LPCTSTR = c_char_p
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_DECOMMIT = 0x00004000
MEM_RELEASE = 0x00008000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFF

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.LPBOOL)
    ]

LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)

def msdn_wrap(func, args, res, error_check=True):
    func.argtypes = args
    func.restype = res
    def wrapper(*args) -> res:
        resp = func(*args)
        if not resp:
            raise WinError()
        return resp
    if error_check:
        return wrapper
    return func

OpenProcess = msdn_wrap(
    kernel32.OpenProcess,
    (
        wintypes.DWORD,
        wintypes.BOOL, 
        wintypes.DWORD,
    ),
    wintypes.HANDLE
)

VirtualAllocEx = msdn_wrap(
    kernel32.VirtualAllocEx,
    (
        wintypes.HANDLE,
        wintypes.LPVOID,
        SIZE_T,
        wintypes.DWORD,
        wintypes.DWORD,
    ),
    wintypes.LPVOID
)

WriteProcessMemory = msdn_wrap(
    kernel32.WriteProcessMemory,
    (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPCVOID,
        SIZE_T,
        POINTER(SIZE_T),
    ),
    wintypes.BOOL
)

GetModuleHandleA = msdn_wrap(
    kernel32.GetModuleHandleA,
    (
        LPCTSTR,
    ),
    wintypes.HANDLE
)

LoadLibraryA = msdn_wrap(
    kernel32.LoadLibraryA,
    (
        wintypes.LPCSTR,
    ),
    wintypes.HANDLE
)

CloseHandle = msdn_wrap(
    kernel32.CloseHandle,
    (
        wintypes.HANDLE,
    ),
    wintypes.BOOL
)

GetProcAddress = msdn_wrap(
    kernel32.GetProcAddress,
    (
        wintypes.HANDLE,
        LPCTSTR,
    ),
    wintypes.LPVOID
)

TerminateThread = msdn_wrap(
    kernel32.TerminateThread,
    (
        wintypes.HANDLE,
        wintypes.DWORD,
    ),
    wintypes.BOOL
)

WaitForSingleObject = msdn_wrap(
    kernel32.WaitForSingleObject,
    (
        wintypes.HANDLE,
        wintypes.DWORD,
    ),
    wintypes.DWORD,
    error_check=False
)

VirtualFreeEx = msdn_wrap(
    kernel32.VirtualFreeEx,
    (
        wintypes.HANDLE,
        wintypes.LPVOID,
        SIZE_T,
        wintypes.DWORD,
    ),
    wintypes.BOOL
)

EnumProcessModules = msdn_wrap(
    windll.psapi.EnumProcessModules,
    (
        wintypes.HANDLE,
        POINTER(wintypes.HMODULE),
        wintypes.DWORD,
        wintypes.LPDWORD,
    ),
    wintypes.BOOL
)

GetModuleBaseNameA = msdn_wrap(
    windll.psapi.GetModuleBaseNameA,
    (
        wintypes.HANDLE,
        wintypes.HMODULE,
        c_char_p,
        wintypes.DWORD,
    ),
    wintypes.BOOL
)

CreateRemoteThread = msdn_wrap(
    kernel32.CreateRemoteThread,
    (
        wintypes.HANDLE,
        LPSECURITY_ATTRIBUTES,
        SIZE_T,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPDWORD,
    ),
    wintypes.HANDLE
)