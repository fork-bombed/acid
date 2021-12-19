from ctypes import *
from ctypes import wintypes

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

def msdn_wrap(func, args, res, error=True):
    func.argtypes = args
    func.restype = res
    def wrapper(*args):
        resp = func(*args)
        if not resp:
            raise WinError()
        return resp
    if error:
        return wrapper
    else:
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
    error=False
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


class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.LPBOOL)
    ]

LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)

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

def get_injectable_code(filename):
    with open(filename) as f:
        code = f.read()
    return code.encode()

def get_module(handle, name):
    module_ptr = (c_void_p * 1024)()
    needed = c_ulong()
    EnumProcessModules(handle, module_ptr, sizeof(module_ptr), byref(needed))
    for module in module_ptr:
        if module is not None:
            module_name = create_string_buffer(200)
            if (GetModuleBaseNameA(handle, module, module_name, sizeof(module_name)) != 0):
                if module is not None:
                    if module_name.value == name:
                        return module

def inject(pid, dll):
    dll_name = dll.decode().split('\\')[-1].encode()
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, wintypes.DWORD(pid))
    print(f'Handle obtained => {hex(handle)}')
    mem = VirtualAllocEx(handle, False, len(dll)+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    WriteProcessMemory(handle, mem, dll, len(dll)+1, None)
    print(f'Memory written => {dll}')
    load_library = GetProcAddress(GetModuleHandleA(b'kernel32.dll'), b'LoadLibraryA')
    thread = CreateRemoteThread(handle, None, 0, load_library, mem, EXECUTE_IMMEDIATELY, None)
    succeed = WaitForSingleObject(thread, wintypes.DWORD(5000))
    if succeed != 0:
        raise WinError()
    VirtualFreeEx(handle, mem, 0, MEM_RELEASE)
    CloseHandle(thread)
    python_lib_h = LoadLibraryA(dll_name)
    print(f'Python lib found => {hex(python_lib_h)}')
    dll_h = get_module(handle, dll_name)
    print(f'{dll_name.decode()} found in process => {hex(dll_h)}')
    py_initialize = dll_h + (GetProcAddress(python_lib_h, b'Py_InitializeEx') - python_lib_h)
    pyrun_simplestring = dll_h + (GetProcAddress(python_lib_h, b'PyRun_SimpleString') - python_lib_h)
    print(f'Initialization located => {hex(py_initialize)}')
    print(f'String execution located => {hex(pyrun_simplestring)}')
    initialize = CreateRemoteThread(handle, None, 0, py_initialize, 0, EXECUTE_IMMEDIATELY, None)
    print(f'Python initialized => {hex(initialize)}')
    succeed = WaitForSingleObject(initialize, wintypes.DWORD(5000))
    if succeed != 0:
        raise WinError()
    code = get_injectable_code('injectme.py')
    code_mem = VirtualAllocEx(handle, False, len(code)+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    WriteProcessMemory(handle, code_mem, code, len(code)+1, None)
    run_string = CreateRemoteThread(handle, None, 0, pyrun_simplestring, code_mem, EXECUTE_IMMEDIATELY, None)
    print(f'Code executed => {hex(run_string)}')



    

