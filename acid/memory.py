from ctypes.wintypes import HANDLE, LPVOID
from msdn import *
from typing import Optional

class Process:
    def __init__(self, pid: int):
        self.pid = pid
        self.handle = OpenProcess(
            PROCESS_ALL_ACCESS,
            False,
            wintypes.DWORD(self.pid)
        )

    def write_memory(self, data: bytes) -> LPVOID:
        data_len = len(data)+1
        memory_loc = VirtualAllocEx(
            self.handle, 
            False, 
            data_len, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )
        WriteProcessMemory(self.handle, memory_loc, data, data_len, None)
        return memory_loc

    def free_memory(self, memory_loc: LPVOID):
        VirtualFreeEx(self.handle, memory_loc, 0, MEM_RELEASE)

    def create_thread(self, function: LPVOID, parameter: LPVOID, wait: int = 5000) -> HANDLE:
        handle = CreateRemoteThread(self.handle, None, 0, function, parameter, EXECUTE_IMMEDIATELY, None)
        succeed = WaitForSingleObject(handle, wintypes.DWORD(wait))
        if succeed != 0:
            raise WinError()
        return handle

    def get_module(self, name: bytes) -> Optional[LPVOID]:
        module_ptr = (LPVOID * 1024)()
        needed = c_ulong()
        EnumProcessModules(self.handle, module_ptr, sizeof(module_ptr), byref(needed))
        for module in module_ptr:
            if module is not None:
                module_name = create_string_buffer(200)
                if (GetModuleBaseNameA(self.handle, module, module_name, sizeof(module_name)) != 0):
                    if module is not None:
                        if module_name.value == name:
                            return module
        return None