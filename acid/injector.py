from ctypes import *
from ctypes import wintypes
from msdn import *
from memory import Process

def get_injectable_code(filename):
    with open(f'acid/{filename}') as f:
        code = f.read()
    return code.encode()

def inject(pid, dll):
    dll_name = dll.decode().split('\\')[-1].encode()
    process = Process(pid)
    dll_addr = process.write_memory(dll)
    load_library = GetProcAddress(GetModuleHandleA(b'kernel32.dll'), b'LoadLibraryA')
    thread = process.create_thread(load_library, dll_addr)
    process.free_memory(dll_addr)
    CloseHandle(thread)
    python_lib_h = LoadLibraryA(dll_name)
    print(f'Python lib found => {hex(python_lib_h)}')
    dll_h = process.get_module(dll_name)
    print(f'{dll_name.decode()} found in process => {hex(dll_h)}')
    py_initialize = dll_h + (GetProcAddress(python_lib_h, b'Py_InitializeEx') - python_lib_h)
    pyrun_simplestring = dll_h + (GetProcAddress(python_lib_h, b'PyRun_SimpleString') - python_lib_h)
    print(f'Initialization located => {hex(py_initialize)}')
    print(f'String execution located => {hex(pyrun_simplestring)}')
    process.create_thread(py_initialize, 0)
    code = get_injectable_code('injectme.py')
    code_mem = process.write_memory(code)
    run_string = process.create_thread(pyrun_simplestring, code_mem)
    print(f'Code executed => {hex(run_string)}')



    

