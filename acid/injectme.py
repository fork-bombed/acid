from ctypes import *
from ctypes import wintypes
import os

MB_ICONEXCLAMATION = 0x00000030
MB_OK = 0x0
MB_SYSTEMMODAL = 0x00001000

MB_TYPE = MB_ICONEXCLAMATION | MB_OK | MB_SYSTEMMODAL

MessageBoxA = windll.user32.MessageBoxA
MessageBoxA.argtypes = (wintypes.HWND, wintypes.LPCSTR, wintypes.LPCSTR, wintypes.UINT)
MessageBoxA.restype = wintypes.INT

txt = wintypes.LPCSTR(f'Parent process ID = {os.getppid()}'.encode())
cap = wintypes.LPCSTR(b'DLL Injected')

MessageBoxA(None, txt, cap, MB_TYPE)