"""Native Windows handle guards. Ancestors cannot be renamed during a read."""
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
import os
from pathlib import Path, PureWindowsPath


def _api():
    if os.name != 'nt': raise RuntimeError('Windows filesystem API unavailable')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    return kernel


class Attributes(ctypes.Structure):
    _fields_ = [('attributes', wintypes.DWORD), ('tag', wintypes.DWORD)]


class WindowsRoot:
    def __init__(self, root):
        self.root = Path(root)
        # Do not scan UNC/network shares, device namespaces or junctions.
        if not self.root.is_absolute() or not self.root.drive or self.root.drive.startswith('\\'):
            raise ValueError('Use a local drive path')
        self.kernel = _api()
        self.handles = []
        self._directory_chain(self.root, self.handles)

    def _open(self, path, directory):
        # OPEN_REPARSE_POINT stops final-link resolution. No FILE_SHARE_DELETE
        # keeps this component stable while later descendants are opened.
        handle = self.kernel.CreateFileW(str(path), 0x80000000, 0x1 | 0x2, None, 3, 0x00200000 | 0x02000000, None)
        if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = Attributes()
            if not self.kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
                raise ValueError('Reparse points and non-regular artifacts are excluded')
            return handle
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise

    def _directory_chain(self, path, handles):
        current = Path(path.anchor)
        try:
            handles.append(self._open(current, True))
            for part in path.parts[1:]:
                current /= part
                handles.append(self._open(current, True))
        except BaseException:
            for handle in reversed(handles): self.kernel.CloseHandle(handle)
            handles.clear()
            raise

    @contextmanager
    def directory(self, relative):
        handles = []
        current = self.root
        try:
            for part in relative.split('/') if relative else ():
                if part in ('', '.', '..') or ':' in part or '\\' in part: raise ValueError('Invalid relative directory')
                current /= part
                handles.append(self._open(current, True))
            yield current
        finally:
            for handle in reversed(handles): self.kernel.CloseHandle(handle)

    @contextmanager
    def file(self, relative):
        import msvcrt
        parts = relative.split('/')
        if not parts or any(part in ('', '.', '..') or ':' in part or '\\' in part for part in parts): raise ValueError('Invalid relative artifact')
        with self.directory('/'.join(parts[:-1])) as parent:
            handle = self._open(parent / parts[-1], False)
            try: fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                self.kernel.CloseHandle(handle)
                raise
            try: yield fd
            finally: os.close(fd)

    def close(self):
        for handle in reversed(self.handles): self.kernel.CloseHandle(handle)
        self.handles.clear()


def protect_private_path(path):
    """Restrict registry/key storage to the current Windows user and SYSTEM."""
    if Path(path).lstat().st_file_attributes & 0x400: raise ValueError('Private storage cannot be a reparse point')
    kernel = _api()
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    token = wintypes.HANDLE()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)): raise ctypes.WinError()
    descriptor = ctypes.c_void_p()
    sid_string = wintypes.LPWSTR()
    try:
        size = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not security.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)): raise ctypes.WinError()
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(sid_string)): raise ctypes.WinError()
        sddl = f'D:P(A;OICI;FA;;;{sid_string.value})(A;OICI;FA;;;SY)'
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None): raise ctypes.WinError()
        security.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
        if not security.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor): raise ctypes.WinError()
    finally:
        kernel.CloseHandle(token)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        if descriptor: kernel.LocalFree(descriptor)
        if sid_string: kernel.LocalFree(ctypes.cast(sid_string, ctypes.c_void_p))
