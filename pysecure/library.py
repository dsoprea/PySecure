from ctypes import cdll
from ctypes.util import find_library

_LIBSSH_FILEPATH = find_library('libssh')
if _LIBSSH_FILEPATH is None:
    _LIBSSH_FILEPATH = 'libssh.so'

libssh = cdll.LoadLibrary(_LIBSSH_FILEPATH)
