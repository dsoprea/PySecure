from ctypes import *

LIBSSH_FILE_PATH = "libssh.so"
libssh = cdll.LoadLibrary(LIBSSH_FILE_PATH)

