import logging
import os

from ctypes import cdll
from ctypes.util import find_library

_logger = logging.getLogger(__name__)

_LIBSSH_FILEPATH = os.environ.get('PS_LIBRARY_FILEPATH', '')
if _LIBSSH_FILEPATH == '':
    _LIBSSH_FILEPATH = find_library('libssh')
    if _LIBSSH_FILEPATH is None:
        _LIBSSH_FILEPATH = 'libssh.so'

_logger.debug("Using library: [%s]", _LIBSSH_FILEPATH)
libssh = cdll.LoadLibrary(_LIBSSH_FILEPATH)
