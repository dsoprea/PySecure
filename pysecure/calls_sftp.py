from ctypes import *

from pysecure.library import libssh
from pysecure.types import *

# Function calls.

# LIBSSH_API sftp_session sftp_new(ssh_session session);
c_sftp_new = libssh.sftp_new
c_sftp_new.argtypes = [c_ssh_session]
c_sftp_new.restype = c_sftp_session

# LIBSSH_API int sftp_init(sftp_session sftp);
c_sftp_init = libssh.sftp_init
c_sftp_init.argtypes = [c_sftp_session]
c_sftp_init.restype = c_int

# LIBSSH_API int sftp_get_error(sftp_session sftp);
c_sftp_get_error = libssh.sftp_get_error
c_sftp_get_error.argtypes = [c_sftp_session]
c_sftp_get_error.restype = c_int

# LIBSSH_API void sftp_free(sftp_session sftp);
c_sftp_free = libssh.sftp_free
c_sftp_free.argtypes = [c_sftp_session]
c_sftp_free.restype = None

# LIBSSH_API sftp_dir sftp_opendir(sftp_session session, const char *path);
c_sftp_opendir = libssh.sftp_opendir
c_sftp_opendir.argtypes = [c_sftp_session, c_char_p]
c_sftp_opendir.restype = c_sftp_dir

# LIBSSH_API sftp_attributes sftp_readdir(sftp_session session, sftp_dir dir);
c_sftp_readdir = libssh.sftp_readdir
c_sftp_readdir.argtypes = [c_sftp_session, c_sftp_dir]
c_sftp_readdir.restype = c_sftp_attributes

# LIBSSH_API void sftp_attributes_free(sftp_attributes file);
c_sftp_attributes_free = libssh.sftp_attributes_free
c_sftp_attributes_free.argtypes = [c_sftp_attributes]
c_sftp_attributes_free.restype = c_sftp_attributes

# LIBSSH_API int sftp_dir_eof(sftp_dir dir);
c_sftp_dir_eof = libssh.sftp_dir_eof
c_sftp_dir_eof.argtypes = [c_sftp_dir]
c_sftp_dir_eof.restype = c_int

# LIBSSH_API int sftp_closedir(sftp_dir dir);
c_sftp_closedir = libssh.sftp_closedir
c_sftp_closedir.argtypes = [c_sftp_dir]
c_sftp_closedir.restype = c_int

