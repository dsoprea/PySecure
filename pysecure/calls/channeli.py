from ctypes import *

from pysecure.library import libssh
from pysecure.types import *

# ssh_channel ssh_channel_new(ssh_session session)
c_ssh_channel_new = libssh.ssh_channel_new
c_ssh_channel_new.argtypes = [c_ssh_session]
c_ssh_channel_new.restype = c_ssh_channel

# int ssh_channel_open_forward(ssh_channel channel, const char *remotehost,int remoteport, const char *sourcehost, int localport)   
c_ssh_channel_open_forward = libssh.ssh_channel_open_forward
c_ssh_channel_open_forward.argtypes = [c_ssh_channel, c_char_p, c_int, c_char_p, c_int]
c_ssh_channel_open_forward.restype = c_int

# void ssh_channel_free(ssh_channel channel)
c_ssh_channel_free = libssh.ssh_channel_free
c_ssh_channel_free.argtypes = [c_ssh_channel]
c_ssh_channel_free.restype = None

# int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len)
c_ssh_channel_write = libssh.ssh_channel_write
c_ssh_channel_write.argtypes = [c_ssh_channel, c_void_p, c_uint32]
c_ssh_channel_write.restype = c_int

# int ssh_channel_read(ssh_channel channel, void *dest, uint32_t count, int is_stderr)
c_ssh_channel_read = libssh.ssh_channel_read
c_ssh_channel_read.argtypes = [c_ssh_channel, c_void_p, c_uint32, c_int]
c_ssh_channel_read.restype = c_int

# int ssh_channel_send_eof(ssh_channel channel)
c_ssh_channel_send_eof = libssh.ssh_channel_send_eof
c_ssh_channel_send_eof.argtypes = [c_ssh_channel]
c_ssh_channel_send_eof.restype = c_int

# int ssh_channel_is_open(ssh_channel channel)
c_ssh_channel_is_open = libssh.ssh_channel_is_open
c_ssh_channel_is_open.argtypes = [c_ssh_channel]
c_ssh_channel_is_open.restype = c_int

# LIBSSH_API int ssh_channel_open_session(ssh_channel channel);
c_ssh_channel_open_session = libssh.ssh_channel_open_session
c_ssh_channel_open_session.argtypes = [c_ssh_channel]
c_ssh_channel_open_session.restype = c_int

# int ssh_channel_request_exec(ssh_channel channel, const char *cmd)
c_ssh_channel_request_exec = libssh.ssh_channel_request_exec
c_ssh_channel_request_exec.argtypes = [c_ssh_channel, c_char_p]
c_ssh_channel_request_exec.restype = c_int

