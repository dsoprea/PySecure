import platform

from ctypes import *
from datetime import datetime

from pysecure.constants import TIME_DATETIME_FORMAT

c_mode_t = c_int
c_uid_t = c_uint32
c_gid_t = c_uint32

# This are very-very unpredictable. We can only hope that this holds up for 
# most systems.

# Returns something like "32bit" or "64bit".
arch_name = platform.architecture()[0]
arch_width = int(arch_name[0:2])

if arch_width == 64:
    c_time_t = c_uint64
    c_suseconds_t = c_uint64
else:
    c_time_t = c_uint32
    c_suseconds_t = c_uint32


class _CSftpAttributesStruct(Structure):
    _fields_ = [('name', c_char_p),
                ('longname', c_char_p),
                ('flags', c_uint32),
                ('type', c_uint8),
                ('size', c_uint64),
                ('uid', c_uint32),
                ('gid', c_uint32),
                ('owner', c_char_p),
                ('group', c_char_p),
                ('permissions', c_uint32),
                ('atime64', c_uint64),
                ('atime', c_uint32),
                ('atime_nseconds', c_uint32),
                ('createtime', c_uint64),
                ('createtime_nseconds', c_uint32),
                ('mtime64', c_uint64),
                ('mtime', c_uint32),
                ('mtime_nseconds', c_uint32),
                ('acl', c_void_p), # NI: ssh_string
                ('extended_count', c_uint32),
                ('extended_type', c_void_p), # NI: ssh_string
                ('extended_data', c_void_p)] # NI: ssh_string

    def __repr__(self):
        mtime_phrase = datetime.fromtimestamp(self.mtime).\
                                strftime(TIME_DATETIME_FORMAT)

        return ('<ATTR "%s" S=(%d) T=(%d) MT=[%s]>' % 
                (self.name, self.size, self.type, mtime_phrase))

_CSftpAttributes = POINTER(_CSftpAttributesStruct)


class CTimeval(Structure):
    _fields_ = [('tv_sec', c_time_t),
                ('tv_usec', c_suseconds_t)]

c_timeval = CTimeval

# Fortunately, we should probably be able to avoid most/all of the mechanics 
# for the vast number of structs.

c_ssh_session = c_void_p #POINTER(CSshSessionStruct)
c_ssh_channel = c_void_p
c_sftp_session = c_void_p
c_sftp_attributes = _CSftpAttributes
c_sftp_dir = c_void_p
c_sftp_file = c_void_p

# A simple aliasing assignment doesn't work, here.
# c_sftp_statvfs = c_void_p

