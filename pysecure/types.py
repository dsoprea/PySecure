from ctypes import *

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

_CSftpAttributes = POINTER(_CSftpAttributesStruct)


# Fortunately, we should probably be able to avoid most/all of the mechanics 
# for the vast number of structs.

c_ssh_session = c_void_p #POINTER(CSshSessionStruct)
c_sftp_session = c_void_p
c_sftp_attributes = _CSftpAttributes
c_sftp_dir = c_void_p

