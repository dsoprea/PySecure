from datetime import datetime
from ctypes import create_string_buffer, cast

from pysecure.constants import SSH_NO_ERROR
from pysecure.calls.sftpi import sftp_get_error, c_sftp_open, c_sftp_write, \
                                 c_sftp_tell, c_sftp_seek, c_sftp_read, \
                                 c_sftp_fstat, c_sftp_rewind, c_sftp_close, \
                                 c_sftp_rename, c_sftp_chmod, c_sftp_chown, \
                                 c_sftp_mkdir, c_sftp_rmdir

from pysecure.exceptions import SftpError

def sftp_new(ssh_session):
    session = c_sftp_new(ssh_session)
    if session is None:
        raise SftpError("Could not create SFTP session.")
        
    return session

def sftp_init(sftp_session):
    result = c_sftp_init(sftp_session)
    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not create SFTP session: %d" % (type_))
        else:
            raise SftpError("Could not create SFTP session. There was an "
                            "unspecified error.")

def sftp_get_error(sftp_session):
    return c_sftp_get_error(sftp_session)

def sftp_free(sftp_session):
    c_sftp_free(sftp_session)

def sftp_opendir(sftp_session, path)
    sd = c_sftp_opendir(sftp_session, path)
    if sd is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not open directory [%s]: %d" % 
                            (path, type_))
        else:
            raise SftpError("Could not open directory [%s]. There was an "
                            "unspecified error." % (path))

    return sd

def sftp_closedir(sd)
    result = c_sftp_closedir(sd)
    if result != SSH_NO_ERROR:
        raise SftpError("Could not close directory.")

def sftp_readdir(sftp_session, sd)
    attr = c_sftp_readdir(sftp_session, sd)
    if attr is None:
        raise SftpError("Could not read directory.")

    return attr

def sftp_attributes_free(attr)
    c_sftp_attributes_free(attr)

def sftp_dir_eof(sd):
    return (c_sftp_dir_eof(sd) == 1)

def sftp_open(sftp_session, filepath, access_type, mode)
    sf = c_sftp_open(sftp_session, filepath, access_type, mode)
    if sf is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not open file [%s]: %d" % 
                            (file_path, type_))
        else:
            raise SftpError("Could not open file [%s]. There was an "
                            "unspecified error." % (file_path))

def sftp_write(sf, buffer_):
    buffer_raw = create_string_buffer(buffer_)
    result = c_sftp_write(sf, cast(buffer_raw, c_void_p), len(buffer_))
    if result < 0:
        raise SftpError("Could not write to file.")

def sftp_tell(sf):
    position = c_sftp_tell(sf)
    if position < 0:
        raise SftpError("Could not read current position in file.")
        
#    print("Current position 1: %d" % (position))

    return position
    
# c_sftp_tell64

def sftp_seek(sf, position):
    if c_sftp_seek(sf, position) < 0:
        raise SftpError("Could not seek to the position (%d)." % (position))
    
# c_sftp_seek64

def sftp_read(sf, count):
    buffer_ = create_string_buffer(count)
    if c_sftp_read(sf, cast(buffer_, c_void_p), c_int(count)) < 0:
        raise SftpError("Read failed.")

    return buffer_.value

def sftp_fstat(sf):
    attr = c_sftp_fstat(sf)
    if attr is None:
        raise SftpError("Could not acquire attributes for FSTAT.")

    return attr

def sftp_stat(sf, file_path):
    attr = c_sftp_fstat(sf, c_char_p(file_path))
    if attr is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not acquire attributes for STAT of [%s]: "
                            "%d" % (file_path, type_))
        else:
            raise SftpError("Could not acquire attributes for STAT of [%s]. "
                            "There was an unspecified error." % (file_path))

    return attr

#    print(attr)

#     position = c_sftp_tell(sf)
#     if position < 0:
#          raise Exception("Could not read current position in file.")
# 
#    print("Current position 2: %d" % (position))

def sftp_rewind(sf):
    # Returns VOID.
    c_sftp_rewind(sf)

#    position = c_sftp_tell(sf)
#    if position < 0:
#        raise Exception("Could not read current position in file.")
#        
#    print("Current position 3: %d" % (position))

def sftp_close(sf):
    result = c_sftp_close(sf)
    if result != SSH_NO_ERROR:
        raise SftpError("Close failed with code (%d)." % (result))

def sftp_rename(sftp_session, filepath_old, filepath_new):
#    filepath_new = ('%s.old' % (filepath))
    result = c_sftp_rename(sftp_session, 
                           c_char_p(filepath_old), 
                           c_char_p(filepath_new))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Rename of [%s] to [%s] failed: %d" % 
                            (filepath_old, filepath_new, type_))
        else:
            raise SftpError("Rename of [%s] to [%s] failed. There was an "
                            "unspecified error." %
                            (filepath_old, filespace_new))

def sftp_chmod(sftp_session, file_path, mode):
    result = c_sftp_chmod(sftp_session, c_char_p(file_path), c_int(mode))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("CHMOD of [%s] for mode [%o] failed: %d" %
                            (file_path, mode, type_))
        else:
            raise SftpError("CHMOD of [%s] for mode [%o] failed. There was " %
                            "an unspecified error." % (file_path, mode))

def sftp_chown(sftp_session, file_path, uid, gid):
    result = c_sftp_chown(sftp_session, 
                          c_char_p(file_path), 
                          c_int(uid), 
                          c_int(gid))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("CHOWN of [%s] for UID (%d) and GID (%d) failed: "
                            "%d" % (file_path, uid, gid, type_))
        else:
            raise SftpError("CHOWN of [%s] for UID (%d) and GID (%d) failed. "
                            "There was an unspecified error." % 
                            (file_path, mode))

def sftp_mkdir(sftp_session, path, mode):
    result = c_sftp_mkdir(sftp_session, c_char_p(path), c_int(mode))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("MKDIR of [%s] for mode [%o] failed: %d" %
                            (path, mode, type_))
        else:
            raise SftpError("MKDIR of [%s] for mode [%o] failed. There was " %
                            "an unspecified error." % (path, mode))

def sftp_rmdir(sftp_session, path):
    result = c_sftp_rmdir(sftp_session, c_char_p(path))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("RMDIR of [%s] failed: %d" % (path, type_))
        else:
            raise SftpError("RMDIR of [%s] failed. There was an unspecified "
                            "error." % (path))

def sftp_lstat(sftp_session, file_path):
    attr = c_sftp_lstat(sftp_session, c_char_p(file_path))

    if attr is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("LSTAT of [%s] failed: %d" % (file_path, type_))
        else:
            raise SftpError("LSTAT of [%s] failed. There was an unspecified "
                            "error." % (file_path))

    return attr

def sftp_unlink(sftp_session, file_path):
    result = c_sftp_lstat(sftp_session, c_char_p(file_path))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Unlink of [%s] failed: %d" % (file_path, type_))
        else:
            raise SftpError("Unlink of [%s] failed. There was an unspecified "
                            "error." % (file_path))

def sftp_readlink(sftp_session, file_path):
    target = c_sftp_readlink(sftp_session, c_char_p(file_path))

    if target is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Read of link [%s] failed: %d" % 
                            (file_path, type_))
        else:
            raise SftpError("Read of link [%s] failed. There was an "
                            "unspecified error." % (file_path))

    return target

def sftp_symlink(sftp_session, to, from_):
    result = c_sftp_symlink(sftp_session, c_char_p(to), c_char_p(from_))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Symlink of [%s] to target [%s] failed: %d" % 
                            (from_, to, type_))
        else:
            raise SftpError("Symlink of [%s] to target [%s] failed. There was "
                            "an unspecified error." % (from_, to))

def sftp_setstat(sftp_session, file_path, attr):
    result = c_sftp_setstat(sftp_session, c_char_p(file_path), attr)

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Set-stat on [%s] failed: %d" % 
                            (file_path, type_))
        else:
            raise SftpError("Set-stat on [%s] failed. There was an "
                            "unspecified error." % (file_path))


#c_sftp_extensions_get_count
#c_sftp_extensions_get_name
#c_sftp_fstatvfs
#c_sftp_server_version
#c_sftp_statvfs
#c_sftp_statvfs_free
#c_sftp_utimes

