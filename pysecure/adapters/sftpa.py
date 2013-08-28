import logging

from datetime import datetime
from ctypes import create_string_buffer, cast, c_void_p, c_int, c_char_p, \
                   c_size_t

from pysecure.constants.ssh import SSH_NO_ERROR
from pysecure.constants import SERVER_RESPONSES
from pysecure.calls.sftpi import c_sftp_get_error, c_sftp_new, c_sftp_init, \
                                 c_sftp_open, c_sftp_write, c_sftp_free, \
                                 c_sftp_opendir, c_sftp_closedir, \
                                 c_sftp_readdir, c_sftp_attributes_free, \
                                 c_sftp_dir_eof, c_sftp_tell, c_sftp_seek, \
                                 c_sftp_read, c_sftp_fstat, c_sftp_rewind, \
                                 c_sftp_close, c_sftp_rename, c_sftp_chmod, \
                                 c_sftp_chown, c_sftp_mkdir, c_sftp_rmdir, \
                                 c_sftp_stat

from pysecure.exceptions import SftpError

def sftp_get_error(sftp_session):
    return c_sftp_get_error(sftp_session)

def sftp_get_error_string(code):
    return ('%s [%s]' % (SERVER_RESPONSES[code][1], SERVER_RESPONSES[code][0]))

def _sftp_new(ssh_session):
    session = c_sftp_new(ssh_session)
    if session is None:
        raise SftpError("Could not create SFTP session.")
        
    return session

def _sftp_free(sftp_session):
    c_sftp_free(sftp_session)

def _sftp_init(sftp_session):
    result = c_sftp_init(sftp_session)
    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not create SFTP session: %s" % 
                            (sftp_get_error_string(type_)))
        else:
            raise SftpError("Could not create SFTP session. There was an "
                            "unspecified error.")

def _sftp_opendir(sftp_session, path):
    sd = c_sftp_opendir(sftp_session, path)
    if sd is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not open directory [%s]: %s" % 
                            (path, sftp_get_error_string(type_)))
        else:
            raise SftpError("Could not open directory [%s]. There was an "
                            "unspecified error." % (path))

    return sd

def _sftp_closedir(sd):
    result = c_sftp_closedir(sd)
    if result != SSH_NO_ERROR:
        raise SftpError("Could not close directory.")

def _sftp_readdir(sftp_session, sd):
    attr = c_sftp_readdir(sftp_session, sd)

    if not attr:
        return None

    return EntryAttributes(attr)

def _sftp_attributes_free(attr):
    c_sftp_attributes_free(attr)

def _sftp_dir_eof(sd):
    return (c_sftp_dir_eof(sd) == 1)

def _sftp_open(sftp_session, filepath, access_type, mode):
    logging.debug("Opening file: %s" % (filepath))

    sf = c_sftp_open(sftp_session, filepath, access_type, mode)
    if sf is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not open file [%s]: %s" % 
                            (filepath, sftp_get_error_string(type_)))
        else:
            raise SftpError("Could not open file [%s]. There was an "
                            "unspecified error." % (filepath))

    logging.debug("File [%s] opened as [%s]." % (filepath, sf))
    return sf

def _sftp_close(sf):
    logging.debug("Closing file: %s" % (sf))

    result = c_sftp_close(sf)
    if result != SSH_NO_ERROR:
        raise SftpError("Close failed with code (%d)." % (result))

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
    if c_sftp_read(sf, cast(buffer_, c_void_p), c_size_t(count)) < 0:
        raise SftpError("Read failed.")

    return buffer_.value

def sftp_fstat(sf):
    attr = c_sftp_fstat(sf)
    if attr is None:
        raise SftpError("Could not acquire attributes for FSTAT.")

    return EntryAttributes(attr)

def sftp_stat(sf, file_path):
    attr = c_sftp_stat(sf, c_char_p(file_path))
    if attr is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Could not acquire attributes for STAT of [%s]: "
                            "%s" % (file_path, sftp_get_error_string(type_)))
        else:
            raise SftpError("Could not acquire attributes for STAT of [%s]. "
                            "There was an unspecified error." % (file_path))

    return EntryAttributes(attr)

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

def sftp_rename(sftp_session, filepath_old, filepath_new):
#    filepath_new = ('%s.old' % (filepath))
    result = c_sftp_rename(sftp_session, 
                           c_char_p(filepath_old), 
                           c_char_p(filepath_new))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Rename of [%s] to [%s] failed: %s" % 
                            (filepath_old, 
                             filepath_new, 
                             sftp_get_error_string(type_)))
        else:
            raise SftpError("Rename of [%s] to [%s] failed. There was an "
                            "unspecified error." %
                            (filepath_old, filespace_new))

def sftp_chmod(sftp_session, file_path, mode):
    result = c_sftp_chmod(sftp_session, c_char_p(file_path), c_int(mode))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("CHMOD of [%s] for mode [%o] failed: %s" %
                            (file_path, mode, sftp_get_error_string(type_)))
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
                            "%s" % 
                            (file_path, uid, gid, 
                             sftp_get_error_string(type_)))
        else:
            raise SftpError("CHOWN of [%s] for UID (%d) and GID (%d) failed. "
                            "There was an unspecified error." % 
                            (file_path, mode))

def sftp_mkdir(sftp_session, path, mode):
    result = c_sftp_mkdir(sftp_session, c_char_p(path), c_int(mode))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("MKDIR of [%s] for mode [%o] failed: %s" %
                            (path, mode, sftp_get_error_string(type_)))
        else:
            raise SftpError("MKDIR of [%s] for mode [%o] failed. There was " %
                            "an unspecified error." % (path, mode))

def sftp_rmdir(sftp_session, path):
    result = c_sftp_rmdir(sftp_session, c_char_p(path))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("RMDIR of [%s] failed: %s" % 
                            (path, sftp_get_error_string(type_)))
        else:
            raise SftpError("RMDIR of [%s] failed. There was an unspecified "
                            "error." % (path))

def sftp_lstat(sftp_session, file_path):
    attr = c_sftp_lstat(sftp_session, c_char_p(file_path))

    if attr is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("LSTAT of [%s] failed: %s" % 
                            (file_path, sftp_get_error_string(type_)))
        else:
            raise SftpError("LSTAT of [%s] failed. There was an unspecified "
                            "error." % (file_path))

    return EntryAttributes(attr)

def sftp_unlink(sftp_session, file_path):
    result = c_sftp_lstat(sftp_session, c_char_p(file_path))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Unlink of [%s] failed: %s" % 
                            (file_path, sftp_get_error_string(type_)))
        else:
            raise SftpError("Unlink of [%s] failed. There was an unspecified "
                            "error." % (file_path))

def sftp_readlink(sftp_session, file_path):
    target = c_sftp_readlink(sftp_session, c_char_p(file_path))

    if target is None:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Read of link [%s] failed: %s" % 
                            (file_path, sftp_get_error_string(type_)))
        else:
            raise SftpError("Read of link [%s] failed. There was an "
                            "unspecified error." % (file_path))

    return target

def sftp_symlink(sftp_session, to, from_):
    result = c_sftp_symlink(sftp_session, c_char_p(to), c_char_p(from_))

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Symlink of [%s] to target [%s] failed: %s" % 
                            (from_, to, sftp_get_error_string(type_)))
        else:
            raise SftpError("Symlink of [%s] to target [%s] failed. There was "
                            "an unspecified error." % (from_, to))

def sftp_setstat(sftp_session, file_path, entry_attributes):
    result = c_sftp_setstat(sftp_session,
                            c_char_p(file_path),
                            entry_attributes.raw)

    if result < 0:
        type_ = sftp_get_error(sftp_session)
        if type_ >= 0:
            raise SftpError("Set-stat on [%s] failed: %s" % 
                            (file_path, sftp_get_error_string(type_)))
        else:
            raise SftpError("Set-stat on [%s] failed. There was an "
                            "unspecified error." % (file_path))

def sftp_listdir(sftp_session, path):
    with SftpDirectory(sftp_session, path) as sd_:
        while 1:
            attributes = _sftp_readdir(sftp_session, sd_)
            if attributes is None:
                break

            yield attributes

        if not _sftp_dir_eof(sd_):
            raise SftpError("We're done iterating the directory, but it's not "
                            "at EOF.")


class SftpSession(object):
    def __init__(self, ssh_session):
        self.__ssh_session = ssh_session

    def __enter__(self):
        self.__sftp_session = _sftp_new(self.__ssh_session)
        _sftp_init(self.__sftp_session)

        return self.__sftp_session

    def __exit__(self, e_type, e_value, e_tb):
        _sftp_free(self.__sftp_session)


class SftpDirectory(object):
    def __init__(self, sftp_session, path):
        self.__sftp_session = sftp_session
        self.__path = path

    def __enter__(self):
        self.__sd = _sftp_opendir(self.__sftp_session, self.__path)
        return self.__sd

    def __exit__(self, e_type, e_value, e_tb):
        _sftp_closedir(self.__sd)


class SftpFile(object):
    def __init__(self, sftp_session, filepath, access_type, mode):
        self.__sftp_session = sftp_session
        self.__filepath = filepath
        self.__access_type = access_type
        self.__mode = mode

    def __enter__(self):
        self.__sf = _sftp_open(self.__sftp_session, 
                               self.__filepath, 
                               self.__access_type, 
                               self.__mode)

        return self.__sf

    def __exit__(self, e_type, e_value, e_tb):
        _sftp_close(self.__sf)


class EntryAttributes(object):
    """This wraps the raw attribute type, and frees it at destruction."""

    def __init__(self, attr_raw):
        self.__attr_raw = attr_raw

    def __del__(self):
        _sftp_attributes_free(self.__attr_raw)

    def __getattr__(self, key):
        return getattr(self.__attr_raw.contents, key)

    def __repr__(self):
        return repr(self.__attr_raw.contents)

    def __str__(self):
        return str(self.__attr_raw.contents)

    @property
    def raw(self):
        return self.__attr_raw

#c_sftp_extensions_get_count
#c_sftp_extensions_get_name
#c_sftp_fstatvfs
#c_sftp_server_version
#c_sftp_statvfs
#c_sftp_statvfs_free
#c_sftp_utimes

