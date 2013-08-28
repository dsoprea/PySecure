from datetime import datetime
from ctypes import *

from pysecure.constants import O_CREAT, SSH_NO_ERROR
from pysecure.sftp_calls import sftp_open, sftp_write, sftp_tell, sftp_seek, \
                                sftp_read, sftp_fstat, sftp_tell, \
                                sftp_rewind, sftp_close, sftp_rename

#c_sftp_new
#c_sftp_init
#c_sftp_get_error
#c_sftp_free
#c_sftp_opendir
#c_sftp_readdir
#c_sftp_attributes_free
#c_sftp_dir_eof
#c_sftp_closedir

# TODO: Write wrappers for all functions. At the very least, they can translate 
#       return codes to exceptions.


def test_file_io(self, sftp_session):
    filepath = ('/tmp/sftp_%s.test' % 
                 (datetime.now().strftime('%Y%m%d-%H%M%S')))

    test_file_content = "test content"

    sf = sftp_open(sftp_session, filepath, O_CREAT, 0o777)
    result = sftp_write(sf, test_file_content)
    position = sftp_tell(sf)
        
    print("Current position 1: %d" % (position))
    
# c_sftp_tell64

    new_position = 0
    sftp_seek(sf, new_position)
    
# c_sftp_seek64

    buffer_ = sftp_read(sf, buffer_size)

    attr = sftp_fstat(sf)
    print(attr)

    position = sftp_tell(sf)
    print("Current position 2: %d" % (position))

c_sftp_rewind

    position = sftp_tell(sf)
        
    print("Current position 3: %d" % (position))

    sftp_close(sf)

    filepath_new = ('%s.old' % (filepath))
    result = sftp_rename(sftp_session, filepath, filepath_new)

#c_sftp_chmod
#c_sftp_chown
#c_sftp_extensions_get_count
#c_sftp_extensions_get_name
#c_sftp_fstatvfs
#c_sftp_lstat
#c_sftp_mkdir
#c_sftp_readlink
#c_sftp_rmdir
#c_sftp_server_version
#c_sftp_setstat
#c_sftp_stat
#c_sftp_statvfs
#c_sftp_statvfs_free
#c_sftp_symlink
#c_sftp_unlink
#c_sftp_utimes

