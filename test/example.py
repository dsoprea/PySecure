#!/usr/bin/env python2.7

import logging

from pysecure import log_config

from pysecure.constants.sftp import O_WRONLY, O_RDWR
from pysecure.adapters.ssha import ssh_is_server_known, \
                                   ssh_write_knownhost, \
                                   ssh_userauth_privatekey_file, SshSession, \
                                   SshConnect, SshSystem, PublicKeyHash

from pysecure.adapters.sftpa import SftpSession, sftp_listdir, SftpFile, \
                                    sftp_write, sftp_tell, sftp_seek, \
                                    sftp_read, sftp_fstat, sftp_rewind

user = 'dustin'
host = 'dustinplex'
key_filepath = '/home/dustin/.ssh/id_dsa'
verbosity = 0

with SshSystem():
    with SshSession(user=user, host=host, verbosity=verbosity) as ssh:
        with SshConnect(ssh):
            logging.debug("Ready to authenticate.")

            def hostkey_gate(hk, would_accept):
                logging.debug("CB HK: %s" % (hk))
                logging.debug("CB Would Accept: %s" % (would_accept))
                
                return would_accept

            ssh_is_server_known(ssh, cb=hostkey_gate)
            ssh_userauth_privatekey_file(ssh, None, key_filepath, None)

            with SftpSession(ssh) as sftp:
                test_data = '1234'
# TODO: Make SftpFile a file-like object.
                with SftpFile(sftp, 'test_sftp_file', O_RDWR, 0o644) as sf:
                    print("Position at top of file: %d" % (sftp_tell(sf)))
                    sftp_write(sf, test_data)
                    print("Position at bottom of file: %d" % (sftp_tell(sf)))

                    sftp_seek(sf, 0)
                    print("Position at position (0): %d" % (sftp_tell(sf)))

                    buffer_ = sftp_read(sf, 100)
                    print("Read: [%s]" % (buffer_))

                    print("Position after read: %d" % (sftp_tell(sf)))
                    sftp_rewind(sf)

                    print("Position after rewind: %d" % (sftp_tell(sf)))
# TODO: Implement str/repr on attributes.
                    attr = sftp_fstat(sf)
                    print(attr)

#def sftp_write(sf, buffer_):
#def sftp_tell(sf):
#def sftp_seek(sf, position):
#def sftp_read(sf, count):
#def sftp_fstat(sf):
#def sftp_rewind(sf):

# TODO: Move all session operations to the session object.

#def sftp_stat(sftp_session, file_path):
#def sftp_rename(sftp_session, filepath_old, filepath_new):
#def sftp_chmod(sftp_session, file_path, mode):
#def sftp_chown(sftp_session, file_path, uid, gid):
#def sftp_mkdir(sftp_session, path, mode):
#def sftp_rmdir(sftp_session, path):
#def sftp_lstat(sftp_session, file_path):
#def sftp_unlink(sftp_session, file_path):
#def sftp_readlink(sftp_session, file_path):
#def sftp_symlink(sftp_session, to, from_):
#def sftp_setstat(sftp_session, file_path, entry_attributes):


