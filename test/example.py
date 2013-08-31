#!/usr/bin/env python2.7

import logging

from pysecure import log_config

from pysecure.constants.sftp import O_WRONLY, O_RDWR, O_CREAT
from pysecure.adapters.ssha import ssh_is_server_known, \
                                   ssh_write_knownhost, \
                                   ssh_userauth_privatekey_file, SshSession, \
                                   SshConnect, SshSystem, PublicKeyHash

from pysecure.adapters.sftpa import SftpSession, sftp_listdir, SftpFile

user = 'dustin'
host = 'dustinlost'
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

            ssh_is_server_known(ssh, allow_new=True, cb=hostkey_gate)
            ssh_userauth_privatekey_file(ssh, None, key_filepath, None)

            with SftpSession(ssh) as sftp:
                test_data = '1234'
# TODO: Make SftpFile a file-like object.
                with SftpFile(sftp, 'test_sftp_file', O_RDWR|O_CREAT, 0o644) as sf:
                    print("Position at top of file: %d" % (sf.position))

                    sf.write(test_data)
                    print("Position at bottom of file: %d" % (sf.position))

                    sf.seek(0)
                    print("Position at position (0): %d" % (sf.position))

                    buffer_ = sf.read(100)
                    print("Read: [%s]" % (buffer_))

                    print("Position after read: %d" % (sf.position))
                    sf.rewind()

                    print("Position after rewind: %d" % (sf.position))
# TODO: Implement str/repr on structures.
                    attr = sf.fstat()
                    print(attr)

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


