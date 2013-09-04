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

from sys import stdout

def dumphex(data):
    data_len = len(data)
    row_size = 16

    i = 0
    while i < data_len:
        stdout.write('%05X:' % (i))
    
        j = 0
        while j < row_size:
            index = i + j

            if j == 8:
                stdout.write(' ')

            try:
                stdout.write(' %02X' % (ord(data[index])))
            except IndexError:
                stdout.write('   ')
        
            j += 1
    
        stdout.write(' | ')
    
        j = 0
        while j < row_size:
            index = i + j

            try:
                byte = data[index]
            except IndexError:
                break
            else:
                if ord(byte) < 32:
                    byte = '.'

                stdout.write('%s' % (byte))

            j += 1

        print

        i += row_size

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
                with SftpFile(sftp, 'test_doc_rfc1958.txt') as sf:
                    i = 0
                    for data in sf:
                        stdout.write("> " + data)

                        if i >= 30:
                            break

                        i += 1
 
# TODO: Implement str/repr on structures.
#                    attr = sf.raw.fstat()
#                    print(attr)

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


