#!/usr/bin/env python2.7

from pysecure.adapters.sftpa import SftpFile

from test_base import connect_sftp

def sftp_cb(ssh, sftp):
    test_data = '1234'
    with SftpFile(sftp, 'sftp_write.txt', 'w') as sf:
        sf.write(test_data)

connect_sftp(sftp_cb)

