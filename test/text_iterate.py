#!/usr/bin/env python2.7

from sys import stdout

from pysecure.adapters.sftpa import SftpFile

from test_base import connect_sftp

def sftp_cb(ssh, sftp):
    with SftpFile(sftp, 'test_doc_rfc1958.txt') as sf:
        i = 0
        for data in sf:
            stdout.write("> " + data)

            if i >= 30:
                break

            i += 1

connect_sftp(sftp_cb)

