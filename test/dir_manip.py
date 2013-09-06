#!/usr/bin/env python2.7

from test_base import connect_sftp

def sftp_cb(ssh, sftp):
    sftp.mkdir("xyz")
    sftp.rmdir("xyz")

connect_sftp(sftp_cb)

