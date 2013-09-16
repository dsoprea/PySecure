#!/usr/bin/env python2.7

from test_base import connect_sftp_test

def sftp_cb(ssh, sftp):
    sftp.mkdir("xyz")
    sftp.rmdir("xyz")

connect_sftp_test(sftp_cb)

