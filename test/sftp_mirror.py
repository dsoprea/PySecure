#!/usr/bin/env python2.7

from test_base import connect_sftp

def sftp_cb(ssh, sftp):
    sftp.mirror_to_local_recursive("Pictures", "/tmp/Pictures", log_files=True)

connect_sftp(sftp_cb)

