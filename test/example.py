#!/usr/bin/env python2.7

from test_base import connect_sftp
from pysecure.sftp_mirror import SftpMirror

from datetime import datetime

def sftp_cb(ssh, sftp):
    mirror = SftpMirror(sftp)

#    sftp.collect_deltas("Pictures", "/tmp/Pictures", log_files=True)
#    mirror.mirror(mirror.mirror_to_local_no_recursion, 
#                  "Pictures", 
#                  "/tmp/Pictures", 
#                  log_files=True)

#    sftp.collect_deltas("Pictures", "/tmp/Pictures", log_files=True)
    mirror.mirror(mirror.mirror_to_remote_no_recursion, 
                  "/home/dustin/Pictures", 
                  "/tmp/RemotePictures", 
                  log_files=True)

connect_sftp(sftp_cb)

