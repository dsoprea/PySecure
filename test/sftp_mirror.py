from unittest import TestCase

from test_base import connect_sftp_test
from pysecure.sftp_mirror import SftpMirror

from datetime import datetime

class SftpMirrorTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        mirror = SftpMirror(sftp)

        mirror.mirror(mirror.mirror_to_local_no_recursion, 
                      "Pictures", 
                      "/tmp/Pictures", 
                      log_files=True)

#        mirror.mirror(mirror.mirror_to_remote_no_recursion, 
#                      "/home/dustin/Pictures", 
#                      "/tmp/RemotePictures", 
#                      log_files=True)

    def test_sftp_mirror(self):
        connect_sftp_test(self.__sftp_cb)

