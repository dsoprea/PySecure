from unittest import TestCase

from pysecure.sftp_mirror import SftpMirror

from test_base import connect_sftp_test, connect_ssh_test

class ExampleTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        mirror = SftpMirror(sftp)

    #    mirror.mirror(mirror.mirror_to_local_no_recursion, 
    #                  "Pictures", 
    #                  "/tmp/Pictures", 
    #                  log_files=True)

        mirror.mirror(mirror.mirror_to_remote_no_recursion, 
                      "/home/dustin/Pictures", 
                      "/tmp/RemotePictures", 
                      log_files=True)

    def test_example(self):
        connect_sftp_test(self.__sftp_cb)

