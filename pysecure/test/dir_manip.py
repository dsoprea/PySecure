from unittest import TestCase

from pysecure.test.test_base import connect_sftp_test

class DirManipTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
#        print("Creating directory.")
        sftp.mkdir("xyz")
        
#        print("Removing directory.")
        sftp.rmdir("xyz")

    def test_dir_manip(self):
        connect_sftp_test(self.__sftp_cb)

