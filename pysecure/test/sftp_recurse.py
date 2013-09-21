from unittest import TestCase

from pysecure.test.test_base import connect_sftp_test

class SftpRecurseTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        def dir_cb(path, full_path, entry):
            print("DIR: %s" % (full_path))

        def listing_cb(path, list_):
            print("[%s]: (%d) files" % (path, len(list_)))

        sftp.recurse('Pictures', dir_cb, listing_cb)

    def test_sftp_recurse(self):
        connect_sftp_test(self.__sftp_cb)

