from unittest import TestCase

from pysecure.adapters.sftpa import SftpFile

from test_base import connect_sftp_test

class BinaryReadTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        with SftpFile(sftp, 'test_libgksu2.so.0', 'r') as sf:
            buffer_ = sf.read()

            with file('/tmp/sftp_dump', 'w') as f:
                f.write(buffer_)

            print("Read (%d) bytes." % (len(buffer_)))

    def test_binary_read(self):
        connect_sftp_test(self.__sftp_cb)

