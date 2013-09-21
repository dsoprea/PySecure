from unittest import TestCase

from pysecure.adapters.sftpa import SftpFile
from pysecure.test.test_base import connect_sftp_test

class BinaryReadTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        print("Opening file.")
    
        with SftpFile(sftp, 'test_libgksu2.so.0', 'r') as sf:
            buffer_ = sf.read()

            with open('/tmp/sftp_dump', 'wb') as f:
                f.write(buffer_)

            print("Read (%d) bytes." % (len(buffer_)))

    def test_binary_read(self):
        connect_sftp_test(self.__sftp_cb)

