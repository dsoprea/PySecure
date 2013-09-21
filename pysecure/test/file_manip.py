from unittest import TestCase

from pysecure.adapters.sftpa import SftpFile
from pysecure.test.test_base import connect_sftp_test

class FileManipTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        test_data = '1234'

        with SftpFile(sftp, 'test_sftp_file', 'r+') as sf:
            print("Position at top of file: %d" % (sf.tell()))

            sf.write(test_data)
            print("Position at bottom of file: %d" % (sf.tell()))

            sf.seek(0)
            print("Position at position (0): %d" % (sf.tell()))

            buffer_ = sf.read(100)
            print("Read: [%s]" % (buffer_))

            print("Position after read: %d" % (sf.tell()))
            sf.seek(0)

            print("Position after rewind: %d" % (sf.tell()))

            buffer_ = sf.read(100)
            print("Read 1: (%d) bytes" % (len(buffer_)))
            print("Position after read 1: %d" % (sf.tell()))

            buffer_ = sf.read(100)
            print("Read 2: (%d) bytes" % (len(buffer_)))
            print("Position after read 2: %d" % (sf.tell()))

            attr = sf.raw.fstat()
            print(attr)

    def test_file_manip(self):
        connect_sftp_test(self.__sftp_cb)

