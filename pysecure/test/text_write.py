from unittest import TestCase

from pysecure.adapters.sftpa import SftpFile
from pysecure.test.test_base import connect_sftp_test

class TextWriteTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        test_data = b'1234'
        with SftpFile(sftp, 'sftp_write.txt', 'w') as sf:
            sf.write(test_data)

    def test_text_write(self):
        connect_sftp_test(self.__sftp_cb)

