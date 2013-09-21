from unittest import TestCase

from sys import stdout

from pysecure.adapters.sftpa import SftpFile
from pysecure.test.test_base import connect_sftp_test

class TextIterateTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
        with SftpFile(sftp, 'test_doc_rfc1958.txt') as sf:
            i = 0
            for data in sf:
                stdout.write("> " + data)

                if i >= 30:
                    break

                i += 1

    def test_text_iterate(self):
        connect_sftp_test(self.__sftp_cb)

