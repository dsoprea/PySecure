import logging

from unittest import TestCase

import pysecure.log_config

from pysecure.easy import EasySsh, get_key_auth_cb
from pysecure.test.test_config import user, host, key_filepath


class SftpNoCb(TestCase):
    def __init__(self, *args, **kwargs):
        super(SftpNoCb, self).__init__(*args, **kwargs)

        self.__log = logging.getLogger('SftpNoCb')

    def setUp(self):
        auth_cb = get_key_auth_cb(key_filepath)
        self.__easy = EasySsh(user, host, auth_cb)
        self.__easy.open_ssh()
        self.__easy.open_sftp()
    
    def tearDown(self):
        self.__easy.close_sftp()
        self.__easy.close_ssh()

    def test_nocb(self):
        entries = self.__easy.sftp.listdir('.')
        self.__log.info("(%d) entries returned." % (len(list(entries))))

