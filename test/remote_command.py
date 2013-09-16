from unittest import TestCase

from test_base import connect_ssh_test

class RemoteCommandTest(TestCase):
    def __ssh_cb(self, ssh):
        data = ssh.execute('lsb_release -a')
        print(data)

        data = ssh.execute('whoami')
        print(data)

    def test_remote_command(self):
        connect_ssh_test(self.__ssh_cb)

