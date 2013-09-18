from unittest import TestCase

from pysecure.adapters.channela import SshChannel

from test_base import connect_ssh_test

class SshStatusesTest(TestCase):
    def __ssh_cb(self, ssh):
        print("Disconnect message: %s" % (ssh.get_disconnect_message(),))

    def test_forward_local(self):
        connect_ssh_test(self.__ssh_cb)

