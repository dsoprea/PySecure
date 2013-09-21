from unittest import TestCase
from time import sleep

from pysecure.test.test_base import connect_ssh_test

class ForwardX11Test(TestCase):
    def __ssh_cb(self, ssh):
        print("Is blocking: %s" % (ssh.is_blocking()))

        server_address = None
        server_port = 8080
        accept_timeout_ms = 60000

        port = ssh.forward_listen(server_address, server_port)
        with ssh.forward_accept(accept_timeout_ms) as sc:
            print("Waiting for X11 connection.")
            x11_channel = sc.accept_x11(60000)

            print("Requesting.")
            x11_channel.request_x11()
            
            print("Looping.")
            while 1:
                sleep(.1)

    def test_forward_x11(self):
        connect_ssh_test(self.__ssh_cb)

