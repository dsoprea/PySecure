#!/usr/bin/env python2.7

from time import sleep

from test_base import connect_ssh

def ssh_cb(ssh):
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

connect_ssh(ssh_cb)

