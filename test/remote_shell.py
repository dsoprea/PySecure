#!/usr/bin/env python2.7

from sys import stdout

from pysecure.adapters.channela import SshChannel

from test_base import connect_ssh

def ssh_cb(ssh):
    with SshChannel(ssh) as sc:
        sc.open_session()
        print(sc.is_open())

        sc.request_pty()
        sc.change_pty_size(80, 24)
        sc.request_shell()
        while sc.is_open() and sc.is_eof() is False:
            buffer_ = sc.read(1024)
            stdout.write(buffer_)

connect_ssh(ssh_cb)

