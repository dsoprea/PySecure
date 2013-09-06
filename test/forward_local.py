#!/usr/bin/env python2.7

from pysecure.adapters.channela import SshChannel

from test_base import connect_ssh

def ssh_cb(ssh):
    host_remote = 'localhost'
    port_remote = 80
    host_source = 'localhost'
    port_local = 1111
    data = "GET / HTTP/1.1\nHost: localhost\n\n"

    with SshChannel(ssh) as sc:
        sc.open_forward(host_remote, 
                        port_remote, 
                        host_source, 
                        port_local)

        sc.write(data)

        received = sc.read(1024)

        print("Received:\n\n%s" % (received))


connect_ssh(ssh_cb)

