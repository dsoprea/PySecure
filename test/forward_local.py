#!/usr/bin/env python2.7

import logging

from pysecure import log_config
from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash
from pysecure.adapters.channela import SshChannel

user = 'dustin'
host = 'localhost'
key_filepath = '/home/dustin/.ssh/id_dsa'
verbosity = 0

with SshSystem():
    with SshSession(user=user, host=host, verbosity=verbosity) as ssh:
        with SshConnect(ssh):
            logging.debug("Ready to authenticate.")

            def hostkey_gate(hk, would_accept):
                logging.debug("CB HK: %s" % (hk))
                logging.debug("CB Would Accept: %s" % (would_accept))
                
                return would_accept

            ssh.is_server_known(allow_new=True, cb=hostkey_gate)
            ssh.userauth_privatekey_file(None, key_filepath, None)

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

