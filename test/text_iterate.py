#!/usr/bin/env python2.7

import logging

from sys import stdout

from pysecure import log_config
from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash
from pysecure.adapters.sftpa import SftpSession, SftpFile

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

            with SftpSession(ssh) as sftp:
                with SftpFile(sftp, 'test_doc_rfc1958.txt') as sf:
                    i = 0
                    for data in sf:
                        stdout.write("> " + data)

                        if i >= 30:
                            break

                        i += 1

