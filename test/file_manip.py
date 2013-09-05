#!/usr/bin/env python2.7

import logging

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
                test_data = '1234'

                with SftpFile(sftp, 'test_sftp_file', 'r+') as sf:
                    print("Position at top of file: %d" % (sf.tell()))

                    sf.write(test_data)
                    print("Position at bottom of file: %d" % (sf.tell()))

                    sf.seek(0)
                    print("Position at position (0): %d" % (sf.tell()))

                    buffer_ = sf.read(100)
                    print("Read: [%s]" % (buffer_))

                    print("Position after read: %d" % (sf.tell()))
                    sf.seek(0)

                    print("Position after rewind: %d" % (sf.tell()))

                    buffer_ = sf.read(100)
                    print("Read 1: (%d) bytes" % (len(buffer_)))
                    print("Position after read 1: %d" % (sf.tell()))

                    buffer_ = sf.read(100)
                    print("Read 2: (%d) bytes" % (len(buffer_)))
                    print("Position after read 2: %d" % (sf.tell()))

                    attr = sf.raw.fstat()
                    print(attr)

