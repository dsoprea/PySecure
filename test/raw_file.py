#!/usr/bin/env python2.7

import logging

from pysecure import log_config

from pysecure.constants.sftp import O_WRONLY, O_RDWR, O_CREAT
from pysecure.adapters.ssha import ssh_is_server_known, \
                                   ssh_write_knownhost, \
                                   ssh_userauth_privatekey_file, SshSession, \
                                   SshConnect, SshSystem, PublicKeyHash

from pysecure.adapters.sftpa import SftpSession, sftp_listdir, SftpFile

user = 'dustin'
host = 'dustinlost'
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

            ssh_is_server_known(ssh, allow_new=True, cb=hostkey_gate)
            ssh_userauth_privatekey_file(ssh, None, key_filepath, None)

            with SftpSession(ssh) as sftp:
                test_data = '1234'

                with SftpFile(sftp, 'test_sftp_file', O_RDWR|O_CREAT, 0o644) as sf:
                    print("Position at top of file: %d" % (sf.position))

                    sf.write(test_data)
                    print("Position at bottom of file: %d" % (sf.position))

                    sf.seek(0)
                    print("Position at position (0): %d" % (sf.position))

                    buffer_ = sf.read(100)
                    print("Read: [%s]" % (buffer_))

                    print("Position after read: %d" % (sf.position))
                    sf.rewind()

                    print("Position after rewind: %d" % (sf.position))

                    buffer_ = sf.read(100)
                    print("Read 1: (%d) bytes" % (len(buffer_)))
                    print("Position after read 1: %d" % (sf.position))

                    buffer_ = sf.read(100)
                    print("Read 2: (%d) bytes" % (len(buffer_)))
                    print("Position after read 2: %d" % (sf.position))

                    attr = sf.fstat()
                    print(attr)

