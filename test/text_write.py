#!/usr/bin/env python2.7

import logging

from pysecure import log_config

from pysecure.constants.sftp import O_WRONLY, O_RDWR, O_CREAT
from pysecure.adapters.ssha import ssh_is_server_known, \
                                   ssh_write_knownhost, \
                                   ssh_userauth_privatekey_file, SshSession, \
                                   SshConnect, SshSystem, PublicKeyHash

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

            ssh_is_server_known(ssh, allow_new=True, cb=hostkey_gate)
            ssh_userauth_privatekey_file(ssh, None, key_filepath, None)

            with SftpSession(ssh) as sftp:
                test_data = '1234'
                with SftpFile(sftp, 'sftp_write.txt', 'w') as sf:
                    sf.write(test_data)

