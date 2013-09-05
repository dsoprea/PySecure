#!/usr/bin/env python2.7

import logging

from pysecure import log_config
from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash
from pysecure.adapters.sftpa import SftpSession

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
                print("Name                         Size Perms    Owner\tGroup\n")
                for attributes in sftp.listdir('.'):
                    print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
                          (attributes.name[0:40], attributes.size, 
                           attributes.permissions, attributes.owner, 
                           attributes.uid, attributes.group, attributes.gid))

