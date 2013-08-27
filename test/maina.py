#!/usr/bin/python

import logging

from pysecure import log_config

from sys import exit
from ctypes import *

from pysecure.constants import SSH_OPTIONS_USER, SSH_OPTIONS_HOST, \
                               SSH_OPTIONS_LOG_VERBOSITY, \
                               SSH_SERVER_KNOWN_OK, SSH_SERVER_KNOWN_CHANGED, \
                               SSH_SERVER_FOUND_OTHER, \
                               SSH_SERVER_FILE_NOT_FOUND, \
                               SSH_SERVER_NOT_KNOWN, SSH_SERVER_ERROR

#ssh_get_pubkey_hash, \
#ssh_get_hexa, \
#free, \
#strerror, 
#ssh_get_error, \
from pysecure.adapters.ssha import ssh_options_set_string, \
                                   ssh_options_set_uint, \
                                   ssh_is_server_known, \
                                   ssh_write_knownhost, \
                                   ssh_userauth_privatekey_file, SshSession, \
                                   SshConnect, SshSystem

from pysecure.adapters.sftpa import sftp_init, SftpSession, sftp_listdir

user = 'dustin'
host = 'dustinplex'
key_filepath = '/home/dustin/.ssh/id_dsa'
verbosity = 0

with SshSystem():
    with SshSession() as session:
        ssh_options_set_string(session, SSH_OPTIONS_USER, user)
        ssh_options_set_string(session, SSH_OPTIONS_HOST, host)
        ssh_options_set_uint(session, SSH_OPTIONS_LOG_VERBOSITY, verbosity)
        
        with SshConnect(session):
            logging.debug("Ready to authenticate.")

            ssh_is_server_known(session, True)
            ssh_userauth_privatekey_file(session, None, key_filepath, None)

            with SftpSession(session) as sftp:
                sftp_init(sftp)

                print("Name                         Size Perms    Owner\tGroup\n")
                for attributes in sftp_listdir(sftp, '.'):
                    print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
                          (attributes.name[0:40], attributes.size, 
                           attributes.permissions,
                           attributes.owner, attributes.uid, attributes.group,
                           attributes.gid))

