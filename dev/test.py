#!/usr/bin/env python2.7

import sys
sys.path.insert(0, '..')

from pysecure.adapters.sftpa import SftpFile

from pysecure.easy import connect_sftp_with_cb, get_key_auth_cb

user = 'dustin'
host = 'dustinbookend'
key_filepath = '/Users/dustin/.ssh/id_dsa'

auth_cb = get_key_auth_cb(key_filepath)

# Or, for SFTP-enabled SSH functionality.

def sftp_cb(ssh, sftp):
    print("Name                         Size Perms    Owner\tGroup\n")
    for attributes in sftp.listdir('.'):
        print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
              (attributes.name[0:40], attributes.size, 
               attributes.permissions, attributes.owner, 
               attributes.uid, attributes.group,
               attributes.gid))

connect_sftp_with_cb(sftp_cb, user, host, auth_cb)
