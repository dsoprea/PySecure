#!/usr/bin/env python2.7

from test_base import connect_sftp_test

def sftp_cb(ssh, sftp):
    print("Name                         Size Perms    Owner\tGroup\n")
    for attributes in sftp.listdir('.'):
        print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
              (attributes.name[0:40], attributes.size, 
               attributes.permissions, attributes.owner, 
               attributes.uid, attributes.group, attributes.gid))

connect_sftp_test(sftp_cb)

