from unittest import TestCase

from pysecure.test.test_base import connect_sftp_test

class SftpLsTest(TestCase):
    def __sftp_cb(self, ssh, sftp):
#        print("Name                         Size Perms    Owner\tGroup\n")
        for attributes in sftp.listdir('.'):
#            print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
#                  (attributes.name[0:40], attributes.size, 
#                   attributes.permissions, attributes.owner, 
#                   attributes.uid, attributes.group, attributes.gid))
            pass

    def test_sftp_ls(self):
        connect_sftp_test(self.__sftp_cb)

