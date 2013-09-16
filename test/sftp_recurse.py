#!/usr/bin/env python2.7

from test_base import connect_sftp_test

def sftp_cb(ssh, sftp):
    def dir_cb(path, entry):
        full_path = ('%s/%s' % (path, entry.name))
        print("DIR: %s" % (full_path))

    def listing_cb(path, list_):
        print("[%s]: (%d) files" % (path, len(list_)))

    sftp.recurse('Pictures', dir_cb, listing_cb)

connect_sftp_test(sftp_cb)

