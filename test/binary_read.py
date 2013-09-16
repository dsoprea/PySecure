#!/usr/bin/env python2.7

from pysecure.adapters.sftpa import SftpFile

from test_base import connect_sftp_test

def sftp_cb(ssh, sftp):
    with SftpFile(sftp, 'test_libgksu2.so.0', 'r') as sf:
#                    buffer_ = sf.read(100)
        buffer_ = sf.read()

        with file('/tmp/sftp_dump', 'w') as f:
            f.write(buffer_)

        print("Read (%d) bytes." % (len(buffer_)))
#                    print("Read: [%s]" % (buffer_))



#                    print("Position at top of file: %d" % (sf.position))
#
#                    sf.write(test_data)
#                    print("Position at bottom of file: %d" % (sf.position))
#
#                    sf.seek(0)
#                    print("Position at position (0): %d" % (sf.position))
#
#                    buffer_ = sf.read(100)
#                    print("Read: [%s]" % (buffer_))
#
#                    print("Position after read: %d" % (sf.position))
#                    sf.rewind()
#
#                    print("Position after rewind: %d" % (sf.position))
#
#                    buffer_ = sf.read(100)
#                    print("Read 1: (%d) bytes" % (len(buffer_)))
#                    print("Position after read 1: %d" % (sf.position))
#
#                    buffer_ = sf.read(100)
#                    print("Read 2: (%d) bytes" % (len(buffer_)))
#                    print("Position after read 2: %d" % (sf.position))

connect_sftp_test(sftp_cb)

