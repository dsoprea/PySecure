#!/usr/bin/env python2.7

from pysecure.adapters.sftpa import SftpFile

from test_base import connect_sftp

def sftp_cb(ssh, sftp):
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

connect_sftp(sftp_cb)

