Introduction
============

This is a library that provides SSH and SFTP functionality from within Python,
using "libssh".

This solution exists as an alternative to Paramiko. I love Paramiko, but as 
"libssh" is very complete and actively-maintained, it has a greater breadth of 
functionality, such as support for elliptic-curve encryption (recently added). 
It is also written in C and battle-hardened, therefore it's faster.

This project is in active development. The documentation will be completed as
primary development approaches completion.


Status
======

> Shared-object interface functions (partially tested).

> Shared-object adapter functions (partially tested).
  > These wrap the interface functions, do parameter conversions, and translate 
    return values to exceptions.

X Wrote classes where necessary to ensure garbage collection of allocated 
  resources.
  X PublicKeyHash
  X EntryAttributes

X Wrote "with" support for all resources that have open/close semantics.
  X SshSystem
  X SshSession
  X SshConnect
  X SftpSession
  X SftpDirectory
  X SftpFile

X Complete proof of concept:
  X 1) Connect SSH
  X 2) Authenticate host.
  X 3) Authenticate user.
  X 4) Activate SFTP.
  X 5) List entries in default path.
  X 6) Display file-entry information for each.
  
> Finish testing remaining SFTP calls/adapters.


Dependencies
============

> libssl


Getting Started
===============

(Finish this.)


Examples
========

File resources are file-like objects that are similar to standard file objects, 
and allow writes. Calls will have traditional syntax, as identified here: 
    
    http://docs.python.org/2/library/stdtypes.html#file-objects

These are examples of how to list a directory and read files:

    import logging

    from pysecure.adapters.ssha import ssh_is_server_known, \
                                       ssh_write_knownhost, \
                                       ssh_userauth_privatekey_file, \
                                       SshSession, SshConnect, SshSystem, \
                                       PublicKeyHash

    from pysecure.adapters.sftpa import SftpSession, sftp_listdir

    user = 'dustin'
    host = 'remote_hostname'
    key_filepath = '/home/dustin/.ssh/id_dsa'
    verbosity = 1

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

                # List entries in home directory.

                print("Name                         Size Perms    Owner\tGroup\n")
                for attributes in sftp_listdir(sftp, '.'):
                    print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
                          (attributes.name[0:40], attributes.size, 
                           attributes.permissions, attributes.owner, 
                           attributes.uid, attributes.group,
                           attributes.gid))

                # To read a text file, line by line.

                with SftpSession(ssh) as sftp:
                    with SftpFile(sftp, 'text_file.txt') as sf:
                        i = 0
                        for data in sf:
                            stdout.write("> " + data)

                            if i >= 30:
                                break

                            i += 1

                # To read a complete file (binary friendly). It could also be
                # ready one chunk at a time.

                with SftpFile(sftp, 'binary_file.dat') as sf:
                    buffer_ = sf.read()

                    print("Read (%d) bytes." % (len(buffer_)))

