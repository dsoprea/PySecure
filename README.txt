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

    import logging

    from pysecure.constants import SSH_OPTIONS_USER, SSH_OPTIONS_HOST, \
                                   SSH_OPTIONS_LOG_VERBOSITY

    from pysecure.adapters.ssha import ssh_options_set_string, \
                                       ssh_options_set_uint, \
                                       ssh_is_server_known, \
                                       ssh_write_knownhost, \
                                       ssh_userauth_privatekey_file, SshSession, \
                                       SshConnect, SshSystem, PublicKeyHash

    from pysecure.adapters.sftpa import SftpSession, sftp_listdir

    user = 'dustin'
    host = 'remote_hostname'
    key_filepath = '/home/dustin/.ssh/id_dsa'
    verbosity = 1

    with SshSystem():
        with SshSession(user=user, host=host, verbosity=verbosity) as session:
            with SshConnect(session):
                logging.debug("Ready to authenticate.")

                def hostkey_gate(hk, would_accept):
                    logging.debug("CB HK: %s" % (hk))
                    logging.debug("CB Would Accept: %s" % (would_accept))

                    # would_accept indicates whether the host-key was to be 
                    # accepted prior to calling this callback. Return a final
                    # decision. This allows you to reference a blacklist/etc..
                    
                    return would_accept

                ssh_is_server_known(session, cb=hostkey_gate)
                ssh_userauth_privatekey_file(session, None, key_filepath, None)

                with SftpSession(session) as sftp:
                    print("Name                         Size Perms    Owner\tGroup\n")
                    for attributes in sftp_listdir(sftp, '.'):
                        print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
                              (attributes.name[0:40], attributes.size, 
                               attributes.permissions, attributes.owner, 
                               attributes.uid, attributes.group,
                               attributes.gid))

