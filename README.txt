Introduction
============

This is a library that provides SSH and SFTP functionality from within Python,
using "libssh". Although libssh2 was considered, it appears that its SFTP 
functionality is slower (1).

This solution exists as an alternative to Paramiko. I love Paramiko, but as 
"libssh" is very complete and actively-maintained, it has a greater breadth of 
functionality, such as support for elliptic-curve encryption (recently added). 
It is also written in C and battle-hardened, therefore it's faster.

This project is in active development.


(1) http://daniel.haxx.se/blog/2010/12/05/re-evaluating-the-criticism/


Status
======

X SFTP functionality.
X Local port forwarding.
X Reverse port forwarding.
X Remote command (single commands).
X Remote execution (shell session).
  Threading support.
  Support X11 forwarding.
  Added SFTP "mirror" functionality.

Dependencies
============

> libssh


Common Setup Code for Examples
==============================

In the examples below, it is assumed that the following code exists above it:

    from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                       PublicKeyHash

    user = 'user'
    host = 'remote_hostname'
    key_filepath = '/home/user/.ssh/id_dsa'
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


SFTP Examples
=============

File resources are file-like objects that are similar to standard file objects. 
Calls will have traditional methods, as identified here: 
    
    http://docs.python.org/2/library/stdtypes.html#file-objects

List a directory:

    from pysecure.adapters.sftpa import SftpSession, SftpFile

    with SftpSession(ssh) as sftp:
        print("Name                         Size Perms    Owner\tGroup\n")
        for attributes in sftp.listdir('.'):
            print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
                  (attributes.name[0:40], attributes.size, 
                   attributes.permissions, attributes.owner, 
                   attributes.uid, attributes.group,
                   attributes.gid))

Recurse a directory:

    with SftpSession(ssh) as sftp:
        def dir_cb(path, entry):
            full_path = ('%s/%s' % (path, entry.name))
            print("DIR: %s" % (full_path))

        def listing_cb(path, list_):
            print("[%s]: (%d) files" % (path, len(list_)))

        sftp.recurse('Pictures', dir_cb, listing_cb)

Mirror a directory:

    sftp.mirror_to_local_recursive("remote_path", "/tmp/local_target")

Read a file:

    with SftpSession(ssh) as sftp:
        with SftpFile(sftp, 'text_file.txt') as sf:
            # Read through text-file, one line at a time.
        
            i = 0
            for data in sf:
                stdout.write("> " + data)
    
                if i >= 30:
                    break
    
                i += 1
    
        # To read a complete file (binary friendly). It could also be
        # read one chunk at a time.
    
        with SftpFile(sftp, 'binary_file.dat') as sf:
            buffer_ = sf.read()
    
            print("Read (%d) bytes." % (len(buffer_)))


Port-Forwarding Examples
========================

Local Forwarding:

    from pysecure.adapters.channela import SshChannel

    host_source = 'localhost'
    port_local = 1111
    host_remote = 'localhost'
    port_remote = 80

    data = "GET / HTTP/1.1\nHost: localhost\n\n"

    with SshChannel(ssh) as sc:
        # The following command activates forwarding, but does not bind any
        # ports. Although a "port_local" parameter is expected, this is 
        # allegedly for little more than logging. Binding is left as a concern
        # for the implementing developer.
        sc.open_forward(host_remote, port_remote, host_source, port_local)

        sc.write(data)

        received = sc.read(1024)
        print("Received:\n\n%s" % (received))

Reverse Forwarding:

        # This functionality starts with an SshSession. Therefore, an import of
        # SshChannel isn't necessary.

        server_address = None
        server_port = 8080
        accept_timeout_ms = 60000

        port = ssh.forward_listen(server_address, server_port)
        with ssh.forward_accept(accept_timeout_ms) as sc:
            while 1:
                data = sc.read(2048)
                if data == '':
                    continue

                # Do something with the data.
                response = "Received."

                sc.write(response)


Remote Execution
================

Remote Command (efficient for single command):

    This functionality can be used to execute one command at a time:

        data = ssh.execute('lsb_release -a')
        print(data)

        data = ssh.execute('whoami')
        print(data)

    Output:

        Distributor ID:	Ubuntu
        Description:	Ubuntu 13.04
        Release:	13.04
        Codename:	raring

        dustin

Remote Shell (efficient for many commands):

    Example:

        ssh.set_blocking(False)
        rsp = RemoteShellProcessor(ssh)
        
        def shell_context_cb(sc, welcome):
            output = rsp.do_command('cat /proc/uptime')
            print(output)

            output = rsp.do_command('whoami')
            print(output)
        
        rsp.shell(shell_context_cb)

    Output:

        $ PYTHONPATH=. test/example.py 
        631852.37 651773.95
        dustin
        $

