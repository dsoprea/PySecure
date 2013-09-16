Introduction
============

This is a library that provides SSH and SFTP functionality from within Python,
using "libssh". Although libssh2 was considered, it appears that its SFTP 
functionality is slower (1).

This solution exists as an alternative to Paramiko. I love Paramiko, but as 
"libssh" is very complete and actively-maintained, it has a greater breadth of 
functionality, such as support for elliptic-curve encryption (recently added). 
It is also written in C.

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
  Support X11 forwarding (waiting on libssh).
X Added SFTP "mirror" functionality.


Dependencies
============

> libssh 0.6.0rc1


Installing
==========

Just expand, and make sure PYTHONPATH includes the directory.

NOTE: Though this project is on PyPI, it's -highly- recommended to use
      "easy_install" to get it, rather than "pip". The latter has the tendency
      to not get the latest version.


Logging
=======

To allow for standard logging to go out to the console, import 
"pysecure.log_config". 

To enable "debug" logging, set the environment variable
"DEBUG" to "1". 

To enable debug verbosity from the "libssh" library, pass the
"verbosity" argument into the connect_* functions with a value of True.


Common Setup Code for Examples
==============================

To make the examples more concise, some code has been removed, so as to not be 
repeated in every case.

A complete, working example using some included convenience functions would 
look like the following:

    from pysecure.easy import connect_ssh, connect_sftp, get_key_auth_cb

    user = 'dustin'
    host = 'localhost'
    key_filepath = '/home/dustin/.ssh/id_dsa'

    auth_cb = get_key_auth_cb(key_filepath)

    # For simple SSH functionality.

    def ssh_cb(ssh):
        # Main logic, here.
        pass

    connect_ssh(ssh_cb, user, host, auth_cb)

    # Or, for SFTP-enabled SSH functionality.

    def sftp_cb(ssh, sftp):
        # Main logic, here.
        pass

    connect_sftp(sftp_cb, user, host, auth_cb)


SFTP Examples
=============

File resources are file-like objects that are similar to standard file objects. 
Calls will have traditional methods, as identified here: 
    
    http://docs.python.org/2/library/stdtypes.html#file-objects

List a directory:

    from pysecure.adapters.sftpa import SftpFile

    print("Name                         Size Perms    Owner\tGroup\n")
    for attributes in sftp.listdir('.'):
        print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
              (attributes.name[0:40], attributes.size, 
               attributes.permissions, attributes.owner, 
               attributes.uid, attributes.group,
               attributes.gid))

Recurse a directory:

    def dir_cb(path, entry):
        full_path = ('%s/%s' % (path, entry.name))
        print("DIR: %s" % (full_path))

    def listing_cb(path, list_):
        print("[%s]: (%d) files" % (path, len(list_)))

    sftp.recurse('Pictures', dir_cb, listing_cb)

Read a file:

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

Mirroring:

    from pysecure.sftp_mirror import SftpMirror

    mirror = SftpMirror(sftp)

    # Mirror from server to local.
    mirror.mirror(mirror.mirror_to_local_no_recursion, 
                  "Pictures", 
                  "/tmp/Pictures")

    # Mirror from local to server.
    mirror.mirror(mirror.mirror_to_remote_no_recursion, 
                  "/home/dustin/Pictures", 
                  "/tmp/RemotePictures")

    Mirroring will ignore special (device) files. It also won't specially 
    handle hard-links.

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

