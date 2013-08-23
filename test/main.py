#!/usr/bin/python

from sys import exit
from ctypes import *

from pysecure.constants import SSH_OPTIONS_USER, SSH_OPTIONS_HOST, \
                               SSH_OPTIONS_LOG_VERBOSITY, \
                               SSH_SERVER_KNOWN_OK, SSH_SERVER_KNOWN_CHANGED, \
                               SSH_SERVER_FOUND_OTHER, \
                               SSH_SERVER_FILE_NOT_FOUND, \
                               SSH_SERVER_NOT_KNOWN, SSH_SERVER_ERROR, \
                               SSH_AUTH_SUCCESS, SSH_AUTH_ERROR, \
                               SSH_AUTH_DENIED, SSH_AUTH_PARTIAL, \
                               SSH_AUTH_AGAIN, SSH_ERROR, SSH_OK

from pysecure.calls_ssh import c_ssh_new, c_ssh_options_set, c_ssh_free, \
                           c_ssh_connect, c_ssh_is_server_known, \
                           c_ssh_get_pubkey_hash, c_ssh_get_hexa, \
                           c_ssh_write_knownhost, c_free, c_strerror, \
                           c_ssh_get_error, c_ssh_userauth_privatekey_file, \
                           c_ssh_disconnect

from pysecure.calls_sftp import c_sftp_new, c_sftp_init, c_sftp_get_error, \
                           c_sftp_free, c_sftp_opendir, c_sftp_readdir, \
                           c_sftp_attributes_free, c_sftp_dir_eof, \
                           c_sftp_closedir

def sftp_list_dir(session, sftp):
    null_ptr = POINTER(c_int)()

    dir = c_sftp_opendir(sftp, '.')
    if not dir:
        print("Directory not opened: %s\n" % (c_ssh_get_error(session)))
        return SSH_ERROR

    print("Name                         Size Perms    Owner\tGroup\n")
    while 1:
        attributes_raw = c_sftp_readdir(sftp, dir)

        if not attributes_raw:
            break
    
        attributes = attributes_raw.contents
    
        print("%-40s %10d %.8o %s(%d)\t%s(%d)" % 
              (attributes.name[0:40], attributes.size, attributes.permissions,
               attributes.owner, attributes.uid, attributes.group,
               attributes.gid))

        c_sftp_attributes_free(attributes_raw)

    if not c_sftp_dir_eof(dir):
        print("Can't list directory: %s" % (c_ssh_get_error(session)))
        c_sftp_closedir(dir)
        return SSH_ERROR

    rc = c_sftp_closedir(dir)
    if rc != SSH_OK:
        print("Can't close directory: %s" % (c_ssh_get_error(session)))
        return rc

def sftp_helloworld(session):
    sftp = c_sftp_new(session)
    if sftp is None:
        print("Error allocating SFTP session: %s" % (c_ssh_get_error(session)))
        return SSH_ERROR

    rc = c_sftp_init(sftp)
    if rc != SSH_OK:
        fprintf(stderr, "Error initializing SFTP session: %d\n", c_sftp_get_error(sftp))
        c_sftp_free(sftp)
        return rc

    print("Ready for SFTP.")

    sftp_list_dir(session, sftp)

    c_sftp_free(sftp)
    return SSH_OK

def verify_knownhost(session, allow_new):
    state = c_ssh_is_server_known(session)

    hash = POINTER(c_ubyte)()
    hlen = c_ssh_get_pubkey_hash(session, byref(hash))

    if hlen < 0:
        return -1;

    is_error = False

    if state == SSH_SERVER_KNOWN_OK:
        print("The server has been authenticated against an existing host-key.")
    elif state == SSH_SERVER_KNOWN_CHANGED:
        print("Host key for server changed: it is now:")

        c_ssh_print_hexa("Public key hash", hash, hlen)
        print("For security reasons, connection will be stopped")

        is_error = True

    elif state == SSH_SERVER_FOUND_OTHER:
        print("The host key for this server was not found but an other type "
              "of key exists.")
        print("An attacker might change the default server key to confuse "
              "your client into thinking the key does not exist")

        is_error = True

    elif state == SSH_SERVER_FILE_NOT_FOUND or state == SSH_SERVER_NOT_KNOWN:
        print("Could not find known host file.")
        
        if state == SSH_SERVER_FILE_NOT_FOUND:
            if allow_new == 0:
                print("Since we will not accept new hosts, it will not be created.")
                
                is_error = True
            else:
                print("It will be created.")

        if state == SSH_SERVER_NOT_KNOWN:
            print("The server is unknown.")
        
        hexa = c_ssh_get_hexa(hash, hlen)
        hexa_string = cast(hexa, c_char_p)
        print("Public key hash: %s" % (hexa_string.value))
        c_free(hexa)

        if allow_new == 0:
            print("An existing host-key was not found. Our policy is to deny new hosts.")
            is_error = True
        else:
            print("An existing host-key was not found. Adding new host.")
        
            if c_ssh_write_knownhost(session) < 0:
                print("Error writing known-hosts file.")
                is_error = True

    elif state == SSH_SERVER_ERROR:
        print("SS server error: %s" % (c_ssh_get_error(session)))
        is_error = True

    c_free(hash);

    if is_error:
        return -1

    return 0

user = c_char_p('dustin')
host = c_char_p('dustinplex')
key_filepath = c_char_p('/home/dustin/.ssh/id_dsa')

verbosity = POINTER(c_int)()
#verbosity.contents = c_int(1)
verbosity.contents = c_int(0)

session = c_ssh_new()
if session is None:
    print("Could not create SSH session.")
    exit(1)

if c_ssh_options_set(session, SSH_OPTIONS_USER, user) < 0:
    c_ssh_free(session)
    exit(2)

if c_ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0:
    c_ssh_free(session)
    exit(3)

if c_ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, cast(verbosity, c_void_p)) < 0:
    c_ssh_free(session)
    exit(4)

if c_ssh_connect(session) > 0:
    c_ssh_free(session)
    exit(5)

print("Ready to authenticate.")

verify_knownhost(session, True)

result = c_ssh_userauth_privatekey_file(session, None, key_filepath, None)
print("Return from auth.")

if result != SSH_AUTH_SUCCESS:
    c_ssh_disconnect(session);
    c_ssh_free(session);

    if result == SSH_AUTH_ERROR:
        print("Login failed: auth error")
    elif result == SSH_AUTH_DENIED:
        print("Login failed: auth denied")
    elif result == SSH_AUTH_PARTIAL:
        print("Login failed: auth partial")
    elif result == SSH_AUTH_AGAIN:
        print("Login failed: auth again")

    exit(6)

print("Authenticated.")

sftp_helloworld(session)

c_ssh_disconnect(session);
c_ssh_free(session)

