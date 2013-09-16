from pysecure import log_config
from pysecure.easy import connect_ssh, connect_sftp, get_key_auth_cb

user = 'dustin'
host = 'localhost'
key_filepath = '/home/dustin/.ssh/id_dsa'
verbosity = 0

def connect_sftp_test(sftp_cb):
    auth_cb = get_key_auth_cb(key_filepath)
    connect_sftp(sftp_cb, user, host, auth_cb, verbosity=verbosity)

def connect_ssh_test(ssh_cb):
    auth_cb = get_key_auth_cb(key_filepath)
    connect_ssh(ssh_cb, user, host, auth_cb, verbosity=verbosity)

