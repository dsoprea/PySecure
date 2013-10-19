from pysecure import log_config
from pysecure.easy import connect_ssh_with_cb, connect_sftp_with_cb, \
                          get_key_auth_cb, get_password_auth_cb
from pysecure.test.test_config import user, host, key_filepath, verbosity

def connect_sftp_test(sftp_cb):
    print("Connecting SFTP with key: %s" % (key_filepath))
    auth_cb = get_key_auth_cb(key_filepath)
    connect_sftp_with_cb(sftp_cb, user, host, auth_cb, verbosity=verbosity)

def connect_ssh_test(ssh_cb):
    print("Connecting SSH with key: %s" % (key_filepath))
    auth_cb = get_key_auth_cb(key_filepath)
    connect_ssh_with_cb(ssh_cb, user, host, auth_cb, verbosity=verbosity)

