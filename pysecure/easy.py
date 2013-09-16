import logging

from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash, ssh_pki_import_privkey_file
from pysecure.adapters.sftpa import SftpSession, SftpFile

def connect_ssh(ssh_cb, user, host, auth_cb, allow_new=True, verbosity=0):
    with SshSystem():
        with SshSession(user=user, host=host, verbosity=verbosity) as ssh:
            with SshConnect(ssh):
                logging.debug("Ready to authenticate.")

                ssh.is_server_known(allow_new=allow_new)

                auth_cb(ssh)
                ssh_cb(ssh)

def connect_sftp(sftp_cb, *args, **kwargs):
    def ssh_cb(ssh):
        with SftpSession(ssh) as sftp:
            sftp_cb(ssh, sftp)

    connect_ssh(ssh_cb, *args, **kwargs)

def get_key_auth_cb(key_filepath):
    """This is just a convenience function."""

    def auth_cb(ssh):
        key = ssh_pki_import_privkey_file(key_filepath)
        ssh.userauth_publickey(key)

    return auth_cb

