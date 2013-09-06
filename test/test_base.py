import logging

from pysecure import log_config
from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash
from pysecure.adapters.sftpa import SftpSession, SftpFile

user = 'dustin'
host = 'localhost'
key_filepath = '/home/dustin/.ssh/id_dsa'
verbosity = 0

def connect_ssh(ssh_cb):
    with SshSystem():
        with SshSession(user=user, host=host, verbosity=verbosity) as ssh:
            with SshConnect(ssh):
                logging.debug("Ready to authenticate.")

                ssh.is_server_known(allow_new=True)
                ssh.userauth_privatekey_file(None, key_filepath, None)

                ssh_cb(ssh)

def connect_sftp(sftp_cb):
    def ssh_cb(ssh):
        with SftpSession(ssh) as sftp:
            sftp_cb(ssh, sftp)

    connect_ssh(ssh_cb)

