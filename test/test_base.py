import logging

from pysecure import log_config
from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash, ssh_pki_import_privkey_file
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
                
                key = ssh_pki_import_privkey_file(key_filepath)
                ssh.userauth_publickey(user, key)
#                ssh.userauth_password(user, 'abc')

# TODO: Broken. Reported.
#                logging.debug("OpenSSH server version: %s" % (ssh.get_openssh_version()))
#                logging.debug("SSH session status: %s" % (ssh.get_status()))
#                logging.debug("Protocol version: %s" % (ssh.get_version()))
#                logging.debug("Server banner: %s" % (ssh.get_serverbanner()))

                ssh_cb(ssh)

def connect_sftp(sftp_cb):
    def ssh_cb(ssh):
        with SftpSession(ssh) as sftp:
            sftp_cb(ssh, sftp)

    connect_ssh(ssh_cb)

