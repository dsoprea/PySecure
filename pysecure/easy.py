import logging

from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash, ssh_pki_import_privkey_file
from pysecure.adapters.sftpa import SftpSession, SftpFile

def connect_ssh_with_cb(ssh_cb, user, host, auth_cb, allow_new=True, 
                        verbosity=0):
    """A "managed" SSH session. When the session is ready, we'll invoke the 
    "ssh_cb" callback.
    """

    with SshSystem():
        with SshSession(user=user, host=host, verbosity=verbosity) as ssh:
            with SshConnect(ssh):
                logging.debug("Ready to authenticate.")

                ssh.is_server_known(allow_new=allow_new)

                auth_cb(ssh)
                ssh_cb(ssh)

def connect_sftp_with_cb(sftp_cb, *args, **kwargs):
    """A "managed" SFTP session. When the SSH session and an additional SFTP 
    session are ready, invoke the sftp_cb callback.
    """

    def ssh_cb(ssh):
        with SftpSession(ssh) as sftp:
            sftp_cb(ssh, sftp)

    connect_ssh_with_cb(ssh_cb, *args, **kwargs)

def get_key_auth_cb(key_filepath):
    """This is just a convenience function."""

    def auth_cb(ssh):
        key = ssh_pki_import_privkey_file(key_filepath)
        ssh.userauth_publickey(key)

    return auth_cb

class EasySsh(object):
    """This class allows a connection to be opened and closed at two separate 
    points (as opposed to the callback methods, above).
    """

    def __init__(self, user, host, auth_cb, allow_new=True, verbosity=0):
        self.__user = user
        self.__host = host
        self.__auth_cb = auth_cb
        self.__allow_new = allow_new
        self.__verbosity = verbosity
        self.__log = logging.getLogger('EasySsh')

        self.__ssh_session = None
        self.__ssh_opened = False

        self.__sftp_session = None
        self.__sftp_opened = False

    def __del__(self):
        if self.__ssh_opened is True:
            self.close_ssh()

    def open_ssh(self):
        self.__log.debug("Opening SSH.")

        if self.__ssh_opened is True:
            raise Exception("Can not open SFTP session that is already open.")

# TODO: This might be required to only be run once, globally.
        self.__system = SshSystem()
        self.__system.open()
        
        self.__ssh_session = SshSession(user=self.__user, host=self.__host)
        self.__ssh_session.open()

        self.__connect = SshConnect(self.__ssh_session)
        self.__connect.open()
        
        self.__ssh_session.is_server_known(allow_new=self.__allow_new)
        self.__auth_cb(self.__ssh_session)

        self.__ssh_opened = True

    def close_ssh(self):    
        self.__log.debug("Closing SSH.")

        if self.__ssh_opened is False:
            raise Exception("Can not close SSH session that is not currently "
                            "opened.")

        if self.__sftp_opened is True:
            self.close_sftp()

        self.__connect.close()
        self.__ssh_session.close()
        self.__system.close()

        self.__ssh_session = None
        self.__ssh_opened = False

    def open_sftp(self):
        self.__log.debug("Opening SFTP.")

        if self.__sftp_opened is True:
            raise Exception("Can not open SFTP session that is already open.")
        
        self.__sftp_session = SftpSession(self.__ssh_session)
        self.__sftp_session.open()

        self.__sftp_opened = True
        
    def close_sftp(self):
        self.__log.debug("Closing SFTP.")

        if self.__sftp_opened is False:
            raise Exception("Can not close SFTP session that is not currently "
                            "opened.")

        self.__sftp_session.close()

        self.__sftp_session = None
        self.__sftp_opened = False

    @property
    def ssh_session(self):
        if self.__ssh_opened is False:
            raise Exception("Can not return an SSH session. A session is not "
                            "open.")
        
        return self.__ssh_session

    @property
    def sftp_session(self):
        if self.__sftp_opened is False:
            raise Exception("Can not return an SFTP session. A session is not "
                            "open.")
        
        return self.__sftp_session

