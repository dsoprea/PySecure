import logging
import contextlib

from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash, ssh_pki_import_privkey_file
from pysecure.adapters.sftpa import SftpSession, SftpFile

@contextlib.contextmanager
def connect_ssh(user, host, auth_cb, allow_new=True, *args, **kwargs):
    with SshSystem():
        with SshSession(user=user, host=host, *args, **kwargs) as ssh:
            with SshConnect(ssh):
                logging.debug("Ready to authenticate.")

                ssh.is_server_known(allow_new=allow_new)

                auth_cb(ssh)
                yield ssh

def connect_ssh_with_cb(ssh_cb, user, host, auth_cb, allow_new=True, 
                        verbosity=0):
    """A "managed" SSH session. When the session is ready, we'll invoke the 
    "ssh_cb" callback.
    """

    with connect_ssh(user, host, auth_cb, allow_new=True, verbosity=0) as ssh:
        ssh_cb(ssh)

@contextlib.contextmanager
def _connect_sftp(ssh, *args, **kwargs):
    """A "managed" SFTP session. When the SSH session and an additional SFTP 
    session are ready, invoke the sftp_cb callback.
    """

    with SftpSession(ssh) as sftp:
        yield (ssh, sftp)

# TODO(dustin): Deprecate this call.
def connect_sftp_with_cb(sftp_cb, *args, **kwargs):
    """A "managed" SFTP session. When the SSH session and an additional SFTP 
    session are ready, invoke the sftp_cb callback.
    """

    with _connect_sftp(*args, **kwargs) as (ssh, sftp):
        sftp_cb(ssh, sftp)

def get_key_auth_cb(key_filepath):
    """This is just a convenience function for key-based login."""

    def auth_cb(ssh):
        key = ssh_pki_import_privkey_file(key_filepath)
        ssh.userauth_publickey(key)

    return auth_cb

def get_password_auth_cb(password):
    """This is just a convenience function for password-based login."""

    def auth_cb(ssh):
        ssh.userauth_password(password)

    return auth_cb

class EasySsh(object):
    """This class allows a connection to be opened and closed at two separate 
    points (as opposed to the callback methods, above).
    """

    def __init__(self, user, host, auth_cb, allow_new=True, **session_args):
        self.__user = user
        self.__host = host
        self.__auth_cb = auth_cb
        self.__allow_new = allow_new
        self.__session_args = session_args
        
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
        
        self.__ssh_session = SshSession(user=self.__user, host=self.__host, 
                                        **self.__session_args)
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
    def ssh(self):
        if self.__ssh_opened is False:
            raise Exception("Can not return an SSH session. A session is not "
                            "open.")
        
        return self.__ssh_session

    @property
    def sftp(self):
        if self.__sftp_opened is False:
            raise Exception("Can not return an SFTP session. A session is not "
                            "open.")
        
        return self.__sftp_session

