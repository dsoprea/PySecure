import logging

from ctypes import c_char_p, c_void_p, c_ubyte, byref, cast, c_uint, \
                   c_int, c_long

from pysecure.exceptions import SshError, SshLoginError, SshHostKeyException, \
                                SshNonblockingTryAgainException, \
                                SshTimeoutException
from pysecure.config import DEFAULT_EXECUTE_READ_BLOCK_SIZE
from pysecure.types import c_ssh_key
from pysecure.constants.ssh import SSH_OK, SSH_ERROR, SSH_AGAIN, SSH_EOF, \
                                   \
                                   SSH_AUTH_ERROR, SSH_AUTH_DENIED, \
                                   SSH_AUTH_PARTIAL, SSH_AUTH_AGAIN, \
                                   SSH_AUTH_SUCCESS, \
                                   \
                                   SSH_SERVER_ERROR, SSH_SERVER_NOT_KNOWN, \
                                   SSH_SERVER_KNOWN_OK, \
                                   SSH_SERVER_KNOWN_CHANGED, \
                                   SSH_SERVER_FOUND_OTHER, SSH_OPTIONS, \
                                   SSH_SERVER_FILE_NOT_FOUND, \
                                   \
                                   SSH_CLOSED, \
                                   SSH_READ_PENDING, \
                                   SSH_WRITE_PENDING, \
                                   SSH_CLOSED_ERROR

from pysecure.calls.sshi import c_free, c_ssh_pki_import_privkey_file, \
                                c_ssh_write_knownhost, c_ssh_get_pubkey_hash, \
                                c_ssh_is_server_known, c_ssh_connect, \
                                c_ssh_disconnect, c_ssh_print_hexa, \
                                c_ssh_get_hexa, c_ssh_free, c_ssh_new, \
                                c_ssh_options_set, c_ssh_init, \
                                c_ssh_finalize, c_ssh_userauth_password, \
                                c_ssh_forward_listen, c_ssh_forward_accept, \
                                c_ssh_key_new, c_ssh_userauth_publickey, \
                                c_ssh_key_free, c_ssh_get_disconnect_message, \
                                c_ssh_get_issue_banner, \
                                c_ssh_get_openssh_version, c_ssh_get_status, \
                                c_ssh_get_version, c_ssh_get_serverbanner, \
                                c_ssh_disconnect, c_ssh_is_blocking, \
                                c_ssh_threads_get_noop, \
                                c_ssh_threads_set_callbacks, \
                                c_ssh_set_blocking 
#                                c_ssh_threads_init, c_ssh_threads_finalize, \
#                                c_ssh_threads_get_type


from pysecure.adapters.channela import SshChannel
from pysecure.error import ssh_get_error, ssh_get_error_code
from pysecure.utility import bytify, stringify

def _ssh_options_set_string(ssh_session, type_, value):
    assert issubclass(value.__class__, str)

    value_charp = c_char_p(bytify(value))

    result = c_ssh_options_set(c_void_p(ssh_session), 
                               c_int(type_), 
                               cast(value_charp, c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session)
        raise SshError("Could not set STRING option (%d) to [%s]: %s" % 
                       (type_, value, error))

def _ssh_options_set_uint(ssh_session, type_, value):
    value_uint = c_uint(value)
    result = c_ssh_options_set(c_void_p(ssh_session), 
                               c_int(type_), 
                               cast(byref(value_uint), c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session)
        raise SshError("Could not set UINT option (%d) to (%d): %s" % 
                       (type_, value, error))

def _ssh_options_set_int(ssh_session, type_, value):
    value_int = c_int(value)
    result = c_ssh_options_set(c_void_p(ssh_session), 
                               c_int(type_), 
                               cast(byref(value_int), c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session)
        raise SshError("Could not set INT option (%d) to (%d): %s" % 
                       (type_, value, error))

def _ssh_options_set_long(ssh_session, type_, value):
    value_long = c_long(value)
    result = c_ssh_options_set(c_void_p(ssh_session), 
                               c_int(type_), 
                               cast(byref(value_long), c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session)
        raise SshError("Could not set LONG option (%d) to (%d): %s" % 
                       (type_, value, error))

def _ssh_new():
    ssh_session = c_ssh_new()
    if ssh_session is None:
        raise SshError("Could not create session.")

    return ssh_session

def _ssh_free(ssh_session):
    c_ssh_free(c_void_p(ssh_session))

def _ssh_connect(ssh_session):
    result = c_ssh_connect(c_void_p(ssh_session))
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        error = ssh_get_error(ssh_session)
        raise SshError("Connect failed: %s" % (error))

def _ssh_disconnect(ssh_session):
    c_ssh_disconnect(c_void_p(ssh_session))

def _ssh_is_server_known(ssh_session, allow_new=False, cb=None):
    result = c_ssh_is_server_known(c_void_p(ssh_session))

    if result == SSH_SERVER_KNOWN_OK:
        if cb is not None:
            hk = repr(PublicKeyHash(ssh_session))
            allow_auth = cb(hk, True)
            
            logging.debug("Host-key callback returned [%s] when a host-key has "
                          "already been accepted." % (allow_auth))

            if allow_auth is False:
                raise SshHostKeyException("Existing host-key was failed by "
                                          "callback.")

        logging.debug("Server host-key authenticated.")
    
        return

    if result == SSH_SERVER_KNOWN_CHANGED:
        raise SshHostKeyException("Host key: Server has changed.")
    elif result == SSH_SERVER_FOUND_OTHER:
        raise SshHostKeyException("Host key: Server -type- has changed.")
    elif result == SSH_SERVER_FILE_NOT_FOUND or result == SSH_SERVER_NOT_KNOWN:
        logging.warn("Server is not already known.")
        if allow_new is False:
            if result == SSH_SERVER_FILE_NOT_FOUND:
                raise SshHostKeyException("Host key: The known-hosts file was "
                                          "not found, and we are not "
                                          "accepting new hosts.")

            raise SshHostKeyException("An existing host-key was not found. "
                                      "Our policy is to deny new hosts.")

        if cb is not None:
            hk = repr(PublicKeyHash(ssh_session))
            allow_auth = cb(hk, allow_new)
            
            logging.debug("Host-key callback returned [%s] when no host-key "
                          "yet available." % (allow_auth))
            
            if allow_auth is False:
                raise SshHostKeyException("New host-key was failed by "
                                          "callback.")

        logging.warn("Recording host-key for server.")
        c_ssh_write_knownhost(ssh_session)
    elif result == SSH_SERVER_ERROR:
        raise SshHostKeyException("Host key: Server error.")
    else:
        raise SshHostKeyException("Host key: Failed (unexpected error).")

def _ssh_print_hexa(title, hash_, hlen):
    assert issubclass(title.__class__, str)

    c_ssh_print_hexa(c_char_p(bytify(title)), hash_, c_int(hlen))

def _ssh_get_hexa(hash_, hlen):
    hexa = c_ssh_get_hexa(hash_, c_int(hlen))
    if hexa is None:
        raise SshError("Could not build hex-string.")

    return hexa

def _ssh_write_knownhost(ssh_session):
    logging.debug("Updating known-hosts file.")

    result = c_ssh_write_knownhost(c_void_p(ssh_session))
    if result != SSH_OK:
        error = ssh_get_error(ssh_session)
        raise SshError("Could not update known-hosts file: %s" % (error))

def _check_auth_response(result):
    if result == SSH_AUTH_ERROR:
        raise SshLoginError("Login failed: Auth error.")
    elif result == SSH_AUTH_DENIED:
        raise SshLoginError("Login failed: Auth denied.")
    elif result == SSH_AUTH_PARTIAL:
        raise SshLoginError("Login failed: Auth partial.")
    elif result == SSH_AUTH_AGAIN:
        raise SshLoginError("Login failed: Auth again.")
    elif result != SSH_AUTH_SUCCESS:
        raise SshLoginError("Login failed (unexpected error).")

def _ssh_userauth_password(ssh_session, username, password):
    if username is not None:
        assert issubclass(username.__class__, str)
    
    assert issubclass(password.__class__, str)

    logging.debug("Authenticating with a password for user [%s]." % (username))
    
    result = c_ssh_userauth_password(c_void_p(ssh_session), \
                                     c_char_p(bytify(username)), \
                                     c_char_p(bytify(password)))

    _check_auth_response(result)

def _ssh_init():
    result = c_ssh_init()
    if result < 0:
        raise SshError("Could not initialize SSH.")

def _ssh_finalize():
    result = c_ssh_finalize()
    if result < 0:
        raise SshError("Could not finalize SSH.")

def _ssh_forward_listen(ssh_session, address, port):
    if address is not None:
        assert issubclass(address.__class__, str)
        address = bytify(address)

    bound_port = c_int()
# BUG: Currently always returns SSH_AGAIN in 0.6.0 . Registered as bug #126.
    result = c_ssh_forward_listen(ssh_session, 
                                  address, 
                                  port, 
                                  byref(bound_port))

    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        error = ssh_get_error(ssh_session)
        raise SshError("Forward-listen failed: %s" % (error))

    return bound_port.value

def _ssh_forward_accept(ssh_session, timeout_ms):
    """Waiting for an incoming connection from a reverse forwarded port. Note
    that this results in a kernel block until a connection is received.
    """

    ssh_channel = c_ssh_forward_accept(c_void_p(ssh_session), 
                                       c_int(timeout_ms))

    if ssh_channel is None:
        raise SshTimeoutException()

    return ssh_channel

def _ssh_key_new():
    key = c_ssh_key_new()
    if key is None:
        raise SshError("Could not create empty key.")

    return key

def _ssh_userauth_publickey(ssh_session, priv_key):
    result = c_ssh_userauth_publickey(c_void_p(ssh_session), 
                                      None, 
                                      priv_key)

    _check_auth_response(result)

def ssh_pki_import_privkey_file(file_path, pass_phrase=None):
    assert issubclass(file_path.__class__, str)

    logging.debug("Importing private-key from [%s]." % (file_path))

    key = c_ssh_key()
# TODO: This needs to be freed. Use our key class.

    file_path = bytify(file_path)
    if pass_phrase is not None:
        assert issubclass(pass_phrase.__class__, str)
        pass_phrase = bytify(pass_phrase)
    
    result = c_ssh_pki_import_privkey_file(c_char_p(file_path), 
                                           c_char_p(pass_phrase), 
                                           None, 
                                           None, 
                                           byref(key))

    if result == SSH_EOF:
        raise SshError("Key file [%s] does not exist or could not be read." % 
                       (file_path))
    elif result != SSH_OK:
        raise SshError("Could not import key.")

    return key

def _ssh_is_blocking(ssh_session):
    result = c_ssh_is_blocking(c_void_p(ssh_session))
    return bool(result)

def _ssh_get_disconnect_message(ssh_session):
    message = c_ssh_get_disconnect_message(c_void_p(ssh_session))
    if message is None:
        return (ssh_get_error_code(ssh_session), True)

    return (message, False)

def _ssh_get_issue_banner(ssh_session):
    """Get the "issue banner" for the server. Note that this function may/will
    fail if the server isn't configured for such a message (like some/all
    Ubuntu installs). In the event of failure, we'll just return an empty 
    string.
    """

    message = c_ssh_get_issue_banner(c_void_p(ssh_session))
# TODO: Does "newly allocated" string have to be freed? We might have to reallocate it as a Python string.
    if message is None:
        return ''

    return stringify(message)

def _ssh_get_openssh_version(ssh_session):
    """Returns an encoded version. Comparisons can be done with the 
    SSH_INT_VERSION macro.
    """

    openssh_server_version = c_ssh_get_openssh_version(c_void_p(ssh_session))
    if openssh_server_version == 0:
        raise SshError("Could not get OpenSSH version. Server may not be "
                       "OpenSSH.")

    return openssh_server_version

def _ssh_get_status(ssh_session):
    result = c_ssh_get_status(c_void_p(ssh_session))

# TODO: This is returning bad flags (SSH_CLOSED_ERROR is True). Reported as bug 
#       #119.
    return { 'SSH_CLOSED': (result & SSH_CLOSED) > 0,
             'SSH_READ_PENDING': (result & SSH_READ_PENDING) > 0,
             'SSH_WRITE_PENDING': (result & SSH_WRITE_PENDING) > 0,
             'SSH_CLOSED_ERROR': (result & SSH_CLOSED_ERROR) > 0 }

def _ssh_get_version(ssh_session):
    protocol_version = c_ssh_get_version(ssh_session)
    if protocol_version < 0:
        raise SshError("Could not determine protocol version.")

    return protocol_version

def _ssh_get_serverbanner(ssh_session):
    result = c_ssh_get_serverbanner(c_void_p(ssh_session))
    if result is None:
        raise SshError("Could not get server-banner.")

    return result

def _ssh_disconnect(ssh_session):
    c_ssh_disconnect(c_void_p(ssh_session))

def ssh_threads_get_noop():
    return c_ssh_threads_get_noop()

def ssh_threads_set_callbacks(cb):
    result = c_ssh_threads_set_callbacks(c_void_p(cb))
    if result != SSH_OK:
        raise SshError("Could not set callbacks.")

def _ssh_set_blocking(ssh_session, blocking):
    c_ssh_set_blocking(c_void_p(ssh_session), c_int(blocking))


class SshSystem(object):
    def __enter__(self):
        return self.open()

    def open(self):
        logging.debug("Initializing SSH system.")
        _ssh_init()

    def __exit__(self, e_type, e_value, e_tb):
        self.close()

    def close(self):
        logging.debug("Cleaning-up SSH system.")
        _ssh_finalize

class SshSession(object):
    def __init__(self, **options):
        self.__options = options

        self.__ssh_session_ptr = _ssh_new()
        self.__log = logging.getLogger('SSH_SESSION(%d)' % 
                                       (self.__ssh_session_ptr))

        self.__log.debug("Created session.")


        if 'blocking' in options:
            self.set_blocking(options['blocking'])
            # SSH_OPTIONS doesn't contain blocking and will crash if it finds it
            del self.__options['blocking']

    def __enter__(self):
        return self.open()

    def open(self):
        for k, v in self.__options.items():
            (option_id, type_) = SSH_OPTIONS[k]
            
            if type_ == 'string':
                option_setter = _ssh_options_set_string
            elif type_ == 'uint':
                option_setter = _ssh_options_set_uint
            elif type_ == 'int':
                option_setter = _ssh_options_set_int
            elif type_ == 'long':
                option_setter = _ssh_options_set_long
            elif type_ == 'bool':
                v = 0 if v is False else 1
                option_setter = _ssh_options_set_int
            else:
                raise SshError("Option type [%s] is invalid." % (type_))
            
            self.__log.debug("Setting option [%s] (%d) to [%s]." % 
                             (k, option_id, v))

            option_setter(self.__ssh_session_ptr, option_id, v)

        return self

    def __exit__(self, e_type, e_value, e_tb):
        self.close()

    def close(self):
        # _ssh_free doesn't seem to imply a formal disconnect.
        self.disconnect()

        (message, is_error) = self.get_disconnect_message()
        self.__log.debug("Disconnect message: %s (error= %s)" % 
                         (message, is_error))

        self.__log.debug("Freeing SSH session: %d" % (self.__ssh_session_ptr))

        _ssh_free(self.__ssh_session_ptr)

    def forward_listen(self, address, port):
        return _ssh_forward_listen(self.__ssh_session_ptr, address, port)

    def forward_accept(self, timeout_ms):
        ssh_channel_int = _ssh_forward_accept(self.__ssh_session_ptr, \
                                              timeout_ms)

        return SshChannel(self, ssh_channel_int)

    def is_server_known(self, allow_new=False, cb=None):
        return _ssh_is_server_known(self.__ssh_session_ptr, allow_new, cb)

    def write_knownhost(self):
        return _ssh_write_knownhost(self.__ssh_session_ptr)

    def userauth_password(self, password):
        return _ssh_userauth_password(self.__ssh_session_ptr, None, password)

    def userauth_publickey(self, privkey):
        """This is the recommended function. Supports EC keys."""
    
        return _ssh_userauth_publickey(self.__ssh_session_ptr, privkey)

    def execute(self, cmd, block_size=DEFAULT_EXECUTE_READ_BLOCK_SIZE):
        """Execute a remote command. This functionality does not support more 
        than one command to be executed on the same channel, so we create a 
        dedicated channel at the session level than allowing direct access at
        the channel level.
        """
    
        with SshChannel(self) as sc:
            self.__log.debug("Executing command: %s" % (cmd))

            sc.open_session()
            sc.request_exec(cmd)

            buffer_ = bytearray()
            while 1:
                bytes = sc.read(block_size)
                yield bytes
                
                if len(bytes) < block_size:
                    break

    def is_blocking(self):
        return _ssh_is_blocking(self.__ssh_session_ptr)

    def set_blocking(self, blocking=True):
        _ssh_set_blocking(self.__ssh_session_ptr, blocking)

    def get_error_code(self):
        return ssh_get_error_code(self.__ssh_session_ptr)

    def get_error(self):
        return ssh_get_error(self.__ssh_session_ptr)

    def get_disconnect_message(self):
        return _ssh_get_disconnect_message(self.__ssh_session_ptr)

    def get_issue_banner(self):
        return _ssh_get_issue_banner(self.__ssh_session_ptr)

    def get_openssh_version(self):
        return _ssh_get_openssh_version(self.__ssh_session_ptr)

    def get_status(self):
        return _ssh_get_status(self.__ssh_session_ptr)

    def get_version(self):
        return _ssh_get_version(self.__ssh_session_ptr)

    def get_serverbanner(self):
        return _ssh_get_serverbanner(self.__ssh_session_ptr)

    def disconnect(self):
        return _ssh_disconnect(self.__ssh_session_ptr)

    @property
    def session_id(self):
        return self.__ssh_session_ptr


class SshConnect(object):
    def __init__(self, ssh_session):
        self.__ssh_session_ptr = getattr(ssh_session, 
                                         'session_id', 
                                         ssh_session)

    def __enter__(self):
        return self.open()

    def open(self):
        logging.debug("Connecting SSH.")
        _ssh_connect(self.__ssh_session_ptr)

    def __exit__(self, e_type, e_value, e_tb):
        self.close()
        
    def close(self):
        logging.debug("Disconnecting SSH.")
        _ssh_disconnect(self.__ssh_session_ptr)


class _PublicKeyHashString(object):
    def __init__(self, hash_, hlen):
        self.__hexa = _ssh_get_hexa(hash_, hlen)
        
    def __repr__(self):
        hexa_string = cast(self.__hexa, c_char_p)
# TODO: We do an empty concatenate just to ensure that we are making a copy.
        return hexa_string.value + ""

    def __del__(self):
        c_free(self.__hexa)


class PublicKeyHash(object):
    def __init__(self, ssh_session):
        ssh_session_int = getattr(ssh_session, 'session_id', ssh_session)
        self.__hasht = _ssh_get_pubkey_hash(ssh_session_int)
        
    def __del__(self):
        c_free(self.__hasht[0])

    def print_string(self, title="Public key"):
        _ssh_print_hexa(title, *self.__hasht)

    def __repr__(self):
        pks = _PublicKeyHashString(*self.__hasht)
        return repr(pks)

