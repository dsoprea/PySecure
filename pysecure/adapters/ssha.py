import logging

from ctypes import c_char_p, c_void_p, c_ubyte, byref, POINTER, cast, c_uint, \
                   c_int
from cStringIO import StringIO

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
                                c_ssh_threads_set_callbacks
#                                c_ssh_threads_init, c_ssh_threads_finalize, \
#                                c_ssh_threads_get_type

#                                c_ssh_set_blocking, 


from pysecure.adapters.channela import SshChannel
from pysecure.error import ssh_get_error, ssh_get_error_code

def _ssh_options_set_string(ssh_session_int, type_, value):
    value_charp = c_char_p(value)

    result = c_ssh_options_set(ssh_session_int, 
                               c_int(type_), 
                               cast(value_charp, c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session_int)
        raise SshError("Could not set STRING option (%d) to [%s]: %s" % 
                       (type_, value, error))

def _ssh_options_set_uint(ssh_session_int, type_, value):
    value_uint = c_uint(value)
    result = c_ssh_options_set(ssh_session_int, 
                               c_int(type_), 
                               cast(byref(value_uint), c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session_int)
        raise SshError("Could not set UINT option (%d) to (%d): %s" % 
                       (type_, value, error))

def _ssh_options_set_int(ssh_session_int, type_, value):
    value_int = c_int(value)
    result = c_ssh_options_set(ssh_session_int, 
                               c_int(type_), 
                               cast(POINTER(value_int), c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session_int)
        raise SshError("Could not set INT option (%d) to (%d): %s" % 
                       (type_, value, error))

def _ssh_options_set_long(ssh_session_int, type_, value):
    value_long = c_long(value)
    result = c_ssh_options_set(ssh_session_int, 
                               c_int(type_), 
                               cast(POINTER(value_long), c_void_p))

    if result < 0:
        error = ssh_get_error(ssh_session_int)
        raise SshError("Could not set LONG option (%d) to (%d): %s" % 
                       (type_, value, error))

def _ssh_new():
    ssh_session_int = c_ssh_new()
    if ssh_session_int is None:
        raise SshError("Could not create session.")

    return ssh_session_int

def _ssh_free(ssh_session_int):
    c_ssh_free(ssh_session_int)

def _ssh_connect(ssh_session_int):
    result = c_ssh_connect(ssh_session_int)
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        error = ssh_get_error(ssh_session_int)
        raise SshError("Connect failed: %s" % (error))

def _ssh_disconnect(ssh_session_int):
    c_ssh_disconnect(ssh_session_int)

def _ssh_is_server_known(ssh_session_int, allow_new=False, cb=None):
    result = c_ssh_is_server_known(ssh_session_int)

    if result == SSH_SERVER_KNOWN_OK:
        if cb is not None:
            hk = repr(PublicKeyHash(ssh_session_int))
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
            hk = repr(PublicKeyHash(ssh_session_int))
            allow_auth = cb(hk, allow_new)
            
            logging.debug("Host-key callback returned [%s] when no host-key "
                          "yet available." % (allow_auth))
            
            if allow_auth is False:
                raise SshHostKeyException("New host-key was failed by "
                                          "callback.")

        logging.warn("Recording host-key for server.")
        c_ssh_write_knownhost(ssh_session_int)
    elif result == SSH_SERVER_ERROR:
        raise SshHostKeyException("Host key: Server error.")
    else:
        raise SshHostKeyException("Host key: Failed (unexpected error).")

def _ssh_print_hexa(title, hash_, hlen):
    c_ssh_print_hexa(c_char_p(title), hash_, hlen)

def _ssh_get_hexa(hash_, hlen):
    hexa = c_ssh_get_hexa(hash_, hlen)
    if hexa is None:
        raise SshError("Could not build hex-string.")

    return hexa

#def _ssh_get_pubkey_hash(ssh_session_int):
#    hash_ = POINTER(c_ubyte)()
#    hlen = c_ssh_get_pubkey_hash(ssh_session_int, byref(hash_))
#    if hlen < 0:
#        error = ssh_get_error(ssh_session_int)
#        raise SshError("Could not build public-key hash: %s" % 
#                       (ssh_session_int))
#
#    return (hash_, hlen)

def _ssh_write_knownhost(ssh_session_int):
    logging.debug("Updating known-hosts file.")

    result = c_ssh_write_knownhost(ssh_session_int)
    if result != SSH_OK:
        error = ssh_get_error(ssh_session_int)
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

def _ssh_userauth_password(ssh_session_int, username, password):
    logging.debug("Authenticating with a password for user [%s]." % (username))
    
    result = c_ssh_userauth_password(ssh_session_int, \
                                     c_char_p(username), \
                                     c_char_p(password))

    _check_auth_response(result)

def _ssh_userauth_privatekey_file(ssh_session_int, username, filepath, 
                                  passphrase=None):

    logging.debug("Authenticating with a private-key for user [%s]." % 
                  (username))

    result = c_ssh_userauth_privatekey_file(ssh_session_int, \
                                            c_char_p(username), \
                                            c_char_p(filepath), \
                                            c_char_p(passphrase))

    _check_auth_response(result)

    logging.debug("Private-key authenticated successfully.")

def _ssh_init():
    result = c_ssh_init()
    if result < 0:
        raise SshError("Could not initialize SSH.")

def _ssh_finalize():
    result = c_ssh_finalize()
    if result < 0:
        raise SshError("Could not finalize SSH.")

def _ssh_forward_listen(ssh_session_int, address, port):
    bound_port = c_int()
    result = c_ssh_forward_listen(ssh_session_int, 
                                  c_char_p(address), 
                                  port, 
                                  byref(bound_port))

    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        error = ssh_get_error(ssh_session_int)
        raise SshError("Forward-listen failed: %s" % (error))

    return bound_port.value

def _ssh_forward_accept(ssh_session_int, timeout_ms):
    """Waiting for an incoming connection from a reverse forwarded port. Note
    that this results in a kernel block until a connection is received.
    """

    # BUG: Due to a bug in libssh, the timeout will be doubled.
    timeout_ms /= 2

    ssh_channel = c_ssh_forward_accept(ssh_session_int, c_int(timeout_ms))
    if ssh_channel is None:
        raise SshTimeoutException()

    return ssh_channel

def _ssh_key_new():
    key = c_ssh_key_new()
    if key is None:
        raise SshError("Could not create empty key.")

    return key

def _ssh_userauth_publickey(ssh_session_int, username, priv_key):
    result = c_ssh_userauth_publickey(ssh_session_int, 
                                      c_char_p(username), 
                                      priv_key)

    _check_auth_response(result)

def ssh_pki_import_privkey_file(file_path, pass_phrase=None):
    logging.debug("Importing private-key from [%s]." % (file_path))

    key = c_ssh_key()
# TODO: This needs to be freed. Use our key class.
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


#def ssh_key_import_private(ssh_session_int, filename, passphrase=None):
#    key = ssh_key_new()
#    result = c_ssh_key_import_private(key,
#                                      ssh_session_int, 
#                                      c_char_p(filename), 
#                                      c_char_p(passphrase))
#
#    if result != SSH_OK:
#        error = ssh_get_error(ssh_session_int)
#        raise SshError("Could not import private-key from [%s]: %s" % 
#                       (filename, error))
#
#    return key

#def _ssh_set_blocking(ssh_session_int, blocking):
#    c_ssh_set_blocking(ssh_session_int, c_int(blocking))

def _ssh_is_blocking(ssh_session_int):
    result = c_ssh_is_blocking(ssh_session_int)
    return bool(result)

def _ssh_get_disconnect_message(ssh_session_int):
# TODO: This never seems to work because an actual disconnect doesn't seem to set its "closed" flag. Reported.
    message = c_ssh_get_disconnect_message(ssh_session_int)
    if message is None:
        return (ssh_get_error_code(ssh_session_int), True)

    return (message, False)

def _ssh_get_issue_banner(ssh_session_int):
    """Get the "issue banner" for the server. Note that this function may/will
    fail if the server isn't configured for such a message (like some/all
    Ubuntu installs). In the event of failure, we'll just return an empty 
    string.
    """

    message = c_ssh_get_issue_banner(ssh_session_int)
# TODO: Does "newly allocated" string have to be freed? We might have to reallocate it as a Python string.
    if message is None:
        return ''

    return message

def _ssh_get_openssh_version(ssh_session_int):
# TODO: This seems to return a bad version (an integer that doesn't seem to 
#       correlate to anything). Reported as bug #120.
    openssh_server_version = c_ssh_get_openssh_version(ssh_session_int)
    if openssh_server_version == 0:
        raise SshError("Could not get OpenSSH version. Server may not be "
                       "OpenSSH.")

    return openssh_server_version

def _ssh_get_status(ssh_session_int):
    result = c_ssh_get_status(ssh_session_int)

# TODO: This is returning bad flags (SSH_CLOSED_ERROR is True). Reported as bug 
#       #119.
    return { 'SSH_CLOSED': (result & SSH_CLOSED) > 0,
             'SSH_READ_PENDING': (result & SSH_READ_PENDING) > 0,
             'SSH_WRITE_PENDING': (result & SSH_WRITE_PENDING) > 0,
             'SSH_CLOSED_ERROR': (result & SSH_CLOSED_ERROR) > 0 }

def _ssh_get_version(ssh_session_int):
    protocol_version = c_ssh_get_version(ssh_session_int)
    if protocol_version < 0:
        raise SshError("Could not determine protocol version.")

    return protocol_version

def _ssh_get_serverbanner(ssh_session_int):
    result = c_ssh_get_serverbanner(ssh_session_int)
# TODO: The return type is not documented. Reported as bug #122.
    if result is None:
        raise SshError("Could not get server-banner.")

    return result

def _ssh_disconnect(ssh_session_int):
    c_ssh_disconnect(ssh_session_int)

def ssh_threads_get_noop():
    return c_ssh_threads_get_noop()

def ssh_threads_set_callbacks(cb):
    result = c_ssh_threads_set_callbacks(c_void_p(cb))
    if result != SSH_OK:
        error = ssh_get_error(ssh_session_int)
        raise SshError("Could not set callbacks: %s" % (error))

#def ssh_threads_init():
#    result = c_ssh_threads_init()
#    if result != SSH_OK:
#        error = ssh_get_error(ssh_session_int)
#        raise SshError("Could not initialize threads: %s" % (error))
#
#def ssh_threads_finalize():
#    c_ssh_threads_finalize()
#
#def ssh_threads_get_type():
#    type_string = c_ssh_threads_get_type()
#    if type_string is None:
#        raise SshError("Threads get-type returned empty.")


class SshSystem(object):
    def __enter__(self):
        logging.debug("Initializing SSH system.")
        _ssh_init()

    def __exit__(self, e_type, e_value, e_tb):
        logging.debug("Cleaning-up SSH system.")
        _ssh_finalize

class SshSession(object):
    def __init__(self, **options):#blocking=True,
        self.__options = options

        self.__ssh_session_int = _ssh_new()
        self.__log = logging.getLogger('SSH_SESSION(%d)' % 
                                       (self.__ssh_session_int))

        self.__log.debug("Created session.")

#        self.set_blocking(blocking)

    def __enter__(self):
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

            option_setter(self.__ssh_session_int, option_id, v)

        return self

    def __exit__(self, e_type, e_value, e_tb):
        # _ssh_free doesn't seem to imply a formal disconnect.
        self.disconnect()

#        (message, is_error) = self.get_disconnect_message()
#        self.__log.debug("Disconnect message: %s (error= %s)" % 
#                         (message, is_error))

        self.__log.debug("Freeing SSH session: %d" % (self.__ssh_session_int))

        _ssh_free(self.__ssh_session_int)

    def forward_listen(self, address, port):
        return _ssh_forward_listen(self.__ssh_session_int, address, port)

    def forward_accept(self, timeout_ms):
# TODO: The timeout is erroneously doubled in this call. Reported as bug #116.
        ssh_channel_int = _ssh_forward_accept(self.__ssh_session_int, \
                                              timeout_ms)

        return SshChannel(self, ssh_channel_int)

    def is_server_known(self, allow_new=False, cb=None):
        return _ssh_is_server_known(self.__ssh_session_int, allow_new, cb)

    def write_knownhost(self):
        return _ssh_write_knownhost(self.__ssh_session_int)

    def userauth_password(self, username, password):
        return _ssh_userauth_password(self.__ssh_session_int, username, password)

    def userauth_privatekey_file(self, username, filepath, passphrase=None):
        """This is the legacy function."""

        return _ssh_userauth_privatekey_file(self.__ssh_session_int, 
                                             username, 
                                             filepath, 
                                             passphrase)

    def userauth_publickey(self, username, privkey):
        """This is the recommended function. Supports EC keys."""
    
        return _ssh_userauth_publickey(self.__ssh_session_int, username, privkey)

    def execute(self, cmd, block_size=DEFAULT_EXECUTE_READ_BLOCK_SIZE):
        """Execute a remote command. This functionality does not support more 
        than one command to be executed on the same channel, so we create a 
        dedicated channel as the session level than allowing direct access at
        the channel level.
        """
    
        with SshChannel(self) as sc:
            self.__log.debug("Executing command: %s" % (cmd))

            sc.open_session()
            sc.request_exec(cmd)

            buffer_ = StringIO()
            while 1:
                bytes = sc.read(block_size)
                buffer_.write(bytes)
                
                if len(bytes) < block_size:
                    break

            return buffer_.getvalue()

#    def set_blocking(self, blocking):
#        _ssh_set_blocking(self.__ssh_session_int, int(blocking))

    def is_blocking(self):
        return _ssh_is_blocking(self.__ssh_session_int)

    def get_error_code(self):
        return ssh_get_error_code(self.__ssh_session_int)

    def get_error(self):
        return ssh_get_error(self.__ssh_session_int)

    def get_disconnect_message(self):
# TODO: This seems like it only may be useful under a sudden/spurious 
#       disconnect, and seems to always fail [otherwise?]. Reported as bug 
#       #121.
        return _ssh_get_disconnect_message(self.__ssh_session_int)

    def get_issue_banner(self):
        return _ssh_get_issue_banner(self.__ssh_session_int)

    def get_openssh_version(self):
        return _ssh_get_openssh_version(self.__ssh_session_int)

    def get_status(self):
        return _ssh_get_status(self.__ssh_session_int)

    def get_version(self):
        return _ssh_get_version(self.__ssh_session_int)

    def get_serverbanner(self):
        return _ssh_get_serverbanner(self.__ssh_session_int)

    def disconnect(self):
        return _ssh_disconnect(self.__ssh_session_int)

    @property
    def session_id(self):
        return self.__ssh_session_int


class SshConnect(object):
    def __init__(self, ssh_session):
        self.__ssh_session_int = getattr(ssh_session, 
                                         'session_id', 
                                         ssh_session)

    def __enter__(self):
        logging.debug("Connecting SSH.")
        _ssh_connect(self.__ssh_session_int)

    def __exit__(self, e_type, e_value, e_tb):
        logging.debug("Disconnecting SSH.")
        _ssh_disconnect(self.__ssh_session_int)



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

