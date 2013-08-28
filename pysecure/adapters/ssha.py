import logging

from ctypes import c_char_p, c_void_p, c_ubyte, byref, POINTER, cast, c_uint, \
                   c_int

from pysecure.exceptions import SshError, SshLoginError, SshHostKeyException, \
                                SshNonblockingTryAgain
from pysecure.constants import SSH_OK, SSH_ERROR, SSH_AGAIN, SSH_AUTH_ERROR, \
                               SSH_AUTH_DENIED, SSH_AUTH_PARTIAL, \
                               SSH_AUTH_AGAIN, SSH_AUTH_SUCCESS, \
                               SSH_SERVER_KNOWN_CHANGED, \
                               SSH_SERVER_FOUND_OTHER, SSH_SERVER_NOT_KNOWN, \
                               SSH_SERVER_FILE_NOT_FOUND, SSH_SERVER_ERROR, \
                               SSH_SERVER_KNOWN_OK, SSH_OPTIONS

from pysecure.calls.sshi import c_free, c_ssh_userauth_privatekey_file, \
                                c_ssh_get_error_code, c_ssh_write_knownhost, \
                                c_ssh_get_pubkey_hash, c_ssh_is_server_known, \
                                c_ssh_connect, c_ssh_disconnect, \
                                c_ssh_print_hexa, c_ssh_get_hexa, c_ssh_free, \
                                c_ssh_new, c_ssh_options_set, c_ssh_init, \
                                c_ssh_finalize

def _ssh_options_set_string(ssh_session, type_, value):
    value_charp = c_char_p(value)

    result = c_ssh_options_set(ssh_session, 
                               c_int(type_), 
                               cast(value_charp, c_void_p))

    if result < 0:
        raise SshError("Could not set STRING option (%d) to [%s]." % 
                       (type_, value))

def _ssh_options_set_uint(ssh_session, type_, value):
    value_uint = c_uint(value)
    result = c_ssh_options_set(ssh_session, 
                               c_int(type_), 
                               cast(byref(value_uint), c_void_p))

    if result < 0:
        raise SshError("Could not set UINT option (%d) to (%d)." % 
                       (type_, value))

def _ssh_options_set_int(ssh_session, type_, value):
    value_int = c_int(value)
    result = c_ssh_options_set(ssh_session, 
                               c_int(type_), 
                               cast(POINTER(value_int), c_void_p))

    if result < 0:
        raise SshError("Could not set INT option (%d) to (%d)." % 
                       (type_, value))

def _ssh_options_set_long(ssh_session, type_, value):
    value_long = c_long(value)
    result = c_ssh_options_set(ssh_session, 
                               c_int(type_), 
                               cast(POINTER(value_long), c_void_p))

    if result < 0:
        raise SshError("Could not set LONG option (%d) to (%d)." % 
                       (type_, value))

def ssh_get_error_code(ssh_session):
    return c_ssh_get_error_code(ssh_session)

def _ssh_new():
    ssh_session = c_ssh_new()
    if ssh_session is None:
        raise SshError("Could not create session.")

    return ssh_session

def _ssh_free(ssh_session):
    c_ssh_free(ssh_session)

def _ssh_connect(ssh_session):
    result = c_ssh_connect(ssh_session)
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgain()
    elif result != SSH_OK:
        raise SshError("Connect failed.")

def _ssh_disconnect(ssh_session):
    c_ssh_disconnect(ssh_session)

def ssh_is_server_known(ssh_session, allow_new=False, cb=None):
    result = c_ssh_is_server_known(ssh_session)

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
            allow_auth = cb(hk, False)
            
            logging.debug("Host-key callback returned [%s] when no host-key "
                          "yet available." % (allow_auth))
            
            if allow_auth is False:
                raise SshHostKeyException("New host-key was failed by "
                                          "callback.")

        logging.warn("Recording host-key for server.")
        c_ssh_write_knownhost(ssh_session)

    elif result == SSH_SERVER_ERROR:
        raise SshHostKeyException("Host key: Server error.")
    elif result != SSH_SERVER_KNOWN_OK:
        raise SshHostKeyException("Host key: Failed (unexpected error).")
    else:
        if cb is not None:
            hk = repr(PublicKeyHash(ssh_session))
            allow_auth = cb(hk, True)
            
            logging.debug("Host-key callback returned [%s] when a host-key has "
                          "already been accepted." % (allow_auth))

            if allow_auth is False:
                raise SshHostKeyException("Existing host-key was failed by "
                                          "callback.")

        logging.debug("Server host-key authenticated.")

def _ssh_print_hexa(title, hash_, hlen):
    c_ssh_print_hexa(c_char_p(title), hash_, hlen)

def _ssh_get_hexa(hash_, hlen):
    hexa = c_ssh_get_hexa(hash_, hlen)
    if hexa is None:
        raise SshError("Could not build hex-string.")

    return hexa

def _ssh_get_pubkey_hash(ssh_session):
    hash_ = POINTER(c_ubyte)()
    hlen = c_ssh_get_pubkey_hash(ssh_session, byref(hash_))
    if hlen < 0:
        raise SshError("Could not build public-key hash.")

    return (hash_, hlen)

def ssh_write_knownhost(ssh_session):
    logging.debug("Updating known-hosts file.")

    result = c_ssh_write_knownhost(ssh_session)
    if result == SSH_ERROR:
        raise SshError("Could not update known-hosts file.")

def ssh_userauth_privatekey_file(ssh_session, username, filepath, passphrase=None):
    logging.debug("Authenticating with a private-key for user [%s]." % 
                  (username))

    result = c_ssh_userauth_privatekey_file(ssh_session, \
                                            c_char_p(username), \
                                            c_char_p(filepath), \
                                            c_char_p(passphrase))

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

    logging.debug("Private-key authenticated successfully.")

def _ssh_init():
    result = c_ssh_init()
    if result < 0:
        raise SshError("Could not initialize SSH.")

def _ssh_finalize():
    result = c_ssh_finalize()
    if result < 0:
        raise SshError("Could not finalize SSH.")


class SshSystem(object):
    def __enter__(self):
        _ssh_init()

    def __exit__(self, e_type, e_value, e_tb):
        _ssh_finalize


class SshSession(object):
    def __init__(self, **options):
        self.__options = options

    def __enter__(self):
        self.__ssh_session = _ssh_new()

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
            
            logging.debug("Setting option [%s] (%d) to [%s]." % 
                          (k, option_id, v))

            option_setter(self.__ssh_session, option_id, v)

        return self.__ssh_session

    def __exit__(self, e_type, e_value, e_tb):
        _ssh_free(self.__ssh_session)


class SshConnect(object):
    def __init__(self, ssh_session):
        self.__ssh_session = ssh_session

    def __enter__(self):
        _ssh_connect(self.__ssh_session)

    def __exit__(self, e_type, e_value, e_tb):
        _ssh_disconnect(self.__ssh_session)


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
        self.__hasht = _ssh_get_pubkey_hash(ssh_session)
        
    def __del__(self):
        c_free(self.__hasht[0])

    def print_string(self, title="Public key"):
        _ssh_print_hexa(title, *self.__hasht)

    def __repr__(self):
        pks = _PublicKeyHashString(*self.__hasht)
        return repr(pks)

