import logging

from ctypes import c_char_p, c_void_p, cast, c_uint32, c_int, \
                   create_string_buffer
from cStringIO import StringIO
from time import time

from pysecure.config import NONBLOCK_READ_TIMEOUT_MS, \
                            DEFAULT_SHELL_READ_BLOCK_SIZE
from pysecure.constants.ssh import SSH_OK, SSH_ERROR, SSH_AGAIN
from pysecure.exceptions import SshError, SshNonblockingTryAgainException, \
                                SshNoDataReceivedException, SshTimeoutException
from pysecure.utility import sync
from pysecure.calls.channeli import c_ssh_channel_new, \
                                    c_ssh_channel_open_forward, \
                                    c_ssh_channel_write, c_ssh_channel_free, \
                                    c_ssh_channel_read, \
                                    c_ssh_channel_send_eof, \
                                    c_ssh_channel_is_open, \
                                    c_ssh_channel_open_session, \
                                    c_ssh_channel_request_exec, \
                                    c_ssh_channel_request_shell, \
                                    c_ssh_channel_request_pty, \
                                    c_ssh_channel_change_pty_size, \
                                    c_ssh_channel_is_eof, \
                                    c_ssh_channel_read_nonblocking, \
                                    c_ssh_channel_request_env, \
                                    c_ssh_channel_get_session, \
                                    c_ssh_channel_accept_x11, \
                                    c_ssh_channel_request_x11
                                    
from pysecure.error import ssh_get_error, ssh_get_error_code

def _ssh_channel_new(ssh_session_int):
    logging.debug("Opening channel on session.")

    result = c_ssh_channel_new(ssh_session_int)
    if result is None:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Could not open channel: %s" % (error))

    return result

def _ssh_channel_open_forward(ssh_channel_int, host_remote, port_remote, 
                              host_source, port_local):

    logging.debug("Requesting forward on channel.")

    result = c_ssh_channel_open_forward(ssh_channel_int, 
                                        c_char_p(host_remote), 
                                        c_int(port_remote), 
                                        c_char_p(host_source), 
                                        c_int(port_local))

    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Forward failed: %s" % (error))

def _ssh_channel_write(ssh_channel_int, data):
    data_len = len(data)
    sent_bytes = c_ssh_channel_write(ssh_channel_int, 
                                     cast(c_char_p(data), c_void_p), 
                                     c_uint32(data_len))

    if sent_bytes == SSH_ERROR:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Channel write failed: %s" % (error))
    elif sent_bytes != data_len:
        raise SshError("Channel write of (%d) bytes failed for length (%d) of "
                       "written data." % (data_len, sent_bytes))

def _ssh_channel_read(ssh_channel_int, count, is_stderr):
    """Do a read on a channel."""

    buffer_ = create_string_buffer(count)
    while 1:
        received_bytes = c_ssh_channel_read(ssh_channel_int, 
                                            cast(buffer_, c_void_p), 
                                            c_uint32(count),
                                            c_int(int(is_stderr)))

        if received_bytes == SSH_ERROR:
            ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
            error = ssh_get_error(ssh_session_int)

            raise SshError("Channel read failed: %s" % (error))

        # BUG: We're not using the nonblocking variant, but this can still 
        # return SSH_AGAIN due to that call's broken dependencies.
# TODO: This call might return SSH_AGAIN, even though we should always be 
#       blocking. Reported as bug #115.
        elif received_bytes == SSH_AGAIN:
            continue

        else:
            break

# TODO: Where is the timeout configured for the read?
    return buffer_.raw[0:received_bytes]

def _ssh_channel_read_nonblocking(ssh_channel_int, count, is_stderr):
    buffer_ = create_string_buffer(count)
    received_bytes = c_ssh_channel_read_nonblocking(ssh_channel_int, 
                                                    cast(buffer_, c_void_p), 
                                                    c_uint32(count),
                                                    c_int(int(is_stderr)))

    if received_bytes == SSH_ERROR:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Channel read (non-blocking) failed: %s" % (error))

    return buffer_.raw[0:received_bytes]

def _ssh_channel_free(ssh_channel_int):
    logging.debug("Freeing channel (%d)." % (ssh_channel_int))

    c_ssh_channel_free(ssh_channel_int)

def _ssh_channel_send_eof(ssh_channel_int):
    result = c_ssh_channel_send_eof(ssh_channel_int)
    if result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Could not send EOF: %s" % (error))

def _ssh_channel_is_open(ssh_channel_int):
    result = c_ssh_channel_is_open(ssh_channel_int)
    return (result != 0)

def _ssh_channel_open_session(ssh_channel_int):
    logging.debug("Request channel open-session.")

    result = c_ssh_channel_open_session(ssh_channel_int)
    elif result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Could not open session on channel: %s" % (error))

    logging.debug("Channel open-session successful.")

def _ssh_channel_request_exec(ssh_channel_int, cmd):
    logging.debug("Requesting channel exec.")

    result = c_ssh_channel_request_exec(ssh_channel_int, c_char_p(cmd))
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Could not execute shell request on channel: %s" % 
                       (error))

    logging.debug("Channel-exec successful.")

def _ssh_channel_request_shell(ssh_channel_int):
    logging.debug("Requesting channel shell.")

    result = c_ssh_channel_request_shell(ssh_channel_int)
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Shell request failed: %s" % (error))

    logging.debug("Channel-shell request successful.")

def _ssh_channel_request_pty(ssh_channel_int):
    logging.debug("Requesting channel PTY.")

    result = c_ssh_channel_request_pty(ssh_channel_int)
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("PTY request failed: %s" % (error))

    logging.debug("Channel PTY request successful.")

def _ssh_channel_change_pty_size(ssh_channel_int, col, row):
    result = c_ssh_channel_change_pty_size(ssh_channel_int, c_int(col), c_int(row))
    if result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("PTY size change failed: %s" % (error))

def _ssh_channel_is_eof(ssh_channel_int):
    result = c_ssh_channel_is_eof(ssh_channel_int)

    return bool(result)

def _ssh_channel_request_env(ssh_channel_int, name, value):
    logging.debug("Setting remote environment variable [%s] to [%s]." % 
                  (name, value))

# TODO: We haven't been able to get this to work. Reported bug #125.
    result = c_ssh_channel_request_env(ssh_channel_int, 
                                       c_char_p(name), 
                                       c_char_p(value))

    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Request-env failed: %s" % (error))

def _ssh_channel_get_session(ssh_channel_int):
    return c_ssh_channel_get_session(ssh_channel_int)

def _ssh_channel_accept_x11(ssh_channel_int, timeout_ms):
    ssh_channel_accepted = c_ssh_channel_accept_x11(ssh_channel_int, 
                                                    timeout_ms)

    if ssh_channel_accepted is None:
        raise SshTimeoutException()

    return ssh_channel_accept

def _ssh_channel_request_x11(ssh_channel_int, screen_number=0, 
                             single_connection=False, protocol=None, 
                             cookie=None):
    result = c_ssh_channel_request_x11(ssh_channel_int, int(single_connection), 
                                       c_char_p(protocol), c_char_p(cookie), 
                                       screen_number)

    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        ssh_session_int = _ssh_channel_get_session(ssh_channel_int)
        error = ssh_get_error(ssh_session_int)

        raise SshError("Channel request-X11 failed: %s" % (error))


class SshChannel(object):
    def __init__(self, ssh_session, ssh_channel=None):
        self.__ssh_session_int = getattr(ssh_session, 
                                         'session_id', 
                                         ssh_session)

        self.__ssh_channel_int = getattr(ssh_channel, 
                                         'session_id', 
                                         ssh_channel)

    def __enter__(self):
        if self.__ssh_channel_int is None:
            self.__ssh_channel_int = _ssh_channel_new(self.__ssh_session_int)

        return self

    def __exit__(self, e_type, e_value, e_tb):
        # The documentation says that a "free" implies a "close", and that a 
        # "close" implies a "send eof". From a cursory glance, this seems
        # accurate.
        _ssh_channel_free(self.__ssh_channel_int)
        self.__ssh_channel_int = None
    
    def __del__(self):
        # The documentation says that a "free" implies a "close", and that a 
        # "close" implies a "send eof". From a cursory glance, this seems
        # accurate.
        if self.__ssh_channel_int is not None:
            _ssh_channel_free(self.__ssh_channel_int)

    def open_forward(self, host_remote, port_remote, host_source, port_local):
        _ssh_channel_open_forward(self.__ssh_channel_int, 
                                  host_remote, 
                                  port_remote, 
                                  host_source, 
                                  port_local)

    def write(self, data):
        _ssh_channel_write(self.__ssh_channel_int, data)

    def read(self, count, is_stderr=False):
        return _ssh_channel_read(self.__ssh_channel_int, count, is_stderr)

    def read_nonblocking(self, count, is_stderr=False):
        return _ssh_channel_read_nonblocking(self.__ssh_channel_int, 
                                             count, 
                                             is_stderr)

    def send_eof(self):
        _ssh_channel_send_eof(self.__ssh_channel_int)

    def is_open(self):
        return _ssh_channel_is_open(self.__ssh_channel_int)

    def open_session(self):
        _ssh_channel_open_session(self.__ssh_channel_int)

    def request_exec(self, cmd):
        """Execute a command. Note that this can only be done once, and may be 
        the only operation performed with the current channel.
        """

        return _ssh_channel_request_exec(self.__ssh_channel_int, cmd)

    def request_shell(self):
        """Activate shell services on the channel (for PTY emulation)."""

        _ssh_channel_request_shell(self.__ssh_channel_int)

    def request_pty(self):
        _ssh_channel_request_pty(self.__ssh_channel_int)

    def change_pty_size(self, col, row):
        _ssh_channel_change_pty_size(self.__ssh_channel_int, col, row)

    def is_eof(self):
        return _ssh_channel_is_eof(self.__ssh_channel_int)
    
    def request_env(self, name, value):
        return _ssh_channel_request_env(self.__ssh_channel_int, name, value)

    def accept_x11(self, timeout_ms):
        ssh_x11_channel_int = _ssh_channel_accept_x11(self.__ssh_channel_int, 
                                                      timeout_ms)

        return SshChannel(self.__ssh_session_int, ssh_x11_channel_int)

    def request_x11(screen_number=0, single_connection=False, protocol=None,
                    cookie=None):
        return _ssh_channel_request_x11(self.__ssh_channel_int, screen_number, 
                                        single_connection, protocol, cookie)


class RemoteShellProcessor(object):
    def __init__(self, ssh_session, block_size=DEFAULT_SHELL_READ_BLOCK_SIZE):
        self.__log = logging.getLogger('RSP')
        self.__log.debug("Initializing RSP.")

        self.__ssh_session = ssh_session
        self.__block_size = block_size

    def __wait_on_output(self, data_cb):
        self.__log.debug("Reading chunked output.")

        start_at = time()
        while self.__sc.is_open() and self.__sc.is_eof() is False:
            buffer_ = self.__sc.read_nonblocking(self.__block_size)
            if buffer_ == '':
                delta = time() - start_at
                if delta * 1000 > NONBLOCK_READ_TIMEOUT_MS:
                    break

                continue

            data_cb(buffer_)
            start_at = time()

    def __wait_on_output_all(self, whole_data_cb):
        self.__log.debug("Reading complete output.")

        received = StringIO()
        def data_cb(buffer_):
            received.write(buffer_)

        self.__wait_on_output(data_cb)
        whole_data_cb(received.getvalue())

    def do_command(self, command, block_cb=None, add_nl=True, 
                   drop_last_line=True, drop_first_line=True):
        self.__log.debug("Sending command: %s" % (command.rstrip()))

        if add_nl is True:
            command += '\n'

        self.__sc.write(command)
        
        if block_cb is not None:
            self.__wait_on_output(block_cb)
        else:
            received_stream = StringIO()
            def data_cb(buffer_):
                received_stream.write(buffer_)
            
            self.__wait_on_output_all(data_cb)
            received = received_stream.getvalue()

            if drop_first_line is True:
                received = received[received.index('\n') + 1:]

            # In all likelihood, the last line is probably the prompt.
            if drop_last_line is True:
                received = received[:received.rindex('\n')]

            return received

    def shell(self, ready_cb, cols=80, rows=24):
        self.__log.debug("Starting RSP shell.")

        with SshChannel(self.__ssh_session) as sc:
            sc.open_session()

            sc.request_pty()
            sc.change_pty_size(cols, rows)
            sc.request_shell()

            welcome_stream = StringIO()
            def welcome_received_cb(data):
                welcome_stream.write(data)
            
            self.__sc = sc
            self.__wait_on_output_all(welcome_received_cb)
            welcome = welcome_stream.getvalue()

            self.__log.debug("RSP shell is ready.")

            ready_cb(sc, welcome)
            self.__sc = None

