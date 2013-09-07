import logging

from ctypes import c_char_p, c_void_p, cast, c_uint32, c_int, \
                   create_string_buffer
from cStringIO import StringIO
from time import time

from pysecure.config import NONBLOCK_READ_TIMEOUT_MS, \
                            DEFAULT_SHELL_READ_BLOCK_SIZE
from pysecure.constants.ssh import SSH_OK, SSH_ERROR, SSH_AGAIN
from pysecure.exceptions import SshError, SshNonblockingTryAgainException, \
                                SshNoDataReceivedException
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
                                    c_ssh_channel_is_eof

def _ssh_channel_new(ssh_session_int):
    result = c_ssh_channel_new(ssh_session_int)
    if result is None:
        raise SshError("Could not open channel.")

    return result

def _ssh_channel_open_forward(ssh_channel_int, host_remote, port_remote, 
                              host_source, port_local):

    result = c_ssh_channel_open_forward(ssh_channel_int, 
                                        c_char_p(host_remote), 
                                        c_int(port_remote), 
                                        c_char_p(host_source), 
                                        c_int(port_local))

    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        raise SshError("Forward failed.")

def _ssh_channel_write(ssh_channel_int, data):
    data_len = len(data)
    sent_bytes = c_ssh_channel_write(ssh_channel_int, 
                                     cast(c_char_p(data), c_void_p), 
                                     c_uint32(data_len))

    if sent_bytes == SSH_ERROR:
        raise SshError("Channel write failed.")
    elif sent_bytes != data_len:
        raise SshError("Channel write of (%d) bytes failed for length (%d) of "
                       "written data." % (data_len, sent_bytes))

def _ssh_channel_read(ssh_channel_int, count):
    """Do a read on a channel."""

    buffer_ = create_string_buffer(count)
    while 1:
        received_bytes = c_ssh_channel_read(ssh_channel_int, 
                                            cast(buffer_, c_void_p), 
                                            c_uint32(count),
                                            0)

        if received_bytes == SSH_ERROR:
            raise SshError("Channel read failed.")

        # BUG: We're not using the nonblocking variant, but this can still 
        # return SSH_AGAIN due to that call's broken dependencies.
        elif received_bytes == SSH_AGAIN:
            continue

        else:
            break

# TODO: Where is the timeout configured for the read?
    return buffer_.raw[0:received_bytes]

def _ssh_channel_free(ssh_channel_int):
    c_ssh_channel_free(ssh_channel_int)

def _ssh_channel_send_eof(ssh_channel_int):
    result = c_ssh_channel_send_eof(ssh_channel_int)
    if result != SSH_OK:
        raise SshError("Could not send EOF.")

def _ssh_channel_is_open(ssh_channel_int):
    result = c_ssh_channel_is_open(ssh_channel_int)
    return (result != 0)

def _ssh_channel_open_session(ssh_channel):
    result = c_ssh_channel_open_session(ssh_channel)
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        raise SshError("Could not open session on channel.")

def _ssh_channel_request_exec(ssh_channel, cmd):
    result = c_ssh_channel_request_exec(ssh_channel, c_char_p(cmd))
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        raise SshError("Could not execute shell request on channel.")

def _ssh_channel_request_shell(ssh_channel):
    result = c_ssh_channel_request_shell(ssh_channel)
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        raise SshError("Shell request failed.")

def _ssh_channel_request_pty(ssh_channel):
    result = c_ssh_channel_request_pty(ssh_channel)
    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        raise SshError("PTY request failed.")

def _ssh_channel_change_pty_size(ssh_channel, col, row):
    result = c_ssh_channel_change_pty_size(ssh_channel, c_int(col), c_int(row))
    if result != SSH_OK:
        raise SshError("PTY size change failed.")

def _ssh_channel_is_eof(ssh_channel):
    result = c_ssh_channel_is_eof(ssh_channel)

    return bool(result)

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

    def open_forward(self, host_remote, port_remote, host_source, port_local):
        _ssh_channel_open_forward(self.__ssh_channel_int, 
                                  host_remote, 
                                  port_remote, 
                                  host_source, 
                                  port_local)

    def write(self, data):
        _ssh_channel_write(self.__ssh_channel_int, data)

    def read(self, count):
        return _ssh_channel_read(self.__ssh_channel_int, count)

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


class RemoteShellProcessor(object):
    def __init__(self, ssh_session, block_size=DEFAULT_SHELL_READ_BLOCK_SIZE):
        logging.debug("Initializing RSP.")

        if ssh_session.is_blocking() is True:
            raise Exception("RemoteShellProcessor requires a non-blocking "
                            "session.")

        self.__ssh_session = ssh_session
        self.__block_size = block_size

    def __wait_on_output(self, data_cb):

        start_at = time()
        while self.__sc.is_open() and self.__sc.is_eof() is False:
            try:
                buffer_ = self.__sc.read(self.__block_size)
            except SshNonblockingTryAgainException:
                buffer_ = ''

            if buffer_ == '':
                delta = time() - start_at
                if delta * 1000 > NONBLOCK_READ_TIMEOUT_MS:
                    break

                continue

            data_cb(buffer_)
            start_at = time()

    def __wait_on_output_all(self, whole_data_cb):

        received = StringIO()
        def data_cb(buffer_):
            received.write(buffer_)

        self.__wait_on_output(data_cb)
        whole_data_cb(received.getvalue())

    def do_command(self, command, block_cb=None, add_nl=True, 
                   drop_last_line=True, drop_first_line=True):
        logging.debug("Sending command: %s" % (command.rstrip()))

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
        logging.debug("Starting RSP shell.")

        with SshChannel(self.__ssh_session) as sc:
            sync(sc.open_session)
            sync(sc.request_pty)

            sc.change_pty_size(cols, rows)
            sync(sc.request_shell)

            welcome_stream = StringIO()
            def welcome_received_cb(data):
                welcome_stream.write(data)
            
            self.__sc = sc
            self.__wait_on_output_all(welcome_received_cb)
            welcome = welcome_stream.getvalue()

            logging.debug("RSP shell is ready.")

            ready_cb(sc, welcome)
            self.__sc = None

