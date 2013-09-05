import logging

from ctypes import c_char_p, c_void_p, cast, c_uint32, c_int, \
                   create_string_buffer

from pysecure.constants.ssh import SSH_OK, SSH_ERROR, SSH_AGAIN
from pysecure.exceptions import SshError, SshNonblockingTryAgainException, \
                                SshNoDataReceivedException
from pysecure.calls.channeli import c_ssh_channel_new, \
                                    c_ssh_channel_open_forward, \
                                    c_ssh_channel_write, c_ssh_channel_free, \
                                    c_ssh_channel_read, \
                                    c_ssh_channel_send_eof, \
                                    c_ssh_channel_is_open


# ssh_channel ssh_channel_new(ssh_session session)
# int ssh_channel_open_forward(ssh_channel channel, const char *remotehost,int remoteport, const char *sourcehost, int localport)
# void ssh_channel_free(ssh_channel channel)
# int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len)

def _ssh_channel_new(ssh_session):
    result = c_ssh_channel_new(ssh_session)
    if result is None:
        raise SshError("Could not open channel.")

    return result

def _ssh_channel_open_forward(ssh_channel, host_remote, port_remote, host_source, port_local):
    result = c_ssh_channel_open_forward(ssh_channel, 
                                        c_char_p(host_remote), 
                                        c_int(port_remote), 
                                        c_char_p(host_source), 
                                        c_int(port_local))

    if result == SSH_AGAIN:
        raise SshNonblockingTryAgainException()
    elif result != SSH_OK:
        raise SshError("Forward failed.")

def _ssh_channel_write(ssh_channel, data):
    data_len = len(data)
    sent_bytes = c_ssh_channel_write(ssh_channel, 
                                     cast(c_char_p(data), c_void_p), 
                                     c_uint32(data_len))

    if sent_bytes == SSH_ERROR:
        raise SshError("Channel write failed.")
    elif sent_bytes != data_len:
        raise SshError("Channel write of (%d) bytes failed for length (%d) of "
                       "written data." % (data_len, sent_bytes))

def _ssh_channel_read(ssh_channel, count):
    """Do a read on a channel."""

    buffer_ = create_string_buffer(count)
    while 1:
        received_bytes = c_ssh_channel_read(ssh_channel, 
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

    logging.debug("(%d) bytes received." % (received_bytes))
# TODO: Where is the timeout configured for the read?
    return buffer_.raw[0:received_bytes]

def _ssh_channel_free(ssh_channel):
    c_ssh_channel_free(ssh_channel)

def _ssh_channel_send_eof(ssh_channel):
    result = c_ssh_channel_send_eof(ssh_channel)
    if result != SSH_OK:
        raise SshError("Could not send EOF.")

def _ssh_channel_is_open(ssh_channel):
    result = c_ssh_channel_is_open(ssh_channel)
    return (result == 0)


class SshChannel(object):
    def __init__(self, ssh_session, ssh_channel_int=None, eof_on_close=False):
        self.__ssh_session = ssh_session.session_id
        self.__ssh_channel_int = ssh_channel_int
        self.__eof_on_close = eof_on_close

    def __enter__(self):
        if self.__ssh_channel_int is None:
            self.__ssh_channel_int = _ssh_channel_new(self.__ssh_session)

        return self

    def __exit__(self, e_type, e_value, e_tb):
        if self.__eof_on_close is True:
            self.send_eof()

        _ssh_channel_free(self.__ssh_channel_int)

    def open_forward(self, host_remote, port_remote, host_source, port_local):
        _ssh_channel_open_forward(self.__ssh_channel_int, 
                                  host_remote, 
                                  port_remote, 
                                  host_source, 
                                  port_local)

    def write(self, data):
        _ssh_channel_write(self.__ssh_channel_int, data)

    def read(self, count, allow_empty=False):
        return _ssh_channel_read(self.__ssh_channel_int, count, allow_empty)

    def send_eof(self):
        return _ssh_channel_send_eof(self.__ssh_channel_int)

    def is_open(self):
        return _ssh_channel_is_open(self.__ssh_channel_int)

