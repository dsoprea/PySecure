import logging

from ctypes import c_char_p, c_void_p, cast, c_uint32, c_int, \
                   create_string_buffer

from pysecure.constants.ssh import SSH_OK, SSH_ERROR, SSH_AGAIN
from pysecure.exceptions import SshError, SshNonblockingTryAgain
from pysecure.calls.channeli import c_ssh_channel_new, \
                                    c_ssh_channel_open_forward, \
                                    c_ssh_channel_write, c_ssh_channel_free, \
                                    c_ssh_channel_read

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
        raise SshNonblockingTryAgain()
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

def _ssh_channel_read(ssh_channel, count, allow_empty=False):
    """Do a read on a channel. "" might be returned in non-blocking mode, hence
    the "allow_empty" parameter.
    """

    buffer_ = create_string_buffer(count)
    received_bytes = c_ssh_channel_read(ssh_channel, 
                                        cast(buffer_, c_void_p), 
                                        c_uint32(count),
                                        0)

    if received_bytes == SSH_ERROR:
        raise SshError("Channel read failed.")
    elif received_bytes == 0 and allow_empty is False:
        raise SshError("No data received.")

    return buffer_.raw[0:received_bytes]

def _ssh_channel_free(ssh_channel):
    c_ssh_channel_free(ssh_channel)


class SshChannel(object):
    def __init__(self, ssh_session):
        self.__ssh_session = ssh_session

    def __enter__(self):
        self.__ssh_channel = _ssh_channel_new(self.__ssh_session)

        return self

    def __exit__(self, e_type, e_value, e_tb):
        _ssh_channel_free(self.__ssh_channel)

    def open_forward(self, host_remote, port_remote, host_source, port_local):
        _ssh_channel_open_forward(self.__ssh_channel, 
                                  host_remote, 
                                  port_remote, 
                                  host_source, 
                                  port_local)

    def write(self, data):
        _ssh_channel_write(self.__ssh_channel, data)

    def read(self, count, allow_empty=False):
        return _ssh_channel_read(self.__ssh_channel, count, allow_empty)

# TODO: Add support for reverse-forwarding.

