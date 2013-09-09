from pysecure.calls.sshi import c_ssh_get_error_code, c_ssh_get_error

def ssh_get_error_code(ssh_session_int):
    return c_ssh_get_error_code(ssh_session_int)

def ssh_get_error(ssh_session_int):
    return c_ssh_get_error(ssh_session_int)

