class SftpException(Exception):
    pass
    
class SftpError(SftpException):
    pass

class SshException(Exception):
    pass

class SshError(SshException):
    pass

class SshLoginError(SshError):
    pass

class SshHostKeyException(SshException):
    pass

class SshNonblockingTryAgain(SshException):
    pass

