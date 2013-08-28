TIME_DATETIME_CONDENSED_FORMAT = '%Y%m%d-%H%M%S'
TIME_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

SERVER_RESPONSES = \
    { 0: ('SSH_FX_OK', 
          "No error."),
      1: ('SSH_FX_EOF', 
          "End-of-file encountered."),
      2: ('SSH_FX_NO_SUCH_FILE', 
          "File doesn't exist."),
      3: ('SSH_FX_PERMISSION_DENIED', 
          "Permission denied."),
      4: ('SSH_FX_FAILURE', 
          "Generic failure."),
      5: ('SSH_FX_BAD_MESSAGE', 
          "Garbage received from server."),
      6: ('SSH_FX_NO_CONNECTION', 
          "No connection has been set up."),
      7: ('SSH_FX_CONNECTION_LOST', 
          "There was a connection, but we lost it."),
      8: ('SSH_FX_OP_UNSUPPORTED', 
          "Operation not supported by the server."),
      9: ('SSH_FX_INVALID_HANDLE', 
          "Invalid file handle."),
      10: ('SSH_FX_NO_SUCH_PATH', 
           "No such file or directory path exists."),
      11: ('SSH_FX_FILE_ALREADY_EXISTS', 
           "An attempt to create an already existing file or "
           "directory has been made."),
      12: ('SSH_FX_WRITE_PROTECT', 
           "We are trying to write on a write-protected "
           "filesystem."),
      13: ('SSH_FX_NO_MEDIA', 
           "No media in remote drive.") }

