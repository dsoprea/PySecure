# ssh_server_known_e
SSH_SERVER_ERROR          = -1
SSH_SERVER_NOT_KNOWN      = 0
SSH_SERVER_KNOWN_OK       = 1
SSH_SERVER_KNOWN_CHANGED  = 2
SSH_SERVER_FOUND_OTHER    = 3
SSH_SERVER_FILE_NOT_FOUND = 4

# ssh_options_e
SSH_OPTIONS_HOST               = 0x0
SSH_OPTIONS_PORT               = 0x1
SSH_OPTIONS_PORT_STR           = 0x2
SSH_OPTIONS_FD                 = 0x3
SSH_OPTIONS_USER               = 0x4
SSH_OPTIONS_SSH_DIR            = 0x5
SSH_OPTIONS_IDENTITY           = 0x6
SSH_OPTIONS_ADD_IDENTITY       = 0x7
SSH_OPTIONS_KNOWNHOSTS         = 0x8
SSH_OPTIONS_TIMEOUT            = 0x9
SSH_OPTIONS_TIMEOUT_USEC       = 0xa
SSH_OPTIONS_SSH1               = 0xb
SSH_OPTIONS_SSH2               = 0xc
SSH_OPTIONS_LOG_VERBOSITY      = 0xd
SSH_OPTIONS_LOG_VERBOSITY_STR  = 0xe
SSH_OPTIONS_CIPHERS_C_S        = 0xf
SSH_OPTIONS_CIPHERS_S_C        = 0x10
SSH_OPTIONS_COMPRESSION_C_S    = 0x11
SSH_OPTIONS_COMPRESSION_S_C    = 0x12
SSH_OPTIONS_PROXYCOMMAND       = 0x13
SSH_OPTIONS_BINDADDR           = 0x14
SSH_OPTIONS_STRICTHOSTKEYCHECK = 0x15
SSH_OPTIONS_COMPRESSION        = 0x16
SSH_OPTIONS_COMPRESSION_LEVEL  = 0x17

_OT_STRING = 'string'
_OT_UINT = 'uint'
_OT_INT = 'int'
_OT_LONG = 'long'
_OT_BOOL = 'bool'

SSH_OPTIONS = { 'user':           (SSH_OPTIONS_USER, _OT_STRING),
                'host':           (SSH_OPTIONS_HOST, _OT_STRING),
                'verbosity':      (SSH_OPTIONS_LOG_VERBOSITY, _OT_UINT),
                'port':           (SSH_OPTIONS_PORT, _OT_UINT),
                'fd':             (SSH_OPTIONS_FD, _OT_INT),
                'ssh_dir':        (SSH_OPTIONS_SSH_DIR, _OT_STRING),
                'identity':       (SSH_OPTIONS_IDENTITY, _OT_STRING),
                'add_identity':   (SSH_OPTIONS_ADD_IDENTITY, None),
                'knownhosts':     (SSH_OPTIONS_KNOWNHOSTS, _OT_STRING),
                'timeout':        (SSH_OPTIONS_TIMEOUT, _OT_LONG),
                'timeout_usec':   (SSH_OPTIONS_TIMEOUT_USEC, _OT_LONG),
                'ssh1':           (SSH_OPTIONS_SSH1, _OT_BOOL),
                'ssh2':           (SSH_OPTIONS_SSH2, _OT_BOOL),
                'cipherscs':      (SSH_OPTIONS_CIPHERS_C_S, _OT_STRING),
                'cipherssc':      (SSH_OPTIONS_CIPHERS_S_C, _OT_STRING),
                'compresscs':     (SSH_OPTIONS_COMPRESSION_C_S, _OT_STRING),
                'compresssc':     (SSH_OPTIONS_COMPRESSION_S_C, _OT_STRING),
                'proxycmd':       (SSH_OPTIONS_PROXYCOMMAND, _OT_STRING),
                'bindaddr':       (SSH_OPTIONS_BINDADDR, _OT_STRING),
                'stricthostkeys': (SSH_OPTIONS_STRICTHOSTKEYCHECK, _OT_BOOL),
                'compression':    (SSH_OPTIONS_COMPRESSION, _OT_STRING),
                'compression_n':  (SSH_OPTIONS_COMPRESSION_LEVEL, _OT_INT) }

# ssh_auth_e
SSH_AUTH_ERROR   = -1
SSH_AUTH_SUCCESS = 0
SSH_AUTH_DENIED  = 1
SSH_AUTH_PARTIAL = 2
SSH_AUTH_INFO    = 3
SSH_AUTH_AGAIN   = 4

# Return codes.
SSH_OK    = 0
SSH_ERROR = -1
SSH_AGAIN = -2
SSH_EOF   = -127

# ssh_error_types_e
SSH_NO_ERROR       = 0
SSH_REQUEST_DENIED = 1
SSH_FATAL          = 2
SSH_EINTR          = 3

# Status flags.
SSH_CLOSED        = 0x01
SSH_READ_PENDING  = 0x02
SSH_WRITE_PENDING = 0x04
SSH_CLOSED_ERROR  = 0x08

