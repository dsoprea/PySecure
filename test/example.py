#!/usr/bin/env python2.7

import logging

from pysecure import log_config

from pysecure.constants.sftp import O_WRONLY, O_RDWR, O_CREAT
from pysecure.adapters.ssha import SshSession, SshConnect, SshSystem, \
                                   PublicKeyHash
from pysecure.adapters.channela import SshChannel
from pysecure.exceptions import SshNoDataReceivedException, \
                                SshNonblockingTryAgainException

user = 'dustin'
host = 'localhost'
key_filepath = '/home/dustin/.ssh/id_dsa'
verbosity = 0

with SshSystem():
    with SshSession(user=user, host=host, verbosity=verbosity) as ssh:
        with SshConnect(ssh):
            logging.debug("Ready to authenticate.")

            def hostkey_gate(hk, would_accept):
                logging.debug("CB HK: %s" % (hk))
                logging.debug("CB Would Accept: %s" % (would_accept))
                
                return would_accept

            ssh.is_server_known(allow_new=True, cb=hostkey_gate)
            ssh.userauth_privatekey_file(None, key_filepath, None)

            def build_body(status_code, status_string, content):
                replacements = { 'scode': status_code,
                                 'sstring': status_string,
                                 'length': len(content),
                                 'content': content }

                return """HTTP/1.1 %(scode)d %(sstring)s
Content-Type: text/html
Content-Length: %(length)d

%(content)s""" % replacements

            response_helloworld = build_body(200, 'OK', """<html>
  <head>
    <title>Hello, World!</title>
  </head>
  <body>
    <h1>Hello, World!</h1>
  </body>
</html>
""")

            response_notfound = build_body(404, 'Not found', """<html>
  <head>
    <title>Not Found</title>
  </head>
  <body>
    <h1>Resource not found.</h1>
  </body>
</html>
""")

            response_error = build_body(500, 'Server error', """<html>
  <head>
    <title>Server Error</title>
  </head>
  <body>
    <h1>There was a server failure.</h1>
  </body>
</html>
""")

            server_address = None
            server_port = 8080
            accept_timeout_ms = 60000

            port = ssh.forward_listen(server_address, server_port)
            with ssh.forward_accept(accept_timeout_ms) as sc:
                while 1:
                    buffer_ = sc.read(2048)
                    if buffer_ == '':
                        continue

                    try:
                        nl_index = buffer_.index('\n')
                    except ValueError:
                        print("Error with:\n%s" % (len(buffer_)))
                        payload = response_error
                    else:
                        request_line = buffer_[:nl_index]

                        if request_line[:6] == 'GET / ':
                            print("Responding: %s" % (request_line))
                            payload = response_helloworld
                        else:
                            print("Ignoring: %s" % (request_line))
                            payload = response_notfound

                    sc.write(payload)
                    print("Sent answer.")

