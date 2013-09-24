from pysecure import log_config

from pysecure.easy import EasySsh, get_password_auth_cb
from pysecure.test.test_config import user, host, key_filepath

auth_cb = get_password_auth_cb('everlove')
easy = EasySsh(user, host, auth_cb, verbosity=1)
easy.open_ssh()

#        entries = self.__easy.sftp.listdir('.')

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

print("Setting listen.")
from time import sleep

n = 10
while n > 0:
    print(n)
    try:
        port = easy.ssh.forward_listen(server_address, server_port)
    except:
        pass
    else:
        break

    n -= 1
    sleep(1)

if False:
    with easy.ssh.forward_accept(accept_timeout_ms) as sc:
        while 1:
            buffer_ = sc.read(2048)
            print(buffer_)
            if buffer_ == b'':
                continue

            try:
                nl_index = buffer_.index(b'\n')
            except ValueError:
                print("Error with:\n%s" % (len(buffer_)))
                payload = response_error
            else:
                request_line = buffer_[:nl_index]

                if request_line[:6] == b'GET / ':
                    print("Responding: %s" % (request_line))
                    payload = response_helloworld
                else:
                    print("Ignoring: %s" % (request_line))
                    payload = response_notfound

            sc.write(payload)
            print("Sent answer.")

