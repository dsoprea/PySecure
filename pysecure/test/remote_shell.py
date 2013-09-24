from unittest import TestCase

from pysecure.adapters.channela import RemoteShellProcessor
from pysecure.test.test_base import connect_ssh_test

class RemoteShellTest(TestCase):
    def __ssh_cb(self, ssh):
        rsp = RemoteShellProcessor(ssh)
        
        def shell_context_cb(sc, welcome):
#            print('-' * 50 + '\n' + 
#                  welcome + '\n' + 
#                  '-' * 50)

            output = rsp.do_command('whoami')
#            print(output)

#            output = rsp.do_command('cat /proc/uptime')
#            print(output)

# Doesn't work. See bug report at libssh.
#        print("Setting environment.")
#        sc.request_env('aa', 'bb')
#        sc.request_env('LANG', 'en_US.UTF-8')

        rsp.shell(shell_context_cb)

    def test_remote_shell(self):
        connect_ssh_test(self.__ssh_cb)

