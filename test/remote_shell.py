from unittest import TestCase

from pysecure.adapters.channela import RemoteShellProcessor

from test_base import connect_ssh_test

class RemoteShell(TestCase):
    def __ssh_cb(self, ssh):
        rsp = RemoteShellProcessor(ssh)
        
        def shell_context_cb(sc, welcome):
            output = rsp.do_command('cat /proc/uptime')
            print(output)

# Doesn't work. See bug report at libssh.
#        print("Setting environment.")
#        sc.request_env('aa', 'bb')
#        sc.request_env('LANG', 'en_US.UTF-8')

            output = rsp.do_command('whoami')
            print(output)

        rsp.shell(shell_context_cb)

    def test_remote_shell(self):
        connect_ssh_test(self.__ssh_cb)

