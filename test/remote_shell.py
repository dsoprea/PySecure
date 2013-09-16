#!/usr/bin/env python2.7

from pysecure.adapters.channela import RemoteShellProcessor

from test_base import connect_ssh_test

def ssh_cb(ssh):
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

connect_ssh_test(ssh_cb)

