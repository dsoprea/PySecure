#!/usr/bin/env python2.7

from pysecure.adapters.channela import RemoteShellProcessor

from test_base import connect_ssh

def ssh_cb(ssh):
    ssh.set_blocking(False)
    rsp = RemoteShellProcessor(ssh)
    
    def shell_context_cb(sc, welcome):
        output = rsp.do_command('cat /proc/uptime')
        print(output)

        output = rsp.do_command('whoami')
        print(output)
    
    rsp.shell(shell_context_cb)

connect_ssh(ssh_cb)

