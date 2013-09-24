from unittest import TestSuite, TestResult, makeSuite
from pprint import pprint
from traceback import print_tb

from pysecure.test import binary_read
from pysecure.test import dir_manip
from pysecure.test import file_manip
from pysecure.test import sftp_ls
from pysecure.test import sftp_mirror
from pysecure.test import sftp_no_cb
from pysecure.test import sftp_recurse
from pysecure.test import text_write
from pysecure.test import text_iterate

from pysecure.test import forward_local
from pysecure.test import forward_reverse
from pysecure.test import forward_x11
from pysecure.test import remote_command
from pysecure.test import remote_shell
from pysecure.test import ssh_statuses

sftp_suite = TestSuite((map(makeSuite, [
                binary_read.BinaryReadTest,
                dir_manip.DirManipTest,
                file_manip.FileManipTest,
                sftp_ls.SftpLsTest,
                sftp_mirror.SftpMirrorTest,
                sftp_no_cb.SftpNoCbTest,
                sftp_recurse.SftpRecurseTest,
                text_write.TextWriteTest,
                text_iterate.TextIterateTest])))

ssh_suite = TestSuite((map(makeSuite, [
                       forward_local.ForwardLocalTest,
#                       forward_reverse.ForwardReverseTest,
#                       forward_x11.ForwardX11Test,
                       remote_command.RemoteCommandTest,
                       remote_shell.RemoteShellTest,
                       ssh_statuses.SshStatusesTest])))

class VerboseTestResult(TestResult):
    def startTest(self, test):
        print("Running: %s" % (test))

    def addError(self, test, err):
        (type_, value, traceback) = err

        print
        print_tb(traceback)
        print
        print("  Error [%s]: %s" % (type_, value))

    def addFailure(self, test, err):
        (type_, value, traceback) = err

        print
        print_tb(traceback)
        print
        print("  Fail [%s]: %s" % (type_, value))

def test_sftp():
    result = VerboseTestResult()
    sftp_suite.run(result)

def test_ssh():
    result = VerboseTestResult()
    ssh_suite.run(result)

