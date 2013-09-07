from sys import stdout

from pysecure.exceptions import SshNonblockingTryAgainException

def dumphex(data):
    data_len = len(data)
    row_size = 16

    i = 0
    while i < data_len:
        stdout.write('%05X:' % (i))

        # Display bytes as hex.
    
        j = 0
        while j < row_size:
            index = i + j

            if j == 8:
                stdout.write(' ')

            try:
                stdout.write(' %02X' % (ord(data[index])))
            except IndexError:
                stdout.write('   ')
        
            j += 1
    
        stdout.write(' ')
    
        # Display bytes as ASCII.
    
        j = 0
        while j < row_size:
            index = i + j

            try:
                byte = data[index]
            except IndexError:
                break
            else:
                if ord(byte) < 32:
                    byte = '.'

                stdout.write('%s' % (byte))

            j += 1

        print

        i += row_size

def sync(cb):
    """A function that will repeatedly invoke a callback until it doesn't 
    return a try-again error.
    """

    while 1:
        try:
            cb()
        except SshNonblockingTryAgainException:
            pass
        else:
            break

