from sys import stdout
from collections import deque
from os import listdir, stat, lstat
from os.path import basename, isfile, isdir, islink
from stat import S_ISCHR, S_ISBLK, S_ISREG, S_ISLNK
from os import SEEK_SET, SEEK_CUR, SEEK_END

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

#        print

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

def stat_is_regular(attr):
    return S_ISREG(attr.st_mode)

def stat_is_special(attr):
    return S_ISCHR(attr.st_mode) or S_ISBLK(attr.st_mode)

def stat_is_symlink(attr):
    return S_ISLNK(attr.st_mode)

def local_recurse(path, dir_cb, listing_cb, max_listing_size=0, 
                  max_depth=None):

    def get_flags_from_attr(attr):
        return (stat_is_regular(attr), 
                stat_is_symlink(attr), 
                stat_is_special(attr))

    q = deque([(path, 0)])
    while q:
        (path, current_depth) = q.popleft()

        entries = listdir(path)
        collected = []

        def push_entry(entry):
            collected.append(entry)
            if max_listing_size > 0 and \
               max_listing_size <= len(collected):
                listing_cb(path, collected)
                del collected[:]

        def push_entry_with_filepath(file_path, name, is_link):
            attr = lstat(file_path) if is_link else stat(file_path)
            entry = (name, 
                     int(attr.st_mtime), 
                     attr.st_size, 
                     get_flags_from_attr(attr))

            push_entry(entry)

        for name in entries:
            file_path = ('%s/%s' % (path, name))
#            print("ENTRY: %s" % (file_path))

            if islink(file_path):
                if listing_cb is not None:
                    push_entry_with_filepath(file_path, name, True)
            elif isdir(file_path):
                if name == '.' or name == '..':
                    continue

                if dir_cb is not None:
                    dir_cb(path, file_path, name)

                new_depth = current_depth + 1
                
                if max_depth is not None and max_depth >= new_depth:
                    q.append((file_path, new_depth))
            elif isfile(file_path):
                if listing_cb is not None:
                    push_entry_with_filepath(file_path, name, False)

        if listing_cb is not None and max_listing_size == 0 or \
           len(collected) > 0:
            listing_cb(path, collected)

def bytify(s):
    if issubclass(s.__class__, str):
        return s.encode('ascii')
    else:
        return s

def stringify(s):
    if issubclass(s.__class__, (bytes, bytearray)):
        return s.decode('ascii')
    else:
        return s


class ByteStream(object):
    def __init__(self):
        self.__array = bytearray()
        self.__position = 0

    def write(self, buf_):
        assert issubclass(buf_.__class__, bytes)

        self.__array.extend(buf_)
        self.__position = len(self.__array)

    def read(self, count):
        slice_ = self.__array[self.__position:self.__position + count]
        self.__position += count

        return bytes(slice_)

    def seek(self, position, whence=SEEK_SET):
        if whence == SEEK_CUR:
            position_final = self.__position + position
        elif whence == SEEK_END:
            position_final = self.__position - position
        else:
            position_final = position

        if position >= len(self.__array):
            raise Exception("[Final] position (%d) exceeds buffer length (%d) "
                            "for seek-type (%d). Argument was (%d)." % 
                            (position_final, len(self.__array), whence, 
                             position))

        self.__position = position_final

    def tell(self):
        return self.__position

    def get_array(self):
        return self.__array

    def get_bytes(self):
        return bytes(self.__array)

