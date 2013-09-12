from sys import stdout
from collections import deque
from os import listdir, stat
from os.path import basename, isfile, isdir, islink

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

def local_recurse(path, dir_cb, listing_cb, max_listing_size=0, 
                  max_depth=None):
    q = deque([(path, 0)])
    while q:
        (path, current_depth) = q.popleft()

        entries = listdir(path)
        collected = []

        def push_entity(entity):
            collected.append(entity)
            if max_listing_size > 0 and \
               max_listing_size <= len(collected):
                listing_cb(path, collected)
                del collected[:]

        for name in entries:
            file_path = ('%s/%s' % (path, name))
            print("ENTRY: %s" % (file_path))

            if islink(file_path):
                if listing_cb is not None:
                    attr = stat(file_path)
                    entity = (name, int(attr.st_mtime), attr.st_size, True)
                    push_entity(entity)
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
                    attr = stat(file_path)
                    entity = (name, int(attr.st_mtime), attr.st_size, False)
                    push_entity(entity)

        if listing_cb is not None and max_listing_size == 0 or \
           len(collected) > 0:
            listing_cb(path, collected)

