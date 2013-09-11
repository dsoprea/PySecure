from ctypes import *

from pysecure.library import libssh
from pysecure.types import *

# Function calls.

#

# LIBSSH_API sftp_session sftp_new(ssh_session session);
c_sftp_new = libssh.sftp_new
c_sftp_new.argtypes = [c_ssh_session]
c_sftp_new.restype = c_sftp_session

# LIBSSH2_SFTP * libssh2_sftp_init(LIBSSH2_SESSION *session);

# LIBSSH_API int sftp_init(sftp_session sftp);
c_sftp_init = libssh.sftp_init
c_sftp_init.argtypes = [c_sftp_session]
c_sftp_init.restype = c_int

#

# LIBSSH_API int sftp_get_error(sftp_session sftp);
c_sftp_get_error = libssh.sftp_get_error
c_sftp_get_error.argtypes = [c_sftp_session]
c_sftp_get_error.restype = c_int

#

# LIBSSH_API void sftp_free(sftp_session sftp);
c_sftp_free = libssh.sftp_free
c_sftp_free.argtypes = [c_sftp_session]
c_sftp_free.restype = None

# LIBSSH2_SFTP_HANDLE * libssh2_sftp_opendir(LIBSSH2_SFTP *sftp, const char *path);

# LIBSSH_API sftp_dir sftp_opendir(sftp_session session, const char *path);
c_sftp_opendir = libssh.sftp_opendir
c_sftp_opendir.argtypes = [c_sftp_session, c_char_p]
c_sftp_opendir.restype = c_sftp_dir

# int libssh2_sftp_readdir(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen, LIBSSH2_SFTP_ATTRIBUTES *attrs);

# LIBSSH_API sftp_attributes sftp_readdir(sftp_session session, sftp_dir dir);
c_sftp_readdir = libssh.sftp_readdir
c_sftp_readdir.argtypes = [c_sftp_session, c_sftp_dir]
c_sftp_readdir.restype = c_sftp_attributes

#

# LIBSSH_API void sftp_attributes_free(sftp_attributes file);
c_sftp_attributes_free = libssh.sftp_attributes_free
c_sftp_attributes_free.argtypes = [c_sftp_attributes]
c_sftp_attributes_free.restype = c_sftp_attributes

#

# LIBSSH_API int sftp_dir_eof(sftp_dir dir);
c_sftp_dir_eof = libssh.sftp_dir_eof
c_sftp_dir_eof.argtypes = [c_sftp_dir]
c_sftp_dir_eof.restype = c_int

# int libssh2_sftp_closedir(LIBSSH2_SFTP_HANDLE *handle)

# LIBSSH_API int sftp_closedir(sftp_dir dir);
c_sftp_closedir = libssh.sftp_closedir
c_sftp_closedir.argtypes = [c_sftp_dir]
c_sftp_closedir.restype = c_int

## int sftp_async_read (sftp_file file, void *data, uint32_t len, uint32_t id)
#c_sftp_async_read = libssh.sftp_async_read
#c_sftp_async_read.argtypes = [c_sftp_file, c_void_p, c_uint32, c_uint32]
#c_sftp_async_read.restype = c_int

## int sftp_async_read_begin (sftp_file file, uint32_t len)
#c_sftp_async_read_begin = libssh.sftp_async_read_begin
#c_sftp_async_read_begin.argtypes = [c_sftp_file, c_uint32]
#c_sftp_async_read_begin.restype = c_int

## char *sftp_canonicalize_path (sftp_session sftp, const char *path)
#c_sftp_canonicalize_path = libssh.sftp_canonicalize_path
#c_sftp_canonicalize_path.argtypes = [c_sftp_session, c_char_p]
#c_sftp_canonicalize_path.restype = c_char_p

# TODO: sftp_chmod, sftp_chown are missing from libssh2.

# int sftp_chmod (sftp_session sftp, const char *file, mode_t mode)
# mode_t = c_int
c_sftp_chmod = libssh.sftp_chmod
c_sftp_chmod.argtypes = [c_sftp_session, c_char_p, c_mode_t]
c_sftp_chmod.restype = c_int

# int sftp_chown (sftp_session sftp, const char *file, uid_t owner, gid_t group)
c_sftp_chown = libssh.sftp_chown
c_sftp_chown.argtypes = [c_sftp_session, c_char_p, c_uid_t, c_gid_t]
c_sftp_chown.restype = c_int

# int libssh2_sftp_close(LIBSSH2_SFTP_HANDLE *handle);

# int sftp_close (sftp_file file)
c_sftp_close = libssh.sftp_close
c_sftp_close.argtypes = [c_sftp_file]
c_sftp_close.restype = c_int

# TODO: The "extension" functions aren't available from libssh2.

# int sftp_extension_supported (sftp_session sftp, const char *name, const char *data)
c_sftp_extension_supported = libssh.sftp_extension_supported
c_sftp_extension_supported.argtypes = [c_sftp_session, c_char_p, c_char_p]
c_sftp_extension_supported.restype = c_int

# unsigned int sftp_extensions_get_count (sftp_session sftp)
c_sftp_extensions_get_count = libssh.sftp_extensions_get_count
c_sftp_extensions_get_count.argtypes = [c_sftp_session]
c_sftp_extensions_get_count.restype = c_int

# const char * sftp_extensions_get_data (sftp_session sftp, unsigned int indexn)
c_sftp_extensions_get_data = libssh.sftp_extensions_get_data
c_sftp_extensions_get_data.argtypes = [c_sftp_session, c_uint]
c_sftp_extensions_get_data.restype = c_char_p

# const char * sftp_extensions_get_name (sftp_session sftp, unsigned int indexn)
c_sftp_extensions_get_name = libssh.sftp_extensions_get_name
c_sftp_extensions_get_name.argtypes = [c_sftp_session, c_uint]
c_sftp_extensions_get_name.restype = c_char_p

# int libssh2_sftp_fstat(LIBSSH2_SFTP_HANDLE *handle, LIBSSH2_SFTP_ATTRIBUTES *attrs);

# sftp_attributes sftp_fstat (sftp_file file)
c_sftp_fstat = libssh.sftp_fstat
c_sftp_fstat.argtypes = [c_sftp_file]
c_sftp_fstat.restype = c_sftp_attributes

#

# sftp_statvfs_t sftp_fstatvfs (sftp_file file)
# c_sftp_statvfs = c_void_p
c_sftp_fstatvfs = libssh.sftp_fstatvfs
c_sftp_fstatvfs.argtypes = [c_sftp_file]
c_sftp_fstatvfs.restype = c_void_p

# int libssh2_sftp_lstat(LIBSSH2_SFTP *sftp, const char *path, LIBSSH2_SFTP_ATTRIBUTES *attrs);

# sftp_attributes sftp_lstat (sftp_session session, const char *path)
# c_sftp_statvfs = c_void_p
c_sftp_lstat = libssh.sftp_lstat
c_sftp_lstat.argtypes = [c_sftp_session, c_char_p]
c_sftp_lstat.restype = c_void_p

# int libssh2_sftp_mkdir(LIBSSH2_SFTP *sftp, const char *path, long mode);

# int sftp_mkdir (sftp_session sftp, const char *directory, mode_t mode)
c_sftp_mkdir = libssh.sftp_mkdir
c_sftp_mkdir.argtypes = [c_sftp_session, c_char_p, c_mode_t]
c_sftp_mkdir.restype = c_int

# LIBSSH2_SFTP_HANDLE * libssh2_sftp_open(LIBSSH2_SFTP *sftp, const char *path, unsigned long flags, long mode);

# sftp_file sftp_open (sftp_session session, const char *file, int accesstype, mode_t mode)
c_sftp_open = libssh.sftp_open
c_sftp_open.argtypes = [c_sftp_session, c_char_p, c_int, c_mode_t]
c_sftp_open.restype = c_sftp_file

# ssize_t libssh2_sftp_read(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen);

# ssize_t sftp_read (sftp_file file, void *buf, size_t count)
c_sftp_read = libssh.sftp_read
c_sftp_read.argtypes = [c_sftp_file, c_void_p, c_size_t]
c_sftp_read.restype = c_ssize_t

# libssh2_sftp_readlink(sftp, path, target, maxlen)

# char * sftp_readlink (sftp_session sftp, const char *path)
c_sftp_readlink = libssh.sftp_readlink
c_sftp_readlink.argtypes = [c_sftp_session, c_char_p]
c_sftp_readlink.restype = c_char_p

# int libssh2_sftp_rename(LIBSSH2_SFTP *sftp, const char *source_filename, const char *destination_filename);

# int sftp_rename (sftp_session sftp, const char *original, const char *newname)
c_sftp_rename = libssh.sftp_rename
c_sftp_rename.argtypes = [c_sftp_session, c_char_p, c_char_p]
c_sftp_rename.restype = c_int

# int libssh2_sftp_rewind(LINBSSH2_SFTP_HANDLE *handle);

# void sftp_rewind (sftp_file file)
c_sftp_rewind = libssh.sftp_rewind
c_sftp_rewind.argtypes = [c_sftp_file]
c_sftp_rewind.restype = None

# libssh2_sftp_rmdir(sftp, path)

# int sftp_rmdir (sftp_session sftp, const char *directory)
c_sftp_rmdir = libssh.sftp_rmdir
c_sftp_rmdir.argtypes = [c_sftp_session, c_char_p]
c_sftp_rmdir.restype = c_int

# void libssh2_sftp_seek(LIBSSH2_SFTP_HANDLE *handle, size_t offset);

# int sftp_seek (sftp_file file, uint32_t new_offset)
c_sftp_seek = libssh.sftp_seek
c_sftp_seek.argtypes = [c_sftp_file, c_uint32]
c_sftp_seek.restype = c_int

# void libssh2_sftp_seek64(LIBSSH2_SFTP_HANDLE *handle,   libssh2_uint64_t offset);

# int sftp_seek64 (sftp_file file, uint64_t new_offset)
c_sftp_seek64 = libssh.sftp_seek64
c_sftp_seek64.argtypes = [c_sftp_file, c_uint64]
c_sftp_seek64.restype = c_int

# 

# int sftp_server_version (sftp_session sftp)
c_sftp_server_version = libssh.sftp_server_version
c_sftp_server_version.argtypes = [c_sftp_session]
c_sftp_server_version.restype = c_int

# int libssh2_sftp_setstat(LIBSSH2_SFTP *sftp, const char *path, LIBSSH2_SFTP_ATTRIBUTES *attr);

# int sftp_setstat (sftp_session sftp, const char *file, sftp_attributes attr)
c_sftp_setstat = libssh.sftp_setstat
c_sftp_setstat.argtypes = [c_sftp_session, c_char_p, c_sftp_attributes]
c_sftp_setstat.restype = c_int

# int libssh2_sftp_stat(LIBSSH2_SFTP *sftp, const char *path, LIBSSH2_STFP_ATTRIBUTES *attrs);

# sftp_attributes sftp_stat (sftp_session session, const char *path)
c_sftp_stat = libssh.sftp_stat
c_sftp_stat.argtypes = [c_sftp_session, c_char_p]
c_sftp_stat.restype = c_sftp_attributes

# int libssh2_sftp_statvfs(LIBSSH2_SFTP *sftp, const char *path, size_t path_len, LIBSSH2_SFTP_STATVFS *st);

# sftp_statvfs_t sftp_statvfs (sftp_session sftp, const char *path)
# c_sftp_statvfs = c_void_p
c_sftp_statvfs = libssh.sftp_statvfs
c_sftp_statvfs.argtypes = [c_sftp_session, c_char_p]
c_sftp_statvfs.restype = c_void_p

# 

# void sftp_statvfs_free (sftp_statvfs_t statvfs_o)
# c_sftp_statvfs = c_void_p
c_sftp_statvfs_free = libssh.sftp_statvfs_free
c_sftp_statvfs_free.argtypes = [c_void_p]
c_sftp_statvfs_free.restype = None

# libssh2_sftp_symlink(sftp, orig, linkpath)

# int sftp_symlink (sftp_session sftp, const char *target, const char *dest)
c_sftp_symlink = libssh.sftp_symlink
c_sftp_symlink.argtypes = [c_sftp_session, c_char_p, c_char_p]
c_sftp_symlink.restype = c_int

# size_t libssh2_sftp_tell(LIBSSH2_SFTP_HANDLE *handle);

# unsigned long sftp_tell (sftp_file file)
c_sftp_tell = libssh.sftp_tell
c_sftp_tell.argtypes = [c_sftp_file]
c_sftp_tell.restype = c_ulong

# libssh2_uint64_t libssh2_sftp_tell64(LIBSSH2_SFTP_HANDLE *handle);

# uint64_t sftp_tell64 (sftp_file file)
c_sftp_tell64 = libssh.sftp_tell64
c_sftp_tell64.argtypes = [c_sftp_file]
c_sftp_tell64.restype = c_uint64

# int libssh2_sftp_unlink(LIBSSH2_SFTP *sftp, const char *filename);

# int sftp_unlink (sftp_session sftp, const char *file)
c_sftp_unlink = libssh.sftp_unlink
c_sftp_unlink.argtypes = [c_sftp_session, c_char_p]
c_sftp_unlink.restype = c_int

#

# int sftp_utimes (sftp_session sftp, const char *file, const struct timeval *times)
c_sftp_utimes = libssh.sftp_utimes
c_sftp_utimes.argtypes = [c_sftp_session, c_char_p, POINTER(c_timeval * 2)]
c_sftp_utimes.restype = c_int

# ssize_t libssh2_sftp_write(LIBSSH2_SFTP_HANDLE *handle, const char *buffer, size_t count);

# ssize_t sftp_write (sftp_file file, const void *buf, size_t count)
c_sftp_write = libssh.sftp_write
c_sftp_write.argtypes = [c_sftp_file, c_void_p, c_size_t]
c_sftp_write.restype = c_ssize_t

