import enum

from trio._core._io_windows import ffi, kernel32

## Additional definitions needed to trio's FFI instance
## Mixing FFI instances can cause issues, so reuse trio's
LIB = """
typedef void (LPOVERLAPPED_COMPLETION_ROUTINE)(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped);

BOOL ReadDirectoryChangesW(
  HANDLE hDirectory,
  LPVOID lpBuffer,
  DWORD nBufferLength,
  BOOL bWatchSubtree,
  DWORD dwNotifyFilter,
  LPDWORD lpBytesReturned,
  LPOVERLAPPED lpOverlapped,
  LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

typedef struct _FILE_NOTIFY_INFORMATION {
  DWORD NextEntryOffset;
  DWORD Action;
  DWORD FileNameLength;
  WCHAR FileName[];
} FILE_NOTIFY_INFORMATION, *PFILE_NOTIFY_INFORMATION;
"""
ffi.cdef(LIB, override=True)


INVALID_HANDLE_VALUE = ffi.cast("HANDLE", -1)
ULONG_MAX = ffi.cast('ULONG', -1)

class ErrorCodes(enum.IntEnum):
    ERROR_NOTIFY_ENUM_DIR = 1022


class FileFlags(enum.IntEnum):
    GENERIC_READ = 0x80000000
    SYNCHRONIZE = 0x00100000
    FILE_FLAG_OVERLAPPED = 0x40000000
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    FILE_SHARE_DELETE = 4
    CREATE_NEW = 1
    CREATE_ALWAYS = 2
    OPEN_EXISTING = 3
    OPEN_ALWAYS = 4
    TRUNCATE_EXISTING = 5
    FILE_LIST_DIRECTORY = 1

class FileNotifyFlags(enum.IntEnum):
    FILE_NOTIFY_CHANGE_FILE_NAME =   0x001
    FILE_NOTIFY_CHANGE_DIR_NAME =    0x002
    FILE_NOTIFY_CHANGE_ATTRIBUTES =  0x004
    FILE_NOTIFY_CHANGE_SIZE =        0x008
    FILE_NOTIFY_CHANGE_LAST_WRITE =  0x010
    FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x020
    FILE_NOTIFY_CHANGE_CREATION =    0x040
    FILE_NOTIFY_CHANGE_SECURITY =    0x100


class FileAction(enum.IntEnum):
    FILE_ACTION_ADDED = 1
    FILE_ACTION_REMOVED = 2
    FILE_ACTION_MODIFIED = 3
    FILE_ACTION_RENAMED_OLD_NAME = 4
    FILE_ACTION_RENAMED_NEW_NAME = 5


def unpack_pascal_string(string_pointer, string_length):
    return ffi.buffer(string_pointer, string_length)[:].decode('utf-16le')


def get_winerror(winerror=None, *, filename=None, filename2=None):
    if winerror is None:
        winerror, msg = ffi.getwinerror()
    else:
        _, msg = ffi.getwinerror(winerror)
    # https://docs.python.org/3/library/exceptions.html#OSError
    return OSError(0, msg, filename, winerror, filename2)

def raise_winerror(winerror=None, *, filename=None, filename2=None):
    raise get_winerror(winerror, filename=filename, filename2=filename2)
