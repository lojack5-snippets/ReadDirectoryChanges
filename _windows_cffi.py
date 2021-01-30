import enum
import re

import cffi

## Mostly copied from trio/_core/_windows_cffi.py
## with additions needed for ReadDirectoryChangesW
## using IOCP
LIB = """
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
typedef int BOOL;
typedef unsigned char BYTE;
typedef BYTE BOOLEAN;
typedef void* PVOID;
typedef PVOID HANDLE;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned int NTSTATUS;
typedef unsigned long u_long;
typedef ULONG *PULONG;
typedef const void *LPCVOID;
typedef void *LPVOID;
typedef const wchar_t *LPCWSTR;

typedef uintptr_t ULONG_PTR;
typedef uintptr_t UINT_PTR;

typedef UINT_PTR SOCKET;

typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        } DUMMYSTRUCTNAME;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    HANDLE  hEvent;
} OVERLAPPED, *LPOVERLAPPED;

typedef OVERLAPPED WSAOVERLAPPED;
typedef LPOVERLAPPED LPWSAOVERLAPPED;
typedef PVOID LPSECURITY_ATTRIBUTES;
typedef PVOID LPCSTR;

typedef void (LPOVERLAPPED_COMPLETION_ROUTINE)(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped);

typedef struct _OVERLAPPED_ENTRY {
    ULONG_PTR lpCompletionKey;
    LPOVERLAPPED lpOverlapped;
    ULONG_PTR Internal;
    DWORD dwNumberOfBytesTransferred;
} OVERLAPPED_ENTRY, *LPOVERLAPPED_ENTRY;

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

HANDLE CreateFileW(
  LPCWSTR               lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

BOOL WINAPI CloseHandle(
  _In_ HANDLE hObject
);

BOOL WINAPI CancelIoEx(
  _In_     HANDLE       hFile,
  _In_opt_ LPOVERLAPPED lpOverlapped
);

BOOL WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);

BOOL ReadFile(
  HANDLE       hFile,
  LPVOID       lpBuffer,
  DWORD        nNumberOfBytesToRead,
  LPDWORD      lpNumberOfBytesRead,
  LPOVERLAPPED lpOverlapped
);
"""

# cribbed from pywincffi
# programmatically strips out those annotations MSDN likes, like _In_
REGEX_SAL_ANNOTATION = re.compile(
    r"\b(_In_|_Inout_|_Out_|_Outptr_|_Reserved_)(opt_)?\b"
)
LIB = REGEX_SAL_ANNOTATION.sub(" ", LIB)


ffi = cffi.FFI()
ffi.cdef(LIB)


kernel32 = ffi.dlopen("kernel32.dll")


INVALID_HANDLE_VALUE = ffi.cast("HANDLE", -1)


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
