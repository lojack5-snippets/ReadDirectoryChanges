import math
import os

import trio

from _windows_cffi import (
    ffi,
    kernel32,
    INVALID_HANDLE_VALUE,
    ULONG_MAX,
    ErrorCodes,
    FileFlags,
    FileNotifyFlags,
    FileAction,
    unpack_pascal_string,
    raise_winerror,
)

class NativeEvent:
    def __init__(self, file_notify_info):
        self.path = unpack_pascal_string(file_notify_info.FileName, file_notify_info.FileNameLength)
        self.action = FileAction(file_notify_info.Action)

    @property
    def is_added(self):
        return self.action == FileAction.FILE_ACTION_ADDED

    @property
    def is_modified(self):
        return self.action == FileAction.FILE_ACTION_MODIFIED

    @property
    def is_removed(self):
        return self.action == FileAction.FILE_ACTION_REMOVED

    @property
    def is_renamed_old(self):
        return self.action == FileAction.FILE_ACTION_RENAMED_OLD_NAME

    @property
    def is_renamed_new(self):
        return self.action == FileAction.FILE_ACTION_RENAMED_NEW_NAME

    def __str__(self):
        return f'NativEvent(action={self.action}, path={self.path})'


class FileEvent:
    """Higher level representation of events happening to monitored files."""
    def __init__(self, path):
        self.path = path

class FileAddedEvent(FileEvent): pass
class FileModifiedEvent(FileEvent): pass
class FileRemovedEvent(FileEvent): pass
class FileRenamedEvent(FileEvent):
    def __init__(self, old_path, new_path):
        self.old_path = old_path
        self.new_path = new_path
class FileScanNeededEvent(FileEvent):
    def __init__(self):
        pass


class WatchError(Exception):
    pass


class FileHandle:
    """Open a file handle to `file_name` with appropriate settings for
        monitoring with ReadDirectoryChanges and IOCP.
    """
    def __init__(self, path_name):
        # Encode the file name
        rawname = os.fspath(path_name).encode('utf-16le') + b'\0\0'
        rawname = ffi.from_buffer(rawname)
        # share flags: allow other processes to read, write, and delete the file
        fileShareFlags = FileFlags.FILE_SHARE_READ | FileFlags.FILE_SHARE_WRITE | FileFlags.FILE_SHARE_DELETE
        # Create the handle and check for errors
        handle = kernel32.CreateFileW(
            ffi.cast('LPCWSTR', rawname),
            FileFlags.FILE_LIST_DIRECTORY,
            fileShareFlags,
            ffi.NULL,
            FileFlags.OPEN_EXISTING,
            FileFlags.FILE_FLAG_BACKUP_SEMANTICS | FileFlags.FILE_FLAG_OVERLAPPED,
            ffi.NULL,
        )
        if handle == INVALID_HANDLE_VALUE:
            raise_winerror()
        self._handle = handle

    def __enter__(self, *args, **kwargs):
        return self

    def __exit__(self, *args, **kwargs):
        kernel32.CloseHandle(self.win32_handle)

    @property
    def win32_handle(self):
        return self._handle


class Watcher:
    def __init__(self, initial_buffer_size=2**10):
        self.buffer_size = initial_buffer_size
        self.listeners = []

    @property
    def buffer_size(self):
        return self._buffer_size

    @buffer_size.setter
    def buffer_size(self, buffer_size):
        """Buffer size for OVERLAPPED is a ULONG, so can't exceede that size."""
        self._buffer_size = max(1, min(buffer_size, ULONG_MAX))

    def create_event_reciever(self):
        send_channel, recieve_channel = trio.open_memory_channel(math.inf)
        self.listeners.append(send_channel)
        return recieve_channel

    def _read_directory_changes(self, handle, overlapped):
        # Types of changes we want to be notified of
        watchFlags = (FileNotifyFlags.FILE_NOTIFY_CHANGE_FILE_NAME |
                      FileNotifyFlags.FILE_NOTIFY_CHANGE_DIR_NAME |
                      FileNotifyFlags.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                      FileNotifyFlags.FILE_NOTIFY_CHANGE_SIZE |
                      FileNotifyFlags.FILE_NOTIFY_CHANGE_LAST_WRITE |
                      FileNotifyFlags.FILE_NOTIFY_CHANGE_SECURITY |
                      FileNotifyFlags.FILE_NOTIFY_CHANGE_LAST_ACCESS |
                      FileNotifyFlags.FILE_NOTIFY_CHANGE_CREATION
        )
        # Use a fresh buffer for each call, so a single watcher can enter
        # 'watch' multiple times
        buffer =  ffi.from_buffer(bytearray(self.buffer_size))
        result = kernel32.ReadDirectoryChangesW(
            handle.win32_handle,
            buffer,
            self.buffer_size,
            True,       # bWatchSubtree
            watchFlags,
            ffi.NULL,   # lpBytesReturned -> unused when using IOCP
            overlapped,
            ffi.NULL,   # lpCompletionRoutine -> unused here
        )
        if result == 0:
            raise_winerror()
        return buffer

    @staticmethod
    def _read_buffer(buffer, number_of_bytes):
        offset = 0
        events = []
        while offset < number_of_bytes:
            notify_info = ffi.cast('PFILE_NOTIFY_INFORMATION', buffer[offset:number_of_bytes])
            events.append(NativeEvent(notify_info))
            offset = notify_info.NextEntryOffset
            if offset == 0:
                # 0 indicates this was the last entry
                offset = number_of_bytes
        return events

    @staticmethod
    def _fold_events(native_events):
        """Merge renamed_old and renamed_new events."""
        renamed_source = None
        events = []
        for idx, event in enumerate(native_events):
            if event.is_renamed_old:
                renamed_source = event
            elif event.is_renamed_new:
                events.append(FileRenamedEvent(renamed_source.path, event.path))
            elif event.is_added:
                events.append(FileAddedEvent(event.path))
            elif event.is_modified:
                events.append(FileModifiedEvent(event.path))
            elif event.is_removed:
                events.append(FileRemovedEvent(event.path))
        return events

    async def watch(self, directory):
        with FileHandle(directory) as handle:
            # Register with IOCP so we can await an overlapped result
            trio.lowlevel.register_with_iocp(handle.win32_handle)
            # Create an OVERLAPPED structure to 'recieve' the results
            overlapped = ffi.new('LPOVERLAPPED')
            # Loop indefinitely
            while True:
                # Notify windows we want to ReadDirectoryChanges with results delivered via IOCP
                buffer = self._read_directory_changes(handle, overlapped)
                # And await the results
                try:
                    result = await trio.lowlevel.wait_overlapped(handle.win32_handle, overlapped)
                except OSError as e:
                    if e.winerror == ErrorCodes.ERROR_NOTIFY_ENUM_DIR:
                        # The buffer was not large enough, we need to manually walk the directory
                        # to find the changes.
                        # Raise the buffer size to avoid this next call
                        self.buffer_size *= 2
                        # And notify the user that they need to walk.
                        events = [FileScanNeededEvent()]
                    else:
                        raise e from None
                else:
                    # No error: unpack the file notify informations
                    native_events = self._read_buffer(buffer, result.dwNumberOfBytesTransferred)
                    # And convert to higher level events
                    events = self._fold_events(native_events)
                # Send the events to the listeners
                for event in events:
                    to_remove = []
                    for listener in self.listeners:
                        try:
                            await listener.send(event)
                        except trio.BrokenResourceError:
                            # The listener closed its recieve channel
                            to_remove.append(listener)
                    # Clean out closed recieve channels
                    for remove in to_remove:
                        self.listeners.remove(remove)


class Listener:
    async def listen(self, recieve_channel):
        async with recieve_channel: # Automatically closes if the watcher closes the send_channel
            async for event in recieve_channel:
                await self.on_event(event)

    async def on_event(self, event):
        if isinstance(event, FileAddedEvent):
            await self.on_added(event.path)
        elif isinstance(event, FileModifiedEvent):
            await self.on_modified(event.path)
        elif isinstance(event, FileRemovedEvent):
            await self.on_removed(event.path)
        elif isinstance(event, FileRenamedEvent):
            await self.on_renamed(event.old_path, event.new_path)
        elif isinstance(event, FileScanNeededEvent):
            await self.on_scan_needed()
        else:
            raise WatchError(f'Unknown file event type: {event}')

    async def on_added(self, path): pass
    async def on_modified(self, path): pass
    async def on_removed(self, path): pass
    async def on_renamed(self, old_path, new_path): pass
    async def on_scan_needed(self): pass
