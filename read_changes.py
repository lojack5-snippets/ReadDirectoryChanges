from functools import partial
from pathlib import Path
import math

import trio

from _windows_cffi import (
    ffi,
    kernel32,
    INVALID_HANDLE_VALUE,
    ErrorCodes,
    FileFlags,
    FileNotifyFlags,
    FileAction,
    unpack_pascal_string,
    raise_winerror,
    get_winerror,
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


class WatchError(Exception):
    pass

class ScanNeededError(WatchError):
    def __init__(self):
        super().__init__('Changes occurred but could not be stored in the internal buffer.  A manual scan of the target needs to be performed.')


class Watcher:
    def __init__(self, initial_buffer_size=2**10):
        self.buffer_size = initial_buffer_size
        self.listeners = []
        self._native_events = []

    def register_listener(self, listener):
        send_channel, recieve_channel = trio.open_memory_channel(math.inf)
        self.listeners.append(send_channel)
        listener.set_recieve_channel(recieve_channel)

    @staticmethod
    def _create_handle(path_name):
        """Open a handle to `file_name` appropriate for monitoring with IOCP
           and ReadDirectoryChanges.
        """
        # Encode the file name
        rawname = str(path_name).encode('utf-16le') + b'\0\0'
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
        return handle

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
            handle,
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

    def _read_buffer(self, buffer, number_of_bytes):
        offset = 0
        while offset < number_of_bytes:
            notify_info = ffi.cast('PFILE_NOTIFY_INFORMATION', buffer[offset:number_of_bytes])
            self._native_events.append(NativeEvent(notify_info))
            offset = notify_info.NextEntryOffset
            if offset == 0:
                # 0 indicates this was the last entry
                offset = number_of_bytes

    async def watch(self, directory):
        ## NOTE: currently reuses a common buffer, so should only be entered once
        handle = self._create_handle(directory)
        print('Watching:', directory)
        # Register with IOCP so we can await an overlapped result
        trio.lowlevel.register_with_iocp(handle)
        # Create an OVERLAPPED structure to 'recieve' the results
        overlapped = ffi.new('LPOVERLAPPED')
        # Loop indefinitely
        self._native_events = []
        while True:
            # Notify windows we want to ReadDirectoryChanges with results delivered via IOCP
            buffer = self._read_directory_changes(handle, overlapped)
            # And await the results
            try:
                result = await trio.lowlevel.wait_overlapped(handle, overlapped)
            except OSError as e:
                if e.winerror == ErrorCodes.ERROR_NOTIFY_ENUM_DIR:
                    # The buffer was not large enough, we need to manually walk the directory
                    # to find the changes.
                    # Raise the buffer size to avoid this next call
                    self.buffer_size *= 2
                    # And notify the user that they need to walk.
                    raise ScanNeededError() from None
                else:
                    raise e from None
            # Unpack the file notify informations
            self._read_buffer(buffer, result.dwNumberOfBytesTransferred)
            # Send the events to the listeners
            for event in self._native_events:
                for listener in self.listeners:
                    await listener.send(event)
            self._native_events.clear()
            ## TODO: convert events to a higher level representation,
            ## for example folding rename_old and rename_new events into
            ## a single rename event (hence the buffer)
        print('Stopped watching:', directory)


class Listener:
    def __init__(self):
        self.recieve_channel = None

    def set_recieve_channel(self, recieve_channel):
        self.recieve_channel = recieve_channel

    async def listen(self):
        async for event in self.recieve_channel:
            await self.on_event(event)

    async def on_event(self, event):
        if event.is_added:
            await self.on_added(event.path)
        elif event.is_modified:
            await self.on_modified(event.path)
        elif event.is_removed:
            await self.on_removed(event.path)
        elif event.is_renamed_old:
            await self.on_renamed_old(event.path)
        elif event.is_renamed_new:
            await self.on_renamed_new(event.path)
        else:
            raise Watcher(f'Unknown file event type: {event}')

    async def on_added(self, path): pass
    async def on_modified(self, path): pass
    async def on_removed(self, path): pass
    async def on_renamed_old(self, path): pass
    async def on_renamed_new(self, path): pass


class PrintListener(Listener):
    async def on_added(self, path):
        print('File Created:', path)

    async def on_modified(self, path):
        print('File Modified:', path)

    async def on_removed(self, path):
        print('File Removed:', path)

    async def on_renamed_old(self, path):
        print('File Renamed, old path:', path)

    async def on_renamed_new(self, path):
        print('File Renamed, new path:', path)


async def main(directory):
    async with trio.open_nursery() as nursery:
        listener = PrintListener()
        watcher = Watcher()
        watcher.register_listener(listener)
        nursery.start_soon(listener.listen)
        nursery.start_soon(partial(watcher.watch, directory))


if __name__ == '__main__':
    trio.run(partial(main, Path.cwd()))
