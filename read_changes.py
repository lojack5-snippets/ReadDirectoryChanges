from functools import partial
from pathlib import Path

import trio

from _windows_cffi import (
    ffi,
    kernel32,
    INVALID_HANDLE_VALUE,
    FileFlags,
    FileNotifyFlags,
    FileAction,
    unpack_pascal_string,
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


class Watcher:
    def __init__(self, buffer_size=2**10):
        self.buffer_size = buffer_size
        self.buffer = ffi.from_buffer(bytearray(buffer_size))
        self.listeners = []
        self._native_events = []

    def register_listener(self, listener):
        self.listeners.append(listener)

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
            ## TODO: get details of the error using GetLastError
            raise WatchHandle(f'Could not create file handle: {path_name}')
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
        result = kernel32.ReadDirectoryChangesW(
            handle,
            self.buffer,
            self.buffer_size,
            True,       # bWatchSubtree
            watchFlags,
            ffi.NULL,   # lpBytesReturned -> unused when using IOCP
            overlapped,
            ffi.NULL,   # lpCompletionRoutine -> unused here
        )
        if result == 0:
            # Indicates error
            # TODO: GetLastError
            raise WatchError('ReadDirectoryChanges failed')

    def _read_buffer(self, number_of_bytes):
        offset = 0
        while offset < number_of_bytes:
            notify_info = ffi.cast('PFILE_NOTIFY_INFORMATION', self.buffer[offset:number_of_bytes])
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
            self._read_directory_changes(handle, overlapped)
            # And await the results
            result = await trio.lowlevel.wait_overlapped(handle, overlapped)
            # Unpack the file notify informations
            self._read_buffer(result.dwNumberOfBytesTransferred)
            # Send the events to the listeners
            for event in self._native_events:
                for listener in self.listeners:
                    await listener.on_event(event)
            self._native_events.clear()
            ## TODO: convert events to a higher level representation,
            ## for example folding rename_old and rename_new events into
            ## a single rename event (hence the buffer)
        print('Stopped watching:', directory)


class Listener:
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
        nursery.start_soon(partial(watcher.watch, directory))


if __name__ == '__main__':
    trio.run(partial(main, Path.cwd()))
