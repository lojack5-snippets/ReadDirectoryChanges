from pathlib import Path
from functools import partial

import trio

from read_changes import Listener, Watcher

class PrintListener(Listener):
    async def on_added(self, path):
        print('File Created:', path)

    async def on_modified(self, path):
        print('File Modified:', path)

    async def on_removed(self, path):
        print('File Removed:', path)

    async def on_renamed(self, old_path, new_path):
        print('File Renamed:', old_path, '->', new_path)

    async def on_scan_needed(self):
        print('Scan needed!')


async def main(directory):
    async with trio.open_nursery() as nursery:
        listener = PrintListener()
        watcher = Watcher()
        nursery.start_soon(partial(listener.listen, watcher.create_event_reciever()))
        print('Watching:', directory)
        nursery.start_soon(partial(watcher.watch, directory))
    print('Finished watching.')


if __name__ == '__main__':
    trio.run(partial(main, Path.cwd()))
