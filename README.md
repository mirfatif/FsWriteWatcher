# Linux Filesystem Watcher (fanotify)

Use `fanotify` to find out which processes are making the most filesystem R/W events.

Run `fs_watcher.py --server` in background (preferably as a `systemd` service). Then run `fs_watcher.py` from terminal
to view collected stats.

```
~$ fs_watcher.py -h

Usage:
	fs_watcher.py [OPTIONS]

Use fanotify to find out which processes are making the most filesystem R/W events.

Common Options:
	-h|--help                Show help
	--sock=<PATH>            Unix socket path (default: /tmp/fs_watcher.py.sock)

Client Options:
	--max=all|<NUM>          Max no. of results (default: 10)
	--filter-<TYPE>=<VALUE>  Apply filters to list
	--old                    Include rotated files too (default: False)

	Filter TYPE:
		uid, cmd, pcmd, event, path

		uid: process user id
		cmd: process commandline
		pcmd: parent cmd
		event: filesystem event
		path: event file path

	Filter VALUE:
		unknown (for: uid, cmd, pcmd)
		EVENT (for: event)
		A value (for: path)

	Filter EVENT:
		CREATE, MODIFY, ATTRIB, MOVED_FROM, MOVED_TO, DELETE

Server Options:
	--server                 Run server
	--mount-path=<PATH>      Filesystem mount path (default: /)
	--dump-file=<PATH>       Dump file path (default: /home/irfan/fs_watcher.py.dump)
	--dump-interval=<SEC>    Dump auto-save interval (default: 1800)
	--rotate=<MBs>           Rotate dump file if exceeds this size (default: 50 MB)
	--debug=1-2              Debug level (default: 0)

Rotated Files:
	Old / archived / rotated dump files have numbers (1 to 10) appended to them with dot.
	Example: /home/irfan/fs_watcher.py.dump.1

	Auto rotation will rename the oldest file if all numbers (1 to 10) are taken.
```

## Installation

Optional dependency: [`priv_exec`](https://github.com/mirfatif/priv_exec). Put the binary on your `$PATH`.

```
~$ export PYTHONUSERBASE=/opt/python_user_base
~$ export PATH=$PYTHONUSERBASE/bin:$PATH

~$ sudo mkdir -p $PYTHONUSERBASE
~$ sudo chown $(id -u) $PYTHONUSERBASE

~$ pip install --ignore-installed --upgrade pip
~$ pip install --upgrade "fs_watcher @ git+https://github.com/mirfatif/FsWriteWatcher"

~$ sudo ln -s $PYTHONUSERBASE/lib/python3.*/site-packages/mirfatif/fs_watcher/etc/systemd/system/fs_watcher.service /etc/systemd/system/
~$ sudo systemctl enable fs_watcher.service
~$ sudo systemctl start fs_watcher.service

~$ fs_watcher.py
```
