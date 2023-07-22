# Linux Filesystem Watcher (fanotify)

Use `fanotify` to find out which processes are making the most filesystem R/W events.

Run `fs_watcher.py --server` in background (preferably as a `systemd` service). Then run `fs_watcher.py` from terminal
to view collected stats.

## Installation

Optional dependency: [priv_exec](https://github.com/mirfatif/priv_exec). Put the binary on your `$PATH`.

    export PYTHONUSERBASE=/opt/python_user_base
    export PATH=$PATH:$PYTHONUSERBASE/bin

    sudo mkdir -p $PYTHONUSERBASE
    sudo chown $(id - u) $PYTHONUSERBASE

    pip install "MyProject @ git+https://github.com/mirfatif/FsWriteWatcher"

    sudo ln -s $PYTHONUSERBASE/lib/python3.*/site-packages/mirfatif/sys_desk_notifd/etc/systemd/system/fs_watcher.service /etc/systemd/system/
    sudo systemctl --user daemon-reload
    sudo systemctl --user enable fs_watcher.service
    sudo systemctl --user start fs_watcher.service

    fs_watcher.py
