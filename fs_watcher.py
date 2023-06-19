#!/usr/bin/python
import builtins
import collections
import copy
import datetime
import functools
import getopt
import hashlib
import inspect
import os.path
import pickle
import signal
import stat
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace
from typing import Callable

import pynng
import pypager

NNG_SOCK_PATH = f'/tmp/{os.path.basename(sys.argv[0])}.sock'

# Server options
MOUNT_PATH = '/'
DUMP_FILE_PATH = f'{os.getenv("HOME") or "/var/log/"}/{os.path.basename(sys.argv[0])}.dump'
DUMP_FILE_SIZE = 50  # MB
DUMP_SAVE_INTERVAL = 1800  # Seconds
DEBUG_LEVEL = 0

# Client options
MAX_RESULTS = 10
INC_OLD_DUMPS = False


# A blocking queue which can be unblocked anytime from other threads.
class Queue:
    def __init__(self):
        self.queue = collections.deque()
        self.lock = threading.Lock()
        self.waiter = threading.Condition(self.lock)
        self.terminated = False

    def put(self, item) -> None:
        with self.waiter:
            self.queue.append(item)
            self.waiter.notify()

    def empty(self) -> bool:
        return not len(self.queue)

    def get(self) -> dict | None:
        with self.waiter:
            while not self.terminated and self.empty():
                self.waiter.wait()

            return None if self.terminated else self.queue.popleft()

    # Return from get() if blocked.
    def end(self):
        self.terminated = True
        with self.waiter:
            self.waiter.notify()


class Thread(threading.Thread):
    def __init__(self, target: Callable, name=None, daemon=False):
        super(Thread, self).__init__(target=Thread._run_target, args=[target], name=name, daemon=daemon)

    @staticmethod
    def _run_target(func: Callable):
        print(f'Starting thread {threading.current_thread().name}...')
        Thread.run_target(func)

    @staticmethod
    def run_target(func: Callable):
        if threading.current_thread() is threading.main_thread():
            sys.excepthook = Thread._handle_uncaught_err
        else:
            threading.excepthook = lambda args: Thread._handle_uncaught_err(*args[:-1])

        func()

        print(f'Exiting {threading.current_thread().name}...')

    @staticmethod
    def _handle_uncaught_err(err_type, value, tb):
        print_err(f'Uncaught exception in thread: {threading.current_thread().name}:')
        traceback.print_exception(err_type, value, tb)
        kill_me()


class ClientCmd:
    CMD_GET_EVENT_LIST: int = 0

    class Filter:
        UNKNOWN: str = 'unknown'

        FILTER_UID: str = 'uid'
        FILTER_CMD: str = 'cmd'
        FILTER_P_CMD: str = 'pcmd'
        FILTER_EVENT: str = 'event'
        FILTER_PATH: str = 'path'

        FILTERS_ALL = [FILTER_UID, FILTER_CMD, FILTER_P_CMD, FILTER_EVENT, FILTER_PATH]

        def __init__(self):
            self.uid: str | None = None
            self.cmd: str | None = None
            self.p_cmd: str | None = None
            self.event: str | None = None
            self.path: str | None = None

        def is_empty(self):
            return not (self.uid or self.cmd or self.p_cmd or self.event or self.path)

    def __init__(self):
        self.cmd: int = self.CMD_GET_EVENT_LIST
        self.filter: ClientCmd.Filter | None = None
        self.max_results: int = MAX_RESULTS
        self.include_old_dumps: bool = INC_OLD_DUMPS


class Data:
    UNKNOWN: str = 'UNKNOWN'

    class EventCount:
        def __init__(self):
            self.total: int = 0
            self.grand_total: int = 0

        def update(self, count: int):
            self.total += 1
            self.grand_total += count

    def __init__(self, start_time: float, file_count: int):
        self.dump_file_count: int = file_count
        self.start_time: float = start_time
        self.total_count: Data.EventCount = Data.EventCount()
        self.lst: list[SimpleNamespace] = []
        self.uid_cnt: dict[str, Data.EventCount] | list[tuple[str, Data.EventCount]] = {}
        self.cmd_cnt: dict[str, Data.EventCount] | list[tuple[str, Data.EventCount]] = {}
        self.p_cmd_cnt: dict[str, Data.EventCount] | list[tuple[str, Data.EventCount]] = {}
        self.event_cnt: dict[str, Data.EventCount] | list[tuple[str, Data.EventCount]] = {}
        self.path_cnt: dict[str, Data.EventCount] | list[tuple[str, Data.EventCount]] = {}

    def update(self, ev: SimpleNamespace):
        self.total_count.update(ev.count)

        if not ev.uid:
            ev.uid = Data.UNKNOWN
        if not ev.gid:
            ev.gid = Data.UNKNOWN
        if not ev.cmd:
            ev.cmd = Data.UNKNOWN
        if not ev.p_cmd:
            ev.p_cmd = Data.UNKNOWN

        self.lst.append(ev)

        if not (ec := self.uid_cnt.get(ev.uid)):
            self.uid_cnt[ev.uid] = ec = Data.EventCount()
        ec.update(ev.count)

        if not (ec := self.cmd_cnt.get(ev.cmd)):
            self.cmd_cnt[ev.cmd] = ec = Data.EventCount()
        ec.update(ev.count)

        if not (ec := self.p_cmd_cnt.get(ev.p_cmd)):
            self.p_cmd_cnt[ev.p_cmd] = ec = Data.EventCount()
        ec.update(ev.count)

        if not (ec := self.event_cnt.get(ev.evt)):
            self.event_cnt[ev.evt] = ec = Data.EventCount()
        ec.update(ev.count)

        path: str = ev.path
        while True:
            if not (ec := self.path_cnt.get(path)):
                self.path_cnt[path] = ec = Data.EventCount()
            ec.update(ev.count)

            if path == '/' or not path.startswith('/'):
                break

            path = path[:(path.rindex('/') or 1)]

    def finalize(self, max_results: int):
        self.lst.sort(key=lambda e: e.count, reverse=True)
        self.uid_cnt = sorted(self.uid_cnt.items(), key=lambda d: d[1].grand_total, reverse=True)
        self.cmd_cnt = sorted(self.cmd_cnt.items(), key=lambda d: d[1].grand_total, reverse=True)
        self.p_cmd_cnt = sorted(self.p_cmd_cnt.items(), key=lambda d: d[1].grand_total, reverse=True)
        self.event_cnt = sorted(self.event_cnt.items(), key=lambda d: d[1].grand_total, reverse=True)
        self.path_cnt = sorted(self.path_cnt.items(), key=lambda d: d[0])
        self.path_cnt.sort(key=lambda d: d[1].grand_total, reverse=True)

        if max_results:
            del self.lst[max_results:]
            del self.uid_cnt[max_results:]
            del self.cmd_cnt[max_results:]
            del self.p_cmd_cnt[max_results:]
            del self.event_cnt[max_results:]
            del self.path_cnt[max_results:]


def print_exc_line():
    etype, value, tb = sys.exc_info()
    print(''.join(traceback.format_exception_only(etype, value)), file=sys.stderr, end='')


def print_exc_line_thread(lineno: int = None):
    if lineno:
        print_err(f'line {lineno}: '
                  f'Exception in {threading.current_thread().name}: ', no_newline=True)
        print_exc_line()
    else:
        print_err(f'Exception in {threading.current_thread().name}')
        traceback.print_exc()


def print_err(msg: str, no_newline: bool = False):
    end = '\n'
    if no_newline:
        end = ''

    print(msg, file=sys.stderr, end=end)


def to_str(lst: list, joiner: str = ' '):
    return joiner.join(str(s) for s in lst)


def kill_me(sig: int = None, *_):
    if sys.stdout.isatty():
        print(f'\r')

    if sig:
        print(f'{signal.strsignal(sig)}, exiting...')
    else:
        print('Exiting...')

    global nng_server
    if nng_server:
        server = nng_server
        nng_server = None

        try:
            server.close()
        except (Exception,):
            print_exc_line_thread(inspect.currentframe().f_lineno)

    # poll() in C receives EINTR only if running on main
    # thread. So we need to exit the loop manually.
    fa_notify.stop_fs_events()

    if raw_events:
        try:
            # Return from blocking get().
            raw_events.end()
        except (Exception,):
            print_exc_line_thread(inspect.currentframe().f_lineno)

    try:
        save_dump(True)
    except (Exception,):
        print_exc_line_thread(inspect.currentframe().f_lineno)


def save_dump(print_msg: bool = False):
    global dump_start_time, events

    with events_lock:
        with open(f'{dump_file_path}.tmp', 'wb') as f:
            pickle.dump(dump_start_time, f)
            pickle.dump(events, f)

        os.rename(f'{dump_file_path}.tmp', dump_file_path)

        if print_msg:
            print(f'Dumped {len(events)} events')

        if os.path.getsize(dump_file_path) < dump_file_size * 1000 * 1000:
            return

        slot = None

        for i in range(1, 10):
            rotated_file = f'{dump_file_path}.{i}'
            if not os.path.exists(rotated_file):
                slot = rotated_file
                break

        if not slot:
            ts: float = 0
            for i in range(1, 10):
                rotated_file = f'{dump_file_path}.{i}'
                if not (dump := load_dump_file(rotated_file)):
                    slot = rotated_file
                    break
                elif ts == 0 or ts < dump[0]:
                    ts = dump[0]
                    slot = rotated_file

        if os.path.exists(slot):
            os.rename(
                slot,
                f'{slot}_{datetime.datetime.fromtimestamp(time.time()).strftime("%d-%m-%y_%H-%M-%S")}'
            )

        os.rename(dump_file_path, slot)
        print(f'Rotated {dump_file_path} to {slot}')

        dump_start_time = time.time()
        events.clear()


def load_dump_file(file: str) -> tuple[float, dict[str, SimpleNamespace]] | None:
    if not os.path.isfile(file):
        return None

    try:
        with open(file, 'rb') as f:
            return pickle.load(f), pickle.load(f)
    except FileNotFoundError:
        return None
    except pickle.UnpicklingError:
        print_err(f'Failed to load dump file {file}')
        return None


def load_dump():
    if dump := load_dump_file(dump_file_path):
        global dump_start_time, events
        dump_start_time = dump[0]
        events = dump[1]
        print(f'Loaded {len(events)} events')


def create_client_response(cmd: ClientCmd) -> Data:
    with events_lock:
        if cmd.include_old_dumps:
            events_tmp = copy.deepcopy(events)
        else:
            events_tmp = events.copy()

    file_count: int = 1
    start_time: float = dump_start_time

    if cmd.include_old_dumps:
        for i in range(1, 10):
            if dump := load_dump_file(f'{dump_file_path}.{i}'):
                file_count += 1

                if dump[0] < start_time:
                    start_time = dump[0]

                for ev in dump[1].values():
                    key: str = create_event_key(ev.uid, ev.gid, ev.cmd, ev.p_cmd, ev.evt, ev.path)

                    if e := events_tmp.get(key):
                        e.count += 1
                    else:
                        events_tmp[key] = ev

    data: Data = Data(start_time, file_count)
    f = cmd.filter

    for ev in list(events_tmp.values()):
        if f:
            if (f.uid == f.UNKNOWN and not ev.uid) or (f.uid is not None and ev.uid != f.uid):
                continue

            if (f.cmd == f.UNKNOWN and ev.cmd) or \
                    (ev.cmd and f.cmd is not None and not ev.cmd.startswith(f.cmd)):
                continue

            if (f.p_cmd == f.UNKNOWN and ev.p_cmd) or \
                    (ev.p_cmd and f.p_cmd is not None and not ev.p_cmd.startswith(f.p_cmd)):
                continue

            if f.event is not None and ev.evt != f.event:
                continue

            if f.path is not None and ev.path and not ev.path.startswith(f.path):
                continue

        data.update(ev)

    data.finalize(cmd.max_results)
    return data


def start_nng_server():
    while server := nng_server:
        try:
            msg: pynng.Message = server.recv_msg()
        except pynng.exceptions.Closed:
            if nng_server:
                print_exc_line_thread(inspect.currentframe().f_lineno)
            return

        try:
            cmd: ClientCmd = pickle.loads(msg.bytes)
        except pickle.UnpicklingError:
            print_err('Bad command received from client: ', no_newline=True)
            print_exc_line()
            continue

        if not isinstance(cmd, ClientCmd):
            print_err(f'Bad command type "{type(cmd)}"')
            continue

        if cmd.cmd != ClientCmd.CMD_GET_EVENT_LIST:
            print_err(f'Bad command received from client: {cmd.cmd}')
            continue

        msg.pipe.send(pickle.dumps(create_client_response(cmd)))


def create_event_key(uid, gid, cmd, p_cmd, evt_name, path) -> str:
    key = uid + '|' + gid + '|' + cmd + '|' + p_cmd + '|' + evt_name + '|' + path
    return hashlib.md5(key.encode()).hexdigest()


def run_queue_parser():
    while evt := raw_events.get():
        uid = evt['uid']
        gid = evt['gid']
        cmd = evt['cmd'].decode()
        p_cmd = evt['p_cmd'].decode()
        evt_name = evt['evt'].decode()
        path = os.path.dirname(evt['path'].decode())

        if uid == -1:
            uid = ''
        else:
            uid = str(uid)

        if gid == -1:
            gid = ''
        else:
            gid = str(gid)

        key: str = create_event_key(uid, gid, cmd, p_cmd, evt_name, path)

        with events_lock:
            if e := events.get(key):
                e.count += 1
            else:
                events[key] = SimpleNamespace(
                    uid=uid,
                    gid=gid,
                    cmd=cmd,
                    p_cmd=p_cmd,
                    evt=evt_name,
                    path=path,
                    count=1
                )

        global last_dump_ts

        if last_dump_ts + dump_save_interval < time.time():
            save_dump(debug_level >= 2)
            last_dump_ts = time.time()


def start_server():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, kill_me)

    load_dump()

    global nng_server
    nng_server = pynng.Rep0(listen=ipc_address, send_timeout=2000)
    os.chmod(nng_sock_path,
             stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

    Thread(target=start_nng_server, name='NNGServer').start()
    Thread(target=lambda: fa_notify.start_fs_events_nat(bytes(mount_path, 'UTF-8'), lambda ev: raw_events.put(ev)),
           name="FsEventListener").start()

    print(f'Parsing raw events queue on {threading.current_thread().name}...')
    Thread.run_target(run_queue_parser)


def print_data(data: Data):
    def header(name: str):
        return [
            ('bold underline fg:#7CB9E8', f'\n{name}\n'),
            ('', '=================================================\n')
        ]

    def sub_header(titles: tuple[str, str, str, str]):
        return [
            ('', f'{titles[0]:>7}   {titles[1]:<10} {titles[2]:<10} {titles[3]}\n'),
            ('', '-------------------------------------------------\n')
        ]

    def summary(lst: list):
        return [
            (
                '',
                f'{100 * i[1].grand_total / data.total_count.grand_total:6.2f}%   '
                f'{i[1].grand_total:<10} '
                f'{i[1].total:<10} {i[0]}\n'
            )
            for i in lst
        ]

    yield [
        ('bold fg:#7CB9E8', 'FILESYSTEM READ/WRITE EVENTS (FANOTIFY)\n'),
        ('', 'https://man7.org/linux/man-pages/man7/fanotify.7.html\n\n'),
        ('bold', 'Since:'),
        ('', f' {datetime.datetime.fromtimestamp(data.start_time).strftime("%d-%b-%y %I:%M %p")}\n\n'),
        ('bold', 'Dumped files:'),
        ('', f' {data.dump_file_count}\n\n'),
        ('bold', 'Total events:'),
        ('', f' {data.total_count.grand_total}\n'),
        ('bold', 'Unique events:'),
        ('', f' {data.total_count.total}\n\n'),
        ('', 'TOTAL: Total number of events\n'),
        ('', 'UNIQUE: Unique number of events\n'),
        ('', '%AGE: Percentage of total events\n\n'),
        ('', 'Unique events are based on a combination of:\n'),
        ('', 'UID, GID, CMD, PARENT CMD, EVENT and PATH\n'),
    ]

    yield header('UID')
    yield sub_header(('%AGE', 'TOTAL', 'UNIQUE', 'UID'))
    yield summary(data.uid_cnt)

    yield header('CMD')
    yield sub_header(('%AGE', 'TOTAL', 'UNIQUE', 'CMD'))
    yield summary(data.cmd_cnt)

    yield header('PARENT CMD')
    yield sub_header(('%AGE', 'TOTAL', 'UNIQUE', 'PARENT'))
    yield summary(data.p_cmd_cnt)

    yield header('EVENT')
    yield sub_header(('%AGE', 'TOTAL', 'UNIQUE', 'EVENT'))
    yield summary(data.event_cnt)

    yield header('PATH')
    yield sub_header(('%AGE', 'TOTAL', 'UNIQUE', 'PATH'))
    yield summary(data.path_cnt)

    yield header('DETAIL')
    yield [
        ('', '%AGE      UNIQUE     UID.GID         EVENT\n'),
        ('', '-------------------------------------------------\n')
    ]
    yield [
        (
            '',
            f"{f'{100 * evt.count / data.total_count.grand_total:<.2f}%':<10}"
            f'{evt.count:<10} {f"{evt.uid}.{evt.gid}":<15} {evt.evt}\n'
            f'CMD:      {evt.cmd}\n'
            f'PARENT:   {evt.p_cmd}\n'
            f'PATH:     {evt.path}\n\n'
        )
        for evt in data.lst
    ]


def run_client() -> None:
    if not os.path.exists(nng_sock_path):
        print_err('Server not running')
        print_usage()
        sys.exit(1)

    client = pynng.Req0(dial=ipc_address, send_timeout=1000, recv_timeout=30000)
    try:
        client.send(pickle.dumps(client_cmd))
        data: Data = pickle.loads(client.recv())
    finally:
        client.close()

    if not data.total_count.grand_total:
        print_err('No events found')
    elif not sys.stdout.isatty():
        for lst in print_data(data):
            for line in lst:
                print(line[1], end='')
    else:
        pager = pypager.pager.Pager()
        pager.add_source(pypager.source.GeneratorSource(print_data(data)))
        pager.run()


def print_usage(ex_code: int = None) -> None:
    print(f'\nUsage:\n\t{os.path.basename(sys.argv[0])} [OPTIONS]')
    print(f'\nUse fanotify to find out which processes are making the most filesystem R/W events.')

    print(f'\nCommon Options:')
    print(f'\t-h|--help                Show help')
    print(f'\t--sock=<PATH>            Unix socket path (default: {NNG_SOCK_PATH})')

    print(f'\nClient Options:')
    print(f'\t--max=all|<NUM>          Max no. of results (default: {MAX_RESULTS})')
    print(f'\t--filter-<TYPE>=<VALUE>  Apply filters to list')
    print(f'\t--old                    Include rotated files too (default: {INC_OLD_DUMPS})')

    f = ClientCmd.Filter

    print('\n\tFilter TYPE:\n\t\t', end='')
    print(', '.join(f.FILTERS_ALL))
    print(f'\n\t\t{f.FILTER_UID}: process user id')
    print(f'\t\t{f.FILTER_CMD}: process commandline')
    print(f'\t\t{f.FILTER_P_CMD}: parent cmd')
    print(f'\t\t{f.FILTER_EVENT}: filesystem event')
    print(f'\t\t{f.FILTER_PATH}: event file path')

    print(f'\n\tFilter VALUE:\n\t\t', end='')
    print(f'{f.UNKNOWN} (for: {f.FILTER_UID}, {f.FILTER_CMD}, {f.FILTER_P_CMD})')
    print(f'\t\tEVENT (for: {f.FILTER_EVENT})')
    print(f'\t\tA value (for: {f.FILTER_PATH})')

    print('\n\tFilter EVENT:\n\t\t', end='')
    print(', '.join(fa_notify.FS_EVENTS))

    print(f'\nServer Options:')
    print(f'\t--server                 Run server')
    print(f'\t--mount-path=<PATH>      Filesystem mount path (default: {MOUNT_PATH})')
    print(f'\t--dump-file=<PATH>       Dump file path (default: {DUMP_FILE_PATH})')
    print(f'\t--dump-interval=<SEC>    Dump auto-save interval (default: {DUMP_SAVE_INTERVAL})')
    print(f'\t--rotate=<MBs>           Rotate dump file if exceeds this size (default: {DUMP_FILE_SIZE} MB)')
    print(f'\t--debug=1|2              Debug level (default: {DEBUG_LEVEL})')

    print('\n\tRotated Files:')
    print(f'\t\tOld / archived / rotated dump files have numbers (1 to 10) appended to them with dot.')
    print(f'\t\tExample: {DUMP_FILE_PATH}.1')
    print(f'\n\t\tAuto rotation will rename the oldest file if all numbers (1 to 10) are taken.')

    print()

    if ex_code is not None:
        sys.exit(ex_code)


def get_opts() -> None:
    opt_help: str = 'help'
    opt_socket: str = 'sock'

    # Client
    opt_max_res: str = 'max'
    opt_old_dumps: str = 'old'
    opt_f_uid: str = 'filter-uid'
    opt_f_cmd: str = 'filter-cmd'
    opt_f_pcmd: str = 'filter-pcmd'
    opt_f_event: str = 'filter-event'
    opt_f_path: str = 'filter-path'

    # Server
    opt_server: str = 'server'
    opt_mount_path: str = 'mount-path'
    opt_dump_file: str = 'dump-file'
    opt_interval: str = 'dump-interval'
    opt_rotate_size: str = 'rotate'
    opt_debug: str = 'debug'

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            'h',
            [
                opt_help,
                f'{opt_socket}=',

                f'{opt_max_res}=',
                opt_old_dumps,
                f'{opt_f_uid}=',
                f'{opt_f_cmd}=',
                f'{opt_f_pcmd}=',
                f'{opt_f_event}=',
                f'{opt_f_path}=',

                opt_server,
                f'{opt_mount_path}=',
                f'{opt_dump_file}=',
                f'{opt_interval}=',
                f'{opt_rotate_size}=',
                f'{opt_debug}='
            ]
        )
    except getopt.GetoptError:
        print_exc_line()
        print_usage()
        sys.exit(1)

    if args:
        print_err(f'Unexpected arguments: {to_str(args)}')
        print_usage(1)

    global nng_sock_path, client_cmd
    global mount_path, dump_file_path, dump_file_size, dump_save_interval, debug_level

    ftr: ClientCmd.Filter | None = None

    if not (f'--{opt_server}', '') in opts:
        client_cmd = ClientCmd()
        ftr = ClientCmd.Filter()

    def assert_client(option: str):
        if not client_cmd:
            print_err(f'{option} is mutually exclusive with --{opt_server}')
            sys.exit(1)

    def assert_server(option: str):
        if client_cmd:
            print_err(f'{option} can only be used with --{opt_server}')
            sys.exit(1)

    def assert_integer(num: str):
        if not num.isdecimal():
            print_err(f'"{num}" is not an integer')
            sys.exit(1)

    for opt, val in opts:
        if opt == f'--{opt_help}' or opt == '-h':
            print_usage(0)
        elif opt == f'--{opt_socket}':
            nng_sock_path = val

        elif opt == f'--{opt_max_res}':
            assert_client(opt)
            if val.startswith('all'):
                client_cmd.max_results = None
            else:
                assert_integer(val)
                client_cmd.max_results = int(val)
        elif opt == f'--{opt_old_dumps}':
            assert_client(opt)
            client_cmd.include_old_dumps = True

        elif opt == f'--{opt_f_uid}':
            assert_client(opt)
            if val != ClientCmd.Filter.UNKNOWN:
                assert_integer(val)
            ftr.uid = val
        elif opt == f'--{opt_f_cmd}':
            assert_client(opt)
            ftr.cmd = val
        elif opt == f'--{opt_f_pcmd}':
            assert_client(opt)
            ftr.p_cmd = val
        elif opt == f'--{opt_f_event}':
            assert_client(opt)
            if val not in fa_notify.FS_EVENTS:
                print_err(f'Bad {opt}: {val}')
                sys.exit(1)
            ftr.event = val
        elif opt == f'--{opt_f_path}':
            assert_client(opt)
            ftr.path = val

        elif opt == f'--{opt_server}':
            pass
        elif opt == f'--{opt_mount_path}':
            assert_server(opt)
            mount_path = val
        elif opt == f'--{opt_dump_file}':
            assert_server(opt)
            dump_file_path = val
        elif opt == f'--{opt_interval}':
            assert_server(opt)
            assert_integer(val)
            dump_save_interval = int(val)
        elif opt == f'--{opt_rotate_size}':
            assert_server(opt)
            assert_integer(val)
            dump_file_size = int(val)
        elif opt == f'--{opt_debug}':
            assert_server(opt)
            assert_integer(val)
            debug_level = int(val)

        else:
            sys.exit(1)  # Should not happen.

    if ftr and not ftr.is_empty():
        client_cmd.filter = ftr


def build_library(mod: str) -> None:
    if not sys.stdin.isatty():
        return

    my_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

    lib = f'{mod}.so'
    if os.path.exists(os.path.join(my_dir, lib)):
        return

    cwd = os.getcwd()
    os.chdir(my_dir)

    print(f'Building module: {mod}')

    def del_file(*files):
        for file in files:
            if os.path.exists(file):
                os.remove(file)

    c = f'{mod}_tmp.c'

    # cproto -f1 proc_event_connector.c | grep -vE '/\*' | sed 's|;\s$||'

    try:
        if not (err := subprocess.call(f'cython -3 {mod}.pyx -o {c}'.split())):
            ver = f'{sys.version_info[0]}.{sys.version_info[1]}'
            cp = subprocess.run(f'python{ver}-config --includes'.split(),
                                stdout=subprocess.PIPE, text=True)

            if not (err := cp.returncode):
                include = cp.stdout[:-1]
                err = err or subprocess.call(f'cc -Wall -shared -fPIC {include} {c} -o {lib}'.split())
                err = err or subprocess.call(f'strip -s -S --strip-unneeded {lib}'.split())

        if err:
            del_file(lib)
            print_err('Failed to build native library')
            sys.exit(err)
    finally:
        del_file(c)
        os.chdir(cwd)


def check_caps() -> None:
    # include <linux/capability.h>
    cap_dac_read_search = 1 << 2
    cap_sys_admin = 1 << 21

    with open(os.path.join(f'/proc/{os.getpid()}/status')) as f:
        lines = f.readlines()

    missing_caps = []

    for line in lines:
        if line.startswith('CapEff:'):
            eff_caps = int(line[line.index('\t') + 1:-1], 16)

            if not eff_caps or not (eff_caps & cap_dac_read_search):
                missing_caps.append('cap_dac_read_search')

            if not eff_caps or not (eff_caps & cap_sys_admin):
                missing_caps.append('cap_sys_admin')

            break

    if len(missing_caps):
        if len(missing_caps) == 1:
            print_err(f'Missing capability: {missing_caps[0]}')
        else:
            print_err(f'Missing capabilities: {to_str(missing_caps, joiner=", ")}')

        if sys.stdin.isatty() and sys.stdout.isatty():
            print_err(' Restarting...')
            os.execvp('priv_exec', ['priv_exec', '--caps=dac_read_search,sys_admin', '--', *sys.argv])
            print_err('Failed to execute priv_exec')

        print_err('Run with root')
        sys.exit(1)


# Builtin print() throws BrokenPipeError on SIGINT when stdout is redirected to pipe.
def override_print():
    if sys.stdout.isatty():
        return

    def _print(*args, **kwargs):
        try:
            builtins.print(*args, **kwargs, flush=True)
        except BrokenPipeError:
            global print
            print = functools.partial(builtins.print, flush=True, file=sys.stderr)

    global print
    print = _print


if __name__ == '__main__':
    nng_sock_path: str = NNG_SOCK_PATH

    # Server options
    mount_path = MOUNT_PATH
    dump_file_path = DUMP_FILE_PATH
    dump_file_size = DUMP_FILE_SIZE
    dump_save_interval: int = DUMP_SAVE_INTERVAL
    debug_level: int = DEBUG_LEVEL

    # Client options
    client_cmd: ClientCmd | None = None

    build_library('fa_notify')
    # noinspection PyUnresolvedReferences
    import fa_notify  # noqa

    get_opts()

    # Better if it's abstract.
    ipc_address: str = f'ipc://{nng_sock_path}'

    if client_cmd:
        run_client()
        sys.exit()

    check_caps()

    print = builtins.print
    override_print()

    raw_events: Queue = Queue()
    events: dict[str, SimpleNamespace] = {}
    events_lock = threading.Lock()

    dump_start_time: float = time.time()
    last_dump_ts: float = 0

    nng_server: pynng.Socket

    start_server()
