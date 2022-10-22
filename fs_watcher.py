#!/usr/bin/python

import collections
import datetime
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
from pypager.pager import Pager
from pypager.source import GeneratorSource

NNG_SOCK_PATH = f'/tmp/{os.path.basename(sys.argv[0])}.sock'
DUMP_FILE_PATH = f'{os.getenv("HOME") or "/var/log/"}/{os.path.basename(sys.argv[0])}.dump'
MAX_RESULTS = 10
DEBUG_LEVEL = 0


def print_exc_line():
    etype, value, tb = sys.exc_info()
    print(''.join(traceback.format_exception_only(etype, value)), file=sys.stderr, end='')


def print_err(msg: str, no_newline: bool = False):
    end = '\n'
    if no_newline:
        end = ''

    print(msg, file=sys.stderr, end=end)


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

            if self.terminated and self.empty():
                return None
            else:
                return self.queue.popleft()

    def end(self):
        self.terminated = True
        with self.waiter:
            self.waiter.notify()


def save_dump(print_msg: bool = False):
    with events_lock:
        with open(f'{dump_file_path}.tmp', 'wb') as f:
            pickle.dump(dump_start_time, f)
            pickle.dump(events, f)

        os.rename(f'{dump_file_path}.tmp', dump_file_path)
        if print_msg:
            print(f'Dumped {len(events)} events')


def load_dumps():
    try:
        with open(dump_file_path, 'rb') as f:
            start_time: float = pickle.load(f)
            loaded_events = pickle.load(f)
    except FileNotFoundError:
        pass
    else:
        global dump_start_time, events
        dump_start_time = start_time
        events = loaded_events
        print(f'Loaded {len(events)} events')


def handle_event(evt: dict):
    raw_events.put(evt)


def kill_me(sig: int = None, *_):
    if sys.stdout.isatty():
        print(f'\r')

    if sig:
        print(f'{signal.strsignal(sig)}, exiting...')
    else:
        print('Exiting...')

    save_dump(True)
    if nng_server:
        nng_server.close()

    # poll() in C receives EINTR only if running on main
    # thread. So we need to exit the loop manually.
    native_bind.stop_fs_events()

    if raw_events:
        raw_events.end()

    global terminated
    terminated = True


class Data:
    UNKNOWN: str = 'UNKNOWN'

    class EventCount:
        def __init__(self):
            self.total: int = 0
            self.grand_total: int = 0

        def update(self, count: int):
            self.total += 1
            self.grand_total += count

    def __init__(self):
        self.start_time: float = dump_start_time
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


def start_nng_server():
    while not terminated:
        try:
            msg: pynng.Message = nng_server.recv_msg()
        except pynng.exceptions.Closed:
            Thread.exit_msg_exc(inspect.currentframe().f_lineno)
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

        with events_lock:
            lst = list(events.values())

        data: Data = Data()
        f = cmd.filter

        for ev in lst:
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
        msg.pipe.send(pickle.dumps(data))


class Thread(threading.Thread):
    def __init__(self, target: Callable, name=None, daemon=False):
        super(Thread, self).__init__(target=Thread._run_target, args=[target], name=name, daemon=daemon)

    @staticmethod
    def _run_target(func: Callable):
        Thread.set_excepthook()
        print(f'Starting thread {threading.current_thread().name}...')
        func()
        Thread.exit_msg()

    @staticmethod
    def set_excepthook():
        if threading.current_thread() is threading.main_thread():
            sys.excepthook = Thread.handle_uncaught_err
        else:
            threading.excepthook = lambda args: Thread.handle_uncaught_err(*args[:-1])

    @staticmethod
    def handle_uncaught_err(err_type, value, tb):
        print_err(f'Uncaught exception in thread: {threading.current_thread().name}:')
        traceback.print_exception(err_type, value, tb)
        kill_me()

    @staticmethod
    def exit_msg():
        print(f'Exiting {threading.current_thread().name}...')

    @staticmethod
    def exit_msg_exc(lineno: int = None):
        if lineno:
            print_err(f'line {lineno}: '
                      f'Exception in {threading.current_thread().name}: ', no_newline=True)
            print_exc_line()
        else:
            print_err(f'Exception in {threading.current_thread().name}')
            traceback.print_exc()


def to_str(lst: list, joiner: str = ' '):
    return joiner.join(str(s) for s in lst)


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
            if not (eff_caps & cap_dac_read_search):
                missing_caps.append('cap_dac_read_search')
            if not (eff_caps & cap_sys_admin):
                missing_caps.append('cap_sys_admin')

            if len(missing_caps) == 1:
                print_err(f'Missing capability: {missing_caps[0]}, restarting...')
            elif len(missing_caps) > 1:
                print_err(f'Missing capabilities: {to_str(missing_caps, joiner=", ")}, restarting...')

            break

    if sys.stdin.isatty() and len(missing_caps):
        os.execvp('priv_exec', ['priv_exec', '--caps=dac_read_search,sys_admin', '--', *sys.argv])
        print_err('Failed to execute priv_exec')
        sys.exit(1)


def start_server():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, kill_me)

    load_dumps()

    global nng_server
    nng_server = pynng.Rep0(listen=ipc_address, send_timeout=2000)
    os.chmod(nng_sock_path,
             stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

    Thread(target=start_nng_server, name='NNGServer').start()
    Thread(target=lambda: native_bind.start_fs_events_nat(handle_event), name="FsEventListener").start()

    Thread.set_excepthook()

    print(f'Parsing raw events queue on {threading.current_thread().name}...')
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

        key = uid + '|' + gid + '|' + cmd + '|' + p_cmd + '|' + evt_name + '|' + path
        key: str = hashlib.md5(key.encode()).hexdigest()

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

        if last_dump_ts + 300 < time.time():
            save_dump(debug_level >= 2)
            last_dump_ts = time.time()

    Thread.exit_msg()


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


def print_data(data: Data):
    def header(name: str):
        return [
            ('bold underline fg:#7CB9E8', f'\n{name}\n'),
            ('', '=================================================\n')
        ]

    def summary(lst: list):
        return [
            (
                '',
                f'{100 * i[1].grand_total / data.total_count.grand_total:6.2f}%   '
                f'{i[1].grand_total:<7} '
                f'{i[1].total:<7} {i[0]}\n'
            )
            for i in lst
        ]

    yield [
        ('', f'Since: {datetime.datetime.fromtimestamp(data.start_time).strftime("%d-%b-%y %I:%M%p")}\n'),
        ('', f'Total events: {data.total_count.grand_total} | {data.total_count.total}\n')
    ]

    yield header('UID')
    yield summary(data.uid_cnt)

    yield header('CMD')
    yield summary(data.cmd_cnt)

    yield header('PARENT CMD')
    yield summary(data.p_cmd_cnt)

    yield header('EVENT')
    yield summary(data.event_cnt)

    yield header('PATH')
    yield summary(data.path_cnt)

    yield header('DETAIL')
    yield [
        (
            '',
            f"{f'{100 * evt.count / data.total_count.grand_total:<.2f}%':<10}"
            f'{evt.count:<10} {f"{evt.uid}.{evt.gid}":<15} {evt.evt}\n'
            f'CMD:      {evt.cmd}\n'
            f'PARENT:   {evt.p_cmd}\n'
            f'DIR:      {evt.path}\n\n'
        )
        for evt in data.lst
    ]


def start_client() -> None:
    if not os.path.exists(nng_sock_path):
        print_err('Server not running')
        print_usage()
        sys.exit(1)

    client = pynng.Req0(dial=ipc_address, send_timeout=1000, recv_timeout=5000)
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
    print(f'\nOptions:')
    print(f'\t-h|--help                Show help')
    print(f'\t--sock=<PATH>            Unix socket path (default: {NNG_SOCK_PATH})')
    print(f'\t--max=all|<NUM>          Max no. of results (default: {MAX_RESULTS})')
    print(f'\t--filter-<TYPE>=<VALUE>  Apply filters to list')
    print(f'\t--server                 Run server')
    print(f'\t--dump-file=<PATH>       Dump file path (default: {DUMP_FILE_PATH})')
    print(f'\t--debug=1|2              Debug level (default: {DEBUG_LEVEL})')

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
    print(f'\t\tA value (not for: {f.FILTER_EVENT})')

    print('\n\tFilter EVENT:\n\t\t', end='')
    print(', '.join(native_bind.FS_EVENTS))

    print()

    if ex_code is not None:
        sys.exit(ex_code)


def get_opts() -> None:
    opt_help: str = 'help'
    opt_server: str = 'server'
    opt_socket: str = 'sock'
    opt_dump_file: str = 'dump-file'
    opt_debug: str = 'debug'
    opt_f_uid: str = 'filter-uid'
    opt_f_cmd: str = 'filter-cmd'
    opt_f_pcmd: str = 'filter-pcmd'
    opt_f_event: str = 'filter-event'
    opt_f_path: str = 'filter-path'
    opt_max_res: str = 'max'

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            'h',
            [
                opt_help,
                opt_server,
                f'{opt_socket}=',
                f'{opt_dump_file}=',
                f'{opt_debug}=',
                f'{opt_f_uid}=',
                f'{opt_f_cmd}=',
                f'{opt_f_pcmd}=',
                f'{opt_f_event}=',
                f'{opt_f_path}=',
                f'{opt_max_res}='
            ]
        )
    except getopt.GetoptError:
        print_exc_line()
        print_usage()
        sys.exit(1)

    if args:
        print_err(f'Unexpected arguments: {to_str(args)}')
        print_usage(1)

    if (f'--{opt_server}', '') in opts:
        cmd = ftr = None
    else:
        cmd: ClientCmd | None = ClientCmd()
        ftr: ClientCmd.Filter | None = ClientCmd.Filter()

    global nng_sock_path, dump_file_path, debug_level, client_cmd

    def assert_not_server(option: str):
        if not cmd:
            print_err(f'--{option} is mutually exclusive with --{opt_server}')
            sys.exit(1)

    def assert_server(option: str):
        if cmd:
            print_err(f'--{option} can only be used with --{opt_server}')
            sys.exit(1)

    for opt, val in opts:
        if opt == f'--{opt_server}':
            pass

        elif opt == f'--{opt_socket}':
            nng_sock_path = val

        elif opt == f'--{opt_debug}':
            assert_server(opt_debug)
            if not val.isdecimal():
                print_err(f'"{val}" is not an integer')
                sys.exit(1)
            debug_level = int(val)

        elif opt == f'--{opt_dump_file}':
            assert_server(opt_dump_file)
            dump_file_path = val

        elif opt == f'--{opt_f_uid}':
            assert_not_server(opt_f_uid)
            if val != ClientCmd.Filter.UNKNOWN and not val.isdecimal():
                print_err(f'Bad {opt_f_uid}: {val}')
                sys.exit(1)
            ftr.uid = val

        elif opt == f'--{opt_f_cmd}':
            assert_not_server(opt_f_cmd)
            ftr.cmd = val

        elif opt == f'--{opt_f_pcmd}':
            assert_not_server(opt_f_pcmd)
            ftr.p_cmd = val

        elif opt == f'--{opt_f_event}':
            assert_not_server(opt_f_event)
            if val not in native_bind.FS_EVENTS:
                print_err(f'Bad {opt_f_event}: {val}')
                sys.exit(1)
            ftr.event = val

        elif opt == f'--{opt_f_path}':
            assert_not_server(opt_f_path)
            ftr.path = val

        elif opt == f'--{opt_max_res}':
            assert_not_server(opt_max_res)
            if val.startswith('all'):
                cmd.max_results = None
            elif not val.isdecimal():
                print_err(f'Bad {opt_max_res}: {val}')
                sys.exit(1)
            else:
                cmd.max_results = int(val)

        elif opt == f'--{opt_help}' or opt == '-h':
            print_usage(0)
        else:
            sys.exit(1)  # Should not happen.

    if ftr and not ftr.is_empty():
        cmd.filter = ftr

    client_cmd = cmd


def build_library(mod) -> None:
    if not sys.stdin.isatty():
        return

    my_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

    lib = f'{mod}.so'
    if os.path.exists(os.path.join(my_dir, lib)):
        return

    cwd = os.getcwd()
    os.chdir(my_dir)

    print('Building native library...')

    def del_file(*files):
        for file in files:
            if os.path.exists(file):
                os.remove(file)

    c = f'{mod}.c'

    # cproto -f1 proc_event_connector.c | grep -vE '/\*' | sed 's|;\s$||'

    try:
        if not (err := subprocess.call(f'cython -3 {mod}.pyx -o {c}'.split())):
            ver = f'{sys.version_info[0]}.{sys.version_info[1]}'
            cp = subprocess.run(f'python{ver}-config --includes'.split(),
                                stdout=subprocess.PIPE, text=True)

            if not (err := cp.returncode):
                include = cp.stdout[:-1]
                err = err or subprocess.call(f'cc -shared -fPIC {include} {c} -o {lib}'.split())
                err = err or subprocess.call(f'strip -s -S --strip-unneeded {lib}'.split())

        if err:
            del_file(lib)
            print_err('Failed to build native library')
            sys.exit(err)
    finally:
        del_file(c)
        os.chdir(cwd)


if __name__ == '__main__':
    build_library('native_bind')
    import native_bind

    nng_sock_path: str = NNG_SOCK_PATH
    dump_file_path = DUMP_FILE_PATH
    debug_level: int = DEBUG_LEVEL
    client_cmd: ClientCmd | None = None

    get_opts()

    ipc_address: str = f'ipc://{nng_sock_path}'

    if client_cmd:
        start_client()
        sys.exit()

    check_caps()

    raw_events: Queue = Queue()
    events: dict[str, SimpleNamespace] = {}
    events_lock = threading.Lock()
    nng_server: pynng.Socket

    dump_start_time: float = time.time()
    last_dump_ts: int = 0
    terminated: bool = False

    start_server()
