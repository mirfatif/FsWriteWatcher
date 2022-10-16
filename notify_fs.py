#!/usr/bin/python

import collections
import getopt
import hashlib
import inspect
import os.path
import pickle
import signal
import sys
import threading
import time
from types import SimpleNamespace
import pynng
import pypager
from pypager.source import GeneratorSource
from pypager.pager import Pager
import native_bind

PROTO_IPC = 'ipc://'
NNG_SOCK_PATH = '/tmp/notify_fs.sock'
DUMP_FILE = '/home/irfan/notify_fs.dump'


def print_err(msg: str):
    print(msg, file=sys.stderr)


def print_exc(ex: Exception):
    print(ex, file=sys.stderr)


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


def save_dump():
    with _events_lock:
        with open(f'{DUMP_FILE}.tmp', 'wb') as f:
            pickle.dump(_events, f)

        os.rename(f'{DUMP_FILE}.tmp', DUMP_FILE)

        print(f'Dumped {len(_events)} events')


def load_dumps():
    try:
        with open(DUMP_FILE, 'rb') as f:
            events = pickle.load(f)
    except FileNotFoundError:
        pass
    else:
        global _events
        _events = events
        print(f'Loaded {len(_events)} events')


def handle_event(evt: dict):
    _queue.put(evt)


def _quit(sig: int = None, *_):
    if sys.stdout.isatty():
        if sig:
            print(f'\rReceived signal {signal.strsignal(sig)}, exiting...')
        else:
            print('\rExiting...')

    save_dump()
    nng_server.close()

    # poll() in C receives EINTR only if running on main
    # thread. So we need to exit the loop manually.
    native_bind.stop_fs_events()

    _queue.end()

    global _terminated
    _terminated = True


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
    while not _terminated:
        try:
            msg: pynng.Message = nng_server.recv_msg()
        except pynng.exceptions.Closed as ex:
            print(f'line {inspect.currentframe().f_lineno}: '
                  f'Exiting {threading.current_thread().name}:', ex)
            return

        try:
            cmd: ClientCmd = pickle.loads(msg.bytes)
        except pickle.UnpicklingError as ex:
            print_err(f'Bad command received from client: {ex}')
            continue

        if not isinstance(cmd, ClientCmd):
            print_err(f'Bad command type "{type(cmd)}"')
            continue

        if cmd.cmd != ClientCmd.CMD_GET_EVENT_LIST:
            print_err(f'Bad command received from client: {cmd.cmd}')
            continue

        with _events_lock:
            lst = list(_events.values())

        data: Data = Data()
        f = cmd.filter

        for ev in lst:
            if f:
                if (f.uid == f.NONE and not ev.uid) or (f.uid is not None and ev.uid != f.uid):
                    continue

                if (f.cmd == f.NONE and ev.cmd) or \
                        (ev.cmd and f.cmd is not None and not ev.cmd.startswith(f.cmd)):
                    continue

                if (f.p_cmd == f.NONE and ev.p_cmd) or \
                        (ev.p_cmd and f.p_cmd is not None and not ev.p_cmd.startswith(f.p_cmd)):
                    continue

                if f.event is not None and ev.evt != f.event:
                    continue

                if f.path is not None and ev.path and not ev.path.startswith(f.path):
                    continue

            data.update(ev)

        data.finalize(cmd.max_results)
        msg.pipe.send(pickle.dumps(data))


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
                print_err(f'Missing capability: {missing_caps[0]}')
            elif len(missing_caps) > 1:
                print_err(f'Missing capabilities: {to_str(missing_caps, joiner=", ")}')

            break

    if len(missing_caps):
        os.system(f'priv_exec --caps=dac_read_search,sys_admin -- {to_str(sys.argv)}')
        sys.exit()


def start_server():
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(sig, _quit)

    load_dumps()

    print('Starting command server...')
    threading.Thread(target=start_nng_server, name='NNGServer', daemon=False).start()

    def call_nat():
        try:
            native_bind.start_fs_events_nat(handle_event)
        except OSError as ex:
            print_err(f'line {inspect.currentframe().f_lineno}: {ex}')
            _quit()

    threading.Thread(target=call_nat, name="FsEventListener", daemon=False).start()

    while evt := _queue.get():
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

        with _events_lock:
            if e := _events.get(key):
                e.count += 1
            else:
                _events[key] = SimpleNamespace(
                    uid=uid,
                    gid=gid,
                    cmd=cmd,
                    p_cmd=p_cmd,
                    evt=evt_name,
                    path=path,
                    count=1
                )

        global _dump_ts

        if _dump_ts + 300 < time.time():
            save_dump()
            _dump_ts = time.time()


class ClientCmd:
    CMD_GET_EVENT_LIST: int = 0
    DEF_MAX_COUNT: int = 10

    class Filter:
        NONE: str = 'none'

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
        self.max_results: int = self.DEF_MAX_COUNT


def print_data(data: Data):
    def header(name: str):
        return [
            ('bold underline fg:red', f'\n{name}\n'),
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

    yield [('', f'Total events: {data.total_count.grand_total} | {data.total_count.total}\n')]

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
    if not os.path.exists(NNG_SOCK_PATH):
        print_err('Server not running')
        exit(1)

    client = pynng.Req0(dial=f'{PROTO_IPC}{NNG_SOCK_PATH}', send_timeout=1000, recv_timeout=5000)
    client.send(pickle.dumps(_client_cmd))
    data: Data = pickle.loads(client.recv())
    client.close()

    if not data.total_count.grand_total:
        print_err('No events found')
    else:
        pager = pypager.pager.Pager()
        pager.add_source(pypager.source.GeneratorSource(print_data(data)))
        pager.run()


def print_help(ex_code: int = None) -> None:
    print()
    print(f'Usage:\n\t{os.path.basename(sys.argv[0])} [-h|--help] '
          f'[--server] [--filter-<FILTER>=<FILTER_VAL>] [--max-results=COUNT]')

    f = ClientCmd.Filter

    print('\n\tFILTER\n\t\t', end='')
    print(*f.FILTERS_ALL)

    print(f'\n\tFILTER_VAL\n\t\t', end='')
    print(f'{ClientCmd.Filter.NONE} (for {f.FILTER_UID}, {f.FILTER_CMD} and {f.FILTER_P_CMD})')
    print(f'\t\tEVENT (for {f.FILTER_EVENT})')
    print(f'\t\tA value (except for {f.FILTER_EVENT})')

    print('\n\tEVENT\n\t\t', end='')
    print(*native_bind.FS_EVENTS)

    print('\n\tCOUNT\n\t\t', end='')
    print(f'{ClientCmd.Filter.NONE} or a number (default {ClientCmd.DEF_MAX_COUNT})')

    print()

    if ex_code is not None:
        sys.exit(ex_code)


def get_opts() -> ClientCmd | None:
    opt_help: str = 'help'
    opt_server: str = 'server'
    opt_sort_by: str = 'sort-by'
    opt_f_uid: str = 'filter-uid'
    opt_f_cmd: str = 'filter-cmd'
    opt_f_pcmd: str = 'filter-pcmd'
    opt_f_event: str = 'filter-event'
    opt_f_path: str = 'filter-path'
    opt_max_res: str = 'max-results'

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            'h',
            [
                opt_help,
                opt_server,
                f'{opt_sort_by}=',
                f'{opt_f_uid}=',
                f'{opt_f_cmd}=',
                f'{opt_f_pcmd}=',
                f'{opt_f_event}=',
                f'{opt_f_path}=',
                f'{opt_max_res}='
            ]
        )
    except getopt.GetoptError as e:
        print_exc(e)
        print_help()
        sys.exit(1)

    if args:
        print_err(f'Unexpected arguments: {to_str(args)}')
        print_help(1)

    cmd: ClientCmd | None = ClientCmd()
    ftr: ClientCmd.Filter | None = ClientCmd.Filter()

    def assert_not_server(option: str):
        if not cmd:
            print_err(f'--{option} is mutually exclusive with --{opt_server}')
            print_help(1)

    for opt, val in opts:
        if opt == f'--{opt_server}':
            cmd = ftr = None

        elif opt == f'--{opt_sort_by}':
            assert_not_server(opt_sort_by)
            if val not in ftr.FILTERS_ALL:
                print_err(f'Bad {opt_sort_by}: {val}')
                print_help(1)
            cmd.sort_by = val

        elif opt == f'--{opt_f_uid}':
            assert_not_server(opt_f_uid)
            if val != ClientCmd.Filter.NONE and not val.isdecimal():
                print_err(f'Bad {opt_f_uid}: {val}')
                print_help(1)
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
                print_help(1)
            ftr.event = val

        elif opt == f'--{opt_f_path}':
            assert_not_server(opt_f_path)
            ftr.path = val

        elif opt == f'--{opt_max_res}':
            assert_not_server(opt_max_res)
            if val == ClientCmd.Filter.NONE:
                cmd.max_results = None
            elif not val.isdecimal():
                print_err(f'Bad {opt_max_res}: {val}')
                print_help(1)
            else:
                cmd.max_results = int(val)

        elif opt == f'--{opt_help}' or opt == '-h':
            print_help(0)
        else:
            sys.exit(1)  # Should not happen.

    if cmd and ftr and not ftr.is_empty():
        cmd.filter = ftr

    return cmd


if __name__ == '__main__':
    if not (_client_cmd := get_opts()):
        check_caps()

        _queue: Queue = Queue()
        _events: dict[str, SimpleNamespace] = {}
        _events_lock = threading.Lock()

        nng_server = pynng.Rep0(listen=f'{PROTO_IPC}{NNG_SOCK_PATH}', send_timeout=2000)

        _dump_ts: int = 0
        _terminated: bool = False

        start_server()
    else:
        start_client()
