import argparse
import collections
import concurrent.futures
import csv
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import uuid

VERSION = '1.0.0'
PROFILES = {
    'syscalls': {
        'description': 'System call counts by process and syscall',
        'script': 'syscall:::entry { @calls[execname, probefunc] = count(); }',
        'columns': ['process', 'syscall', 'count'],
        'kind': 'aggregation',
    },
    'syscall-latency': {
        'description': 'System call latency distribution in microseconds',
        'script': 'syscall:::entry { self->start[probefunc] = timestamp; } syscall:::return /self->start[probefunc]/ { @latency[execname, probefunc] = quantize((timestamp - self->start[probefunc]) / 1000); self->start[probefunc] = 0; }',
        'columns': ['process', 'syscall', 'latency_histogram'],
        'kind': 'aggregation',
    },
    'process-exec': {
        'description': 'Process execution events',
        'script': 'proc:::exec-success { printf("EVENT|%lld|exec|%d|%s|%s\\n", walltimestamp, pid, execname, probefunc); }',
        'columns': ['timestamp_ns', 'event', 'pid', 'process', 'detail'],
        'kind': 'event',
    },
    'process-exit': {
        'description': 'Process exit events',
        'script': 'proc:::exit { printf("EVENT|%lld|exit|%d|%s|%s\\n", walltimestamp, pid, execname, probefunc); }',
        'columns': ['timestamp_ns', 'event', 'pid', 'process', 'detail'],
        'kind': 'event',
    },
    'scheduler': {
        'description': 'CPU scheduler on/off CPU counts',
        'script': 'sched:::on-cpu { @oncpu[execname] = count(); } sched:::off-cpu { @offcpu[execname] = count(); }',
        'columns': ['process', 'count'],
        'kind': 'aggregation',
    },
    'io': {
        'description': 'Filesystem IO operation counts by process',
        'script': 'io:::start { @io[execname] = count(); }',
        'columns': ['process', 'count'],
        'kind': 'aggregation',
    },
    'io-bytes': {
        'description': 'IO request size distribution',
        'script': 'io:::start /args[0] != NULL/ { @size[execname] = quantize(args[0]->b_bcount); }',
        'columns': ['process', 'bytes_histogram'],
        'kind': 'aggregation',
    },
    'tcp': {
        'description': 'TCP connection events where tcp provider exists',
        'script': 'tcp:::connect-request { @connect[execname] = count(); } tcp:::accept-established { @accept[execname] = count(); }',
        'columns': ['process', 'count'],
        'kind': 'aggregation',
    },
    'profile': {
        'description': 'CPU sampling by process',
        'script': 'profile-97 /arg0/ { @samples[execname] = count(); }',
        'columns': ['process', 'samples'],
        'kind': 'aggregation',
    },
}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, started TEXT NOT NULL, finished TEXT NOT NULL,
 profile TEXT NOT NULL, duration REAL NOT NULL, returncode INTEGER,
 hostname TEXT, os_release TEXT, pid INTEGER, exit_reason TEXT,
 stdout_sha256 TEXT, stderr TEXT, output TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_profile_started ON runs(profile, started);
CREATE TABLE IF NOT EXISTS events (
 run_id TEXT NOT NULL, timestamp_ns INTEGER, event TEXT,
 pid INTEGER, process TEXT, detail TEXT,
 FOREIGN KEY(run_id) REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS events_run ON events(run_id);
'''


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def emit(value, fmt='text'):
    if fmt == 'json':
        print(json.dumps(value, indent=2, ensure_ascii=False, default=str))
    elif isinstance(value, str):
        print(value)
    elif isinstance(value, list):
        for item in value:
            print(json.dumps(item, ensure_ascii=False, default=str))
    elif isinstance(value, dict):
        for key, val in value.items():
            print(f'{key}: {val}')
    else:
        print(value)


def require_freebsd():
    if platform.system() != 'FreeBSD':
        raise RuntimeError('Tracing requires FreeBSD; report and history work on other systems')


def command_available(name):
    return shutil.which(name) is not None


def execute(args, timeout=15):
    try:
        result = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout)
        return {'command': args, 'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    except subprocess.TimeoutExpired as exc:
        return {'command': args, 'returncode': 124, 'stdout': '', 'stderr': str(exc)}
    except OSError as exc:
        return {'command': args, 'returncode': 127, 'stdout': '', 'stderr': str(exc)}


def sysctl(name):
    result = execute(['sysctl', '-n', name], timeout=5)
    return result['stdout'].strip() if result['returncode'] == 0 else None


def system_info():
    details = {
        'timestamp': utc_now(),
        'hostname': platform.node(),
        'platform': platform.system(),
        'release': platform.release(),
        'machine': platform.machine(),
        'python': platform.python_version(),
        'dtrace_binary': shutil.which('dtrace'),
        'effective_uid': os.geteuid() if hasattr(os, 'geteuid') else None,
        'dtrace_module': sysctl('kern.module_path') if platform.system() == 'FreeBSD' else None,
    }
    if platform.system() == 'FreeBSD':
        for name in ['kern.ostype', 'kern.osrelease', 'kern.osrevision', 'kern.securelevel', 'security.bsd.unprivileged_proc_debug']:
            details[name] = sysctl(name)
        details['loaded_modules'] = execute(['kldstat'], timeout=8)
        details['dtrace_devices'] = [str(p) for p in pathlib.Path('/dev').glob('dtrace*')]
    return details


def list_probes(provider=None, pattern=None, limit=100, timeout=20):
    require_freebsd()
    if not command_available('dtrace'):
        raise RuntimeError('dtrace executable is not installed or not on PATH')
    selector = f'{provider}:::' if provider else '*:::*'
    result = execute(['dtrace', '-l', '-n', selector], timeout=timeout)
    if result['returncode'] != 0:
        raise RuntimeError(result['stderr'].strip() or 'Unable to enumerate DTrace probes')
    lines = result['stdout'].splitlines()
    entries = []
    regex = re.compile(pattern) if pattern else None
    for line in lines[1:]:
        parts = line.split(None, 4)
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        item = dict(zip(['id', 'provider', 'module', 'function', 'name'], parts))
        if regex and not regex.search(' '.join(parts)):
            continue
        entries.append(item)
        if limit and len(entries) >= limit:
            break
    return entries


def check_profile(profile, timeout=12):
    require_freebsd()
    if not command_available('dtrace'):
        return {'profile': profile, 'available': False, 'reason': 'dtrace not found'}
    result = execute(['dtrace', '-e', '-s', '-'], timeout=timeout)
    source = PROFILES[profile]['script']
    try:
        proc = subprocess.run(['dtrace', '-e', '-n', source], capture_output=True, text=True, timeout=timeout)
        return {'profile': profile, 'available': proc.returncode == 0, 'reason': proc.stderr.strip(), 'description': PROFILES[profile]['description']}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'profile': profile, 'available': False, 'reason': str(exc)}


def validate_script(script, timeout=15):
    require_freebsd()
    if not command_available('dtrace'):
        raise RuntimeError('dtrace executable is not available')
    try:
        proc = subprocess.run(['dtrace', '-e', '-s', '/dev/stdin'], input=script, text=True, capture_output=True, timeout=timeout)
        return {'valid': proc.returncode == 0, 'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}
    except subprocess.TimeoutExpired:
        return {'valid': False, 'returncode': 124, 'stderr': 'validation timeout'}


def database(path):
    target = pathlib.Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=15)
    conn.execute('PRAGMA busy_timeout=15000')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.executescript(SCHEMA)
    return conn


def parse_events(output):
    events = []
    for line in output.splitlines():
        if not line.startswith('EVENT|'):
            continue
        parts = line.split('|', 5)
        if len(parts) != 6:
            continue
        try:
            events.append({'timestamp_ns': int(parts[1]), 'event': parts[2], 'pid': int(parts[3]), 'process': parts[4], 'detail': parts[5]})
        except ValueError:
            continue
    return events


def store_run(path, record):
    conn = database(path)
    try:
        with conn:
            conn.execute('''INSERT INTO runs
                (id, started, finished, profile, duration, returncode, hostname,
                 os_release, pid, exit_reason, stdout_sha256, stderr, output)
                 VALUES (:id, :started, :finished, :profile, :duration, :returncode,
                 :hostname, :os_release, :pid, :exit_reason, :stdout_sha256, :stderr, :output)''', record)
            conn.executemany('''INSERT INTO events(run_id, timestamp_ns, event, pid, process, detail)
                 VALUES (:run_id, :timestamp_ns, :event, :pid, :process, :detail)''',
                 [dict(event, run_id=record['id']) for event in parse_events(record['output'])])
    finally:
        conn.close()


def trace(profile, duration, pid=None, database_path=None, output=None, quiet=False):
    require_freebsd()
    if not command_available('dtrace'):
        raise RuntimeError('dtrace executable not found')
    if duration < 1 or duration > 86400:
        raise ValueError('duration must be between 1 and 86400 seconds')
    if pid is not None and pid <= 0:
        raise ValueError('PID must be positive')
    spec = PROFILES[profile]
    script = spec['script']
    command = ['dtrace', '-q']
    if pid is not None:
        command.extend(['-p', str(pid)])
    command.extend(['-n', script])
    started = utc_now()
    start_clock = time.monotonic()
    reason = 'duration'
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace', start_new_session=True)
    except OSError as exc:
        raise RuntimeError(f'Unable to start dtrace: {exc}') from exc
    try:
        try:
            stdout, stderr = proc.communicate(timeout=duration)
            reason = 'process-exited'
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGINT)
            try:
                stdout, stderr = proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    stdout, stderr = proc.communicate()
                    reason = 'forced-termination'
    except KeyboardInterrupt:
        reason = 'interrupted'
        os.killpg(proc.pid, signal.SIGINT)
        try:
            stdout, stderr = proc.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
    elapsed = round(time.monotonic() - start_clock, 3)
    record = {
        'id': str(uuid.uuid4()), 'started': started, 'finished': utc_now(),
        'profile': profile, 'duration': elapsed, 'returncode': proc.returncode,
        'hostname': platform.node(), 'os_release': platform.release(),
        'pid': pid, 'exit_reason': reason,
        'stdout_sha256': hashlib.sha256(stdout.encode('utf-8')).hexdigest(),
        'stderr': stderr, 'output': stdout,
    }
    if output:
        path = pathlib.Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stdout, encoding='utf-8')
    if database_path:
        store_run(database_path, record)
    if not quiet:
        if stdout:
            print(stdout, end='' if stdout.endswith('\n') else '\n')
        if stderr:
            print(stderr, file=sys.stderr, end='' if stderr.endswith('\n') else '\n')
        print(f'Run {record["id"]} | {profile} | {elapsed}s | exit {proc.returncode}', file=sys.stderr)
    return record


def get_runs(path, limit=20, profile=None):
    conn = database(path)
    conn.row_factory = sqlite3.Row
    try:
        sql = '''SELECT id, started, finished, profile, duration, returncode,
                 hostname, os_release, pid, exit_reason, stdout_sha256,
                 length(output) AS output_bytes FROM runs'''
        params = []
        if profile:
            sql += ' WHERE profile = ?'
            params.append(profile)
        sql += ' ORDER BY started DESC LIMIT ?'
        params.append(limit)
        return [dict(row) for row in conn.execute(sql, params)]
    finally:
        conn.close()


def get_run(path, run_id):
    conn = database(path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute('SELECT * FROM runs WHERE id = ?', (run_id,)).fetchone()
        if row is None:
            raise ValueError(f'Run not found: {run_id}')
        result = dict(row)
        result['events'] = [dict(event) for event in conn.execute('SELECT timestamp_ns, event, pid, process, detail FROM events WHERE run_id = ? ORDER BY timestamp_ns', (run_id,))]
        return result
    finally:
        conn.close()


def summarize_output(profile, output):
    lines = [line for line in output.splitlines() if line.strip()]
    events = parse_events(output)
    summary = {'profile': profile, 'line_count': len(lines), 'event_count': len(events), 'bytes': len(output.encode('utf-8'))}
    if events:
        summary['event_types'] = dict(collections.Counter(e['event'] for e in events))
        summary['top_processes'] = collections.Counter(e['process'] for e in events).most_common(15)
    counts = []
    for line in lines:
        parts = line.split()
        if parts and parts[-1].isdigit() and not line.startswith('EVENT|'):
            counts.append({'label': ' '.join(parts[:-1]), 'count': int(parts[-1])})
    if counts:
        summary['top_counts'] = sorted(counts, key=lambda item: item['count'], reverse=True)[:20]
    return summary


def compare_runs(path, left_id, right_id):
    left = get_run(path, left_id)
    right = get_run(path, right_id)
    a = summarize_output(left['profile'], left['output'])
    b = summarize_output(right['profile'], right['output'])
    result = {'left': left_id, 'right': right_id, 'same_profile': left['profile'] == right['profile'],
              'same_output': left['stdout_sha256'] == right['stdout_sha256'],
              'duration_delta': round(right['duration'] - left['duration'], 3),
              'line_count_delta': b['line_count'] - a['line_count'],
              'event_count_delta': b['event_count'] - a['event_count']}
    if left['profile'] == right['profile']:
        a_counts = {item['label']: item['count'] for item in a.get('top_counts', [])}
        b_counts = {item['label']: item['count'] for item in b.get('top_counts', [])}
        result['count_deltas'] = [{'label': key, 'before': a_counts.get(key, 0), 'after': b_counts.get(key, 0), 'delta': b_counts.get(key, 0) - a_counts.get(key, 0)} for key in sorted(a_counts.keys() | b_counts.keys())]
    return result


def export_runs(path, destination, fmt, limit=100):
    conn = database(path)
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(row) for row in conn.execute('SELECT * FROM runs ORDER BY started DESC LIMIT ?', (limit,))]
    finally:
        conn.close()
    target = pathlib.Path(destination).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    if fmt == 'json':
        target.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding='utf-8')
    elif fmt == 'jsonl':
        target.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')
    elif fmt == 'csv':
        with target.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ['id'])
            writer.writeheader()
            writer.writerows(rows)
    return {'path': str(target), 'records': len(rows), 'format': fmt}


def environment_check():
    info = system_info()
    findings = []
    if platform.system() != 'FreeBSD':
        findings.append({'severity': 'error', 'message': 'Live tracing is supported only on FreeBSD'})
    if not command_available('dtrace'):
        findings.append({'severity': 'error', 'message': 'dtrace is not on PATH'})
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        findings.append({'severity': 'warning', 'message': 'Most DTrace operations require root privileges'})
    if platform.system() == 'FreeBSD':
        result = execute(['kldstat'], timeout=8)
        if result['returncode'] == 0:
            if 'dtrace' not in result['stdout'].lower():
                findings.append({'severity': 'info', 'message': 'No DTrace module name found in kldstat; kernel support may still be built in'})
        else:
            findings.append({'severity': 'warning', 'message': 'Unable to inspect loaded kernel modules'})
    return {'system': info, 'findings': findings}


def build_parser():
    parser = argparse.ArgumentParser(prog='freebsd-dtrace-observer', description='Read-only FreeBSD DTrace observation and forensic history')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--database', default='~/.local/share/dtrace-observer/observations.sqlite3')
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('doctor', help='Inspect DTrace prerequisites and FreeBSD environment')
    sub.add_parser('profiles', help='List built-in trace profiles')
    probes = sub.add_parser('probes', help='List available kernel DTrace probes')
    probes.add_argument('--provider')
    probes.add_argument('--pattern')
    probes.add_argument('--limit', type=int, default=100)
    check = sub.add_parser('check', help='Check a profile using DTrace compile-only mode')
    check.add_argument('profile', choices=sorted(PROFILES))
    record = sub.add_parser('record', help='Capture a bounded observation session')
    record.add_argument('profile', choices=sorted(PROFILES))
    record.add_argument('--duration', type=int, default=15)
    record.add_argument('--pid', type=int)
    record.add_argument('--output')
    record.add_argument('--no-store', action='store_true')
    record.add_argument('--quiet', action='store_true')
    history = sub.add_parser('history', help='List recorded sessions')
    history.add_argument('--limit', type=int, default=20)
    history.add_argument('--profile', choices=sorted(PROFILES))
    report = sub.add_parser('report', help='Summarize a stored session')
    report.add_argument('run_id')
    report.add_argument('--raw', action='store_true')
    diff = sub.add_parser('diff', help='Compare two recorded sessions')
    diff.add_argument('left_id')
    diff.add_argument('right_id')
    export = sub.add_parser('export', help='Export recorded sessions')
    export.add_argument('destination')
    export.add_argument('--type', choices=['json', 'jsonl', 'csv'], default='jsonl')
    export.add_argument('--limit', type=int, default=100)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.action == 'doctor':
            emit(environment_check(), args.format)
        elif args.action == 'profiles':
            emit([{'name': name, 'description': spec['description'], 'kind': spec['kind']} for name, spec in sorted(PROFILES.items())], args.format)
        elif args.action == 'probes':
            emit(list_probes(args.provider, args.pattern, args.limit), args.format)
        elif args.action == 'check':
            emit(validate_script(PROFILES[args.profile]['script']), args.format)
        elif args.action == 'record':
            record = trace(args.profile, args.duration, args.pid, None if args.no_store else args.database, args.output, args.quiet)
            if args.format == 'json':
                emit({key: val for key, val in record.items() if key != 'output'}, 'json')
            if record['returncode'] not in (0, 130, -signal.SIGINT) and record['exit_reason'] == 'process-exited':
                return 1
        elif args.action == 'history':
            emit(get_runs(args.database, args.limit, args.profile), args.format)
        elif args.action == 'report':
            record = get_run(args.database, args.run_id)
            summary = summarize_output(record['profile'], record['output'])
            result = {key: val for key, val in record.items() if key not in ('output', 'events')}
            result['summary'] = summary
            if args.raw:
                result['output'] = record['output']
                result['events'] = record['events']
            emit(result, args.format)
        elif args.action == 'diff':
            emit(compare_runs(args.database, args.left_id, args.right_id), args.format)
        elif args.action == 'export':
            emit(export_runs(args.database, args.destination, args.type, args.limit), args.format)
        return 0
    except (RuntimeError, ValueError, OSError, sqlite3.Error, re.error) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
