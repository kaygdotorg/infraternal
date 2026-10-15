#!/usr/bin/env python3
"""Correlate bounded numeric host records with synthetic probe ranges [D270]."""
import bisect
import json
from pathlib import Path
from ppu_stages import read_header


def index_records(records):
    groups = {}
    for row in records:
        for field in ('session', 'fd'):
            groups.setdefault((row['stage'], field, row[field]), []).append(row)
    for rows in groups.values():
        rows.sort(key=lambda row: row['ns'])
    return groups


def correlate(probe, records, origin):
    """Require causal input/output ranges, not a nearest unrelated socket write."""
    session = origin + probe['session']
    groups = records if isinstance(records, dict) else index_records(records)
    def find(stage, predicate, after=0, fd=None):
        rows = groups.get((stage, 'session', session) if fd is None else (stage, 'fd', fd), [])
        start = bisect.bisect_left(rows, after, key=lambda row: row['ns'])
        for row in rows[start:]:
            if predicate(row):
                return row
        raise ValueError(f'missing stage {stage} for session {probe["session"]}, probe {probe["number"]}')
    queued = find(2, lambda row: row['extra'] == probe['writer']
                  and row['offset'] <= probe['input_start']
                  and row['offset'] + row['bytes'] >= probe['input_end'], probe['send_before_ns'])
    written = find(4, lambda row: row['extra'] == queued['extra']
                   and row['offset'] - row['bytes'] < probe['input_end'] <= row['offset'], queued['ns'])
    read = find(5, lambda row: row['offset'] < probe['output_end'] <= row['offset'] + row['bytes'], written['ns'])
    parsed = find(6, lambda row: (row['offset'], row['bytes']) == (read['offset'], read['bytes']), read['ns'])
    built = find(7, lambda row: row['fd'] == queued['fd']
                 and row['offset'] < probe['output_end'] <= row['offset'] + row['bytes'], parsed['ns'])
    build_start = find(14, lambda row: row['offset'] == built['offset'] and row['fd'] == built['fd'], parsed['ns'])
    socket_start = find(8, lambda _: True, built['ns'], fd=built['fd'])
    socket_done = find(9, lambda row: row['offset'] == row['extra'] == built['extra'], socket_start['ns'], fd=built['fd'])
    if build_start['ns'] > built['ns']:
        raise ValueError('frame completed before construction began')
    if socket_start['ns'] > probe['receive_ns']:
        raise ValueError('matching frame began after marker receipt')
    # Logging after a successful write can itself be descheduled. The reader
    # may finish before SocketWriteDone is recorded: preserve both causal bounds.
    ms = lambda end, begin: (end - begin) / 1_000_000
    return probe | dict(queued_ns=queued['ns'], pty_written_ns=written['ns'],
        pty_read_ns=read['ns'], parsed_ns=parsed['ns'], frame_start_ns=build_start['ns'],
        frame_built_ns=built['ns'], socket_start_ns=socket_start['ns'], socket_done_ns=socket_done['ns'],
        ingress_ms=ms(queued['ns'], probe['send_before_ns']),
        input_queue_ms=ms(written['ns'], queued['ns']),
        shell_and_read_wait_ms=ms(read['ns'], written['ns']),
        parse_ms=ms(parsed['ns'], read['ns']),
        parse_to_build_ms=ms(build_start['ns'], parsed['ns']),
        frame_build_ms=ms(built['ns'], build_start['ns']),
        frame_to_socket_ms=ms(socket_start['ns'], built['ns']),
        socket_syscall_ms=ms(socket_done['ns'], socket_start['ns']),
        reader_delay_lower_ms=max(0, ms(probe['receive_ns'], socket_done['ns'])),
        reader_delay_upper_ms=ms(probe['receive_ns'], socket_start['ns']))


def report(root):
    """Reject dropped records or missing stages instead of summarizing partial data."""
    probes = json.loads((root / 'stage-probes.json').read_text())
    with (root / 'stages.log').open() as source:
        read_header(source)
    records = []
    for line in (root / 'stages.log').read_text().splitlines():
        row = json.loads(line)
        if row['kind'] == 'stages' and row['dropped']:
            raise ValueError('host stage ring overflowed')
        if row['kind'] == 'stage':
            records.append(row)
    groups = index_records(records)
    rows = [correlate(probe, groups, probes['origin']) for probe in probes['probes']]
    return dict(diagnostic_only=True, complete=probes['complete'] and len(rows) == probes['matched'],
                rows=rows, stage_records=len(records))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    result = report(args.root)
    (args.root / 'stage-correlation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(complete=result['complete'], probes=len(result['rows']),
                         stage_records=result['stage_records'])))
    raise SystemExit(0 if result['complete'] else 1)
