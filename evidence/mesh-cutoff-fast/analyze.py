#!/usr/bin/env python3
"""Summarize locked-VM cutoff samples; nearest-rank p99 is the maximum of 31 samples [242,256]."""
import argparse
import json
import math
import re
from pathlib import Path

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check', type=Path, help='Require summary clocks for every configured node in a tightening sample')
args = parser.parse_args()
if args.check:
    result = json.loads((args.check / 'summary.json').read_text())
    assert result['change'] in ('RuleRemoval', 'DefaultTightening')
    expected = {str(i) for i in range(len(result['installed_peers_before']))}
    assert set(result['refusal_clock']) == expected, 'summary omitted a configured node'
    frames = [json.loads(line) for line in (args.check / 'control-frames.jsonl').read_text().splitlines()]
    accepted = [f for f in frames if f['dispatched_ns'] >= result['change_started_ns'] and f['last'] and f.get('refusing_ns')]
    assert {str(f['node']) for f in accepted} == expected
    assert max(f['refusing_ns'] for f in accepted) == result['last_apply_ns']
    print('PASS: every configured node contributes its successful kernel-install clock')
    raise SystemExit(0)
rows = []
for variant in ('baseline', 'head', 'removal'):
    for backend in ('nft', 'compat'):
        samples = []
        stages = {}
        for directory in sorted((root / f'final-{variant}' / backend).iterdir(), key=lambda p: int(p.name)):
            result = json.loads((directory / 'summary.json').read_text())
            assert result['result'] == 'PASS'
            assert result['public_journal']
            assert result['installed_peers_before'] == [1000, 1000, 1000]
            assert set(result['refusal_clock'].values()) == {'kernel-install'}
            frames = [json.loads(line) for line in (directory / 'control-frames.jsonl').read_text().splitlines()]
            change = [frame for frame in frames if frame['dispatched_ns'] >= result['change_started_ns']]
            final_version = max(f['version'] for f in change)
            for log in ('run.log', 'coordinator.log'):
                for node, version, phase, microseconds in re.findall(r'CUTOFF_STAGE node=(\d+) version=(\d+) phase=(\S+) us=(\d+)', (directory / log).read_text()):
                    if int(version) == final_version:
                        stages.setdefault(phase, []).append(int(microseconds) / 1000)
            cutoffs = {}
            completions = {}
            for i in range(3):
                final = [f for f in change if f['node'] == i and f['last'] and f.get('refusing_ns')]
                assert final, 'every configured node must have a successful final installation'
                accepted = min(final, key=lambda f: f['refusing_ns'])
                cutoffs[str(i)] = accepted['refusing_ns']
                completions[str(i)] = accepted['at_ns']
            # Earlier summary files measured receivers only. Preserve originals,
            # and derive the stricter all-three-node result from their raw clocks.
            samples.append({
                'sample': int(directory.name),
                'refusal_ms': (max(cutoffs.values()) - result['change_started_ns']) / 1e6,
                'raw_cutoffs_ns': cutoffs,
                'original_summary_refusal_ms': result['revocation_to_last_peer_refusing_us'] / 1000,
                'durable_completion_ms': (max(completions.values()) - result['change_started_ns']) / 1e6,
                'first_dispatch_ms': (min(f['dispatched_ns'] for f in change) - result['change_started_ns']) / 1e6,
                'frames_per_node': {str(i): sum(f['node'] == i for f in change) for i in range(3)},
                'load': result['load'],
                'rtt_ms': result['measured_underlay_rtt_ms'],
                'node_rss_bytes': result['node_fixture_rss_bytes'],
                'coordinator_rss_bytes': result['coordinator_three_live_workers_rss_bytes'],
            })
        assert len(samples) == 31
        def quantile(field, fraction):
            values = sorted(sample[field] for sample in samples)
            return values[math.ceil(len(values) * fraction) - 1]
        stage_summary = {}
        for phase, values in stages.items():
            values.sort()
            stage_summary[phase] = {'n': len(values), 'p50_ms': values[math.ceil(len(values)*.5)-1], 'p99_ms': values[math.ceil(len(values)*.99)-1]}
        rows.append({'stages': stage_summary, 'variant': variant, 'backend': backend, 'n': len(samples),
                     'refusal_p50_ms': quantile('refusal_ms', .5),
                     'refusal_p99_ms': quantile('refusal_ms', .99),
                     'durable_p50_ms': quantile('durable_completion_ms', .5),
                     'durable_p99_ms': quantile('durable_completion_ms', .99),
                     'samples': samples})
(root / 'statistics.json').write_text(json.dumps(rows, indent=2) + '\n')
for row in rows:
    print(f"{row['variant']} {row['backend']} n={row['n']} refusal p50={row['refusal_p50_ms']:.3f} p99={row['refusal_p99_ms']:.3f} ms; durable p50={row['durable_p50_ms']:.3f} p99={row['durable_p99_ms']:.3f} ms")
