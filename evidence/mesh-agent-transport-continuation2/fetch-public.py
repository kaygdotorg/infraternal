"""Copies only named public D215 reports and diagnostics from the perf VM."""
import shlex
import subprocess
import tarfile
from pathlib import Path

E = Path.cwd() / 'evidence/mesh-agent-transport-continuation2'
remote = '''from pathlib import Path
import sys, tarfile
root = Path('/root/infraternal-bench/mat129-c2')
names = ['retained-200.log','retained-200.exit','review-r5.log','review-r5.exit','scale.log','scale.exit','scale-unguarded.log','scale-unguarded.exit','tcp-spacing-perf.log','tcp-spacing-perf.exit']
names += [f'rtt-{r}/{n}' for r in [0,150,300] for n in [f'namespace-transport-{r}.json','test.log','test.exit','load-before.txt','load-after.txt','server-firewall-observed.nft','node-firewall-observed.nft']]
names += [str(p.relative_to(root)) for p in (root/'scale').glob('*.json')]
t = tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz')
for n in names:
    if (root/n).is_file(): t.add(root/n, arcname=n, recursive=False)
t.close()
'''
command = 'python3 -c ' + shlex.quote(remote)
with (E/'public-results.tar.gz').open('wb') as output, (E/'fetch.log').open('w') as log:
    result = subprocess.run(['netbird','ssh','--no-browser','root@10.69.69.208',command], stdout=output, stderr=log)
    assert result.returncode == 0
with tarfile.open(E/'public-results.tar.gz','r:gz') as archive:
    archive.extractall(E/'perf-results', filter='data')
print('Public proof artifacts:', E/'perf-results')
