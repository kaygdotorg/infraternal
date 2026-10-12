"""Measure exact baseline/fixed release modules locally with machine/load evidence."""
from pathlib import Path
import os, platform, resource, subprocess
root = Path(__file__).parent
print(f"ENVIRONMENT machine={platform.node()} kernel={platform.release()} arch={platform.machine()} cores={os.cpu_count()} cpu_weight=10000", flush=True)
for label, case in [("baseline", "cross_architecture_cold_and_warm_cache_measurements"), ("fixed", "cross_architecture_cold_and_warm_cache_measurements"), ("fixed", "fifty_abandoned_downloads_startup_measurement")]:
    print(f"RUN source={label} test={case} load_before={Path('/proc/loadavg').read_text().split()[:3]}", flush=True)
    subprocess.run([str(root / f"{label}-bench-runner"), case, "--ignored", "--nocapture"], check=True)
    print(f"RESULT source={label} load_after={Path('/proc/loadavg').read_text().split()[:3]} fixture_process_maxrss_kib={resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}", flush=True)
