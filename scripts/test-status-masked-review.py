#!/usr/bin/env python3
"""Check D303 for retained server data beside a healthy host daemon (#237).

Run with a stripped static infraternal image as the sole argument. Disposable
container roots exercise release path detection without changing host units.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    scratch = Path(os.environ.get(
        "CARGO_TARGET_DIR",
        str(Path.home() / ".cache/codex-scratch/review-status-crash-loop-237-r2"),
    ))
    scratch.mkdir(parents=True, exist_ok=True)
    failures = []
    with tempfile.TemporaryDirectory(prefix="masked-status-", dir=scratch) as temporary:
        for masked in (False, True):
            case = Path(temporary) / ("masked" if masked else "missing")
            for directory in ("units", "data", "bin"):
                (case / directory).mkdir(parents=True)
            if masked:
                (case / "units/infraternal-server.service").symlink_to("/dev/null")
            (case / "data/infraternal.sqlite").touch()
            (case / "units/infraternal-agent.service").write_text(
                "[Service]\nExecStart=/usr/bin/infraternal agent run\n"
            )
            manager = case / "bin/systemctl"
            manager.write_text(
                "#!/bin/sh\nfor unit; do :; done\n"
                "case \"$unit\" in *server*) printf '%s\\n' "
                "LoadState=masked ActiveState=inactive SubState=dead MainPID=0; exit 0;; esac\n"
                "printf '%s\\n' ActiveState=active SubState=running "
                "MainPID=42 NRestarts=0 ExecMainStartTimestampMonotonic=1\n"
            )
            manager.chmod(0o755)
            for json_output in (False, True):
                command = [
                    "docker", "run", "--rm", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "-v", f"{binary}:/infraternal:ro",
                    "-v", f"{case}/units:/etc/systemd/system:ro",
                    "-v", f"{case}/data:/var/lib/infraternal:ro",
                    "-v", f"{case}/bin:/fixture-bin:ro",
                    "-e", "PATH=/fixture-bin:/usr/bin:/bin", "ubuntu:22.04",
                    "/infraternal", "status",
                ]
                if json_output:
                    command.append("--json")
                output = subprocess.run(
                    command, capture_output=True, text=True, timeout=20, check=False
                )
                label = f"masked={masked} json={json_output}"
                print(f"{label} exit={output.returncode}\n{output.stdout}{output.stderr}")
                if output.returncode != 5:
                    failures.append(f"{label}: expected exit 5, got {output.returncode}")
                if json_output:
                    envelope = json.loads(output.stdout)
                    assert envelope["schema_version"] == 1
                    server = next(row for row in envelope["data"]["components"]
                                  if row["name"] == "server")
                    assert server["state"] == "Stopped"
                    if envelope["ok"] is not False:
                        failures.append(f"{label}: known stopped server returned ok=true")
                if "server and the infraternal agent are running" in output.stdout:
                    failures.append(f"{label}: false grouped running headline")
    assert not failures, "\n".join(failures)


if __name__ == "__main__":
    main()
