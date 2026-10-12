#!/usr/bin/python3
"""Probe nested production-style shell quoting on the owned target using synthetic public text only (#190)."""
import subprocess

def quoted(value):
    return "'" + value.replace("'", "'\\''") + "'"

program = "printf 'public-quote-proof\\n'"
for depth in range(1, 5):
    program = "sh -c " + quoted(program)
    for shell in ("/bin/bash", "/bin/fish"):
        result = subprocess.run([shell, "-c", program], capture_output=True, text=True)
        print(f"QUOTE depth={depth} shell={shell} exit={result.returncode} proof={result.stdout == 'public-quote-proof'+chr(10)}")
        if result.returncode:
            print(result.stderr)
