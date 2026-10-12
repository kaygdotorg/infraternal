"""Locate the exact source-contract break already reproduced against the real SSH engine."""
from pathlib import Path
import sys
bootstrap = Path('crates/plugins/ssh/src/bootstrap.rs').read_text()
auth = Path('crates/plugins/ssh/src/auth_order.rs').read_text()
# The real-engine before test proves exact Pending admission fails locally.
# This bisect checks when production first passed a different initial command.
if 'if script != CHECK_SCRIPT || !matches!(input, Input::Empty)' not in auth:
    sys.exit(125)
combined = 'previous_attempt::check_script(target.mode)' in bootstrap
print('initial_command=' + ('composite' if combined else 'CHECK_SCRIPT') + ' admission=exact_CHECK_SCRIPT')
sys.exit(1 if combined else 0)
