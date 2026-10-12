"""Exercise an already-open TCP socket after both nodes remove its initiating access [242], #173."""
import contextlib
import copy
import importlib.util
import json
import socket
import sys
from pathlib import Path

repo, fixture, evidence = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
family, fallback = sys.argv[4], sys.argv[5] == "compatibility"
spec = importlib.util.spec_from_file_location("stateproof", repo / "scripts/mesh-access-state-proof.py")
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)
campaign = state.HeldCampaign.__new__(state.HeldCampaign)
client = None
server_code = """import socket,sys,threading
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET)
s.bind((sys.argv[1],5540));s.listen();print('ready',flush=True)
c,a=s.accept();print('accepted',flush=True)
def echo():
 while True:
  b=c.recv(4096)
  if not b:break
  c.sendall(b)
threading.Thread(target=echo,daemon=True).start()
for line in sys.stdin:
 c.sendall(b'reverse-probe');print('sent',flush=True)
"""

try:
    with (evidence / "setup.log").open("w") as log, contextlib.redirect_stdout(log):
        campaign.__init__(fixture, fallback)
    destination = campaign.addresses[1][family]
    server = campaign.spawn("python3", "-c", server_code, destination)
    assert server.stdout.readline().strip() == "ready"
    client = socket.socket(socket.AF_INET6 if family == "ipv6" else socket.AF_INET)
    client.settimeout(2)
    client.connect((destination, 5540))
    assert server.stdout.readline().strip() == "accepted"
    client.sendall(b"before")
    assert client.recv(64) == b"before"
    before = json.loads(campaign.remote("python3", str(repo / "scripts/mesh-access-state-proof.py"), "--dump"))
    replies = []
    for index, node in enumerate((campaign.left, campaign.right)):
        chunk = copy.deepcopy(campaign.chunks[index])
        chunk.update(from_version=campaign.version, version=campaign.version + 1)
        # A -> B is removed at both ends. B -> A remains permitted, as under
        # the community default with one directed restricting rule.
        chunk["upserted"][str(2 - index)]["outbound" if index == 0 else "inbound"] = "None"
        replies.append(state.proof.request(node, chunk))
        assert replies[-1]["applied"]
    after = json.loads(campaign.remote("python3", str(repo / "scripts/mesh-access-state-proof.py"), "--dump"))
    assert not any(row["dst"] == destination and row["dport"] == 5540 for row in after)
    # Transmit on the SAME accepted TCP socket, without creating a socket,
    # reconnecting or sending a SYN. Loose tracking must not reopen A -> B.
    server.stdin.write("send\n")
    server.stdin.flush()
    assert server.stdout.readline().strip() == "sent"
    try:
        reverse = client.recv(64)
        client.sendall(b"after")
        received = client.recv(64)
    except OSError:
        reverse, received = b"", b""
    recreated = json.loads(campaign.remote("python3", str(repo / "scripts/mesh-access-state-proof.py"), "--dump"))
    result = dict(family=family, backend="compatibility" if fallback else "nft",
                  acknowledged=replies, before=before, after=after, recreated=recreated,
                  reverse=reverse.decode(), received=received.decode(), refused=received != b"after")
    (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("family", "backend", "reverse", "received", "refused")}))
    assert result["refused"], "retired TCP connection resumes after permitted reverse traffic"
finally:
    if client:
        client.close()
    for process in getattr(campaign, "processes", []):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
