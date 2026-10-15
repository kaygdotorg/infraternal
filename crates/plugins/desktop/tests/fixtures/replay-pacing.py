# Role: prove repair controls coalesce into the replay's next source interval, using an owned framed Unix helper (#146).
import base64, json, os, pathlib, shutil, socket, struct, subprocess, sys, time, uuid

helper = pathlib.Path(__file__).with_name("source-helper.py").resolve()
parent = pathlib.Path(sys.argv[1])
parent.mkdir(parents=True, exist_ok=True)
root = parent / ("replay-" + uuid.uuid4().hex)
root.mkdir(mode=0o700)
for name in ("r", "c"):
    (root / name).mkdir(mode=0o700)
(root / "clip.json").write_text(json.dumps({"role":"Synthetic framing fixture only", "width":960,"height":600,"bytes_base64":base64.b64encode(b"\x00\x00\x00\x01\x65").decode()}))
environment = dict(os.environ, INFRATERNAL_BENCH_REPLAY_CLIP=str(root / "clip.json"), INFRATERNAL_BENCH_REPLAY_FPS="1", INFRATERNAL_BENCH_REPLAY_TIMER="select", INFRATERNAL_BENCH_REPLAY_QOS="0")
child = subprocess.Popen([sys.executable,str(helper),"r","--once","--companion-runtime","c"],cwd=root,env=environment)
connection = socket.socket(socket.AF_UNIX)
def exact(count):
    result=b""
    while len(result)<count:
        part=connection.recv(count-len(result))
        if not part: raise EOFError()
        result+=part
    return result
def packet(kind, body):
    body=json.dumps(body).encode()
    return struct.pack(">IBB",len(body)+2,1,kind)+body
def receive():
    length,version,kind=struct.unpack(">IBB",exact(6))
    assert version==1 and 2<=length<=65536
    return kind,exact(length-2)
try:
    deadline=time.monotonic()+5
    while not (root/"r/desktop.sock").exists():
        assert time.monotonic()<deadline and child.poll() is None
        time.sleep(.01)
    # Binding uses a short relative name in the child; Linux connects through
    # its directory descriptor path without exceeding sun_path under scratch.
    previous=os.getcwd();os.chdir(root)
    try: connection.connect("r/desktop.sock")
    finally: os.chdir(previous)
    connection.settimeout(5)
    connection.sendall(packet(2,{"target":{"type":"screen","display_id":1},"size":{"width":960,"height":600,"canvas_width":480,"canvas_height":300,"backing_scale":2}}))
    assert receive()[0]==66
    assert receive()[0]==70
    connection.sendall(packet(7,{})*20)
    for _ in range(20):
        kind,_=receive()
        assert kind==68, "repair controls generated unpaced video instead of coalescing"
    kind,body=receive()
    assert kind==70 and body[8]==1
    print("replay repair coalescing: PASS (20 controls, one paced keyframe)")
finally:
    connection.close()
    try: child.wait(timeout=5)
    except subprocess.TimeoutExpired: child.terminate();child.wait(timeout=5)
    shutil.rmtree(root)
