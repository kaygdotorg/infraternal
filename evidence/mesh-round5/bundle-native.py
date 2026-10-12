"""Bundle identical native artifacts with a private loader for the authorized perf VM."""
import hashlib,json,re,shutil,struct,subprocess,sys
from pathlib import Path
source=Path(sys.argv[1]);destination=Path(sys.argv[2]);root=destination.parent;libs=root/'lib';libs.mkdir(parents=True,exist_ok=True)
blob=bytearray(source.read_bytes());assert blob[:6]==b'\x7fELF\x02\x01'
phoff=struct.unpack_from('<Q',blob,32)[0];size,count=struct.unpack_from('<HH',blob,54)
interpreter=None
for index in range(count):
 off=phoff+index*size
 if struct.unpack_from('<I',blob,off)[0]==3:
  start=struct.unpack_from('<Q',blob,off+8)[0];length=struct.unpack_from('<Q',blob,off+32)[0]
  interpreter=bytes(blob[start:start+length]).rstrip(b'\0').decode()
  new=b'/root/infraternal-bench/mesh-policy/round5/lib/ld.so\0';assert len(new)<=length
  blob[start:start+length]=new.ljust(length,b'\0')
# Replace the existing native search path as well, including manager-launched
# shims whose environment need not carry LD_LIBRARY_PATH.
loads=[];dynamic=None
for index in range(count):
 off=phoff+index*size;kind=struct.unpack_from('<I',blob,off)[0]
 start=struct.unpack_from('<Q',blob,off+8)[0];virtual=struct.unpack_from('<Q',blob,off+16)[0];length=struct.unpack_from('<Q',blob,off+32)[0]
 if kind==1: loads.append((virtual,start,length))
 if kind==2: dynamic=(start,length)
assert dynamic
strings=None;paths=[]
for off in range(dynamic[0],dynamic[0]+dynamic[1],16):
 kind,value=struct.unpack_from('<QQ',blob,off)
 if kind==5: strings=value
 if kind in (15,29): paths.append(value)
assert strings and paths
strstart=next(start+strings-virtual for virtual,start,length in loads if virtual<=strings<virtual+length)
for offset in paths:
 start=strstart+offset;end=blob.index(0,start);new=b'/root/infraternal-bench/mesh-policy/round5/lib'
 assert len(new)<=end-start;blob[start:end]=new.ljust(end-start,b'\0')
assert interpreter
shutil.copyfile(interpreter,libs/'ld.so');(libs/'ld.so').chmod(0o755)
for line in subprocess.check_output(['ldd',str(source)],text=True).splitlines():
 match=re.search(r'\s+(\S+) => (/\S+)',line)
 if match and not Path(match.group(1)).is_absolute():shutil.copyfile(match.group(2),libs/match.group(1))
destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(blob);destination.chmod(0o755)
subprocess.run(['strip','--strip-debug',str(destination)],check=True)
def code_hash(value):
 offset=struct.unpack_from('<Q',value,32)[0];entry_size,number=struct.unpack_from('<HH',value,54);code=bytearray()
 for index in range(number):
  at=offset+index*entry_size;kind,flags=struct.unpack_from('<II',value,at)
  if kind==1 and flags&1:
   start=struct.unpack_from('<Q',value,at+8)[0];length=struct.unpack_from('<Q',value,at+32)[0];code.extend(value[start:start+length])
 return hashlib.sha256(code).hexdigest()
original_code=code_hash(source.read_bytes());adapted_code=code_hash(destination.read_bytes());assert original_code==adapted_code
metadata={'source':str(source),'executable_segments_sha256':original_code,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'adapted_sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'adaptation':'private PT_INTERP/RUNPATH plus debug-section stripping; code/profile unchanged'}
(destination.with_suffix('.artifact.json')).write_text(json.dumps(metadata,indent=2)+'\n')
print('portable artifact PASS')
