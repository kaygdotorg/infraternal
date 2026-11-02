"""Role: measure the real native window through the production canvas on the named Mac; keep authority in memory and prove owned-PID cleanup."""
import base64,ctypes,io,json,os,pathlib,queue,signal,subprocess,sys,threading,time,traceback,uuid
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
from PIL import Image
ROOT=pathlib.Path.home()/'infraternal-bench/app-windows-latency'
sys.path.insert(0,str(ROOT))
from process_identity import process_identity

def validate_helper_archive_descriptor(value):
 """Validate the content-free paths and hashes for one signed helper archive."""
 required={'archive','archive_sha256','executable_sha256','leaf_sha1'}
 if not isinstance(value,dict) or set(value)!=required:raise ValueError('invalid helper archive descriptor')
 if any(not isinstance(value[key],str) for key in required):raise ValueError('invalid helper archive descriptor')
 if not value['archive'].startswith('/') or len(value['archive_sha256'])!=64 or len(value['executable_sha256'])!=64 or len(value['leaf_sha1'])!=40:raise ValueError('invalid helper archive descriptor')
 if any(c not in '0123456789abcdef' for key in ('archive_sha256','executable_sha256','leaf_sha1') for c in value[key].lower()):raise ValueError('invalid helper archive descriptor')
 return {**value,'archive_sha256':value['archive_sha256'].lower(),'executable_sha256':value['executable_sha256'].lower(),'leaf_sha1':value['leaf_sha1'].lower()}

def validate_helper_binary(value,default,bench_root):
 """Keep an isolated helper build inside the job bench; otherwise use the shipped artifact."""
 if value is None:return default
 if not isinstance(value,str) or not pathlib.Path(value).is_absolute():raise ValueError('invalid helper binary path')
 path=pathlib.Path(value).resolve(strict=True);bench=pathlib.Path(bench_root).resolve(strict=True)
 if not path.is_file() or not path.is_relative_to(bench):raise ValueError('helper binary outside Mac bench directory')
 return path

args=json.loads(sys.stdin.readline())
job=args.get('job','app-windows-latency')
os.environ['TRACER_TEST_PORT']=str(args.get('port',4346))
helper_variant=args.get('helper_variant')
helper_restore=args.get('helper_restore')
if bool(helper_variant)!=bool(helper_restore):raise ValueError('helper variant and restoration archives must be supplied together')
if helper_variant:
 helper_variant=validate_helper_archive_descriptor(helper_variant)
 helper_restore=validate_helper_archive_descriptor(helper_restore)
elif helper_restore is not None:raise ValueError('helper restoration requires a selected variant')
native=pathlib.Path(args.get('native') or '/Users/kayg/infraternal-bench/app-windows/InfraternalCaptureHelper.app/Contents/MacOS/InfraternalCaptureHelper')
if args.get('native') and not native.resolve().is_relative_to((ROOT/'native-diagnostic').resolve()):raise RuntimeError('diagnostic companion outside owned directory')
if helper_variant and native.resolve()!=(ROOT/'native-diagnostic'/'InfraternalCaptureHelper.app'/'Contents'/'MacOS'/'InfraternalCaptureHelper').resolve():raise RuntimeError('helper archive requires the single diagnostic bundle')
import re

def picker_title_pattern(title):
 """Match a complete app-window title within the picker option's accessible name."""
 return re.compile(rf", {re.escape(title)}, on ")

def open_concurrent_fixture_windows(page,host_id,owner_pid,window_ids):
 """Use cached production palette actions in one browser turn, before any picture wait."""
 actions=[f'{host_id}/w-{owner_pid}-{window_id}' for window_id in window_ids]
 page.wait_for_function("actions=>{const rows=window.__appwin?.paletteEntries()??[];return actions.every(action=>rows.some(row=>row.action==='canvas:appwin:'+action))}",arg=actions,timeout=10000)
 page.evaluate("actions=>actions.forEach((action,index)=>{window.__firstPictures.open(index);window.__appwin.openFromPalette(action)})",actions)

def show_fixture_cohort(page,count):
 """Keep all ten viewers eligible through the production overview, including idle samples."""
 if count!=10:return
 page.evaluate('window.__appwinCx.nav.showOverview(true)')
 page.wait_for_function("""count=>{
  const viewport=document.querySelector('.cl-viewport')?.getBoundingClientRect();
  const cards=[...document.querySelectorAll('.ui-window[data-kind="app"]')];
  return !!viewport&&cards.length===count&&cards.every(card=>{
   const r=card.getBoundingClientRect();
   return r.width>0&&r.height>0&&r.right>viewport.left&&r.left<viewport.right&&r.bottom>viewport.top&&r.top<viewport.bottom;
  });
 }""",arg=count,timeout=10000)

if not re.fullmatch(r'[a-z0-9-]{1,48}',job) or not re.fullmatch(r'[a-z0-9-]{1,48}',args['label']):raise SystemExit(2)
E=ROOT/'evidence'/args['label'];E.mkdir(parents=True,exist_ok=False)
BIN=ROOT/'bin'
helper_binary=validate_helper_binary(args.get('helper_binary'),BIN/'helper',pathlib.Path.home()/'infraternal-bench')
for mode in ('ten_window_idle','first_picture_idle','flood','input_only'):
 if type(args.get(mode,False)) is not bool:raise ValueError('invalid measurement mode')
TEN_WINDOW_IDLE=args.get('ten_window_idle',False)
FIRST_PICTURE_IDLE=args.get('first_picture_idle',False)
FLOOD=args.get('flood',False)
OPEN_MODE=args.get('open_mode','serial')
if OPEN_MODE not in ('serial','concurrent'):raise ValueError('invalid fixture open mode')
if TEN_WINDOW_IDLE and FIRST_PICTURE_IDLE:raise ValueError('ten-window idle modes cannot run together')
if (TEN_WINDOW_IDLE or FIRST_PICTURE_IDLE) and FLOOD:raise ValueError('idle and flood cohorts cannot run together')
FIXTURE_WINDOW_COUNT=args.get('fixture_window_count',1)
if type(FIXTURE_WINDOW_COUNT) is not int or not 1<=FIXTURE_WINDOW_COUNT<=10:raise ValueError('invalid fixture window count')
if TEN_WINDOW_IDLE and FIXTURE_WINDOW_COUNT!=10:raise ValueError('idle cohort requires ten fixture windows')
if FIRST_PICTURE_IDLE and FIXTURE_WINDOW_COUNT!=10:raise ValueError('first-picture check requires ten fixture windows')
if OPEN_MODE=='concurrent' and FIXTURE_WINDOW_COUNT!=10:raise ValueError('concurrent opening requires ten fixture windows')
if FLOOD and FIXTURE_WINDOW_COUNT!=1:raise ValueError('flood cohort requires one fixture window')
RUN_TIMEOUT_SECONDS=1800 if TEN_WINDOW_IDLE or FLOOD else 900
CLEANUP_RESERVE_SECONDS=30
INPUT_SAMPLE_COUNT=80 if args.get('input_only') else 40
STABILITY_SECONDS=args.get('stability_seconds',600)
RECOVERY_ENABLED=args.get('recovery',False)
if type(STABILITY_SECONDS) is not int or STABILITY_SECONDS not in (180,600):raise ValueError('invalid stability duration')
if (TEN_WINDOW_IDLE or FLOOD) and STABILITY_SECONDS!=600:raise ValueError('soak cohorts require exactly ten minutes')
RECONNECT_ITERATION=3
REOPEN_ITERATION=6

def known_soak_text():
 """Only known fixture text enters the exact-order stability comparison."""
 return ('infraternal keeps every key in order 0123456789. '*6)[:240]

def soak_burst(iteration):
 """Sixty ten-second steps contain forty six-key bursts and twenty idle checks."""
 if not 0<=iteration<60:raise ValueError('invalid stability step')
 phase=iteration%6
 if phase in (3,4):return ''
 start=((iteration//6)*4+{0:0,1:1,2:2,5:3}[phase])*6
 return known_soak_text()[start:start+6]

def soak_input_matches(rows, expected):
 """Counts alone cannot detect reordered or substituted keys; fail on unstamped input."""
 inputs=[row for row in rows if row.get('kind')=='input']
 return len(inputs)==len(expected) and all(isinstance(row.get('characters'),str) and len(row['characters'])==1 for row in inputs) and ''.join(row['characters'] for row in inputs)==expected

def helper_resource_delta(before, after, elapsed_seconds):
 """Aggregate matched-helper CPU time and wakeups while retaining current RSS."""
 if elapsed_seconds<=0:raise ValueError('invalid helper sample interval')
 matched=set(before)&set(after)
 cpu_ns=sum(max(0,after[pid]['cpu_ns']-before[pid]['cpu_ns']) for pid in matched)
 wakeups=sum(max(0,after[pid]['wakeups']-before[pid]['wakeups']) for pid in matched)
 rss={str(pid):int(row['rss_kb']) for pid,row in after.items()}
 return {'matched_helpers':len(matched),'helper_count':len(after),'cpu_cores':cpu_ns/(elapsed_seconds*1e9),
         'wakeups_per_second':wakeups/elapsed_seconds,'rss_kb':sum(rss.values()),'rss_by_pid_kb':rss}

def companion_metric_summary(path, offset=0):
 """Count source callbacks, fresh deliveries, explicit drops and configured queue depth."""
 queue_depth=[];source_callbacks=0;damaged_callbacks=0;deliveries=0;encoder_drops=0
 if path.exists():
  with path.open('rb') as stream:
   stream.seek(offset);data=stream.read().decode('utf-8',errors='replace')
  for line in data.splitlines():
   if not line.startswith('METRIC '):continue
   parts=line.split();name=parts[1] if len(parts)>1 else ''
   fields=dict(part.split('=',1) for part in parts[2:] if '=' in part)
   if name=='source_capture_config' and fields.get('queue_depth','').isdecimal():queue_depth.append(int(fields['queue_depth']))
   elif name=='source_frame':
    source_callbacks+=1
    if fields.get('damaged')=='true':damaged_callbacks+=1
   elif name=='surface_delivery' and fields.get('fresh')=='true':deliveries+=1
   elif name=='encoder_drop=1':encoder_drops+=1
 return {'queue_depth_max':max(queue_depth,default=0),'source_callbacks':source_callbacks,
         'damaged_callbacks':damaged_callbacks,'fresh_deliveries':deliveries,
         'latest_only_callback_gap':max(0,damaged_callbacks-deliveries),
         'encoder_drops':encoder_drops}

class RusagePrefix(ctypes.Structure):
 """The rusage_info_v4 prefix used for per-process CPU and wakeups."""
 # Request type 4 returns rusage_info_v4; these offsets are its leading fields.
 _fields_=[('uuid',ctypes.c_uint8*16),('user_ns',ctypes.c_uint64),('system_ns',ctypes.c_uint64),
           ('package_wakeups',ctypes.c_uint64),('interrupt_wakeups',ctypes.c_uint64)]

def process_usage(pid):
 """Read cumulative nanoseconds and wakeups through macOS libproc."""
 buffer=ctypes.create_string_buffer(512)
 library=ctypes.CDLL('/usr/lib/libproc.dylib')
 query=library.proc_pid_rusage
 query.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p]
 query.restype=ctypes.c_int
 if query(pid,4,ctypes.byref(buffer))!=0:raise RuntimeError('helper resource sample unavailable')
 sample=RusagePrefix.from_buffer(buffer)
 return {'cpu_ns':int(sample.user_ns+sample.system_ns),
         'wakeups':int(sample.package_wakeups+sample.interrupt_wakeups)}

def expected_capture_retirement(retired, captures, previous_controls, current_controls, previous_dimensions, current_dimensions, resize_ack):
 """A native resize replaces capture, while the same control owner must survive."""
 return bool(retired and retired<=captures and previous_controls and previous_controls==current_controls and previous_dimensions and current_dimensions and previous_dimensions!=current_dimensions and resize_ack)

def read_resize_acks(path, cursor):
 """Read only newly completed diagnostic lines; partial or begin records prove no resize."""
 with path.open('rb') as stream:
  stream.seek(cursor);data=stream.read()
 complete=data.rfind(b'\n')+1
 rows=[]
 for line in data[:complete].splitlines():
  if b' stage=helper_native_end ' not in line:continue
  fields=dict(part.split('=',1) for part in line.decode('ascii',errors='replace').split() if '=' in part)
  if fields.get('kind')=='3':rows.append(fields)
 return cursor+complete,rows

class PhaseComplete(Exception):
 """Finish a short phase through cleanup, whose result still controls exit status."""
 pass
owned=set();children=[];browser=None;play=None;lock=pathlib.Path('/tmp/infraternal-bench.lock');locked=False;cua_pid=None;cua_birth=None;restore_pending=False
runtime_owned=False
start=time.monotonic();stage='lock';all_draws=[];native_metrics=[];results=[];failed=False;cleanup_remaining=0
output_lock=threading.Lock()
def emit(value):
 # Main sampling, consent checks and RTT receipts share one JSON-line stream.
 with output_lock:print(json.dumps(value),flush=True)
def command(argv,**kw):return subprocess.run(argv,capture_output=True,text=True,check=True,**kw).stdout

def replace_signed_helper_bundle(bundle, archive, archive_sha256, executable_sha256, leaf_sha1):
 """Replace the one diagnostic bundle from a verified, signed archive."""
 import hashlib,shutil
 bundle=pathlib.Path(bundle);archive=pathlib.Path(archive)
 if bundle.name!='InfraternalCaptureHelper.app' or bundle.parent.name!='native-diagnostic':raise RuntimeError('unexpected helper bundle path')
 bench=pathlib.Path.home()/'infraternal-bench'
 if not archive.is_absolute() or not archive.resolve().is_relative_to(bench.resolve()):raise RuntimeError('helper archive outside the Mac bench directory')
 if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest()!=archive_sha256:raise RuntimeError('helper archive hash mismatch')
 if len(executable_sha256)!=64 or any(c not in '0123456789abcdef' for c in executable_sha256):raise RuntimeError('invalid helper executable hash')
 if len(leaf_sha1)!=40 or any(c not in '0123456789abcdef' for c in leaf_sha1.lower()):raise RuntimeError('invalid helper leaf hash')
 if bundle.exists():shutil.rmtree(bundle)
 extracted=subprocess.run(['/usr/bin/ditto','-x','-k','--sequesterRsrc',str(archive),str(bundle.parent)],capture_output=True,text=True)
 if extracted.returncode:raise RuntimeError('helper archive extraction failed')
 executable=bundle/'Contents'/'MacOS'/'InfraternalCaptureHelper'
 if not executable.is_file() or hashlib.sha256(executable.read_bytes()).hexdigest()!=executable_sha256:raise RuntimeError('restored helper executable hash mismatch')
 verified=subprocess.run(['/usr/bin/codesign','--verify','--strict',str(bundle)],capture_output=True,text=True)
 if verified.returncode:raise RuntimeError('restored helper signature verification failed')
 requirement=subprocess.run(['/usr/bin/codesign','-d','-r-',str(bundle)],capture_output=True,text=True)
 description=(requirement.stdout+'\n'+requirement.stderr).lower()
 if requirement.returncode or 'identifier "com.infraternal.desktop.helper"' not in description or f'certificate leaf = h"{leaf_sha1.lower()}"' not in description:raise RuntimeError('restored helper leaf hash mismatch')
 return {'archive_sha256':archive_sha256,'executable_sha256':executable_sha256,'leaf_sha1':leaf_sha1.lower()}

def restore_helper_bundle(bundle, archive, archive_sha256, executable_sha256, leaf_sha1):
 """Restore the shipped capture helper while the MacBook lease is still held."""
 return replace_signed_helper_bundle(bundle,archive,archive_sha256,executable_sha256,leaf_sha1)

def capture_environment(pipeline, inherited):
 """Select the production capture route or its explicit owned-pixel diagnostic."""
 if pipeline not in ('default','surface','owned'):raise ValueError('invalid capture path')
 env=dict(inherited)
 # Since D266, production defaults to same-process IOSurface capture. Keep the
 # historical surface spelling as an alias; only owned opts into pixel copies.
 env.pop('INFRATERNAL_DESKTOP_SURFACE',None);env.pop('INFRATERNAL_DESKTOP_OWNED',None)
 if pipeline=='owned':env['INFRATERNAL_DESKTOP_OWNED']='1'
 return env

def launch(argv,**kw):
 p=subprocess.Popen(argv,**kw);owned.add(p.pid);children.append(p);return p

def logged_capture_identity(row):
 """Parse only signed-app rows that carry the launch-time kernel identity."""
 parts=row.split()
 if len(parts)!=4 or parts[0] not in ('native','capture'):return None
 try:pid,seconds,microseconds=map(int,parts[1:])
 except ValueError:raise RuntimeError('invalid signed-app process identity row')
 if pid<=0 or seconds<=0 or not 0<=microseconds<1_000_000:raise RuntimeError('invalid signed-app process identity row')
 return parts[0],pid,(pid,seconds,microseconds)

def descendants(seed):
 rows=[r.strip().split(None,2) for r in command(['ps','-axo','pid=,ppid=,comm=']).splitlines()]
 ids=set(seed);again=True
 while again:
  again=False
  for row in rows:
   if len(row)>2 and int(row[1]) in ids and int(row[0]) not in ids:ids.add(int(row[0]));again=True
 return ids

def browser_processes():
 rows=command(['ps','-axo','pid=,comm=']).splitlines()
 prefix=str(ROOT/'browsers')+'/'
 return {int(parts[0]) for row in rows if len(parts:=row.strip().split(None,1))==2 and parts[1].startswith(prefix)}

def console_state():
 import ctypes,plistlib
 registry = plistlib.loads(subprocess.check_output(['/usr/sbin/ioreg', '-n', 'Root', '-d', '1', '-a']))
 root = registry if isinstance(registry, dict) else registry[0] if registry and isinstance(registry[0], dict) else {}
 active = next((entry for entry in root.get('IOConsoleUsers', [])
                if entry.get('kCGSSessionUserIDKey') == os.getuid()
                and entry.get('kCGSSessionOnConsoleKey') is True), {})
 carbon = ctypes.CDLL('/System/Library/Frameworks/Carbon.framework/Carbon')
 secure = carbon.IsSecureEventInputEnabled
 secure.argtypes = []
 secure.restype = ctypes.c_ubyte
 state = {
     'own_console_session': bool(active),
     'login_done': active.get('kCGSessionLoginDoneKey'),
     'screen_locked': active.get('CGSSessionScreenIsLocked'),
     'console_locked': root.get('IOConsoleLocked'),
     'secure_input': bool(secure()),
 }
 state['ready'] = bool(active) and state['login_done'] is True and state['screen_locked'] is not True and state['console_locked'] is False and state['secure_input'] is False
 return state

def battery():
 text=command(['pmset','-g','batt']);emit({'kind':'battery','text':text})
 import re
 m=re.search(r'(\d+)%;',text)
 if not m or int(m[1])<30:raise RuntimeError('battery below allowed level or unknown')

fixture_build=ROOT/'fixture-build'/args['label'];fixture_build.mkdir(parents=True,exist_ok=False)
fixture_source=fixture_build/'latency-window.swift';fixture_source.write_text(args['fixture_source'])
fixture=fixture_build/'latency-window'

def cua(name,params):
 return json.loads(command([str(pathlib.Path.home()/'.local/bin/cua-driver'),'call',name,json.dumps(params)],timeout=20))

def capture_projection(state):
 """Project the selected window through auxiliary capture bounds and letterboxing."""
 import math
 actual,capture,content=(state[name] for name in ('actual','capture_rect','content_rect'))
 values=[state['width'],state['height']]+[rect[key] for rect in (actual,capture,content) for key in ('x','y','width','height')]
 if not all(isinstance(value,(int,float)) and math.isfinite(value) for value in values):raise RuntimeError('invalid capture geometry')
 if any(rect[key]<=0 for rect in (actual,capture,content) for key in ('width','height')) or state['width']<=0 or state['height']<=0:raise RuntimeError('empty capture geometry')
 sx,sy=content['width']/capture['width'],content['height']/capture['height']
 def point(x,y):
  return ((content['x']+(actual['x']-capture['x']+actual['width']*x)*sx)/state['width'],(content['y']+(actual['y']-capture['y']+actual['height']*y)*sy)/state['height'])
 colour=point(.75,.75)
 native_cell=actual['width']*.2/40
 marker=point(.8,.7-native_cell/2/actual['height'])
 projection={'width':state['width'],'height':state['height'],'colourX':colour[0],'colourY':colour[1],'markerX':marker[0],'markerY':marker[1],'cell':native_cell*sx/state['width']}
 if not all(0<projection[key]<1 for key in ('colourX','colourY','markerX','markerY','cell')) or projection['markerX']+40*projection['cell']>1:raise RuntimeError('fixture outside capture geometry')
 return projection

def compositor_target(surface, viewport, projection=None):
 # Opening/following can change the canvas shape after its first picture. Read
 # bounds for each stimulus; never retain that startup rectangle for sampling.
 rectangle=surface.bounding_box()
 if not rectangle or not viewport:raise RuntimeError('viewer target unavailable')
 # Match the worker's lower-right fixture sample, away from the centre cursor.
 x=(rectangle['x']+rectangle['width']*(projection['colourX'] if projection else .75))/viewport['width']
 y=(rectangle['y']+rectangle['height']*(projection['colourY'] if projection else .75))/viewport['height']
 if not 0<=x<1 or not 0<=y<1:raise RuntimeError('viewer target outside viewport')
 return {'x':x,'y':y,'rectangle':rectangle,'viewport':viewport}

def compositor_pixel(target, metadata, image_width, image_height):
 # A managed browser window can exceed its emulated viewport. CDP copies the
 # whole device surface, including the surrounding area outside that viewport.
 width=metadata['deviceWidth'];height=metadata['deviceHeight']
 scale=metadata['pageScaleFactor'];top=metadata['offsetTop']
 if not 0<width<=32768 or not 0<height<=32768 or not 0<scale<=10:raise RuntimeError('invalid compositor dimensions')
 x=target['x']*target['viewport']['width']*scale
 y=target['y']*target['viewport']['height']*scale+top
 if not 0<=x<width or not 0<=y<height:raise RuntimeError('compositor target outside device')
 return min(image_width-1,round(x*image_width/width)),min(image_height-1,round(y*image_height/height))

def focus_input(surface):
 # The first press may only activate the card (D208). Both presses use the
 # picture centre; sampling starts only after the real lease and DOM focus.
 consent_guard()
 # Native activation can move the viewer out of focus during the first
 # control press. Use the measured cohort's same focus mode from admission,
 # while retaining its real control lease and focused-element checks.
 if not any(args.get(mode) for mode in ('resources_only','demo_only','owner_preview')):
  cdp.send('Emulation.setFocusEmulationEnabled',{'enabled':True})
 surface.click()
 surface.click()
 page.locator('.aw-control[data-kind="controlled"]').wait_for(timeout=10000)
 focused=surface.evaluate('(canvas)=>canvas.parentElement===document.activeElement')
 if not focused:raise RuntimeError('fixture input did not receive typing focus')
 consent_guard()
 emit({'kind':'input_ready','controlled':True,'focused':True})

def first_picture(previous=None):
 # Observe a terminal refusal as soon as it appears. Waiting only for live
 # would keep native capture alive until timeout even after permission failed.
 try:
  state=page.wait_for_function("""(old)=>{
   const cards=[...document.querySelectorAll('.ui-window[data-kind="app"]')].filter(n=>n.dataset.windowId!==old);
   for(const card of cards){
    const state=card.querySelector('.aw-card[data-shown="true"]')?.dataset.signature?.split(':')[0];
    if(['permission','failed','closed','unsupported'].includes(state))return state;
    if(card.querySelector('.aw-stage[data-picture="live"]'))return 'live';
   }
   return false;
  }""",arg=previous,timeout=10000).json_value()
  if state!='live':raise RuntimeError('capture refused before first picture')
 except Exception:
  stop_capture()
  raise

def wait_for_first_picture(card,index,failures):
 """Record a missing native picture and retire capture before any next window or phase."""
 try:card.locator('.aw-stage[data-picture="live"]').wait_for(timeout=15000)
 except PlaywrightTimeoutError:
  if not args.get('first_picture_idle'):raise
  failure={'fixture_index':index+1,
           'window_id':card.get_attribute('data-window-id'),
           'card_state':card.locator('.aw-card').get_attribute('data-signature'),
           'picture':card.locator('.aw-stage').get_attribute('data-picture'),
           'card_rect':card.bounding_box(),
           'stage_rect':card.locator('.aw-stage').bounding_box(),
           'page_state':card.evaluate('(node) => ({hidden: document.hidden, innerWidth: window.innerWidth, innerHeight: window.innerHeight})')}
  failures.append(failure);emit({'kind':'first_picture_failure',**failure})
  stop_capture()
  raise RuntimeError('native first picture unavailable')
 consent_check()

def fixture_target_rows(reports,canvas_ids,window_ids,owner_pid):
 """Bind each canvas model to its unique native fixture window before reporting the cohort."""
 if len(canvas_ids)!=len(window_ids) or len(set(canvas_ids))!=len(canvas_ids) or len(set(window_ids))!=len(window_ids):
  raise RuntimeError('fixture target identities are not unique')
 by_id={}
 for row in reports:
  if not isinstance(row,dict) or not isinstance(row.get('id'),str) or row['id'] in by_id:
   raise RuntimeError('canvas target report is incomplete')
  by_id[row['id']]=row.get('target')
 mapped=[]
 for index,(canvas_id,window_id) in enumerate(zip(canvas_ids,window_ids)):
  expected={'type':'window','windowId':window_id,'ownerPid':owner_pid}
  if by_id.get(canvas_id)!=expected:
   raise RuntimeError('canvas target mismatch: fixture_index='+str(index+1))
  mapped.append({'fixture_index':index+1,'canvas_id':canvas_id,'target':expected})
 return mapped

def consent_check():
 # Inspect metadata before requesting any screenshot; never retain an unrelated window inventory.
 inventory=cua('list_windows',{'on_screen_only':True})
 def walk(v):
  if isinstance(v,dict):
   yield v
   for x in v.values():yield from walk(x)
  elif isinstance(v,list):
   for x in v:yield from walk(x)
 privacy_titles={'screen & system audio recording','screen and system audio recording','screen recording'}
 matches=[v for v in walk(inventory) if str(v.get('title','')).strip().lower() in privacy_titles or any(name in (str(v.get('title',''))+' '+str(v.get('app_name',''))).lower() for name in ['infraternalcapturehelper','infraternal-desktop-helper','netbird','requesting to bypass'])]
 for v in matches:
  if not v.get('pid') or not v.get('window_id'):continue
  session='app-windows-latency-consent'
  state=cua('get_window_state',{'pid':v['pid'],'window_id':v['window_id'],'session':session,'include_screenshot':False,'max_depth':12,'max_elements':300})
  controls=list(walk(state))
  # A re-signed diagnostic must retain existing permission. Never approve a
  # new permission request or type into a password sheet in this measurement.
  allow_control=any('button' in str(x.get('role','')).lower() and any(str(x.get(key,'')).strip().lower()=='allow' for key in ('title','name','label','value')) for x in controls)
  if any('secure' in str(x.get('role','')).lower() or 'password' in str(x.get('role','')).lower() for x in controls) or allow_control:
   emit({'kind':'helper_permission_changed','controls':[{key:x[key] for key in ('role','title','name','label') if key in x} for x in controls]})
   raise RuntimeError('helper permission changed; owner intervention required')
 emit({'kind':'consent','checked':True,'our_windows':len(matches)})

def retire_signal(signum,frame):raise KeyboardInterrupt()
signal.signal(signal.SIGTERM,retire_signal);signal.signal(signal.SIGHUP,retire_signal)
emit({'kind':'runner','pid':os.getpid()})
try:
 stage='fixture build';battery()
 compiler=launch(['swiftc','-O',str(fixture_source),'-o',str(fixture)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  _,compile_error=compiler.communicate(timeout=60)
 except subprocess.TimeoutExpired:
  compiler.kill();compiler.communicate();owned.discard(compiler.pid);children.remove(compiler)
  compiler_check=subprocess.run(['ps','-p',str(compiler.pid),'-o','pid=,stat=,comm='],capture_output=True,text=True)
  emit({'kind':'process_exit','pid':compiler.pid,'role':'swiftc','exit':compiler.returncode,'ps_exit':compiler_check.returncode,'row':compiler_check.stdout.strip()})
  raise RuntimeError('native fixture build timed out')
 compiler_check=subprocess.run(['ps','-p',str(compiler.pid),'-o','pid=,stat=,comm='],capture_output=True,text=True)
 emit({'kind':'fixture_build','pid':compiler.pid,'exit':compiler.returncode,'diagnostic':'compiler_refused' if compiler.returncode else 'ok'})
 emit({'kind':'process_exit','pid':compiler.pid,'role':'swiftc','exit':compiler.returncode,'ps_exit':compiler_check.returncode,'row':compiler_check.stdout.strip()})
 owned.discard(compiler.pid);children.remove(compiler)
 if compiler.returncode:
  import shutil
  shutil.rmtree(fixture_build);raise RuntimeError('native fixture build failed')
 for attempt in range(90):
  try:lock.mkdir();locked=True;break
  except FileExistsError:
   if attempt==0 or attempt%5==0:emit({'kind':'lock_wait','owner':(lock/'owner').read_text()})
   time.sleep(60)
 if not locked:raise RuntimeError('Mac lock unavailable')
 (lock/'owner').write_text(job+'\n');(lock/'pid').write_text(str(args['controller_pid'])+'\n');(lock/'started').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z')+'\n')
 stage='VM readiness';emit({'kind':'vm_readiness_request'})
 readiness=json.loads(sys.stdin.readline());emit({'kind':'vm_readiness','idle':readiness.get('idle',[]),'phase':readiness.get('phase','vm'),'refusal':readiness.get('refusal')})
 if not readiness.get('ready'):raise RuntimeError('named VM or private server unavailable')
 args.update(readiness)
 if helper_variant:
  battery()
  existing=subprocess.run(['/usr/bin/pgrep','-x','InfraternalCaptureHelper'],capture_output=True,text=True)
  if existing.returncode==0:raise RuntimeError('capture helper already running before archive replacement')
  if existing.returncode!=1:raise RuntimeError('capture helper process check unavailable')
  # Keep bundle replacement and cleanup within the same lease so another Mac run sees only the shipped build.
  restore_pending=True
  installed=replace_signed_helper_bundle(native.parent.parent.parent,helper_variant['archive'],helper_variant['archive_sha256'],helper_variant['executable_sha256'],helper_variant['leaf_sha1'])
  emit({'kind':'helper_variant_installed',**installed})
 def run_deadline(signum,frame):raise TimeoutError('measurement run exceeded its bounded time limit')
 run_started=time.monotonic();run_deadline_at=run_started+RUN_TIMEOUT_SECONDS
 signal.signal(signal.SIGALRM,run_deadline);signal.alarm(RUN_TIMEOUT_SECONDS)
 environment=command(['sw_vers'])+command(['sysctl','-n','hw.model','hw.ncpu','hw.memsize'])
 environment+=command(['uptime'])
 battery();emit({'kind':'environment','text':environment})
 console=console_state();emit({'kind':'console','state':console})
 if not console['ready']:raise RuntimeError('console is locked or secure input is active')
 launch(['/usr/bin/caffeinate','-d','-i','-w',str(os.getpid())],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 stage='CUA daemon'
 previous_status=json.loads(command([str(pathlib.Path.home()/'.local/bin/cua-driver'),'permissions','status','--json']))
 previous_cua=previous_status.get('source',{}).get('pid')
 command(['open','-g','-j','/Applications/CuaDriver.app','--args','serve'])
 time.sleep(1)
 status=json.loads(command([str(pathlib.Path.home()/'.local/bin/cua-driver'),'permissions','status','--json']))
 cua_pid=status.get('source',{}).get('pid') if not previous_cua else None
 if cua_pid:
  owned.add(cua_pid);cua_birth=process_identity(cua_pid)
  if cua_birth is None:raise RuntimeError('cannot identify the owned CUA process')
 if not status.get('accessibility') or not status.get('screen_recording'):raise RuntimeError('existing CUA permissions unavailable')
 emit({'kind':'cua','pid':cua_pid,'accessibility':True,'screen_recording':True})
 stage='clock'
 clock=launch([str(BIN/'clock-bridge')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
 base=json.loads(clock.stdout.readline());timebase=base['numer']/base['denom']
 def native_clock():
  samples=[]
  for i in range(16):
   before=time.perf_counter_ns();clock.stdin.write('x');clock.stdin.flush();v=json.loads(clock.stdout.readline());after=time.perf_counter_ns()
   samples.append({'before_ns':before,'after_ns':after,**v,'lower':before-v['after_ticks']*timebase,'upper':after-v['before_ticks']*timebase})
  best=min(samples,key=lambda x:x['upper']-x['lower']);return {'samples':samples,'lower':best['lower'],'upper':best['upper']}
 native_mapping=None if args.get('first_picture_idle') else native_clock()
 emit({'kind':'runtime_artifacts','sha256':{name:command(['shasum','-a','256',str(BIN/name)]).split()[0] for name in ('source','helper','clock-bridge')}})
 stage='helper wrappers'
 consent_errors=[]
 runtime=pathlib.Path.home()/'infraternal-bench'/('wl-'+uuid.uuid4().hex[:4]);runtime.mkdir(mode=0o700);runtime_owned=True
 helper_hash=command(['shasum','-a','256',str(native)]).split()[0]
 emit({'kind':'native_helper','hash':helper_hash})
 command(['codesign','--verify','--strict',str(native.parent.parent.parent)])
 if helper_hash!=(args.get('native_hash') or '7b7ad2bcbc18f4f390f00d001b59984b1998665c8ddae9846520b83875001dc5'):raise RuntimeError('approved companion version changed')
 pidlog=E/'helper-pids.txt';pidlog.write_text('');(E/'helper-metrics.log').write_text('');helper_births={};capture_helpers=set()
 def helper_resource_snapshot():
  samples={}
  for pid in sorted(tuple(capture_helpers)):
   birth=helper_births.get(pid)
   if birth is None or process_identity(pid)!=birth:continue
   rss=command(['ps','-p',str(pid),'-o','rss=']).strip()
   if not rss.isdecimal():raise RuntimeError('helper RSS sample unavailable')
   samples[pid]={**process_usage(pid),'rss_kb':int(rss)}
  return samples
 for name,target in [('helper',helper_binary)]:
  wrapper=runtime/name
  wrapper.write_text('#!/bin/sh\n# Role: record only an owned helper PID before preserving its pipes and process identity.\nprintf "'+name+' %s\\n" "$$" >> "'+str(pidlog)+'"\nexec "'+str(target)+'" "$@" 2>> "'+str(E/'helper-metrics.log')+'"\n');wrapper.chmod(0o700)
 # Native capture must be a LaunchServices app, never an exec in this SSH tree.
 import shlex
 bridge=ROOT/'launch-companion.py'
 # Rust formatting can append fragments. Keep native records on their own
 # stream so an inherited helper stderr writer cannot split their fields.
 (E/'companion-metrics.log').write_text('')
 argv=[sys.executable,str(bridge),str(native),str(runtime),str(E/'companion-metrics.log'),str(pidlog)]
 (runtime/'native').write_text('#!/bin/sh\n# Role: bridge to an independently launched signed app.\ntest ! -e '+shlex.quote(str(runtime/'capture-refused'))+' || exit 1\nexec '+shlex.join(argv)+' "$@"'+(' --hevc' if args.get('codec')=='hevc' else '')+'\n')
 (runtime/'native').chmod(0o700)
 def stop_capture():
  # Seal new launches before stopping existing native capture, on either the
  # consent monitor or the main failure path. Never await browser cleanup first.
  # The watcher and main failure handler may both arrive here. Seal once so
  # a second SIGINT cannot interrupt the source's orderly control retirement.
  try:
   with (runtime/'capture-refused').open('x'):pass
  except FileExistsError:return
  if 'source' in globals():
   try:source.send_signal(signal.SIGINT)
   except ProcessLookupError:pass
  for pid in list(capture_helpers):
   birth=helper_births.get(pid)
   if birth is None:continue
   if process_identity(pid)==birth:
    try:os.kill(pid,signal.SIGTERM)
    except ProcessLookupError:pass
 stop_monitor=threading.Event()
 def watch_launches():
  # Inventory requests launch a signed helper that exits after one response.
  # Only an exact, still-live launch identity may enter cleanup tracking; a
  # retired or reused PID is never authority to signal its current process.
  seen=set()
  while not stop_monitor.wait(.5):
   try:
    rows=pidlog.read_text().splitlines()
    if any(row not in seen for row in rows):
     for row in rows:
      if row in seen:continue
      seen.add(row)
      identity=logged_capture_identity(row)
      if identity is None:continue
      role,pid,birth=identity
      if process_identity(pid)!=birth:continue
      helper_births[pid]=birth
      if role=='capture':capture_helpers.add(pid)
    consent_check()
   except Exception as e:
    consent_errors.append(type(e).__name__)
    stop_capture()
    return
 monitor=threading.Thread(target=watch_launches,daemon=True);monitor.start()
 def consent_guard():
  # The watcher cannot raise on the browser thread. Refuse its next operation
  # instead of continuing a whole measurement after a changed permission.
  if consent_errors:raise RuntimeError('helper consent monitor refused the run')
 env=dict(os.environ,INFRATERNAL_DESKTOP_COMPANION=str(runtime/'native'),INFRATERNAL_DESKTOP_MEASURE='1',INFRATERNAL_DESKTOP_BENCH_DIR=str(runtime),INFRATERNAL_DESKTOP_BENCH_HELPER=str(runtime/'helper'))
 if args.get('resources_only') or not args.get('pipeline_diagnostics',True):env.pop('INFRATERNAL_DESKTOP_MEASURE',None)
 pipeline=args.get('pipeline','default');env=capture_environment(pipeline,env)
 capture_path='owned-copy' if pipeline=='owned' else 'signed-surface'
 emit({'kind':'pipeline','mode':pipeline,'capture_path':capture_path,'browser_dpr':2})
 preflight=launch([str(runtime/'helper'),'--check-permissions'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 consent_check();out,err=preflight.communicate(timeout=20)
 permissions=json.loads(out);emit({'kind':'helper_permissions','pid':preflight.pid,'exit':preflight.returncode,'permissions':permissions})
 if preflight.returncode or not permissions.get('screen_recording') or not permissions.get('device_control'):raise RuntimeError('installed helper permissions unavailable')
 stage='source supervisor'
 source=launch([str(BIN/'source')],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 hello=json.loads(source.stdout.readline());emit({'kind':'source','pid':source.pid})
 def metric_reader():
  for line in source.stderr:
   if line.startswith('METRIC '):native_metrics.append(line.rstrip())
 threading.Thread(target=metric_reader,daemon=True).start()
 stage='browser'
 os.environ['PLAYWRIGHT_BROWSERS_PATH']=str(ROOT/'browsers');os.environ['TMPDIR']=str(ROOT/'browser-tmp');pathlib.Path(os.environ['TMPDIR']).mkdir(exist_ok=True)
 if browser_processes():raise RuntimeError('earlier browser in this job directory remains')
 play=sync_playwright().start();owned.add(play._impl_obj._connection._transport._proc.pid)
 browser=play.chromium.launch(headless=False,args=['--host-resolver-rules=MAP localhost 10.69.69.125','--disable-renderer-backgrounding','--disable-background-timer-throttling','--window-position=50,50'])
 owned.update(browser_processes())
 context=browser.new_context(ignore_https_errors=True,viewport={'width':832,'height':720},device_scale_factor=2)
 page=context.new_page();cdp=context.new_cdp_session(page)
 decoder_properties=[]
 def media_properties(event):
  for entry in event.get('properties',[]):
   if entry.get('name') in ['kVideoDecoderName','kIsPlatformVideoDecoder','kVideoDecoderType'] and len(decoder_properties)<128:decoder_properties.append(entry)
 cdp.on('Media.playerPropertiesChanged',media_properties)
 try:cdp.send('Media.enable')
 except Exception:pass
 # Regression receipt for the old readiness predicate: its false result must
 # never be accepted as readiness by the measurement controller.
 false_result=page.wait_for_function('async()=>false',timeout=2000).json_value()
 emit({'kind':'old_async_readiness','resolved_false':false_result is False})
 cdp.send('WebAuthn.enable');cdp.send('WebAuthn.addVirtualAuthenticator',{'options':{'protocol':'ctap2','ctap2Version':'ctap2_1','transport':'internal','hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True,'hasPrf':True}})
 page.goto(args['origin']+'/?bg=none')
 page.locator('#setup-token').fill(args.pop('token'));page.get_by_role('button',name='Continue',exact=True).click()
 page.locator('#setup-username').fill('window_measurement');page.locator('#setup-display-name').fill('App window measurement');page.get_by_role('button',name='Continue',exact=True).click();page.get_by_role('button',name='Create passkey').click();page.get_by_role('heading',name='Save your recovery key').wait_for();page.locator('.auth-check').click();page.get_by_role('button',name='Open infraternal').click();page.locator('.cl-viewport').wait_for()
 unlock=page.get_by_label('Hosts settings').get_by_role('button',name='Unlock',exact=True,include_hidden=True)
 unlock.wait_for(state='attached')
 for i in range(100):
  if unlock.get_attribute('data-shown')=='true':break
  page.wait_for_timeout(100)
 unlock.evaluate('(b)=>b.click()')
 # Await each response before deciding readiness. A Promise itself is truthy
 # to the page predicate poller even when its eventual value is false.
 for attempt in range(200):
  authority=page.evaluate("async()=>{const r=await fetch('/remote/ca/status',{method:'POST'});if(!r.ok)return null;const s=await r.json();return {initialized:s.initialized===true,locked:s.locked!==false};}")
  if authority and authority['initialized'] and not authority['locked']:break
  page.wait_for_timeout(100)
 else:raise RuntimeError('private signer did not become ready')
 emit({'kind':'authority_ready',**authority})
 stage='enrollment'
 enrollment=page.evaluate('''async({csr,uid})=>{const host_id=crypto.randomUUID();const r=await fetch('/remote/invitations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host_id,mode:'rootless',execution_uid:uid})});if(!r.ok)return {failure:{stage:'invitation',status:r.status}};const invite=await r.json();const encoded=btoa(String.fromCharCode(...csr)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');const j=await fetch('/remote/join',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host_id,mode:'rootless',token:invite.token,csr_der:encoded})});if(!j.ok)return {failure:{stage:'join',status:j.status}};const joined=await j.json();const bytes=s=>Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));return {host_id,certificate_der:bytes(joined.certificate_der),ca_der:bytes(invite.ca_der),endpoint:invite.endpoint,server_name:invite.server_name};}''',{'csr':hello['csr_der'],'uid':hello['uid']})
 if enrollment.get('failure'):
  emit({'kind':'enrollment_refused',**enrollment['failure']});raise RuntimeError('fixture enrollment refused')
 host_id=enrollment.pop('host_id');source.stdin.write(json.dumps(enrollment)+'\n');source.stdin.flush()
 emit({'kind':'host','host_id':host_id})
 if args.get('diagnostic_only'):
  emit({'kind':'enrollment_accepted'});raise PhaseComplete()
 context.add_init_script(args['probe'])
 context.route('**/decode.worker*.js',lambda route:route.fulfill(status=200,content_type='text/javascript',body=args['worker'] if args.get('resources_only') else args['observer']+'\n'+args['worker']))
 page.goto(args['origin']+('/?bg=none' if args.get('resources_only') else '/?appwinMeasure=1&bg=none'));page.locator('.cl-viewport').wait_for()
 def call(action,input=None):
  consent_guard()
  result=page.evaluate("async([a,i])=>{try{return {ok:true,value:await window.__appWindowBench.call(a,i)}}catch(e){return {ok:false,reason:['forbidden','conflict','not found','unavailable','invalid','rejected'].includes(e.reason)?e.reason:'other',name:e.name==='ActionRefused'?'ActionRefused':'Error',failure:['connection closed','connection lost','fixture action timeout','fixture socket timeout'].includes(e.message)?e.message:'refused'}}}",[action,input or {}])
  if not result['ok']:
   emit({'kind':'action_refused','action':action,'reason':result['reason'],'name':result['name'],'failure':result['failure']});raise RuntimeError('fixture action refused')
  return result['value']
 call('plugins.set_enabled',{'plugin':'desktop','enabled':True})
 page.reload();page.locator('.cl-viewport').wait_for()
 for i in range(150):
  hosts=call('remote.host.list')
  if any(h['id']==host_id and h.get('online') for h in hosts.get('hosts',[])):break
  page.wait_for_timeout(200)
 else:raise RuntimeError('source never became online')
 browser_ids=descendants({play._impl_obj._connection._transport._proc.pid})-{play._impl_obj._connection._transport._proc.pid};owned.update(browser_ids)
 def live_helpers():
  # LaunchServices companions are not source descendants. Include their exact
  # recorded identities, or resource receipts would silently omit native capture.
  live=set()
  for pid,birth in list(helper_births.items()):
   if process_identity(pid)==birth:live.add(pid)
  return live
 def resource_sample(label):
  consent_guard()
  source_ids=descendants({source.pid})|live_helpers();owned.update(source_ids);ids=source_ids|browser_ids|({window.pid} if 'window' in globals() else set())
  begin=time.perf_counter_ns();worker_before=page.evaluate('window.__appWindowBench.stats()');draw_before=len(all_draws)
  rows=[];sample_times=[]
  for i in range(5):
   consent_guard()
   sample_times.append(time.perf_counter_ns());rows.append(command(['ps','-p',','.join(map(str,ids)),'-o','pid=,ppid=,%cpu=,rss=,time=,comm=']));page.wait_for_timeout(1000)
  worker_after=page.evaluate('window.__appWindowBench.stats()');end=time.perf_counter_ns()
  host=command(['top','-l','2','-s','1','-n','0'])
  emit({'kind':'resources','label':label,'worker_before':worker_before,'worker_after':worker_after,'source_draws':len(all_draws)-draw_before,'begin_perf_ns':begin,'end_perf_ns':end,'host':host,'rows':rows,'sample_times_ns':sample_times,'source_pids':list(source_ids),'browser_pids':list(browser_ids),'uptime':command(['uptime'])})
  if label=='idle' and args.get('require_idle'):
   if len(all_draws)!=draw_before or not worker_before or not worker_after or any(worker_after[k]!=worker_before[k] for k in ('received','decoded','painted')):raise RuntimeError('unchanged native window still sends or paints frames')
  return worker_after
 # Remove the fixture's initial terminal before both resource baselines.
 initial_terminal=page.locator('.ui-window[data-kind="terminal"] [data-action="close"]')
 if initial_terminal.count():initial_terminal.first.evaluate('(b)=>b.click()')
 page.wait_for_timeout(1000)
 if not args.get('first_picture_idle'):resource_sample('empty')
 stage='native fixture'
 # The current fixture and input ledger are built before taking the Mac lock.
 emit({'kind':'native_fixture','sha256':command(['shasum','-a','256',str(fixture)]).split()[0],'source_sha256':command(['shasum','-a','256',str(fixture_source)]).split()[0]})
 # Exercise AppKit's actual content/title-bar projection before opening capture.
 # A synthetic worker bitmap cannot detect a marker drawn on the wrong row.
 marker=launch([str(fixture),'--check-content-marker'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 marker_out,_=marker.communicate(timeout=10)
 if marker.returncode:raise RuntimeError('native fixture content marker check failed')
 marker_rows=[json.loads(line) for line in marker_out.splitlines()]
 marker_check=next(row for row in marker_rows if row.get('kind')=='marker_check')
 emit({**marker_check,'kind':'native_fixture_marker','pid':marker.pid})
 fixture_window_count=FIXTURE_WINDOW_COUNT
 window=launch([str(fixture),'--window-count',str(fixture_window_count)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 ready_by_index={}
 while len(ready_by_index)<fixture_window_count:
  ready_row=json.loads(window.stdout.readline())
  if ready_row.get('kind')=='ready':
   index=ready_row.get('fixture_index')
   if type(index) is not int or index in ready_by_index or not 0<=index<fixture_window_count:raise RuntimeError('invalid native fixture window identity')
   ready_by_index[index]=ready_row
  else:all_draws.append(ready_row)
 ready_rows=[ready_by_index[index] for index in range(fixture_window_count)]
 window_id=ready_rows[0]['window_id'];window_ids=[row['window_id'] for row in ready_rows];native_queue=queue.Queue()
 if fixture_window_count==1 and ready_rows[0]['frame_x']<850:raise RuntimeError('display cannot keep both owned windows visible')
 browser_window=cdp.send('Browser.getWindowForTarget')
 cdp.send('Browser.setWindowBounds',{'windowId':browser_window['windowId'],'bounds':{'left':0,'top':32,'width':848,'height':820,'windowState':'normal'}})
 def draw_reader():
  for line in window.stdout:
   row=json.loads(line);all_draws.append(row);native_queue.put(row)
 threading.Thread(target=draw_reader,daemon=True).start()
 def native_command(value):
  consent_guard();window.stdin.write(value+'\n');window.stdin.flush()
 def own_inventory():return [w for w in call('desktop.windows',{'host_id':host_id})['windows'] if w['owner_pid']==window.pid]
 for attempt in range(10):
  try:
   inventory=own_inventory()
   if any(w['window_id']==window_id for w in inventory):break
  except RuntimeError:pass
  page.wait_for_timeout(500)
 else:raise RuntimeError('owned native window inventory unavailable')
 if len([w for w in inventory if w.get('window_id') in window_ids])!=fixture_window_count:raise RuntimeError('native fixture window inventory incomplete')
 emit({'kind':'windows','pid':window.pid,'count':fixture_window_count,'window_ids':window_ids,'inventory':inventory,
       'display_maximum_fps':ready_rows[0]['display_maximum_fps'],
       'animation_interval_seconds':ready_rows[0]['animation_interval_seconds']})
 stage='open canvas window'
 page.bring_to_front();page.keyboard.press('Meta+k');page.get_by_role('option',name='Settings: Hosts').click()
 toggle=page.get_by_role('switch',name='Stream app windows')
 if not toggle.is_checked():toggle.click()
 close=page.locator('.ui-settings-close')
 if close.is_visible():close.click()
 terminals=page.locator('.ui-window[data-kind="terminal"] [data-action="close"]')
 if terminals.count():terminals.first.evaluate('(b)=>b.click()')
 first_picture_failures=[]
 page.evaluate(args['first_picture_observer'])
 if OPEN_MODE=='concurrent':
  open_concurrent_fixture_windows(page,host_id,window.pid,window_ids)
  consent_check()
  page.wait_for_function('(count)=>document.querySelectorAll(\'.ui-window[data-kind="app"]\').length===count',arg=fixture_window_count,timeout=10000)
  show_fixture_cohort(page,fixture_window_count)
 for index in range(fixture_window_count):
  if OPEN_MODE=='serial':
   title='App window measurement' if fixture_window_count==1 else f'App window measurement {index+1}'
   before=page.locator('.ui-window[data-kind="app"]').count()
   page.get_by_role('button',name='New window',exact=True).click()
   # Stamp the same browser task that dispatches the production picker click.
   page.get_by_role('option',name=picker_title_pattern(title)).evaluate('(option,index)=>{window.__firstPictures.open(index);option.click()}',index)
   consent_check()
   page.wait_for_function('(count)=>document.querySelectorAll(\'.ui-window[data-kind="app"]\').length>count',arg=before,timeout=10000)
  card=page.locator('.ui-window[data-kind="app"]').nth(index)
  try:wait_for_first_picture(card,index,first_picture_failures)
  finally:emit({'kind':'stream_first_pictures','open_mode':OPEN_MODE,'streams':page.evaluate('window.__firstPictures.rows()')})
  if index==0 and not args.get('first_picture_idle'):first_picture()
 if OPEN_MODE=='serial':show_fixture_cohort(page,fixture_window_count)
 page.evaluate('window.__firstPictures.stop()')
 if page.locator('.ui-window[data-kind="app"]').count()!=fixture_window_count:raise RuntimeError('canvas fixture window count mismatch')
 canvas_ids=page.locator('.ui-window[data-kind="app"]').evaluate_all('(nodes)=>nodes.map(n=>n.dataset.windowId)')
 target_reports=page.evaluate('()=>window.__appwin.targets()')
 canvas_targets=fixture_target_rows(target_reports,canvas_ids,window_ids,window.pid)
 emit({'kind':'canvas_window_targets','targets':canvas_targets})
 emit({'kind':'canvas_windows_ready','count':fixture_window_count,'window_ids':canvas_ids})
 consent_check()
 emit({'kind':'canvas_context','receipts':page.evaluate('window.__appWindowBench.take()')})
 if not args.get('ten_window_idle') and not args.get('first_picture_idle'):page.screenshot(path=str(E/'canvas-native-before.png'))
 surface=page.locator('.ui-window[data-kind="app"] .aw-surface').first
 if not args.get('ten_window_idle') and not args.get('first_picture_idle'):focus_input(surface)
 # Every capture helper launch is followed by a consent check, including inventory helpers.
 consent_check()
 if args.get('owner_preview'):
  stage='owner preview'
  # Keep a cleanup reserve before the hard per-run deadline.
  duration=min(args.get('owner_preview_seconds',900),max(1,int(run_deadline_at-time.monotonic()-CLEANUP_RESERVE_SECONDS)))
  emit({'kind':'owner_preview_ready','origin':args['origin'],'seconds':duration,'host':'App window measurement','window':'App window measurement'})
  deadline=time.monotonic()+duration
  while time.monotonic()<deadline and browser.is_connected() and context.pages:
   consent_guard()
   if source.poll() is not None or window.poll() is not None:raise RuntimeError('owner preview source exited')
   try:page.wait_for_timeout(1000)
   except Exception:
    if not browser.is_connected() or not context.pages:break
    raise
  emit({'kind':'owner_preview_finished'});raise PhaseComplete()
 def browser_clock():
  samples=[]
  for i in range(16):
   before=time.perf_counter_ns();value=page.evaluate('performance.timeOrigin+performance.now()');after=time.perf_counter_ns()
   samples.append({'before_ns':before,'after_ns':after,'epoch_ms':value,'lower':before-value*1e6,'upper':after-value*1e6})
  best=min(samples,key=lambda x:x['upper']-x['lower']);return {'samples':samples,'lower':best['lower'],'upper':best['upper']}
 browser_mapping=None if args.get('first_picture_idle') else browser_clock()
 worker_mapping=None
 if not args.get('resources_only') and not args.get('first_picture_idle'):
  samples=[page.evaluate('window.__appWindowBench.workerClock()') for _ in range(16)]
  best=min(samples,key=lambda r:r['after']-r['before'])
  worker_mapping={'samples':samples,'lower_ms':best['before']-best['worker'],'upper_ms':best['after']-best['worker']}
 if not args.get('first_picture_idle'):emit({'kind':'clocks','timebase':base,'native':native_mapping,'browser':browser_mapping,'worker':worker_mapping})
 def source_round_trips(phase):
  samples=[page.evaluate("async()=>{const began=performance.timeOrigin+performance.now();await window.__appWindowBench.call('desktop.session.clock',{session_id:window.__appWindowBench.session});return {at:performance.timeOrigin+performance.now(),ms:performance.timeOrigin+performance.now()-began};}") for _ in range(8)]
  emit({'kind':'source_round_trips','phase':phase,'samples':samples})
 if not args.get('resources_only') and not args.get('first_picture_idle'):source_round_trips('before')
 if not args.get('first_picture_idle'):
  info=browser.new_browser_cdp_session().send('SystemInfo.getInfo');emit({'kind':'browser_rendering','version':browser.version,'gpu':info.get('gpu')})
 def drain():
  consent_guard()
  return page.evaluate('()=>({probe:window.__appWindowBench.take(),frames:window.__infraternalAppWindowTrace?.take()??[]})')
 # Actual compositor pixels are sampled separately below; worker readback is not presentation.
 composites=[]
 palette=[[38,89,204],[38,191,89],[204,64,51],[179,64,191],[38,179,191],[204,166,38],[102,64,204],[191,102,51]]
 copy_target=None
 def observe_compositor(event):
  cdp.send('Page.screencastFrameAck',{'sessionId':event['sessionId']})
  image=Image.open(io.BytesIO(base64.b64decode(event['data']))).convert('RGB')
  if not composites:
   (E/'compositor-first.jpg').write_bytes(base64.b64decode(event['data']))
   (E/'compositor-first-metadata.json').write_text(json.dumps({'metadata':event['metadata'],'image_width':image.width,'image_height':image.height,'target':copy_target}))
  if copy_target is None:return
  x,y=compositor_pixel(copy_target,event['metadata'],image.width,image.height)
  rgb=image.getpixel((x,y));distances=[sum((a-b)**2 for a,b in zip(rgb,p)) for p in palette]
  composites.append({'timestamp_ms':event['metadata'].get('timestamp',0)*1000,'colour':distances.index(min(distances)),'distance':min(distances),'received_perf_ns':time.perf_counter_ns(),'rgb':list(rgb),'target':copy_target,'metadata':event['metadata'],'image_width':image.width,'image_height':image.height})
 # Keep the Mac/server leg sampled concurrently with browser protocol pings.
 if not args.get('first_picture_idle'):
  network_ping=launch(['ping','-n','-i','1','10.69.69.125'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
  def network_ping_reader():
   for line in network_ping.stdout:emit({'kind':'network_leg_rtt','leg':'Mac_server','at_perf_ns':time.perf_counter_ns(),'raw':line.strip()})
  threading.Thread(target=network_ping_reader,daemon=True).start()
  emit({'kind':'network_rtt_before','raw':command(['ping','-n','-c','5','-W','1000','10.69.69.125'])})
 if not console_state()['ready']:raise RuntimeError('console changed before sampling')
 own_windows=cua('list_windows',{'on_screen_only':True}).get('windows',[])
 emit({'kind':'owned_window_layout','windows':[{k:w.get(k) for k in ['pid','window_id','bounds']} for w in own_windows if w.get('pid') in owned]})
 if not args.get('first_picture_idle'):emit({'kind':'viewer_animation_frames','times':page.evaluate('()=>new Promise(resolve=>{const times=[];const next=t=>{times.push(t);if(times.length===96)resolve(times);else requestAnimationFrame(next)};requestAnimationFrame(next)})')})
 def fixture_projection(phase):
  state=call('desktop.session.clock',{'session_id':page.evaluate('window.__appWindowBench.session')})
  projection=capture_projection(state)
  emit({'kind':'fixture_projection','phase':phase,'state':state,'projection':projection})
  return projection
 if args.get('first_picture_idle'):
  stage='ten-window first-picture idle check'
  if fixture_window_count!=10:raise RuntimeError('first-picture check requires ten fixture windows')
  native_command('idle');battery()
  deadline=time.monotonic()+30
  while True:
   consent_guard()
   live={pid for pid in capture_helpers if helper_births.get(pid)==process_identity(pid)}
   if len(live)==10 or time.monotonic()>=deadline:break
   page.wait_for_timeout(250)
  live_pictures=len(page.locator('.ui-window[data-kind="app"] .aw-stage[data-picture="live"]').all())
  if live_pictures!=10 or first_picture_failures:
   emit({'kind':'first_picture_summary','expected':10,'live':live_pictures,'failures':first_picture_failures})
  drain()
  metric_path=E/'companion-metrics.log';metric_offset=metric_path.stat().st_size if metric_path.exists() else 0
  baseline_draws=sum(row.get('kind')=='draw' for row in all_draws)
  def worker_stats():
   try:return page.evaluate('window.__appWindowBench.stats()')
   except Exception as error:
    # A failed first picture can prevent worker creation; native and frame
    # receipts still make the idle interval useful for diagnosing that failure.
    if first_picture_failures and 'worker counters unavailable' in str(error):return None
    raise
  browser_worker_before=worker_stats()
  phase_start=time.monotonic();deadline=phase_start+60
  emit({'kind':'first_picture_idle_plan','seconds':60,'fixture_windows':fixture_window_count,'capture_helpers':len(live)})
  while time.monotonic()<deadline:
   consent_guard()
   live={pid for pid in capture_helpers if helper_births.get(pid)==process_identity(pid)}
   if source.poll() is not None or window.poll() is not None or not browser.is_connected():raise RuntimeError('first-picture idle cohort process exited')
   page.wait_for_timeout(min(1000,max(1,int((deadline-time.monotonic())*1000))))
  live={pid for pid in capture_helpers if helper_births.get(pid)==process_identity(pid)}
  if source.poll() is not None or window.poll() is not None or not browser.is_connected():raise RuntimeError('first-picture idle cohort process exited')
  battery();receipt=drain();browser_worker_after=worker_stats()
  source_draws=sum(row.get('kind')=='draw' for row in all_draws)-baseline_draws
  worker_counters_available=browser_worker_before is not None and browser_worker_after is not None
  worker_delta=({key:max(0,int(browser_worker_after.get(key,0))-int(browser_worker_before.get(key,0)))
                for key in ('received','decoded','painted','dropped','superseded','repairs')}
               if worker_counters_available else None)
  metric_summary=companion_metric_summary(metric_path,metric_offset)
  browser_frames=len(receipt['probe']['videos']);worker_frames=len(receipt['frames'])
  result={'kind':'first_picture_idle_result','seconds':time.monotonic()-phase_start,'fixture_windows':fixture_window_count,
          'capture_helpers':len(live),'source_draws':source_draws,'browser_frames':browser_frames,
          'worker_frames':worker_frames,'worker_counters_available':worker_counters_available,'worker_delta':worker_delta,
          'source_callbacks':metric_summary['source_callbacks'],'fresh_deliveries':metric_summary['fresh_deliveries'],
          'live_pictures':live_pictures,'first_picture_failures':first_picture_failures}
  emit(result)
  if result['seconds']<60:
   raise RuntimeError('first-picture idle check ended before 60 seconds')
  if len(live)!=10 or live_pictures!=10 or first_picture_failures or worker_frames or browser_frames or source_draws or (worker_delta is not None and any(worker_delta.values())) or metric_summary['source_callbacks'] or metric_summary['fresh_deliveries']:
   raise RuntimeError('first-picture idle check did not meet the 60-second no-work bound')
  battery();emit({'kind':'result','status':'first_picture_idle_measured'});raise PhaseComplete()
 if args.get('ten_window_idle'):
  stage='ten-window idle soak'
  if fixture_window_count!=10:raise RuntimeError('idle cohort requires ten fixture windows')
  native_command('idle');battery()
  deadline=time.monotonic()+30
  while True:
   consent_guard()
   live={pid for pid in capture_helpers if helper_births.get(pid)==process_identity(pid)}
   if len(live)==10:break
   if time.monotonic()>=deadline:raise RuntimeError('ten live capture helpers unavailable')
   page.wait_for_timeout(250)
  if len(page.locator('.ui-window[data-kind="app"] .aw-stage[data-picture="live"]').all())<10:raise RuntimeError('ten live canvas windows unavailable')
  drain()
  helper_before=helper_resource_snapshot()
  if len(helper_before)!=10:raise RuntimeError('ten helper resource baselines unavailable')
  metric_path=E/'companion-metrics.log';metric_offset=metric_path.stat().st_size
  baseline_draws=sum(row.get('kind')=='draw' for row in all_draws)
  browser_worker_before=page.evaluate('window.__appWindowBench.stats()')
  phase_start=time.monotonic();previous_at=phase_start;previous_helpers=helper_before
  resource_samples=[{'checkpoint':0,'elapsed_seconds':0.0,'matched_helpers':10,'helper_count':10,
                     'cpu_cores':0.0,'wakeups_per_second':0.0,
                     'rss_kb':sum(row['rss_kb'] for row in helper_before.values()),
                     'rss_by_pid_kb':{str(pid):row['rss_kb'] for pid,row in helper_before.items()}}]
  browser_frames=[];frame_traces=[];source_draws=0
  emit({'kind':'ten_window_idle_plan','seconds':600,'fixture_windows':fixture_window_count,'capture_helpers':len(helper_before),'source_frames':0})
  for checkpoint in range(1,11):
   target=phase_start+checkpoint*60
   while time.monotonic()<target:
    consent_guard()
    if source.poll() is not None or window.poll() is not None or not browser.is_connected():raise RuntimeError('idle soak process exited')
    page.wait_for_timeout(min(1000,max(1,int((target-time.monotonic())*1000))))
   battery();receipt=drain();browser_frames.extend(receipt['probe']['videos']);frame_traces.extend(receipt['frames'])
   browser_worker_after=page.evaluate('window.__appWindowBench.stats()')
   source_draws=sum(row.get('kind')=='draw' for row in all_draws)-baseline_draws
   after_helpers=helper_resource_snapshot();sample_at=time.monotonic()
   delta=helper_resource_delta(previous_helpers,after_helpers,sample_at-previous_at)
   sample={'checkpoint':checkpoint,'elapsed_seconds':sample_at-phase_start,**delta,'source_draws':source_draws,
           'browser_frames':len(browser_frames),'worker_frames':len(frame_traces),
           'worker_stats':browser_worker_after}
   resource_samples.append(sample);emit({'kind':'ten_window_idle_sample',**sample})
   previous_helpers=after_helpers;previous_at=sample_at
  metric_summary=companion_metric_summary(metric_path,metric_offset)
  metric_bounds=companion_metric_summary(metric_path)
  max_cpu=max((row['cpu_cores'] for row in resource_samples),default=0.0)
  worker_delta={key:max(0,int(browser_worker_after.get(key,0))-int(browser_worker_before.get(key,0)))
                for key in ('received','decoded','painted','dropped','superseded')}
  result={'kind':'ten_window_idle_result','seconds':time.monotonic()-phase_start,'fixture_windows':fixture_window_count,
          'capture_helpers':len(previous_helpers),'source_draws':source_draws,'browser_frames':len(browser_frames),
          'worker_frames':len(frame_traces),'worker_delta':worker_delta,
          'max_helper_cpu_cores':max_cpu,'max_queue_depth':metric_bounds['queue_depth_max'],
          'source_callbacks':metric_summary['source_callbacks'],'damaged_callbacks':metric_summary['damaged_callbacks'],
          'fresh_deliveries':metric_summary['fresh_deliveries'],
          'rss_start_kb':resource_samples[0]['rss_kb'],'rss_end_kb':resource_samples[-1]['rss_kb'],
          'rss_delta_kb':resource_samples[-1]['rss_kb']-resource_samples[0]['rss_kb'],
          'rss_samples':[{'elapsed_seconds':r['elapsed_seconds'],'rss_kb':r['rss_kb']} for r in resource_samples],
          'wakeups_per_second':[r['wakeups_per_second'] for r in resource_samples],
          'max_helper_wakeups_per_second':max((r['wakeups_per_second'] for r in resource_samples[1:]),default=0.0)}
  emit(result)
  if result['seconds']<599 or result['capture_helpers']!=10 or any(r['matched_helpers']!=10 or r['helper_count']!=10 for r in resource_samples) or any(worker_delta.values()) or source_draws or browser_frames or frame_traces or metric_summary['source_callbacks'] or metric_summary['fresh_deliveries'] or max_cpu>0.01 or metric_bounds['queue_depth_max']>3:
   raise RuntimeError('ten-window idle soak did not meet the no-work bound')
  battery();emit({'kind':'result','status':'ten_window_idle_measured'});raise PhaseComplete()
 if not args.get('resources_only') and not args.get('demo_only'):
  stage='change samples'
  projection=fixture_projection('change samples')
  for index in range(48):
   if index==24:
    copy_target=compositor_target(surface,page.viewport_size,projection)
    cdp.on('Page.screencastFrame',observe_compositor)
    cdp.send('Page.startScreencast',{'format':'jpeg','quality':80,'maxWidth':1280,'maxHeight':900,'everyNthFrame':1})
   native_command('idle');page.wait_for_timeout(150+(index*37)%103)
   sequence=max([r['sequence'] for r in all_draws if r['kind']=='draw'] or [0])+1
   drain();page.evaluate('([id,colour,sequence,projection])=>window.__appWindowBench.arm(id,{colour,sequence,projection})',[index,sequence%8,sequence,projection])
   if index>=24:copy_target=compositor_target(surface,page.viewport_size,projection)
   composite_begin=len(composites)
   native_command('next');deadline=time.monotonic()+5;effect=None;events=[]
   while time.monotonic()<deadline:
    receipt=drain();events.append(receipt)
    effect=next((e for e in receipt['probe']['events'] if e.get('t')=='bench-effect' and e['id']==index),None)
    if effect:break
    page.wait_for_timeout(5)
   if not effect:
    emit({'kind':'change_sample_failure','index':index,'expected_sequence':sequence,'projection':projection,'state':call('desktop.session.clock',{'session_id':page.evaluate('window.__appWindowBench.session')}),'events':events})
    raise RuntimeError('numbered native change not observed')
   draw=next((r for r in all_draws if r['kind']=='draw' and r['sequence']==sequence),None)
   if not draw:raise RuntimeError('native draw receipt missing')
   compositor=None
   if index>=24:
    for i in range(100):
     compositor=next((c for c in composites[composite_begin:] if c['colour']==sequence%8 and c['distance']<2500),None)
     if compositor:break
     page.wait_for_timeout(5)
    if not compositor:raise RuntimeError('native change absent from compositor copies')
   result={'kind':'sample','index':index,'source':draw,'effect':effect,'events':events,'compositor':compositor};results.append(result);emit(result)
  stage='input samples'
  # Compositor observations can outlive focus/control acquired at window open.
  # Emulate the viewer's focus independently of the OS foreground app. Actual
  # native input must keep its app forward without making every key switch apps.
  cdp.send('Emulation.setFocusEmulationEnabled',{'enabled':True})
  emit({'kind':'input_focus','mode':'emulated','native_activation':False})
  focus_input(surface)
  projection=fixture_projection('input samples')
  flood_start=None;flood_metric_offset=0;flood_helpers_before={};flood_previous_at=0;flood_baseline_draws=0
  flood_resource_samples=[];flood_worker_before=None;flood_worker_after=None
  if args.get('flood'):
   native_command('motion 0')
  emit({'kind':'input_sample_plan','count':INPUT_SAMPLE_COUNT,'trigger':'immediate after key event'})
  for index in range(INPUT_SAMPLE_COUNT):
   # Keep control/DOM admission explicit without changing the native foreground.
   if not surface.evaluate('(canvas)=>canvas.parentElement===document.activeElement'):focus_input(surface)
   page.wait_for_function('document.hasFocus()',timeout=5000)
   sequence=max(r['sequence'] for r in all_draws if r['kind']=='draw')+1
   drain();copy_target=compositor_target(surface,page.viewport_size,projection);composite_begin=len(composites);events=[];effect=None
   if args.get('flood'):
    input_cursor=len([r for r in all_draws if r.get('kind')=='input']);page.keyboard.type('x')
    input_deadline=time.monotonic()+2;native_input=None
    while time.monotonic()<input_deadline and native_input is None:
     receipt=drain();events.append(receipt)
     native_input=next((r for r in all_draws[input_cursor:] if r.get('kind')=='input' and r.get('characters')=='x'),None)
     if native_input is None:page.wait_for_timeout(2)
    if native_input is None:raise RuntimeError('flood input did not reach the native fixture')
    sequence=native_input['sequence']
    page.evaluate('([id,colour,sequence,projection])=>window.__appWindowBench.arm(id,{colour,sequence,projection})',[100+index,sequence%8,sequence,projection])
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
     receipt=drain();events.append(receipt);effect=next((e for e in receipt['probe']['events'] if e.get('t')=='bench-effect' and e['id']==100+index),None)
     if effect:break
     page.wait_for_timeout(5)
   else:
    page.evaluate('([id,colour,sequence,projection])=>window.__appWindowBench.arm(id,{colour,sequence,projection})',[100+index,sequence%8,sequence,projection]);page.keyboard.type('x');deadline=time.monotonic()+5
    while time.monotonic()<deadline:
     receipt=drain();events.append(receipt);effect=next((e for e in receipt['probe']['events'] if e.get('t')=='bench-effect' and e['id']==100+index),None)
     if effect:break
     page.wait_for_timeout(5)
   if not effect:
    focus=surface.evaluate('(canvas)=>({surface:canvas.parentElement===document.activeElement,document:document.hasFocus()})')
    emit({'kind':'input_sample_failure','index':index,'expected_sequence':sequence,'events':events,'focus':focus})
    raise RuntimeError('input change not observed')
   compositor=None
   key_event_at=next((row['eventAt'] for receipt in events for row in receipt['probe']['domInputs']),None)
   for attempt in range(200):
    if args.get('flood'):
     compositor=next((c for c in composites[composite_begin:] if key_event_at is not None and c['timestamp_ms']>=key_event_at and c['distance']<2500),None)
    else:compositor=next((c for c in composites[composite_begin:] if c['colour']==sequence%8 and c['distance']<2500),None)
    if compositor:break
    page.wait_for_timeout(5)
   if not compositor:raise RuntimeError('input change absent from compositor copies')
   result={'kind':'input_sample','index':index,'effect':effect,'events':events,'compositor':compositor,
           **({'native_input':native_input,'flood':True} if args.get('flood') else {})};results.append(result);emit(result)
  cdp.send('Page.stopScreencast');cdp.remove_listener('Page.screencastFrame',observe_compositor)
 if args.get('flood'):
  stage='flood soak'
  # The latency samples run under animation first. Start a fresh, full ten-minute
  # flood window after them so setup time cannot shorten the requested soak.
  native_command('idle')
  flood_baseline_draws=sum(row.get('kind')=='draw' for row in all_draws)
  flood_metric_offset=(E/'companion-metrics.log').stat().st_size
  flood_helpers_before=helper_resource_snapshot()
  if len(flood_helpers_before)!=1:raise RuntimeError('flood cohort requires one live capture helper')
  flood_worker_before=page.evaluate('window.__appWindowBench.stats()')
  if not flood_worker_before:raise RuntimeError('flood worker counters unavailable')
  flood_resource_samples=[{'checkpoint':0,'elapsed_seconds':0.0,'matched_helpers':1,'helper_count':1,
                           'cpu_cores':0.0,'wakeups_per_second':0.0,
                           'rss_kb':sum(row['rss_kb'] for row in flood_helpers_before.values()),
                           'rss_by_pid_kb':{str(pid):row['rss_kb'] for pid,row in flood_helpers_before.items()}}]
  flood_start=time.monotonic();flood_previous_at=flood_start
  native_command('motion 0')
  emit({'kind':'flood_plan','seconds':600,'input_samples':INPUT_SAMPLE_COUNT,'fixture_windows':fixture_window_count,'capture_helpers':len(flood_helpers_before)})
  previous_helpers=flood_helpers_before;previous_at=flood_previous_at
  for checkpoint in range(1,11):
   target=flood_start+checkpoint*60
   while time.monotonic()<target:
    consent_guard()
    if source.poll() is not None or window.poll() is not None or not browser.is_connected():raise RuntimeError('flood process exited')
    page.wait_for_timeout(min(1000,max(1,int((target-time.monotonic())*1000))))
   battery();receipt=drain();flood_worker_after=page.evaluate('window.__appWindowBench.stats()')
   if not flood_worker_after:raise RuntimeError('flood worker counters unavailable')
   # Drain a second time after the counters so the raw receipt includes every
   # trace delivered at this checkpoint without stretching the soak by seconds.
   receipt=drain()
   after_helpers=helper_resource_snapshot();sample_at=time.monotonic()
   delta=helper_resource_delta(previous_helpers,after_helpers,sample_at-previous_at)
   source_draws=sum(row.get('kind')=='draw' for row in all_draws)-flood_baseline_draws
   sample={'checkpoint':checkpoint,'elapsed_seconds':sample_at-flood_start,**delta,
           'source_draws':source_draws,'worker_stats':flood_worker_after}
   flood_resource_samples.append(sample);emit({'kind':'flood_resource_sample',**sample})
   previous_helpers=after_helpers;previous_at=sample_at
  native_command('idle')
  metric_path=E/'companion-metrics.log'
  metrics_all=companion_metric_summary(metric_path)
  metrics_flood=companion_metric_summary(metric_path,flood_metric_offset)
  source_draws=sum(row.get('kind')=='draw' for row in all_draws)-flood_baseline_draws
  worker_delta={key:max(0,int(flood_worker_after.get(key,0))-int(flood_worker_before.get(key,0)))
                for key in ('received','decoded','painted','dropped','superseded')}
  max_cpu=max((row['cpu_cores'] for row in flood_resource_samples),default=0.0)
  display_maximum_fps=ready_rows[0]['display_maximum_fps']
  flood_seconds=time.monotonic()-flood_start
  source_draw_rate=source_draws/max(1,flood_seconds)
  source_draw_rate_ratio=source_draw_rate/max(1,display_maximum_fps)
  result={'kind':'flood_result','seconds':flood_seconds,'fixture_windows':fixture_window_count,
          'capture_helpers':len(previous_helpers),'display_maximum_fps':display_maximum_fps,
          'source_draws':source_draws,'source_draws_per_second':source_draw_rate,'source_draw_rate_ratio':source_draw_rate_ratio,
          'browser_video_frames':worker_delta['received'],'worker_painted_frames':worker_delta['painted'],
          'worker_superseded_frames':worker_delta['superseded'],'worker_dropped_frames':worker_delta['dropped'],
          'max_queue_depth':metrics_all['queue_depth_max'],'source_callbacks':metrics_flood['source_callbacks'],
          'fresh_deliveries':metrics_flood['fresh_deliveries'],'latest_only_callback_gap':metrics_flood['latest_only_callback_gap'],
          'encoder_drops':metrics_flood['encoder_drops'],'max_helper_cpu_cores':max_cpu,
          'rss_start_kb':sum(row['rss_kb'] for row in flood_helpers_before.values()),
          'rss_end_kb':flood_resource_samples[-1]['rss_kb'],'rss_samples':[{'elapsed_seconds':r['elapsed_seconds'],'rss_kb':r['rss_kb']} for r in flood_resource_samples],
          'rss_delta_kb':flood_resource_samples[-1]['rss_kb']-sum(row['rss_kb'] for row in flood_helpers_before.values()),
          'wakeups_per_second':[r['wakeups_per_second'] for r in flood_resource_samples],
          'max_helper_wakeups_per_second':max((r['wakeups_per_second'] for r in flood_resource_samples[1:]),default=0.0)}
  emit(result)
  if result['seconds']<599 or result['capture_helpers']!=1 or any(r['matched_helpers']!=1 or r['helper_count']!=1 for r in flood_resource_samples) or source_draw_rate_ratio<0.9 or metrics_all['queue_depth_max']>3:
   raise RuntimeError('flood soak did not meet the bounded-queue run conditions')
  battery();emit({'kind':'result','status':'flood_measured'});raise PhaseComplete()
 if args.get('input_only'):
  # This cohort ends before the bounded 80-character display suffix is used
  # by the independent demo. Keep its clocks and ordinary cleanup receipts.
  source_round_trips('after')
  resource_sample('input_idle')
  emit({'kind':'clocks_after','native':native_clock(),'browser':browser_clock()})
  battery();emit({'kind':'result','status':'input_measured','count':INPUT_SAMPLE_COUNT})
  raise PhaseComplete()
 stage='shape'
 if not args.get('resources_only'):emit({'kind':'source_geometry_before','state':call('desktop.session.clock',{'session_id':page.evaluate('window.__appWindowBench.session')})})
 before=page.locator('.ui-window[data-kind="app"]').bounding_box();native_command('shape');page.wait_for_timeout(2500);after=page.locator('.ui-window[data-kind="app"]').bounding_box()
 page.screenshot(path=str(E/'canvas-native-shaped.png'));emit({'kind':'shape','before':before,'after':after})
 if not args.get('resources_only'):emit({'kind':'source_geometry_after','state':call('desktop.session.clock',{'session_id':page.evaluate('window.__appWindowBench.session')})})
 stage='resources'
 browser_ids=descendants({play._impl_obj._connection._transport._proc.pid})-{play._impl_obj._connection._transport._proc.pid};owned.update(browser_ids)
 native_command('idle');page.wait_for_timeout(5000);resource_sample('idle')
 native_command('motion');page.wait_for_timeout(5000);resource_sample('motion');native_command('idle')
 if args.get('resources_only'):
  battery();emit({'kind':'result','status':'resources_measured'});raise PhaseComplete()
 # Save a short recording of compositor output after authentication, containing only this isolated canvas.
 stage='recording'
 # Earlier input samples must not make an incomplete demo look successful.
 typed_before=max((r.get('typed_count',0) for r in all_draws),default=0)
 demo_text=('infraternal demo',' typing')
 cdp.send('Page.startScreencast',{'format':'jpeg','quality':75,'maxWidth':2560,'maxHeight':1800,'everyNthFrame':1})
 frames=[]
 def screencast(event):
  frames.append({'timestamp':event['metadata'].get('timestamp'),'metadata':event['metadata'],'data':event['data']});cdp.send('Page.screencastFrameAck',{'sessionId':event['sessionId']})
 cdp.on('Page.screencastFrame',screencast)
 focus_input(surface);page.wait_for_timeout(2500)
 page.keyboard.type(demo_text[0],delay=120);page.wait_for_timeout(2000)
 native_command('wide');page.wait_for_timeout(2500)
 page.keyboard.type(demo_text[1],delay=120);page.wait_for_timeout(2000)
 cdp.send('Page.stopScreencast')
 typed_count=max((r.get('typed_count',0) for r in all_draws),default=0)
 if typed_count-typed_before!=sum(map(len,demo_text)) or not frames:raise RuntimeError('demo typing or recording incomplete')
 page.screenshot(path=str(E/'canvas-demo-after.png'))
 for i,frame in enumerate(frames):(E/('record-%04d.jpg'%i)).write_bytes(base64.b64decode(frame['data']))
 (E/'recording-timestamps.json').write_text(json.dumps([f['timestamp'] for f in frames]))
 (E/'recording-metadata.json').write_text(json.dumps({'viewport':page.viewport_size,'frames':[f['metadata'] for f in frames]}))
 emit({'kind':'recording','frames':len(frames),'typed_before':typed_before,'typed_count':typed_count,'typed_expected':sum(map(len,demo_text)),'canvas_after':page.locator('.ui-window[data-kind="app"]').bounding_box()})
 if args.get('soak'):
  stage='stability soak'
  emit({'kind':'stability_plan','seconds':STABILITY_SECONDS,'recovery':RECOVERY_ENABLED,'reconnect_iteration':RECONNECT_ITERATION,'reopen_iteration':REOPEN_ITERATION})
  soak_start=time.monotonic();counts={'crashes':0,'stuck_frames':0,'requested_drops':0,'reconnects':0,'reopens':0,'typed':0,'resizes':0,'idle_checks':0,'unexpected_helper_exits':0,'slow_worker_updates':0};iteration=0
  def live_helper_pids():
   return {pid for pid,birth in helper_births.items() if process_identity(pid)==birth}
  previous_helpers=live_helper_pids()
  initial_frames=drain()['frames'];initial_painted=[f for f in initial_frames if f.get('outcome')=='painted' and f.get('width') and f.get('height')]
  last_dimensions=(initial_painted[-1]['width'],initial_painted[-1]['height']) if initial_painted else None
  resize_cursor=(E/'helper-metrics.log').stat().st_size;recent_resize_acks=[]
  soak_sockets_before=page.evaluate('window.__appWindowBench.sockets');soak_native_start=len(all_draws)
  soak_windows_before=page.locator('.ui-window[data-kind="app"]').evaluate_all('(nodes)=>nodes.map(n=>n.dataset.windowId)')
  while time.monotonic()-soak_start<STABILITY_SECONDS:
   consent_guard();battery();receipts=[]
   if source.poll() is not None or window.poll() is not None or not browser.is_connected():
    counts['crashes']+=1;break
   if RECOVERY_ENABLED and iteration==RECONNECT_ITERATION:
    prior_sockets=page.evaluate('window.__appWindowBench.sockets')
    emit({'kind':'network_drop_request'});counts['requested_drops']+=1
    ack=json.loads(sys.stdin.readline())
    if ack.get('kind')!='network_restored':raise RuntimeError('private route restoration unavailable')
    try:
     page.wait_for_function('(prior)=>window.__appWindowBench.sockets.opened>prior.opened&&window.__appWindowBench.sockets.closed>prior.closed',arg=prior_sockets,timeout=10000)
     first_picture()
     after_sockets=page.evaluate('window.__appWindowBench.sockets')
     counts['reconnects']+=max(0,after_sockets['opened']-prior_sockets['opened'])
     emit({'kind':'soak_reconnect','before':prior_sockets,'after':after_sockets})
    except Exception:counts['stuck_frames']+=1
   if RECOVERY_ENABLED and iteration==REOPEN_ITERATION:
    previous=page.locator('.ui-window[data-kind="app"]').first
    previous_id=previous.get_attribute('data-window-id')
    if not previous_id:raise RuntimeError('app window identity unavailable')
    previous.locator('[data-action="close"]').evaluate('(button)=>button.click()')
    page.get_by_role('button',name='New window',exact=True).click();page.get_by_role('option',name=picker_title_pattern('App window measurement')).click()
    replacement=page.locator('.ui-window[data-kind="app"]').filter(has=page.locator('.aw-stage[data-picture="live"]'))
    try:
     first_picture(previous_id)
     counts['reopens']+=1
     emit({'kind':'soak_reopen','previous_id':previous_id,'replacement_id':replacement.last.get_attribute('data-window-id')})
    except Exception:counts['stuck_frames']+=1
   if RECOVERY_ENABLED and iteration%6==2:
    native_command('shape' if iteration%12==2 else 'wide');counts['resizes']+=1
   if iteration%6 in (3,4):
    native_command('idle');page.wait_for_timeout(1500)
    before=page.evaluate('window.__appWindowBench.stats()');page.wait_for_timeout(2500);after=page.evaluate('window.__appWindowBench.stats()')
    emit({'kind':'soak_idle','before':before,'after':after});counts['idle_checks']+=1
   else:
    surface=page.locator('.aw-surface');focus_input(surface);page.wait_for_timeout(2200)
    burst=soak_burst(iteration)
    sequence=max(r['sequence'] for r in all_draws if r['kind']=='draw')+len(burst)
    prior_inputs=sum(r.get('kind')=='input' for r in all_draws);draw_start=len(all_draws)
    projection=fixture_projection('soak '+str(iteration))
    drain();page.evaluate('([id,colour,sequence,projection])=>window.__appWindowBench.arm(id,{colour,sequence,projection})',[1000+iteration,sequence%8,sequence,projection]);page.keyboard.type(burst,delay=90)
    deadline=time.monotonic()+5;observed=False;effect=None;dom_inputs=[];receipts=[]
    while time.monotonic()<deadline:
     receipt=drain();receipts.append(receipt);dom_inputs.extend(receipt['probe']['domInputs'])
     effect=effect or next((e for e in receipt['probe']['events'] if e.get('t')=='bench-effect' and e['id']==1000+iteration),None)
     draw=next((r for r in all_draws if r.get('kind')=='draw' and r['sequence']==sequence),None)
     received_inputs=sum(r.get('kind')=='input' for r in all_draws)-prior_inputs
     if effect and draw and soak_input_matches(all_draws[draw_start:],burst) and int(effect['frame']['captureNs'])>=draw['end_ticks']*timebase:observed=True;break
     page.wait_for_timeout(10)
    # Keep every stage even when the predicate fails; a counter alone cannot
    # distinguish input loss, stale colour, timestamp ordering or delivery loss.
    emit({'kind':'soak_typing_receipt','iteration':iteration,'expected_sequence':sequence,'expected_text':burst,'timebase':timebase,'observed':observed,'effect':effect,'draw':draw,'received_inputs':received_inputs,'native':all_draws[draw_start:],'receipts':receipts})
    if observed:
     counts['typed']+=len(burst)
     delay=effect['begin']-dom_inputs[-1]['at'] if dom_inputs else None
     if delay is not None and delay>=1000:counts['slow_worker_updates']+=1
     emit({'kind':'soak_typing','iteration':iteration,'characters':len(burst),'last_key_to_worker_ms':delay})
    else:counts['stuck_frames']+=1
   step_receipt=drain()
   painted=[frame for receipt in receipts+[step_receipt] for frame in receipt['frames'] if frame.get('outcome')=='painted' and frame.get('width') and frame.get('height')]
   newest=max(painted,key=lambda frame:frame['receivedAt']) if painted else None
   current_dimensions=(newest['width'],newest['height']) if newest else last_dimensions
   resize_cursor,resize_acks=read_resize_acks(E/'helper-metrics.log',resize_cursor)
   recent_resize_acks=[(step,ack) for step,ack in recent_resize_acks if iteration-step<=1]+[(iteration,ack) for ack in resize_acks]
   current_helpers=live_helper_pids();retired=previous_helpers-current_helpers
   # Resize notifications retire capture asynchronously; keep that attribution
   # through the next observation, while unexplained exits still fail the soak.
   native_resize=expected_capture_retirement(retired,capture_helpers,previous_helpers-capture_helpers,current_helpers-capture_helpers,last_dimensions,current_dimensions,bool(recent_resize_acks))
   # A requested recovery does not authorize helper loss; only a proven resize
   # with the same surviving control owner can explain a capture retirement.
   expected_retirement=native_resize
   if retired:
    emit({'kind':'soak_helper_retirement','iteration':iteration,'expected':expected_retirement,'pids':sorted(retired),'native_resize':native_resize,'resize_acks':[ack for _,ack in recent_resize_acks],'previous_dimensions':last_dimensions,'current_dimensions':current_dimensions,'previous_controls':sorted(previous_helpers-capture_helpers),'current_controls':sorted(current_helpers-capture_helpers)})
    if not expected_retirement:counts['unexpected_helper_exits']+=len(retired)
   previous_helpers=current_helpers;last_dimensions=current_dimensions
   emit({'kind':'soak_step','iteration':iteration,'elapsed_seconds':time.monotonic()-soak_start,'counts':counts.copy()})
   iteration+=1
   page.wait_for_timeout(max(0,int((soak_start+iteration*10-time.monotonic())*1000)))
  final_sockets=page.evaluate('window.__appWindowBench.sockets')
  final_windows=page.locator('.ui-window[data-kind="app"]').evaluate_all('(nodes)=>nodes.map(n=>n.dataset.windowId)')
  expected_text=''.join(soak_burst(step) for step in range(STABILITY_SECONDS//10))
  exact_text=soak_input_matches(all_draws[soak_native_start:],expected_text)
  emit({'kind':'soak_input_comparison','expected':expected_text,'expected_characters':len(expected_text),'exact_match':exact_text,'native':all_draws[soak_native_start:]})
  opened_reconnects=max(0,final_sockets['opened']-soak_sockets_before['opened'])
  counts['reconnects']=max(counts['reconnects'],opened_reconnects) if RECOVERY_ENABLED else opened_reconnects
  if not RECOVERY_ENABLED:
   counts['reopens']=int(final_windows!=soak_windows_before)
  emit({'kind':'soak_result','seconds':time.monotonic()-soak_start,'counts':counts,'sockets_before':soak_sockets_before,'sockets_after':final_sockets})
  if counts['crashes'] or counts['stuck_frames'] or counts['unexpected_helper_exits'] or counts['reconnects']!=int(RECOVERY_ENABLED) or counts['reopens']!=int(RECOVERY_ENABLED) or not exact_text or counts['typed']!=len(expected_text):raise RuntimeError('stability soak did not pass')
 source_round_trips('after')
 emit({'kind':'network_rtt_after','raw':command(['ping','-n','-c','5','-W','1000','10.69.69.125'])})
 console=console_state();emit({'kind':'console_after','state':console})
 if not console['ready']:raise RuntimeError('console changed during sampling')
 emit({'kind':'decoder_properties','properties':decoder_properties})
 consent_guard()
 emit({'kind':'clocks_after','native':native_clock(),'browser':browser_clock()});battery();emit({'kind':'result','status':'measured','phase_seconds':time.monotonic()-start})
except PhaseComplete:
 pass
except Exception as error:
 if 'stop_capture' in globals():stop_capture()
 if stage in ['open canvas window','change samples','input samples','shape','resources','recording','stability soak'] and browser:
  try:
   page.screenshot(path=str(E/'canvas-failure.png'))
   emit({'kind':'canvas_failure_state','states':page.locator('.aw-stage').evaluate_all('(nodes)=>nodes.map(n=>({picture:n.dataset.picture,text:n.innerText.slice(0,300)}))')})
  except Exception:pass
 emit({'kind':'failure','stage':stage,'error_type':type(error).__name__,'location':[{'file':pathlib.Path(t.filename).name,'line':t.lineno,'function':t.name} for t in traceback.extract_tb(error.__traceback__) if pathlib.Path(t.filename).name in ('venue-mac.py','measure-mac.py')]})
 # Exceptions may contain authority values in page-evaluation arguments: never print their text.
 failed=True
finally:
 if not locked:
  for p in reversed(children):
   if p.poll() is None:
    try:p.kill();p.wait(timeout=5)
    except:pass
    check=subprocess.run(['ps','-p',str(p.pid),'-o','pid=,stat=,comm='],capture_output=True,text=True)
    emit({'kind':'process_exit','pid':p.pid,'role':pathlib.Path(p.args[0]).name,'exit':p.returncode,
          'ps_exit':check.returncode,'row':check.stdout.strip()})
 if locked:
  if 'stop_monitor' in locals():
   stop_monitor.set();monitor.join(timeout=25)
  for p in children:owned.update(descendants({p.pid}))
  if play:
   try:owned.update(descendants({play._impl_obj._connection._transport._proc.pid}))
   except:pass
  owned.update(browser_processes())
  if browser:
   try:browser.close()
   except:pass
  if play:
   try:play.stop()
   except:pass
  for p in reversed(children):
   if p.poll() is None:
    try:
     if p.args[0].endswith('/source'):p.send_signal(signal.SIGINT)
     elif p.stdin:p.stdin.close()
     else:p.terminate()
     p.wait(timeout=15 if p.args[0].endswith('/source') else 8)
    except:
     try:p.terminate();p.wait(timeout=3)
     except:pass
   emit({'kind':'process_exit','pid':p.pid,'role':pathlib.Path(p.args[0]).name,'exit':p.returncode})
   if p.args[0].endswith('/source') and p.returncode!=0:failed=True
  if 'helper_births' in locals():
   for pid,birth in helper_births.items():
    if process_identity(pid)==birth:
     emit({'kind':'cleanup_term','pid':pid});os.kill(pid,signal.SIGTERM)
     time.sleep(.5)
     if process_identity(pid)==birth:
      os.kill(pid,signal.SIGKILL);emit({'kind':'cleanup_kill','pid':pid});failed=True
  if cua_pid and process_identity(cua_pid)==cua_birth:
   try:os.kill(cua_pid,signal.SIGTERM)
   except ProcessLookupError:pass
  try:
   if 'pidlog' in locals():
    for line in pidlog.read_text().splitlines():owned.add(int(line.split()[1]))
  except:pass
  time.sleep(1)
  checks=[]
  for pid in sorted(p for p in owned if p):
   p=subprocess.run(['ps','-p',str(pid),'-o','pid=,stat=,comm='],capture_output=True,text=True);checks.append({'pid':pid,'ps_exit':p.returncode,'row':p.stdout.strip()})
  cleanup_remaining=sum(c['ps_exit']==0 for c in checks)
  emit({'kind':'cleanup','checks':checks,'remaining':cleanup_remaining})
  emit({'kind':'consent_monitor','errors':consent_errors if 'consent_errors' in locals() else []})
  if restore_pending:
   active_helpers=[pid for pid,birth in helper_births.items() if process_identity(pid)==birth] if 'helper_births' in locals() else []
   try:
    if active_helpers:raise RuntimeError('owned capture helper remains active')
    restored=restore_helper_bundle(native.parent.parent.parent,helper_restore['archive'],helper_restore['archive_sha256'],helper_restore['executable_sha256'],helper_restore['leaf_sha1'])
    restore_pending=False
    emit({'kind':'helper_restoration','status':'restored',**restored})
   except Exception as restore_error:
    failed=True
    emit({'kind':'helper_restoration','status':'failed','error_type':type(restore_error).__name__,'active_helpers':active_helpers})
  if runtime_owned:
   import shutil
   shutil.rmtree(runtime)
  signal.alarm(0)
  try:lock_owner=(lock/'owner').read_text().strip();lock_pid=(lock/'pid').read_text().strip()
  except OSError:lock_owner=lock_pid=''
  if lock_owner==job and lock_pid==str(args['controller_pid']):
   for name in ['owner','pid','started']:(lock/name).unlink()
   lock.rmdir();locked=False
   emit({'kind':'lock_released'})
 if 'composites' in locals():(E/'compositor-copies.json').write_text(json.dumps(composites))
 (E/'native-metrics.log').write_text('\n'.join(native_metrics)+'\n');(E/'source-draws.json').write_text(json.dumps(all_draws));(E/'samples.json').write_text(json.dumps(results))
 if fixture_build.exists():
  import shutil
  shutil.rmtree(fixture_build)

raise SystemExit(1 if failed or cleanup_remaining else 0)
