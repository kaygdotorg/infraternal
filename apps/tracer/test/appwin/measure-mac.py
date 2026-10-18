"""Role: measure the real native window through the production canvas on the named Mac; keep authority in memory and prove owned-PID cleanup."""
import base64,io,json,os,pathlib,queue,signal,subprocess,sys,threading,time,traceback,uuid
from playwright.sync_api import sync_playwright
from PIL import Image
os.environ['TRACER_TEST_PORT']='4346'
ROOT=pathlib.Path.home()/'infraternal-bench/app-windows-latency'
args=json.loads(sys.stdin.readline())
import re
if not re.fullmatch(r'[a-z0-9-]{1,48}',args['label']):raise SystemExit(2)
E=ROOT/'evidence'/args['label'];E.mkdir(parents=True,exist_ok=False)
BIN=ROOT/'bin'
class PhaseComplete(Exception):
 """Finish a short phase through cleanup, whose result still controls exit status."""
 pass
owned=set();children=[];browser=None;play=None;lock=pathlib.Path('/tmp/infraternal-bench.lock');locked=False;cua_pid=None
runtime_owned=False
start=time.monotonic();stage='lock';all_draws=[];native_metrics=[];results=[];failed=False;cleanup_remaining=0
def emit(value): print(json.dumps(value),flush=True)
def command(argv,**kw):return subprocess.run(argv,capture_output=True,text=True,check=True,**kw).stdout

def launch(argv,**kw):
 p=subprocess.Popen(argv,**kw);owned.add(p.pid);children.append(p);return p

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

def cua(name,params):
 return json.loads(command([str(pathlib.Path.home()/'.local/bin/cua-driver'),'call',name,json.dumps(params)],timeout=20))

def consent_check():
 # Inspect metadata before requesting any screenshot; never retain an unrelated window inventory.
 inventory=cua('list_windows',{'on_screen_only':True})
 def walk(v):
  if isinstance(v,dict):
   yield v
   for x in v.values():yield from walk(x)
  elif isinstance(v,list):
   for x in v:yield from walk(x)
 matches=[v for v in walk(inventory) if any(name in str(v.get('title',''))+' '+str(v.get('app_name','')) for name in ['InfraternalCaptureHelper','infraternal-desktop-helper'])]
 for v in matches:
  if not v.get('pid') or not v.get('window_id'):continue
  session='app-windows-latency-consent'
  state=cua('get_window_state',{'pid':v['pid'],'window_id':v['window_id'],'session':session,'include_screenshot':False,'max_depth':12,'max_elements':300})
  controls=list(walk(state));safe=json.dumps(state)
  # A prompt for our helper may be accepted; password controls are never filled.
  if any('secure' in str(x.get('role','')).lower() or 'password' in str(x.get('role','')).lower() for x in controls):
   emit({'kind':'helper_password_sheet','controls':[{key:x[key] for key in ('role','title','name','label') if key in x} for x in controls]})
   cancel=next((x for x in controls if x.get('title')=='Cancel' or x.get('name')=='Cancel' or x.get('label')=='Cancel'),None)
   if cancel and cancel.get('element_token'):cua('click',{'pid':v['pid'],'window_id':v['window_id'],'session':session,'delivery_mode':'foreground','element_token':cancel['element_token']})
   raise RuntimeError('helper password sheet requires owner; no input supplied')
  if 'Allow' in safe and ('requesting' in safe or 'bypass' in safe):
   fresh=cua('get_window_state',{'pid':v['pid'],'window_id':v['window_id'],'session':session,'include_screenshot':True,'screenshot_out_file':str(E/'helper-consent-before.png'),'max_depth':12,'max_elements':300})
   buttons=[x for x in walk(fresh) if x.get('title')=='Allow' or x.get('name')=='Allow' or x.get('label')=='Allow']
   if len(buttons)!=1:raise RuntimeError('helper Allow control ambiguous')
   button=buttons[0]
   click={'pid':v['pid'],'window_id':v['window_id'],'session':session,'delivery_mode':'foreground'}
   if button.get('element_token'):click['element_token']=button['element_token']
   else:raise RuntimeError('helper Allow control lacks stable token')
   cua('click',click)
   after=cua('get_desktop_state',{'session':session,'screenshot_out_file':str(E/'helper-consent-after.png')})
   if 'requesting to bypass' in json.dumps(after):raise RuntimeError('helper prompt remains')
 emit({'kind':'consent','checked':True,'our_windows':len(matches)})

emit({'kind':'runner','pid':os.getpid()})
try:
 for attempt in range(90):
  try:lock.mkdir();locked=True;break
  except FileExistsError:
   if attempt==0 or attempt%5==0:emit({'kind':'lock_wait','owner':(lock/'owner').read_text()})
   time.sleep(60)
 if not locked:raise RuntimeError('Mac lock unavailable')
 (lock/'owner').write_text('app-windows-latency\n');(lock/'pid').write_text(str(args['controller_pid'])+'\n');(lock/'started').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z')+'\n')
 stage='VM readiness';emit({'kind':'vm_readiness_request'})
 readiness=json.loads(sys.stdin.readline());emit({'kind':'vm_readiness','idle':readiness.get('idle',[])})
 if not readiness.get('ready'):raise RuntimeError('named VM or private server unavailable')
 args.update(readiness)
 def screen_deadline(signum,frame):raise TimeoutError('owned on-screen deadline')
 ledger=ROOT/'evidence/on-screen-ledger.json';used=json.loads(ledger.read_text()).get('seconds',0) if ledger.exists() else 0
 if used>=43*60:raise RuntimeError('owned on-screen allowance exhausted')
 screen_start=time.monotonic()
 signal.signal(signal.SIGALRM,screen_deadline);signal.alarm(max(1,int(44*60-used)))
 battery();emit({'kind':'environment','text':command(['sw_vers'])+command(['sysctl','-n','hw.model','hw.ncpu','hw.memsize'])+command(['uptime'])})
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
 if cua_pid:owned.add(cua_pid)
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
 native_mapping=native_clock()
 stage='helper wrappers'
 consent_errors=[]
 runtime=pathlib.Path.home()/'infraternal-bench'/('wl-'+uuid.uuid4().hex[:4]);runtime.mkdir(mode=0o700);runtime_owned=True
 native=pathlib.Path('/Users/kayg/infraternal-bench/app-windows/InfraternalCaptureHelper.app/Contents/MacOS/InfraternalCaptureHelper')
 helper_hash=command(['shasum','-a','256',str(native)]).split()[0]
 emit({'kind':'native_helper','hash':helper_hash})
 command(['codesign','--verify','--strict',str(native.parent.parent.parent)])
 if helper_hash!='7b7ad2bcbc18f4f390f00d001b59984b1998665c8ddae9846520b83875001dc5':raise RuntimeError('approved companion version changed')
 pidlog=E/'helper-pids.txt';pidlog.write_text('');(E/'helper-metrics.log').write_text('');helper_births={}
 for name,target in [('helper',BIN/'helper'),('native',native)]:
  wrapper=runtime/name
  codec_argument=' --hevc' if name=='native' and args.get('codec')=='hevc' else ''
  wrapper.write_text('#!/bin/sh\n# Role: record only an owned helper PID before preserving its pipes and process identity.\nprintf "'+name+' %s\\n" "$$" >> "'+str(pidlog)+'"\nexec "'+str(target)+'" "$@"'+codec_argument+' 2>> "'+str(E/'helper-metrics.log')+'"\n');wrapper.chmod(0o700)
 stop_monitor=threading.Event()
 def watch_launches():
  seen=set()
  while not stop_monitor.wait(.1):
   try:
    rows=pidlog.read_text().splitlines()
    if any(row not in seen for row in rows):
     for row in rows:
      if row in seen:continue
      pid=int(row.split()[1]);birth=subprocess.run(['ps','-p',str(pid),'-o','lstart='],capture_output=True,text=True)
      if birth.returncode==0:helper_births[pid]=birth.stdout.strip()
     seen.update(rows);consent_check();time.sleep(.3);consent_check()
   except Exception as e:
    consent_errors.append(type(e).__name__)
 monitor=threading.Thread(target=watch_launches,daemon=True);monitor.start()
 env=dict(os.environ,INFRATERNAL_DESKTOP_COMPANION=str(runtime/'native'),INFRATERNAL_DESKTOP_MEASURE='1',INFRATERNAL_DESKTOP_BENCH_DIR=str(runtime),INFRATERNAL_DESKTOP_BENCH_HELPER=str(runtime/'helper'))
 if args.get('resources_only'):env.pop('INFRATERNAL_DESKTOP_MEASURE',None)
 env.pop('INFRATERNAL_DESKTOP_SURFACE',None);env.pop('INFRATERNAL_DESKTOP_OWNED',None)
 if args.get('pipeline')=='surface':env['INFRATERNAL_DESKTOP_SURFACE']='1'
 if args.get('pipeline')=='owned':env['INFRATERNAL_DESKTOP_OWNED']='1'
 emit({'kind':'pipeline','mode':args.get('pipeline','owned'),'browser_dpr':2})
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
 def resource_sample(label):
  source_ids=descendants({source.pid});owned.update(source_ids);ids=source_ids|browser_ids|({window.pid} if 'window' in globals() else set())
  begin=time.perf_counter_ns();worker_before=page.evaluate('window.__appWindowBench.stats()');draw_before=len(all_draws)
  rows=[];sample_times=[]
  for i in range(5):
   sample_times.append(time.perf_counter_ns());rows.append(command(['ps','-p',','.join(map(str,ids)),'-o','pid=,ppid=,%cpu=,rss=,time=,comm=']));page.wait_for_timeout(1000)
  worker_after=page.evaluate('window.__appWindowBench.stats()');end=time.perf_counter_ns()
  host=command(['top','-l','2','-s','1','-n','0'])
  emit({'kind':'resources','label':label,'worker_before':worker_before,'worker_after':worker_after,'source_draws':len(all_draws)-draw_before,'begin_perf_ns':begin,'end_perf_ns':end,'host':host,'rows':rows,'sample_times_ns':sample_times,'source_pids':list(source_ids),'browser_pids':list(browser_ids),'uptime':command(['uptime'])})
 # Remove the fixture's initial terminal before both resource baselines.
 initial_terminal=page.locator('.ui-window[data-kind="terminal"] [data-action="close"]')
 if initial_terminal.count():initial_terminal.first.evaluate('(b)=>b.click()')
 page.wait_for_timeout(1000)
 resource_sample('empty')
 stage='native fixture'
 window=launch([str(BIN/'latency-window')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 while True:
  ready=json.loads(window.stdout.readline())
  if ready.get('kind')=='ready':break
  all_draws.append(ready)
 window_id=ready['window_id'];native_queue=queue.Queue()
 if ready['frame_x']<850:raise RuntimeError('display cannot keep both owned windows visible')
 browser_window=cdp.send('Browser.getWindowForTarget')
 cdp.send('Browser.setWindowBounds',{'windowId':browser_window['windowId'],'bounds':{'left':0,'top':32,'width':848,'height':820,'windowState':'normal'}})
 def draw_reader():
  for line in window.stdout:
   row=json.loads(line);all_draws.append(row);native_queue.put(row)
 threading.Thread(target=draw_reader,daemon=True).start()
 def native_command(value):window.stdin.write(value+'\n');window.stdin.flush()
 def own_inventory():return [w for w in call('desktop.windows',{'host_id':host_id})['windows'] if w['owner_pid']==window.pid]
 for attempt in range(10):
  try:
   inventory=own_inventory()
   if any(w['window_id']==window_id for w in inventory):break
  except RuntimeError:pass
  page.wait_for_timeout(500)
 else:raise RuntimeError('owned native window inventory unavailable')
 emit({'kind':'window','pid':window.pid,'window_id':window_id,'inventory':inventory})
 stage='open canvas window'
 page.bring_to_front();page.keyboard.press('Meta+k');page.get_by_role('option',name='Settings: Hosts').click()
 toggle=page.get_by_role('switch',name='Stream app windows')
 if not toggle.is_checked():toggle.click()
 close=page.locator('.ui-settings-close')
 if close.is_visible():close.click()
 terminals=page.locator('.ui-window[data-kind="terminal"] [data-action="close"]')
 if terminals.count():terminals.first.evaluate('(b)=>b.click()')
 page.get_by_role('button',name='New window',exact=True).click();page.get_by_role('option',name='App window measurement',exact=False).click()
 page.locator('.aw-stage[data-picture="live"]').wait_for(timeout=45000)
 consent_check()
 emit({'kind':'canvas_context','receipts':page.evaluate('window.__appWindowBench.take()')})
 page.screenshot(path=str(E/'canvas-native-before.png'))
 surface=page.locator('.aw-surface');surface.click(position={'x':200,'y':170})
 # Every capture helper launch is followed by a consent check, including inventory helpers.
 consent_check()
 def browser_clock():
  samples=[]
  for i in range(16):
   before=time.perf_counter_ns();value=page.evaluate('performance.timeOrigin+performance.now()');after=time.perf_counter_ns()
   samples.append({'before_ns':before,'after_ns':after,'epoch_ms':value,'lower':before-value*1e6,'upper':after-value*1e6})
  best=min(samples,key=lambda x:x['upper']-x['lower']);return {'samples':samples,'lower':best['lower'],'upper':best['upper']}
 browser_mapping=browser_clock()
 worker_mapping=None
 if not args.get('resources_only'):
  samples=[page.evaluate('window.__appWindowBench.workerClock()') for _ in range(16)]
  best=min(samples,key=lambda r:r['after']-r['before'])
  worker_mapping={'samples':samples,'lower_ms':best['before']-best['worker'],'upper_ms':best['after']-best['worker']}
 emit({'kind':'clocks','timebase':base,'native':native_mapping,'browser':browser_mapping,'worker':worker_mapping})
 info=browser.new_browser_cdp_session().send('SystemInfo.getInfo');emit({'kind':'browser_rendering','version':browser.version,'gpu':info.get('gpu')})
 def drain():return page.evaluate('()=>({probe:window.__appWindowBench.take(),frames:window.__infraternalAppWindowTrace?.take()??[]})')
 # Actual compositor pixels are sampled separately below; worker readback is not presentation.
 composites=[]
 palette=[[38,89,204],[38,191,89],[204,64,51],[179,64,191],[38,179,191],[204,166,38],[102,64,204],[191,102,51]]
 rectangle=surface.bounding_box()
 def observe_compositor(event):
  cdp.send('Page.screencastFrameAck',{'sessionId':event['sessionId']})
  image=Image.open(io.BytesIO(base64.b64decode(event['data']))).convert('RGB')
  x=round((rectangle['x']+rectangle['width']/2)*image.width/832);y=round((rectangle['y']+rectangle['height']/2)*image.height/720)
  rgb=image.getpixel((x,y));distances=[sum((a-b)**2 for a,b in zip(rgb,p)) for p in palette]
  composites.append({'timestamp_ms':event['metadata'].get('timestamp',0)*1000,'colour':distances.index(min(distances)),'distance':min(distances),'received_perf_ns':time.perf_counter_ns()})
 emit({'kind':'network_rtt_before','raw':command(['ping','-n','-c','5','-W','1000','10.69.69.125'])})
 if not console_state()['ready']:raise RuntimeError('console changed before sampling')
 own_windows=cua('list_windows',{'on_screen_only':True}).get('windows',[])
 emit({'kind':'owned_window_layout','windows':[{k:w.get(k) for k in ['pid','window_id','bounds']} for w in own_windows if w.get('pid') in owned]})
 emit({'kind':'viewer_animation_frames','times':page.evaluate('()=>new Promise(resolve=>{const times=[];const next=t=>{times.push(t);if(times.length===96)resolve(times);else requestAnimationFrame(next)};requestAnimationFrame(next)})')})
 if not args.get('resources_only'):
  stage='change samples'
  for index in range(48):
   if index==24:
    cdp.on('Page.screencastFrame',observe_compositor)
    cdp.send('Page.startScreencast',{'format':'jpeg','quality':80,'maxWidth':1280,'maxHeight':900,'everyNthFrame':1})
   native_command('idle');page.wait_for_timeout(150+(index*37)%103)
   sequence=max([r['sequence'] for r in all_draws if r['kind']=='draw'] or [0])+1
   drain();page.evaluate('([id,colour])=>window.__appWindowBench.arm(id,{colour})',[index,sequence%8])
   composite_begin=len(composites)
   native_command('next');deadline=time.monotonic()+5;effect=None;events=[]
   while time.monotonic()<deadline:
    receipt=drain();events.append(receipt)
    effect=next((e for e in receipt['probe']['events'] if e.get('t')=='bench-effect' and e['id']==index),None)
    if effect:break
    page.wait_for_timeout(5)
   if not effect:raise RuntimeError('numbered native change not observed')
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
  for index in range(16):
   page.wait_for_timeout(150+(index*37)%103);sequence=max(r['sequence'] for r in all_draws if r['kind']=='draw')+1
   drain();page.evaluate('([id,colour])=>window.__appWindowBench.arm(id,{colour})',[100+index,sequence%8]);page.keyboard.type('x');deadline=time.monotonic()+5;events=[];effect=None
   while time.monotonic()<deadline:
    receipt=drain();events.append(receipt);effect=next((e for e in receipt['probe']['events'] if e.get('t')=='bench-effect' and e['id']==100+index),None)
    if effect:break
    page.wait_for_timeout(5)
   if not effect:raise RuntimeError('input change not observed')
   result={'kind':'input_sample','index':index,'effect':effect,'events':events};results.append(result);emit(result)
  cdp.send('Page.stopScreencast');cdp.remove_listener('Page.screencastFrame',observe_compositor)
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
 cdp.send('Page.startScreencast',{'format':'jpeg','quality':75,'maxWidth':1280,'maxHeight':900,'everyNthFrame':1})
 frames=[]
 def screencast(event):
  frames.append({'timestamp':event['metadata'].get('timestamp'),'data':event['data']});cdp.send('Page.screencastFrameAck',{'sessionId':event['sessionId']})
 cdp.on('Page.screencastFrame',screencast);native_command('motion');page.wait_for_timeout(5000);native_command('idle');cdp.send('Page.stopScreencast')
 for i,frame in enumerate(frames):(E/('record-%04d.jpg'%i)).write_bytes(base64.b64decode(frame['data']))
 (E/'recording-timestamps.json').write_text(json.dumps([f['timestamp'] for f in frames]))
 emit({'kind':'recording','frames':len(frames)})
 emit({'kind':'network_rtt_after','raw':command(['ping','-n','-c','5','-W','1000','10.69.69.125'])})
 console=console_state();emit({'kind':'console_after','state':console})
 if not console['ready']:raise RuntimeError('console changed during sampling')
 emit({'kind':'decoder_properties','properties':decoder_properties})
 if consent_errors:raise RuntimeError('consent monitor could not verify every launch')
 emit({'kind':'clocks_after','native':native_clock(),'browser':browser_clock()});battery();emit({'kind':'result','status':'measured','phase_seconds':time.monotonic()-start})
except PhaseComplete:
 pass
except Exception as error:
 if stage in ['open canvas window','change samples','input samples','shape','resources','recording'] and browser:
  try:
   page.screenshot(path=str(E/'canvas-failure.png'))
   emit({'kind':'canvas_failure_state','states':page.locator('.aw-stage').evaluate_all('(nodes)=>nodes.map(n=>({picture:n.dataset.picture,text:n.innerText.slice(0,300)}))')})
  except Exception:pass
 emit({'kind':'failure','stage':stage,'error_type':type(error).__name__,'location':[{'file':pathlib.Path(t.filename).name,'line':t.lineno,'function':t.name} for t in traceback.extract_tb(error.__traceback__) if pathlib.Path(t.filename).name in ('venue-mac.py','measure-mac.py')]})
 # Exceptions may contain authority values in page-evaluation arguments: never print their text.
 failed=True
finally:
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
    current=subprocess.run(['ps','-p',str(pid),'-o','lstart='],capture_output=True,text=True)
    if current.returncode==0 and current.stdout.strip()==birth:
     emit({'kind':'cleanup_term','pid':pid});os.kill(pid,signal.SIGTERM)
     time.sleep(.5)
     current=subprocess.run(['ps','-p',str(pid),'-o','lstart='],capture_output=True,text=True)
     if current.returncode==0 and current.stdout.strip()==birth:
      os.kill(pid,signal.SIGKILL);emit({'kind':'cleanup_kill','pid':pid});failed=True
  if cua_pid:
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
  (E/'native-metrics.log').write_text('\n'.join(native_metrics)+'\n');(E/'source-draws.json').write_text(json.dumps(all_draws));(E/'samples.json').write_text(json.dumps(results))
  if runtime_owned:
   import shutil
   shutil.rmtree(runtime)
  signal.alarm(0)
  if 'screen_start' in locals():
   total=used+time.monotonic()-screen_start;ledger.write_text(json.dumps({'seconds':total}));emit({'kind':'on_screen_ledger','seconds':total})
  if (lock/'owner').read_text().strip()=='app-windows-latency' and (lock/'pid').read_text().strip()==str(args['controller_pid']):
   for name in ['owner','pid','started']:(lock/name).unlink()
   lock.rmdir();emit({'kind':'lock_released'})

raise SystemExit(1 if failed or cleanup_remaining else 0)
