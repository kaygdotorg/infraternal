/**
 * Role: own a private real server and the named Mac measurement process, passing fixture authority only over stdin.
 *
 * Run with `bun test/appwin/measure.ts` from apps/tracer through the build-slot wrapper.
 * APP_WINDOW_BINARY selects a desktop-enabled static server; the Mac job directory
 * must already contain the source supervisor, Rust helper, clock bridge, native
 * Python environment and browser installation. The controller sends the fixture
 * source, which the Mac runner compiles in a per-run directory before taking the
 * capture lock. The approved signed native
 * companion is verified, never installed or replaced here.
 *
 * APP_WINDOW_RUN_LABEL names a fresh receipt directory. APP_WINDOW_RESOURCES_ONLY=1
 * measures the production path without frame diagnostics or pixel observations.
 * APP_WINDOW_DEMO_ONLY=1 records typing and source resize without latency samples.
 * APP_WINDOW_NATIVE and APP_WINDOW_NATIVE_HASH select an already signed diagnostic
 * in the owned Mac diagnostic directory; a changed permission stops the run.
 * APP_WINDOW_HELPER_BINARY selects an isolated Rust helper binary under the Mac
 * bench directory; the first-picture check requires it to avoid shared binaries.
 * Optional pipeline, codec, worker, decoder hint and context settings are isolated
 * experiments; the input manifest records them alongside exact artifact hashes.
 * APP_WINDOW_SOAK=1 defaults to an uninterrupted 600-second/240-character run.
 * APP_WINDOW_RECOVERY=1 explicitly enables the separate drop/reopen/resize case;
 * APP_WINDOW_STABILITY_SECONDS=180 selects its short diagnostic duration.
 * APP_WINDOW_FIRST_PICTURE_IDLE=1 verifies ten first pictures and checks
 * frame and draw counts across 60 seconds without CPU/RSS or latency sampling.
 * APP_WINDOW_OPEN_MODE=concurrent opens ten cached fixture targets in one browser turn.
 * APP_WINDOW_MAC_ONLY=1 omits guest access and records no guest-idle evidence.
 * APP_WINDOW_PROBE_TRACE=1 records bounded, content-free control-probe handling
 * for reconnect diagnosis; it never changes the production liveness deadline.
 * APP_WINDOW_INPUT_ONLY=1 collects 80 quiet inputs, records idle resources and
 * cleans up without the separate demo, motion or stability phases.
 * Measured keyboard cohorts emulate page focus through CDP, so native input
 * can keep its app forward without OS app switching before every sample.
 */
import { startRealServer, type DesktopStage, type ProbeStage } from '../../real/server';
import { plainCloseReason } from '../../src/close-reasons';
import { resolve } from 'node:path';
import { homedir } from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, writeFile, mkdir, symlink, unlink } from 'node:fs/promises';
import { Database } from 'bun:sqlite';
import { createInterface } from 'node:readline';
const ROOT=resolve(process.env.APP_WINDOW_BENCH_DIR??homedir()+'/.cache/codex-scratch/app-windows-latency');
const pipeline=process.env.APP_WINDOW_PIPELINE??'default';
if(!['default','surface','owned'].includes(pipeline))throw Error('invalid capture path');
const desynchronized=process.env.APP_WINDOW_DESYNCHRONIZED==='1';
const resourcesOnly=process.env.APP_WINDOW_RESOURCES_ONLY==='1';
const firstPictureIdle=process.env.APP_WINDOW_FIRST_PICTURE_IDLE==='1';
const helperBinary=process.env.APP_WINDOW_HELPER_BINARY;
if(helperBinary&&!helperBinary.startsWith('/'))throw Error('Mac helper binary path must be absolute');
const inputOnly=process.env.APP_WINDOW_INPUT_ONLY==='1';
const pipelineDiagnostics=!resourcesOnly&&(firstPictureIdle||process.env.APP_WINDOW_PIPELINE_DIAGNOSTICS!=='0');
const probeTrace=process.env.APP_WINDOW_PROBE_TRACE==='1';
const codec=process.env.APP_WINDOW_CODEC??'h264';
const hardwareHint=process.env.APP_WINDOW_HARDWARE_HINT??'';
if(!['','no-preference','prefer-hardware','prefer-software'].includes(hardwareHint))throw Error('invalid decoder hint');
if(!['h264','hevc'].includes(codec))throw Error('invalid codec candidate');
const native=process.env.APP_WINDOW_NATIVE;
const nativeHash=process.env.APP_WINDOW_NATIVE_HASH;
if(Boolean(native)!==Boolean(nativeHash)||(nativeHash&&!/^[a-f0-9]{64}$/.test(nativeHash)))throw Error('diagnostic path and SHA-256 must be supplied together');
const variantArchive=process.env.APP_WINDOW_VARIANT_ARCHIVE;
const variantArchiveHash=process.env.APP_WINDOW_VARIANT_ARCHIVE_SHA256;
const restoreArchive=process.env.APP_WINDOW_RESTORE_HELPER_ARCHIVE;
const restoreArchiveHash=process.env.APP_WINDOW_RESTORE_HELPER_ARCHIVE_SHA256;
const restoreExecutableHash=process.env.APP_WINDOW_RESTORE_HELPER_EXECUTABLE_SHA256;
const helperLeafSha1=process.env.APP_WINDOW_HELPER_LEAF_SHA1;
const variantRequested=[variantArchive,variantArchiveHash].some(Boolean);
const restoreRequested=[restoreArchive,restoreArchiveHash,restoreExecutableHash].some(Boolean);
if(variantRequested!==restoreRequested)throw Error('helper variant and restoration archives must be supplied together');
if(variantRequested&&(!native||!nativeHash||!variantArchive||!variantArchiveHash||!restoreArchive||!restoreArchiveHash||!restoreExecutableHash||!helperLeafSha1))throw Error('helper variant restoration settings are incomplete');
for(const [path,name] of [[variantArchive,'variant'],[restoreArchive,'restoration']] as const){
 if(path&&!path.startsWith('/'))throw Error(`helper ${name} archive path must be absolute`);
}
for(const [hash,name] of [[variantArchiveHash,'variant archive'],[restoreArchiveHash,'restoration archive'],[restoreExecutableHash,'restoration executable']] as const){
 if(hash&&!/^[a-f0-9]{64}$/.test(hash))throw Error(`invalid helper ${name} SHA-256`);
}
if(helperLeafSha1&&!/^[a-f0-9]{40}$/.test(helperLeafSha1))throw Error('invalid helper leaf SHA-1');
const helperVariant=variantRequested?{archive:variantArchive!,archive_sha256:variantArchiveHash!,executable_sha256:nativeHash!,leaf_sha1:helperLeafSha1!}:undefined;
const helperRestore=restoreRequested?{archive:restoreArchive!,archive_sha256:restoreArchiveHash!,executable_sha256:restoreExecutableHash!,leaf_sha1:helperLeafSha1!}:undefined;
const job=process.env.APP_WINDOW_JOB??'app-windows-latency';
if(!/^[a-z0-9-]{1,48}$/.test(job))throw Error('invalid job name');
const requireIdle=process.env.APP_WINDOW_REQUIRE_IDLE==='1';
// A Mac-only brief must never contact the guest for readiness. Its load is
// recorded on the named Mac; guest-idle evidence is absent in this mode.
const macOnly=process.env.APP_WINDOW_MAC_ONLY==='1';
const demoOnly=process.env.APP_WINDOW_DEMO_ONLY==='1';
const soak=process.env.APP_WINDOW_SOAK==='1';
const recovery=process.env.APP_WINDOW_RECOVERY==='1';
const stabilitySeconds=Number(process.env.APP_WINDOW_STABILITY_SECONDS??600);
if(![180,600].includes(stabilitySeconds))throw Error('invalid stability duration');
const tenWindowIdle=process.env.APP_WINDOW_TEN_WINDOW_IDLE==='1';
const flood=process.env.APP_WINDOW_FLOOD==='1';
if(tenWindowIdle&&firstPictureIdle)throw Error('ten-window idle modes cannot run together');
if((tenWindowIdle||firstPictureIdle)&&flood)throw Error('idle and flood cohorts cannot run together');
const fixtureWindowCount=tenWindowIdle||firstPictureIdle?10:1;
const openMode=process.env.APP_WINDOW_OPEN_MODE??'serial';
if(!['serial','concurrent'].includes(openMode))throw Error('invalid fixture open mode');
if(openMode==='concurrent'&&fixtureWindowCount!==10)throw Error('concurrent opening requires ten fixture windows');
const ownerPreview=process.env.APP_WINDOW_OWNER_PREVIEW==='1';
if((tenWindowIdle||flood)&&stabilitySeconds!==600)throw Error('soak cohorts require exactly ten minutes');
if(tenWindowIdle&&(resourcesOnly||demoOnly||soak||recovery||inputOnly||ownerPreview))throw Error('ten-window idle cohort cannot include another phase');
if(firstPictureIdle&&(resourcesOnly||demoOnly||soak||recovery||inputOnly||ownerPreview||probeTrace))throw Error('first-picture idle check cannot include another phase');
if(firstPictureIdle&&!helperBinary)throw Error('first-picture idle check requires a Mac helper binary');
if(flood&&(resourcesOnly||demoOnly||soak||recovery||inputOnly||ownerPreview))throw Error('flood cohort cannot include another phase');
if(inputOnly&&(resourcesOnly||demoOnly||soak||ownerPreview))throw Error('input-only mode cannot include another measurement phase');
const ownerPreviewSeconds=Number(process.env.APP_WINDOW_OWNER_PREVIEW_SECONDS??900);
if(!Number.isInteger(ownerPreviewSeconds)||ownerPreviewSeconds<1||ownerPreviewSeconds>900)throw Error('invalid owner preview duration');
const port=Number(process.env.TRACER_TEST_PORT??'4346');
if(!Number.isInteger(port)||port<1024||port>64535)throw Error('invalid measurement port');
const label=process.env.APP_WINDOW_RUN_LABEL??pipeline+'-'+Date.now();
if(!/^[a-z0-9-]{1,48}$/.test(label))throw Error('invalid measurement label');
const E=ROOT+'/evidence/'+label;await mkdir(E,{recursive:true,mode:0o700});
const worktree=resolve(import.meta.dirname,'../../../..');
process.env.INFRATERNAL_BIN=process.env.APP_WINDOW_BINARY??ROOT+'/target/x86_64-unknown-linux-musl/release/infraternal';
const workerOverride=process.env.APP_WINDOW_WORKER;
process.env.TRACER_DIST=worktree+'/apps/tracer/dist';
process.env.TRACER_TEST_PORT=String(port);
const runtime=ROOT+'/runtime';await mkdir(runtime,{recursive:true,mode:0o700});
const runtimeAlias=resolve(homedir(),'.cache/codex-scratch/w'+process.pid.toString(36));
await symlink(runtime,runtimeAlias);
process.env.INFRATERNAL_TEST_STATE_ROOT=runtimeAlias;
if(!pipelineDiagnostics)delete process.env.INFRATERNAL_DESKTOP_MEASURE;else process.env.INFRATERNAL_DESKTOP_MEASURE='1';
process.env.REAL_SERVER_LOG='1';
process.env.RUST_LOG='infraternal_server::remote_enrollment=debug';

const diagnostics:string[]=[];const fixtureStages:unknown[]=[];
const probeStages:ProbeStage[]=[];let droppedProbeStages=0;
const stderr=process.stderr.write.bind(process.stderr);let pending='';
process.stderr.write=((data:unknown,...rest:unknown[])=>{
 const value=String(data);
 if(value.startsWith('SERVER ')){
  pending+=value.slice(7);const lines=pending.split('\n');pending=lines.pop()!.slice(-4096);
  for(const line of lines){
   if(line.startsWith('METRIC app_window_'))diagnostics.push(line);
   if(line.includes('remote enrollment refused')){
    const plain=line.replace(/\x1b\[[0-9;]*m/g,'');
    const stage=/stage="?(signer_load|signer_material|preflight|csr|signer|certificate|redeem)/.exec(plain)?.[1];
    if(stage){diagnostics.push('METRIC enrollment_refusal stage='+stage);console.log(JSON.stringify({kind:'enrollment_stage',stage}));}
   }
  }
  return true;
 }
 return stderr(data as string);
}) as typeof process.stderr.write;
let server:Awaited<ReturnType<typeof startRealServer>>|undefined;
let mac:ReturnType<typeof spawn>|undefined;
let preparing:Promise<void>|undefined;
let macRunnerPid:number|undefined;
let vmIdle:number[]=[];
let readinessPhase:'vm'|'server'='vm';
const cancellation=()=>{mac?.kill('SIGTERM');};
process.once('SIGINT',cancellation);process.once('SIGTERM',cancellation);
try{
 const build=spawn('bun',['run','build'],{cwd:worktree+'/apps/tracer',stdio:'ignore'});
 const [built]=await once(build,'exit');if(built!==0)throw Error('production frontend build failed');
 const bundle=await Bun.build({entrypoints:[worktree+'/apps/tracer/test/appwin/bench-probe.ts'],target:'browser',format:'iife',minify:true});
 if(!bundle.success)throw Error('probe build failed');
 const manifest:Record<string,unknown>={head:new TextDecoder().decode(Bun.spawnSync(['git','rev-parse','HEAD'],{cwd:worktree}).stdout).trim(),desynchronized,resourcesOnly,pipeline,capturePath:pipeline==='owned'?'owned-copy':'signed-surface',pipelineDiagnostics,codec,hardwareHint,job,macOnly,demoOnly,requireIdle,port,soak,recovery,stabilitySeconds,tenWindowIdle,firstPictureIdle,flood,fixtureWindowCount,openMode,ownerPreview,ownerPreviewSeconds,...(native?{native,nativeHash:nativeHash!}:{}),...(helperBinary?{helperBinary}:{}),...(helperVariant?{helperVariant,helperRestore}:{})};
 for(const [name,path] of Object.entries({binary:process.env.INFRATERNAL_BIN!,controller:import.meta.path,macDriver:import.meta.dirname+'/measure-mac.py',companionLauncher:import.meta.dirname+'/launch-companion.py',processIdentity:import.meta.dirname+'/process_identity.py',pixelObserver:import.meta.dirname+'/worker-pixel-observer.js',firstPictureObserver:import.meta.dirname+'/first-picture-observer.js',probe:import.meta.dirname+'/bench-probe.ts',nativeFixture:worktree+'/crates/plugins/desktop/tests/fixtures/latency-window.swift',worker:workerOverride??worktree+'/apps/tracer/dist/decode.worker.on-demand.js'}))manifest[name]=new Bun.CryptoHasher('sha256').update(await readFile(path)).digest('hex');
 manifest.worktreeDiffSha256=new Bun.CryptoHasher('sha256').update(Bun.spawnSync(['git','diff','HEAD'],{cwd:worktree}).stdout).digest('hex');
 manifest.probeBundle=new Bun.CryptoHasher('sha256').update(await bundle.outputs[0]!.text()).digest('hex');
 manifest.probeTrace=probeTrace;
 manifest.inputOnly=inputOnly;manifest.inputSampleCount=inputOnly?80:40;
 manifest.inputFocusEmulation=!resourcesOnly&&!demoOnly&&!ownerPreview;
 await writeFile(E+'/input-manifest.json',JSON.stringify(manifest,null,2));
 const staged=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','cat > ~/infraternal-bench/app-windows-latency/venue-mac.py'],{stdio:['pipe','ignore','pipe']});
 staged.stdin!.end(await readFile(import.meta.dirname+'/measure-mac.py'));
 const [stagedCode]=await once(staged,'exit');if(stagedCode!==0)throw Error('Mac fixture staging refused');
 const launcher=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','cat > ~/infraternal-bench/app-windows-latency/launch-companion.py'],{stdio:['pipe','ignore','pipe']});
 launcher.stdin!.end(await readFile(import.meta.dirname+'/launch-companion.py'));launcher.stderr!.resume();
 const [launcherCode]=await once(launcher,'exit');if(launcherCode!==0)throw Error('companion launcher staging refused');
 const identity=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','cat > ~/infraternal-bench/app-windows-latency/process_identity.py'],{stdio:['pipe','ignore','pipe']});
 identity.stdin!.end(await readFile(import.meta.dirname+'/process_identity.py'));identity.stderr!.resume();
 const [identityCode]=await once(identity,'exit');if(identityCode!==0)throw Error('process identity staging refused');
 mac=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','~/infraternal-bench/app-windows-latency/tools/bin/python -u ~/infraternal-bench/app-windows-latency/venue-mac.py'],{stdio:['pipe','pipe','pipe']});
 mac.stdin!.write(JSON.stringify({controller_pid:process.pid,port,pipeline,label,codec,job,input_only:inputOnly,demo_only:demoOnly,soak,recovery,stability_seconds:stabilitySeconds,ten_window_idle:tenWindowIdle,first_picture_idle:firstPictureIdle,open_mode:openMode,first_picture_observer:await readFile(import.meta.dirname+'/first-picture-observer.js','utf8'),flood,fixture_window_count:fixtureWindowCount,owner_preview:ownerPreview,owner_preview_seconds:ownerPreviewSeconds,require_idle:requireIdle,native,native_hash:nativeHash,helper_binary:helperBinary,helper_variant:helperVariant,helper_restore:helperRestore,resources_only:resourcesOnly,pipeline_diagnostics:pipelineDiagnostics,fixture_source:await readFile(worktree+'/crates/plugins/desktop/tests/fixtures/latency-window.swift','utf8'),diagnostic_only:process.env.APP_WINDOW_DIAGNOSTIC_ONLY==='1',probe:(hardwareHint?'window.__benchHardwareHint='+JSON.stringify(hardwareHint)+';\n':'')+(resourcesOnly?'window.__benchResourcesOnly=true;\n':'')+await bundle.outputs[0]!.text(),observer:(desynchronized?'self.__benchDesynchronized=true;\n':'')+(flood?'self.__benchFlood=true;\n':'')+await readFile(import.meta.dirname+'/worker-pixel-observer.js','utf8'),worker:await readFile(workerOverride??worktree+'/apps/tracer/dist/decode.worker.on-demand.js','utf8')})+'\n');
 const prepare=async()=>{
  if(!macOnly){
   const vm=spawn('netbird',['ssh','--no-browser','calternal@10.69.69.21','top -l 3 -s 1 -n 0'],{stdio:['ignore','pipe','pipe']});
   let status='';vm.stdout!.on('data',bytes=>{status+=String(bytes);});vm.stderr!.resume();
   const [code]=await once(vm,'exit');await writeFile(E+'/vm-idle.log',status);
   const idle=Array.from(status.matchAll(/CPU usage:.*?([0-9.]+)% idle/g),m=>Number(m[1]));
   vmIdle=idle;
   const ready=code===0&&idle.length===3&&idle.slice(-2).every(value=>value>=90);
   if(!ready){mac!.stdin!.write(JSON.stringify({ready:false,idle})+'\n');return;}
  }
  readinessPhase='server';
  server=await startRealServer({address:'10.69.69.125',hostname:'localhost',port,remoteListen:'10.69.69.125:'+String(port+1000),stateRoot:ROOT+'/server-state',lean:true,...(!probeTrace?{}:{onProbeStage:(receipt:ProbeStage)=>{if(probeStages.length<100000)probeStages.push(receipt);else droppedProbeStages++;}}),...(!pipelineDiagnostics?{}:{onDesktopStage:(receipt:DesktopStage)=>{fixtureStages.push(receipt);}})});
  console.log(JSON.stringify({kind:'server',pid:server.pid,controller_pid:process.pid,label}));
  mac!.stdin!.write(JSON.stringify({ready:true,idle:vmIdle,origin:server.origin,token:server.token})+'\n');
 };
 mac.stdin!.on('error',()=>{});
 const lines=createInterface({input:mac.stdout!});
 lines.on('line',(line)=>{
  try{
   const row=JSON.parse(line);
   if(row.kind==='runner')macRunnerPid=row.pid;
   if(row.kind==='vm_readiness_request'&&!preparing)preparing=prepare().catch((error:unknown)=>{
    const message=error instanceof Error?error.message:'';
    const refusal=message==='server startup failed'?'server_startup':message==='setup capability unavailable'?'setup_capability':message==='invalid setup capability response'?'invalid_setup_capability':'fixture_preparation';
    console.log(JSON.stringify({kind:'preparation_refused',phase:readinessPhase,refusal}));
    mac?.stdin?.write(JSON.stringify({ready:false,idle:vmIdle,phase:readinessPhase,refusal})+'\n');
   });
   if(row.kind==='network_drop_request'){
    void server!.interruptBrowserRoutes(2000).then(()=>mac!.stdin!.write(JSON.stringify({kind:'network_restored'})+'\n'));
   }
   if(row.kind==='host'){
    const db=new Database(server!.dataDir+'/infraternal.sqlite');
    db.query('INSERT INTO remote_host_bootstrap(host_id,address,os) VALUES(?,?,?)').run(Buffer.from(row.host_id.replaceAll('-',''),'hex'),'window-measurement@MacBook','macOS');db.close();
   }
   console.log(JSON.stringify(row));
  }catch{console.log(JSON.stringify({kind:'fixture_line_refused'}));}
 });
 mac.stderr!.on('data',()=>{});
 const [code]=await once(mac,'exit');
 await preparing;
 if(macRunnerPid){
  const check=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','ps -p '+macRunnerPid+' -o pid=,stat=,comm='],{stdio:['ignore','pipe','pipe']});
  let row='';check.stdout!.on('data',bytes=>{row+=String(bytes);});check.stderr!.resume();const [psExit]=await once(check,'exit');console.log(JSON.stringify({kind:'runner_cleanup',pid:macRunnerPid,ps_exit:psExit,row:row.trim()}));
 }
 console.log(JSON.stringify({kind:'mac_exit',code,label}));
 process.exitCode=code===0?0:1;
}finally{
 // Bridge state also contains private fixture authority; persist this whitelist only.
 await writeFile(E+'/socket-bridges.json',JSON.stringify(server?.bridges.map(bridge=>({id:bridge.id,closed:bridge.closed,at:bridge.closedAt,side:/^(browser|server) [0-9]+$/.test(bridge.closedBy??'')?bridge.closedBy:'other',reason:plainCloseReason(bridge.closedReason,'other'),serverReason:plainCloseReason(bridge.serverClose,'other')}))??[]));
 await writeFile(E+'/fixture-stages.json',JSON.stringify(fixtureStages));
 await writeFile(E+'/fixture-probes.json',JSON.stringify({dropped:droppedProbeStages,events:probeStages}));
 if(probeTrace){console.log(JSON.stringify({kind:'probe_trace',recorded:probeStages.length,dropped:droppedProbeStages}));if(droppedProbeStages)process.exitCode=1;}
 await writeFile(E+'/server-stages.log',diagnostics.join('\n')+'\n');
 try { await server?.dispose(); } finally { await unlink(runtimeAlias); }
 console.log(JSON.stringify({kind:'local_cleanup',server_pid:server?.pid}));
}
