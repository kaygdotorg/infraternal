/**
 * Role: own a private real server and the named Mac measurement process, passing fixture authority only over stdin.
 *
 * Run with `bun test/appwin/measure.ts` from apps/tracer through the build-slot wrapper.
 * APP_WINDOW_BINARY selects a desktop-enabled static server; the Mac job directory
 * must already contain the source supervisor, Rust helper, clock bridge, native
 * fixture, Python environment and browser installation. The approved signed native
 * companion is verified, never installed or replaced here.
 *
 * APP_WINDOW_RUN_LABEL names a fresh receipt directory. APP_WINDOW_RESOURCES_ONLY=1
 * measures the production path without frame diagnostics or pixel observations.
 * APP_WINDOW_DEMO_ONLY=1 records typing and source resize without latency samples.
 * APP_WINDOW_NATIVE and APP_WINDOW_NATIVE_HASH select an already signed diagnostic
 * in the owned Mac diagnostic directory; a changed permission stops the run.
 * Optional pipeline, codec, worker, decoder hint and context settings are isolated
 * experiments; the input manifest records them alongside exact artifact hashes.
 */
import { startRealServer, type DesktopStage } from '../../real/server';
import { resolve } from 'node:path';
import { homedir } from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, writeFile, mkdir, symlink, unlink } from 'node:fs/promises';
import { Database } from 'bun:sqlite';
import { createInterface } from 'node:readline';
const ROOT=resolve(process.env.APP_WINDOW_BENCH_DIR??homedir()+'/.cache/codex-scratch/app-windows-latency');
const pipeline=process.env.APP_WINDOW_PIPELINE??'default';
if(!['default','surface'].includes(pipeline))throw Error('invalid capture path');
const desynchronized=process.env.APP_WINDOW_DESYNCHRONIZED==='1';
const resourcesOnly=process.env.APP_WINDOW_RESOURCES_ONLY==='1';
const pipelineDiagnostics=!resourcesOnly&&process.env.APP_WINDOW_PIPELINE_DIAGNOSTICS!=='0';
const codec=process.env.APP_WINDOW_CODEC??'h264';
const hardwareHint=process.env.APP_WINDOW_HARDWARE_HINT??'';
if(!['','no-preference','prefer-hardware','prefer-software'].includes(hardwareHint))throw Error('invalid decoder hint');
if(!['h264','hevc'].includes(codec))throw Error('invalid codec candidate');
const native=process.env.APP_WINDOW_NATIVE;
const nativeHash=process.env.APP_WINDOW_NATIVE_HASH;
if(Boolean(native)!==Boolean(nativeHash)||(nativeHash&&!/^[a-f0-9]{64}$/.test(nativeHash)))throw Error('diagnostic path and SHA-256 must be supplied together');
const job=process.env.APP_WINDOW_JOB??'app-windows-latency';
if(!/^[a-z0-9-]{1,48}$/.test(job))throw Error('invalid job name');
const requireIdle=process.env.APP_WINDOW_REQUIRE_IDLE==='1';
const demoOnly=process.env.APP_WINDOW_DEMO_ONLY==='1';
const soak=process.env.APP_WINDOW_SOAK==='1';
const ownerPreview=process.env.APP_WINDOW_OWNER_PREVIEW==='1';
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
 const manifest:Record<string,string|boolean|number>={head:new TextDecoder().decode(Bun.spawnSync(['git','rev-parse','HEAD'],{cwd:worktree}).stdout).trim(),desynchronized,resourcesOnly,pipelineDiagnostics,codec,hardwareHint,job,demoOnly,requireIdle,port,soak,ownerPreview,ownerPreviewSeconds,...(native?{native,nativeHash:nativeHash!}:{})};
 for(const [name,path] of Object.entries({binary:process.env.INFRATERNAL_BIN!,controller:import.meta.path,macDriver:import.meta.dirname+'/measure-mac.py',companionLauncher:import.meta.dirname+'/launch-companion.py',pixelObserver:import.meta.dirname+'/worker-pixel-observer.js',probe:import.meta.dirname+'/bench-probe.ts',nativeFixture:worktree+'/crates/plugins/desktop/tests/fixtures/latency-window.swift',worker:workerOverride??worktree+'/apps/tracer/dist/decode.worker.on-demand.js'}))manifest[name]=new Bun.CryptoHasher('sha256').update(await readFile(path)).digest('hex');
 manifest.worktreeDiffSha256=new Bun.CryptoHasher('sha256').update(Bun.spawnSync(['git','diff','HEAD'],{cwd:worktree}).stdout).digest('hex');
 manifest.probeBundle=new Bun.CryptoHasher('sha256').update(await bundle.outputs[0]!.text()).digest('hex');
 await writeFile(E+'/input-manifest.json',JSON.stringify(manifest,null,2));
 const staged=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','cat > ~/infraternal-bench/app-windows-latency/venue-mac.py'],{stdio:['pipe','ignore','pipe']});
 staged.stdin!.end(await readFile(import.meta.dirname+'/measure-mac.py'));
 const [stagedCode]=await once(staged,'exit');if(stagedCode!==0)throw Error('Mac fixture staging refused');
 const launcher=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','cat > ~/infraternal-bench/app-windows-latency/launch-companion.py'],{stdio:['pipe','ignore','pipe']});
 launcher.stdin!.end(await readFile(import.meta.dirname+'/launch-companion.py'));launcher.stderr!.resume();
 const [launcherCode]=await once(launcher,'exit');if(launcherCode!==0)throw Error('companion launcher staging refused');
 mac=spawn('netbird',['ssh','--no-browser','kayg@10.69.69.101','~/infraternal-bench/app-windows-latency/tools/bin/python -u ~/infraternal-bench/app-windows-latency/venue-mac.py'],{stdio:['pipe','pipe','pipe']});
 mac.stdin!.write(JSON.stringify({controller_pid:process.pid,port,pipeline,label,codec,job,demo_only:demoOnly,soak,owner_preview:ownerPreview,owner_preview_seconds:ownerPreviewSeconds,require_idle:requireIdle,native,native_hash:nativeHash,resources_only:resourcesOnly,pipeline_diagnostics:pipelineDiagnostics,diagnostic_only:process.env.APP_WINDOW_DIAGNOSTIC_ONLY==='1',probe:(hardwareHint?'window.__benchHardwareHint='+JSON.stringify(hardwareHint)+';\n':'')+(resourcesOnly?'window.__benchResourcesOnly=true;\n':'')+await bundle.outputs[0]!.text(),observer:(desynchronized?'self.__benchDesynchronized=true;\n':'')+await readFile(import.meta.dirname+'/worker-pixel-observer.js','utf8'),worker:await readFile(workerOverride??worktree+'/apps/tracer/dist/decode.worker.on-demand.js','utf8')})+'\n');
 const prepare=async()=>{
  const vm=spawn('netbird',['ssh','--no-browser','calternal@10.69.69.21','top -l 3 -s 1 -n 0'],{stdio:['ignore','pipe','pipe']});
  let status='';vm.stdout!.on('data',bytes=>{status+=String(bytes);});vm.stderr!.resume();
  const [code]=await once(vm,'exit');await writeFile(E+'/vm-idle.log',status);
  const idle=Array.from(status.matchAll(/CPU usage:.*?([0-9.]+)% idle/g),m=>Number(m[1]));
  vmIdle=idle;
  const ready=code===0&&idle.length===3&&idle.slice(-2).every(value=>value>=90);
  if(!ready){mac!.stdin!.write(JSON.stringify({ready:false,idle})+'\n');return;}
  readinessPhase='server';
  server=await startRealServer({address:'10.69.69.125',hostname:'localhost',port,remoteListen:'10.69.69.125:'+String(port+1000),stateRoot:ROOT+'/server-state',lean:true,...(!pipelineDiagnostics?{}:{onDesktopStage:(receipt:DesktopStage)=>{fixtureStages.push(receipt);}})});
  console.log(JSON.stringify({kind:'server',pid:server.pid,controller_pid:process.pid,label}));
  mac!.stdin!.write(JSON.stringify({ready:true,idle,origin:server.origin,token:server.token})+'\n');
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
 await writeFile(E+'/fixture-stages.json',JSON.stringify(fixtureStages));
 await writeFile(E+'/server-stages.log',diagnostics.join('\n')+'\n');
 try { await server?.dispose(); } finally { await unlink(runtimeAlias); }
 console.log(JSON.stringify({kind:'local_cleanup',server_pid:server?.pid}));
}
