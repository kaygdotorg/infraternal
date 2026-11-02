// Renders the pictures the app-window test double streams: four generic "machine windows" (a notebook, an editor, a browser
// and a whole screen), each in a wide and a tall shape, as Annex-B H.264 with no frame reordering (the shape the real
// encoder produces, contracts/desktop-helper.md). Needs ffmpeg with libx264 and the tracer's Playwright. Output: the
// directory given as argv[2] (default $HOME/.cache/codex-scratch/ui-app-windows/fixtures). Nothing here is committed output.
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const out = process.argv[2] ?? join(homedir(), ".cache/codex-scratch/ui-app-windows/fixtures");
const FRAMES = 120, FPS = 60;
const shapes = { wide: [1280, 800], tall: [800, 1280] };
const apps = ["notebook", "editor", "browser", "screen"];

const page_html = (app, w, h) => `<!doctype html><meta charset=utf-8><style>
*{box-sizing:border-box;margin:0}body{width:${w}px;height:${h}px;overflow:hidden;font:15px/1.5 ui-monospace,Menlo,monospace;background:#f6f6f4;color:#222}
.bar{height:44px;display:flex;align-items:center;gap:8px;padding:0 14px;background:#e9e9e6;border-bottom:1px solid #d4d4d0}
.dot{width:12px;height:12px;border-radius:50%}.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}
.title{margin-left:12px;color:#555;font-weight:600}
.side{position:absolute;top:44px;bottom:0;left:0;width:${Math.min(240, w * 0.28)}px;background:#efefec;border-right:1px solid #d4d4d0;padding:12px}
.side div{padding:6px 8px;border-radius:6px;margin-bottom:2px}.side .on{background:#d9d9d4}
.main{position:absolute;top:44px;bottom:0;right:0;left:${Math.min(240, w * 0.28)}px;padding:22px 28px}
h1{font-size:26px;margin-bottom:14px}p{margin-bottom:10px;color:#444}
.meter{height:10px;border-radius:5px;background:#dcdcd6;margin:18px 0;overflow:hidden}.meter i{display:block;height:100%;background:#3b82f6}
.ed{background:#1d1f24;color:#d7dae0}.ed .bar{background:#16181c;border-color:#2a2d33}.ed .title{color:#9aa0aa}
.ed .main{left:0;padding:14px 0}.ed .ln{display:inline-block;width:52px;text-align:right;padding-right:16px;color:#5c6370}
.k{color:#c678dd}.s{color:#98c379}.f{color:#61afef}.c{color:#7f848e}
.status{position:absolute;bottom:0;left:0;right:0;height:28px;background:#2563eb;color:#fff;padding:3px 14px;font-size:13px}
.br{background:#fff}.br .bar{background:#f1f3f4}.url{flex:1;margin-left:14px;height:28px;border-radius:14px;background:#fff;border:1px solid #d4d4d0;padding:3px 14px;color:#555}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px;margin-top:16px}.card{height:120px;border-radius:12px;color:#fff;padding:12px;font-weight:700}
.scr{background:linear-gradient(135deg,#1e3a8a,#7c3aed 55%,#db2777)}.menu{height:30px;background:rgba(255,255,255,.22);display:flex;gap:18px;padding:3px 16px;color:#fff;font-size:14px}
.win{position:absolute;border-radius:10px;background:#f6f6f4;box-shadow:0 18px 50px rgba(0,0,0,.45);overflow:hidden}.win .bar{height:34px}.dock{position:absolute;bottom:14px;left:50%;transform:translateX(-50%);display:flex;gap:10px;padding:8px 12px;border-radius:18px;background:rgba(255,255,255,.25)}.dock i{width:46px;height:46px;border-radius:12px;display:block}
.live{position:absolute;right:16px;bottom:12px;font-size:13px;color:#888}
</style><body id=b></body><script>
const W=${w},H=${h},app=${JSON.stringify(app)};
const lines=['import { stream } from "./stream";','','export function frame(n) {','  // each tick draws the next picture','  return stream.next(n);','}','','const fps = 60;','let ticks = 0;','setInterval(() => ticks++, 1000 / fps);'];
function draw(i){
  const t=i/${FPS},bar=(50+45*Math.sin(t*Math.PI))|0,caret=(i%40)<24?'|':' ';
  let html='';
  if(app==='notebook'){
    html='<div class=bar><i class="dot r"></i><i class="dot y"></i><i class="dot g"></i><span class=title>Notebook</span></div><div class=side><div class=on>Today</div><div>Ideas</div><div>Reading list</div><div>Recipes</div><div>Trip planning</div></div><div class=main><h1>Today</h1><p>Plan the week and write down what matters.</p><p>1. Review the deploy notes'+caret+'</p><p>2. Reply to the team</p><p>3. Pick up groceries</p><div class=meter><i style="width:'+bar+'%"></i></div><p>Saved '+(i%100)+' moments ago</p></div>';
  } else if(app==='editor'){
    html='<div class="bar"><i class="dot r"></i><i class="dot y"></i><i class="dot g"></i><span class=title>stream.ts</span></div><div class=main>'+lines.map((l,k)=>'<div><span class=ln>'+(k+1)+'</span>'+l.replace(/(import|export|function|return|const|let)/g,'<span class=k>$1</span>').replace(/"[^"]*"/g,m=>'<span class=s>'+m+'</span>').replace(/\\/\\/.*/,m=>'<span class=c>'+m+'</span>')+(k===(i>>4)%lines.length?caret:'')+'</div>').join('')+'</div><div class=status>Ln '+((i>>4)%lines.length+1)+'  frame '+i+'  UTF-8</div>';
  } else if(app==='browser'){
    html='<div class=bar><i class="dot r"></i><i class="dot y"></i><i class="dot g"></i><div class=url>docs.example/guide</div></div><div class=main style="left:0"><h1>Getting started</h1><p>A page that is loading and moving, to show a live picture.</p><div class=meter><i style="width:'+bar+'%"></i></div><div class=cards>'+['#ef4444','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ec4899'].map((c,k)=>'<div class=card style="background:'+c+';transform:translateY('+(Math.sin(t*4+k)*6|0)+'px)">Card '+(k+1)+'</div>').join('')+'</div></div>';
  } else {
    html='<div class=scr style="position:absolute;inset:0"><div class=menu><b>●</b><span>Finder</span><span>File</span><span>Edit</span><span>View</span><span style="margin-left:auto">'+String(10+((i/600)|0)).padStart(2,'0')+':'+String(i%60).padStart(2,'0')+'</span></div>'
      +'<div class=win style="left:'+(W*0.06|0)+'px;top:'+(H*0.12|0)+'px;width:'+(W*0.55|0)+'px;height:'+(H*0.5|0)+'px"><div class=bar><i class="dot r"></i><i class="dot y"></i><i class="dot g"></i><span class=title>Notebook</span></div><div style="padding:16px"><h1 style="font-size:20px">Today</h1><div class=meter><i style="width:'+bar+'%"></i></div></div></div>'
      +'<div class="win ed" style="left:'+(W*0.34|0)+'px;top:'+(H*0.34|0)+'px;width:'+(W*0.5|0)+'px;height:'+(H*0.42|0)+'px"><div class=bar><i class="dot r"></i><i class="dot y"></i><i class="dot g"></i><span class=title>stream.ts</span></div><div style="padding:12px;color:#d7dae0">frame '+i+caret+'</div></div>'
      +'<div class=dock>'+['#60a5fa','#34d399','#fbbf24','#f87171','#a78bfa'].map(c=>'<i style="background:'+c+'"></i>').join('')+'</div></div>';
  }
  document.getElementById('b').className=app==='editor'?'ed':app==='browser'?'br':'';
  document.getElementById('b').innerHTML=html;
}
window.draw=draw;draw(0);
</script>`;

await mkdir(out, { recursive: true });
const appWindowBrowser = process.env.TRACER_APPWIN_BROWSER;
const chromeExecutable = process.env.TRACER_CHROME_EXECUTABLE;
if (appWindowBrowser !== undefined && appWindowBrowser !== "chrome") {
  throw new Error("TRACER_APPWIN_BROWSER must be unset or chrome");
}
if (chromeExecutable !== undefined && appWindowBrowser !== "chrome") {
  throw new Error("TRACER_CHROME_EXECUTABLE requires TRACER_APPWIN_BROWSER=chrome");
}
// Match the fixture renderer to Playwright's configured browser so it does not
// fall back to the bundled Chromium when the test needs a proprietary codec.
const browser = await chromium.launch({
  ...(appWindowBrowser === "chrome"
    ? chromeExecutable === undefined ? { channel: "chrome" } : { executablePath: chromeExecutable }
    : {}),
});
try {
  for (const app of apps) for (const [shape, [w, h]] of Object.entries(shapes)) {
    const dir = join(out, `.frames-${app}-${shape}`);
    await rm(dir, { recursive: true, force: true }); await mkdir(dir, { recursive: true });
    const page = await browser.newPage({ viewport: { width: w, height: h } });
    await page.setContent(page_html(app, w, h));
    for (let i = 0; i < FRAMES; i++) {
      await page.evaluate((n) => window.draw(n), i);
      await page.screenshot({ path: join(dir, `f${String(i).padStart(4, "0")}.png`) });
    }
    await page.close();
    // Low delay, no reordering, a keyframe every half second, parameter sets repeated at each one, an access-unit delimiter in front of every unit.
    await new Promise((resolve, reject) => {
      const ff = spawn("ffmpeg", ["-y", "-v", "error", "-framerate", String(FPS), "-i", join(dir, "f%04d.png"), "-vf", "format=yuv420p", "-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-profile:v", "high", "-bf", "0", "-g", "30", "-keyint_min", "30", "-sc_threshold", "0", "-x264-params", "aud=1:repeat-headers=1:scenecut=0", "-f", "h264", join(out, `${app}-${shape}.h264`)], { stdio: "inherit" });
      ff.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`ffmpeg ${code}`))));
    });
    await rm(dir, { recursive: true, force: true });
    console.log("wrote", `${app}-${shape}.h264`, `${w}x${h}`);
  }
} finally { await browser.close(); }
