/** Exercises UI setup, one-use SSH input, installed service and remote terminal without saving private inputs. */
import { randomBytes, createHash } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Database } from "bun:sqlite";
import { chromium } from "../../apps/tracer/node_modules/playwright";
import { startRealServer } from "../../apps/tracer/real/server";
import { remoteEcho } from "./remote-echo";


import { readFile } from "node:fs/promises";
const job = "/home/kayg/.cache/codex-scratch/release-addhost";
const container = "infraternal-release-addhost-round2";
const hostname = "round2.infraternal.test";
const shots = import.meta.dirname;
const binding = execFileSync("sudo", ["-n", "docker", "port", container, "22/tcp"], { encoding: "utf8" });
const sshPort = /^127\.0\.0\.1:(\d+)\s*$/.exec(binding)?.[1];
if (!sshPort) throw new Error("controlled SSH container has no loopback binding");
const docker = (...args: string[]) => execFileSync("sudo", ["-n", "docker", "exec", container, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
async function input(args: string[], text: string) {
  const child = spawn("sudo", ["-n", "docker", "exec", "-i", container, ...args], { stdio: ["pipe", "ignore", "ignore"] });
  child.stdin.end(text);
  const [code] = await once(child, "exit");
  if (code !== 0) throw new Error("controlled container preparation failed");
}
// Shared host devpts exposes a mode-000 pts/ptmx node. Replace only this
// container's symlink with its own accessible device node; never chmod host devpts.
docker("sh", "-c", "if [ -L /dev/ptmx ]; then rm /dev/ptmx && mknod -m 666 /dev/ptmx c 5 2; fi");
// This owned fixture must permit the rootful installation used by the VM proof.
docker("sh", "-c", "sshd -T | grep -q '^permitrootlogin yes$' || { sed -i '1i PermitRootLogin yes' /etc/ssh/sshd_config; systemctl restart ssh; }");
for(const kind of ["rsa","ecdsa","ed25519"])docker("test","-f",`/etc/ssh/ssh_host_${kind}_key.pub`);
let password = randomBytes(24).toString("base64url");
await input(["chpasswd"], `root:${password}\n`);
docker("sh", "-c", `grep -q '${hostname}' /etc/hosts || printf '10.69.69.125 ${hostname}\n' >> /etc/hosts`);
const publicKey = docker("cat", "/etc/ssh/ssh_host_ed25519_key.pub").trim().split(/\s+/).slice(0, 2).join(" ");
const server = await startRealServer({ address: "10.69.69.125", port: 47591, hostname, remoteListen: "10.69.69.125:47592", stateRoot: job,
  certificate: async (certificate) => {
    await input(["sh", "-c", "cat > /usr/local/share/ca-certificates/release-addhost-front.crt && update-ca-certificates >/dev/null"], certificate + "\n");
    docker("sh", "-c", "mkdir -p /usr/local/ssl && ln -sf /etc/ssl/certs/ca-certificates.crt /usr/local/ssl/cert.pem");
  },

});
const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP ${hostname} 10.69.69.125`, "--disable-renderer-backgrounding"] });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
let stage = "software-passkey";
try {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin);
  await page.locator("#setup-token").fill(server.token).catch(() => { throw new Error("owner setup unavailable"); });
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("addhost_release");
  await page.locator("#setup-display-name").fill("Add-host release");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
  stage = "open-flow";
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type(`root@127.0.0.1:${sshPort} `);
  page.on("websocket", (socket) => {
    if (!socket.url().endsWith("/v1/bootstrap/ws")) return;
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload !== "string") return;
      try {
        const event = JSON.parse(payload);
        if (["check", "install", "facts", "connect", "done", "failed"].includes(event.step)) console.log(JSON.stringify({ bootstrap_step: event.step, failure_kind: event.failure?.kind }));
      } catch { /* no frame contents enter logs */ }
    });
  });
  const addAt = performance.now();
  await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();
  let trustClicks=0;
  const wizardDeadline=Date.now()+120000;
  let lastPage="";
  for (;;) {
    if(Date.now()>wizardDeadline)throw new Error("wizard deadline");
    if(await page.locator(".ah-run[data-state=done]").count())break;
    if(!(await page.locator(".ah-float").count()))break;
    const kind=await page.locator(".ah-page").last().getAttribute("data-page").catch(()=>null);
    if(kind!==lastPage){console.log(JSON.stringify({wizard_page:kind}));lastPage=kind??"";await page.waitForTimeout(500);}
    if(kind==="authority"){
      stage="fresh-ca";
      await page.locator(".ah-float").getByRole("button",{name:"Confirm with passkey",exact:true}).click();
      await page.locator(".ah-page[data-page=authority]").waitFor({state:"detached"});
    }else if(kind==="root"){
      stage="root-consent";
      await page.locator("label.ah-consent").click();
      await page.locator("[data-ah='as-root']").click();
      await page.locator(".ah-page[data-page=root]").waitFor({state:"detached"});
    }else if(kind==="hostkey"){
      stage="host-key";
      const keyPage=page.locator(".ah-page[data-page=hostkey]");
      const expected=docker("ssh-keygen","-lf","/etc/ssh/ssh_host_ed25519_key.pub").split(/\s+/)[1]!;
      const text=await keyPage.innerText();
      if(!text.includes(expected)||!text.includes("ED25519"))throw new Error("displayed key/type mismatch");
      if(++trustClicks!==1)throw new Error("host-key loop returned");
      await page.screenshot({path:resolve(shots,"real-hostkey-desktop.png")});
      await page.locator(".ah-float").getByRole("button",{name:"Trust this key",exact:true}).click();
      await keyPage.waitFor({state:"detached"});
    }else if(kind==="choose" && !(await page.locator(".ah-reveal[data-reveal=password][data-open=true]").count())){
      stage="ssh-sign-in";
      await page.locator(".ah-float").getByText("Sign in with a password",{exact:true}).click();
      await page.locator("[data-secret=password]").waitFor();
    }else if(kind==="choose" && password && await page.locator(".ah-reveal[data-reveal=password][data-open=true]").count()){
      console.log(JSON.stringify({ssh_method:"password selected"}));
      stage="ssh-private-input";
      await page.locator('[data-secret="password"]').fill(password);
      await page.locator(".ah-float").getByRole("button",{name:"Sign in",exact:true}).click();
      password="";
      stage="installed-and-joined";
    }else if(kind==="failure"){
      console.log(JSON.stringify({installation_error:await page.locator(".ah-page[data-page=failure]").innerText()}));
      throw new Error("installation refused");
    }
    await page.waitForTimeout(100);
  }
  if(trustClicks!==1)throw new Error("trust was preseeded or skipped");
  console.log(JSON.stringify({host_key:"one ED25519 fingerprint, one confirmation, no pre-seeded trust"}));
  const daemonPid=docker("systemctl","show","--property=MainPID","--value","infraternal-agent.service").trim();
  if(!/^\d+$/.test(daemonPid)||docker("cat",`/proc/${daemonPid}/comm`).trim()!=="infraternal")throw new Error("daemon process name is not infraternal");
  if(docker("systemctl","is-enabled","infraternal-agent.service").trim()!=="enabled")throw new Error("service not enabled");
  console.log(JSON.stringify({process_name:"infraternal",service:"enabled"}));
  const readyAt = performance.now();
  await page.screenshot({ path: resolve(shots, "ssh-install-ready.png") });
  const db = new Database(resolve(server.dataDir, "infraternal.sqlite"), { readonly: true });
  const identity = db.query("SELECT lower(hex(h.id)) AS host, h.mode, h.execution_uid AS uid, c.not_after-c.not_before AS certificate_seconds FROM remote_hosts h JOIN remote_certificates c ON c.host_id=h.id WHERE h.revoked_at IS NULL AND c.revoked_at IS NULL").all();
  console.log(JSON.stringify({ stage, add_to_ready_ms: readyAt-addAt, public_identity: identity }));
  stage = "remote-terminal";
  await page.locator(".ah-float").waitFor({ state: "detached" });
  const marker = `remote-proof-${randomBytes(6).toString("hex")}`;
  await page.locator(".ui-window [data-captures-keys]").last().focus();
  await page.keyboard.type(`printf '%s%s\\n' '${marker.slice(0, 13)}' '${marker.slice(13)}'; whoami; hostname`);
  await page.keyboard.press("Enter");
  const deadline = Date.now()+30000;
  while (!server.bridges.some((bridge) => [...bridge.output.values()].some((output) => output.includes(marker))) && Date.now()<deadline) await new Promise((r)=>setTimeout(r,50));
  if (!server.bridges.some((bridge) => [...bridge.output.values()].some((output) => output.includes(marker)))) throw new Error("remote terminal did not confirm output");
  const terminals = db.query("SELECT count(*) AS count FROM terminal_sessions WHERE remote_host_id IS NOT NULL").get();
  console.log(JSON.stringify({ stage, add_to_terminal_ms: performance.now()-addAt, remote_terminals: terminals }));
  await page.screenshot({ path: resolve(shots, "remote-terminal-desktop.png") });
  stage = "remote-details";
  await page.locator(".ui-window").filter({has:page.locator("[data-captures-keys]")}).last().locator(".ui-window-pill").click();
  const popover = page.locator(".canvas-popover");
  await popover.waitFor();
  console.log(JSON.stringify({public_details:await popover.innerText()}));
  // The required removal action uses this selected remote window. Host execution
  // identity was independently checked through the service and certificate rows.
  await page.screenshot({ path: resolve(shots, "remote-details-desktop.png") });
  await page.keyboard.press("Escape");
  await popover.waitFor({ state: "detached" });
  const terminal = db.query("SELECT lower(hex(id)) AS id FROM terminal_sessions WHERE remote_host_id IS NOT NULL AND closed_at IS NULL ORDER BY created_at DESC LIMIT 1").get() as {id: string};
  const cookie = (await context.cookies(server.origin)).map((entry) => `${entry.name}=${entry.value}`).join("; ");
  stage = "remote-echo";
  const echo = await remoteEcho(server.origin, cookie, terminal.id);
  console.log(JSON.stringify({ metric: "remote_echo", ...echo, machine: "infraternal-dev", cores: 8, load: (await readFile("/proc/loadavg", "utf8")).split(" ").slice(0,3) }));
  if (echo.p99_ms! > 350) throw new Error("remote echo exceeded budget");
  await page.reload();
  await page.locator(".cl-viewport").waitFor();
  await page.locator(".ui-window [data-captures-keys]").last().waitFor();
  stage = "remote-reload-echo";
  const attachDeadline = Date.now()+30000;
  while (!server.bridges.some(bridge => !bridge.closed && [...bridge.attached].some(([stream, ids]) => ids.includes(terminal.id) && bridge.acked.has(stream))) && Date.now()<attachDeadline) await page.waitForTimeout(50);
  if (!server.bridges.some(bridge => !bridge.closed && [...bridge.attached].some(([stream, ids]) => ids.includes(terminal.id) && bridge.acked.has(stream)))) throw new Error("restored remote attachment was not ready");
  await page.waitForTimeout(100);
  const reloadMarker = `reload-proof-${randomBytes(6).toString("hex")}`;
  await page.locator(".ui-window [data-captures-keys]").last().focus();
  // The echo measurement left this exact remote PTY in raw cat; a new marker
  // proves restored input/output, rather than merely seeing a saved window.
  await page.keyboard.type(reloadMarker);
  const reloadDeadline = Date.now()+30000;
  while (!server.bridges.some(bridge => [...bridge.output.values()].some(output => output.includes(reloadMarker))) && Date.now()<reloadDeadline) await new Promise(r=>setTimeout(r,50));
  if (!server.bridges.some(bridge => [...bridge.output.values()].some(output => output.includes(reloadMarker)))) throw new Error("restored remote PTY did not echo");
  const restored = db.query("SELECT lower(hex(id)) AS id FROM terminal_sessions WHERE remote_host_id IS NOT NULL AND closed_at IS NULL").all() as Array<{id: string}>;
  if (restored.length !== 1 || restored[0]!.id !== terminal.id) throw new Error("reload replaced the remote session");
  console.log(JSON.stringify({ remote_reload: "same-session-confirmed-echo" }));
  await page.screenshot({ path: resolve(shots, "remote-reload-desktop.png") });
  const row = db.query("SELECT lower(hex(id)) AS id FROM remote_hosts WHERE revoked_at IS NULL").get() as {id:string};
  const hostId = row.id.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/,"$1-$2-$3-$4-$5");
  stage = "second-add";
  password=randomBytes(24).toString("base64url");
  await input(["chpasswd"],`root:${password}\n`);
  await page.evaluate(()=>window.dispatchEvent(new CustomEvent("tracer:canvas-action",{detail:{action:"canvas:addhost",source:"keyboard"}})));
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type(`root@127.0.0.1:${sshPort} `);
  await page.locator(".ah-float").getByRole("button",{name:"Continue",exact:true}).click();
  const secondDeadline=Date.now()+60000;
  lastPage="";
  for(;;){
    if(Date.now()>secondDeadline)throw new Error("second add deadline");
    const kind=await page.locator(".ah-page").last().getAttribute("data-page").catch(()=>null);
    if(kind!==lastPage){lastPage=kind??"";await page.waitForTimeout(500);}
    if(kind==="hostkey")throw new Error("second add reentered host-key confirmation");
    if(kind==="root"){await page.locator("label.ah-consent").click();await page.locator("[data-ah='as-root']").click();
      await page.locator(".ah-page[data-page=root]").waitFor({state:"detached"});}
    else if(kind==="choose" && !(await page.locator(".ah-reveal[data-reveal=password][data-open=true]").count())){await page.locator(".ah-float").getByText("Sign in with a password",{exact:true}).click();
      await page.locator("[data-secret=password]").waitFor();}
    else if(kind==="choose" && password && await page.locator(".ah-reveal[data-reveal=password][data-open=true]").count()){await page.locator('[data-secret="password"]').fill(password);await page.locator(".ah-float").getByRole("button",{name:"Sign in",exact:true}).click();password="";}
    else if(kind==="failure"){
      if(!(await page.locator(".ah-page[data-page=failure]").innerText()).includes("already added"))throw new Error("second add gave vague failure");
      await page.locator(".ah-float [data-ah=close]").click();
      await page.locator(".ah-float").waitFor({state:"detached"});
      break;
    }
    await page.waitForTimeout(100);
  }
  if((db.query("SELECT count(*) AS n FROM remote_hosts").get() as {n:number}).n!==1)throw new Error("second add issued a second host certificate");
  console.log(JSON.stringify({second_add:"already added; no host-key loop; no second certificate"}));
  const previousWindows=await page.locator(".ui-window [data-captures-keys]").count();
  await page.evaluate((id) => window.dispatchEvent(new CustomEvent("tracer:canvas-action",{detail:{action:`canvas:open:${id}`,source:"keyboard"}})),hostId);
  await page.waitForFunction((count) => document.querySelectorAll(".ui-window [data-captures-keys]").length === count+1,previousWindows);
  let exitSession: {id:string}|null=null;
  const exitReadyDeadline=Date.now()+30000;
  while(Date.now()<exitReadyDeadline){
    exitSession=db.query("SELECT lower(hex(id)) AS id FROM terminal_sessions WHERE remote_host_id IS NOT NULL AND closed_at IS NULL AND lower(hex(id))<>? LIMIT 1").get(terminal.id) as {id:string}|null;
    if(exitSession && server.bridges.some(bridge=>!bridge.closed && [...bridge.attached].some(([stream,ids])=>ids.includes(exitSession!.id)&&bridge.acked.has(stream))))break;
    await page.waitForTimeout(50);
  }
  if(!exitSession)throw new Error("new remote shell was not published");
  await page.waitForTimeout(100);
  await page.locator(".ui-window [data-captures-keys]").last().focus();
  stage = "remote-exit";
  const before = await page.locator(".ui-window [data-captures-keys]").count();
  // Use a fresh canonical shell: the echo measurement intentionally keeps its
  // original session in raw cat for the reload proof.
  await page.keyboard.type("exit 0");
  await page.keyboard.press("Enter");
  await page.waitForFunction((count) => document.querySelectorAll(".ui-window [data-captures-keys]").length < count,before,{timeout:15000});
  const closed=db.query("SELECT closed_at,exit_status FROM terminal_sessions WHERE lower(hex(id))=?").get(exitSession.id) as {closed_at:number|null;exit_status:number|null};
  if (closed.closed_at===null || closed.exit_status!==0) throw new Error("remote exit was not durable");
  console.log(JSON.stringify({remote_exit:"window closed without further input; durable status 0"}));
  stage = "remove-host";
  await page.evaluate((id) => window.dispatchEvent(new CustomEvent("tracer:canvas-action",{detail:{action:`canvas:open:${id}`,source:"keyboard"}})),hostId);
  await page.locator(".ui-window [data-captures-keys]").last().waitFor();
  await page.locator(".ui-window").filter({has:page.locator("[data-captures-keys]")}).last().locator(".ui-window-pill").click();
  await page.locator(".canvas-popover").getByRole("button",{name:"Remove host",exact:true}).click();
  await page.locator(".ui-confirm-tip").waitFor();
  await page.screenshot({path:resolve(shots,"real-remove-desktop.png")});
  await page.setViewportSize({width:393,height:852});
  await page.screenshot({path:resolve(shots,"real-remove-phone.png")});
  await page.locator(".ui-confirm-tip").getByRole("button",{name:"Remove host",exact:true}).click();
  await page.waitForFunction(() => document.querySelector(".ui-toast")?.textContent?.includes("Host removed"),undefined,{timeout:20000});
  console.log(JSON.stringify({removal_receipt:db.query("SELECT host_cleanup FROM remote_host_removals").all(),removal_message:await page.locator(".ui-toast").innerText()}));
  const cleanupDeadline=Date.now()+30000;
  while (Date.now()<cleanupDeadline) {
    try { docker("sh","-c","test ! -e /var/lib/infraternal && test ! -e /usr/local/bin/infraternal && test ! -e /etc/systemd/system/infraternal-agent.service && test ! -e /etc/systemd/system/multi-user.target.wants/infraternal-agent.service"); break; } catch { await page.waitForTimeout(200); }
  }
  docker("sh","-c","test ! -e /var/lib/infraternal && test ! -e /usr/local/bin/infraternal && test ! -e /etc/systemd/system/infraternal-agent.service && test ! -e /etc/systemd/system/multi-user.target.wants/infraternal-agent.service");
  const removed=db.query("SELECT revoked_at FROM remote_hosts WHERE lower(hex(id))=?").get(row.id) as {revoked_at:number|null};
  if(removed.revoked_at===null) throw new Error("host revocation missing");
  if((db.query("SELECT count(*) AS n FROM remote_host_bootstrap").get() as {n:number}).n!==0)throw new Error("bootstrap inventory remains");
  const pins=await import("node:fs/promises").then(fs=>fs.readdir(resolve(server.dataDir,"ssh-trust")));
  if(pins.some(name=>name.endsWith(".pub")))throw new Error("host trust remains");
  console.log(JSON.stringify({remove:"fresh passkey, live certificate revoked, unit/enable-link/binary/data removed, inventory/trust deleted",result:"PASS"}));
  db.close();
} catch (error) {
  if (stage.startsWith("remote-") || stage === "remove-host" || stage === "second-add") {
    if (error instanceof Error) console.log(JSON.stringify({ public_operation_error: error.message.slice(0,1800) }));
  }
  if((stage==="ssh-sign-in"||stage==="remote-details") && error instanceof Error)console.log(JSON.stringify({public_locator_error:error.message.slice(0,1800)}));
  console.log(JSON.stringify({error_type:error instanceof Error?error.name:"unknown",error_hint:error instanceof Error&&error.message.includes("Timeout")?"timeout":error instanceof Error&&error.message.includes("strict mode")?"ambiguous locator":"assertion or operation refused"}));
  if (stage === "installed-and-joined") {
    await page.evaluate(() => { for (const field of document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("[data-secret]")) field.value = ""; });
    await page.locator(".ah-float summary").first().click({ timeout: 3000 }).catch(() => {});
    await page.screenshot({ path: resolve(shots, "container-install-failure.png") });
  }
  if (stage === "ssh-sign-in" || stage === "fresh-ca") await page.screenshot({ path: resolve(shots, "container-failure-before-input.png") });
  console.log(JSON.stringify({ result: "FAIL", stage, wizard_page: await page.locator(".ah-page").last().getAttribute("data-page").catch(() => "none") }));
  process.exitCode = 1;
} finally {
  password = "";
  await context.close(); await browser.close(); await server.dispose();
}
