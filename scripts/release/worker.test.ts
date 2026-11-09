/** Tests the owner-authored channel Worker with an in-memory bucket and ephemeral in-memory signing key [224,226]. */
import { expect, test } from "bun:test";
import worker from "../../apps/release-signer/src/index.js";
const enc = new TextEncoder();
/** The complete set of human-readable notices covered by every new signature. */
const licenseNotices=[
 "licenses/libghostty-vt/README.md",
 "licenses/libghostty-vt/Unicode-3.0.txt",
 "licenses/libghostty-vt/aro-MIT.txt",
 "licenses/libghostty-vt/highway-Apache-2.0.txt",
 "licenses/libghostty-vt/highway-BSD-3-Clause.txt",
 "licenses/libghostty-vt/libghostty-vt-MIT.txt",
 "licenses/libghostty-vt/simdutf-Apache-2.0.txt",
 "licenses/libghostty-vt/simdutf-MIT.txt",
 "licenses/libghostty-vt/translate_c-MIT.txt",
 "licenses/libghostty-vt/uucode-MIT.txt",
 "licenses/libghostty-vt/wuffs-Apache-2.0.txt",
 "licenses/libghostty-vt/wuffs-MIT.txt",
];
// The Worker runtime supplies this method; the local stand-in compares digests only.
Object.defineProperty(crypto.subtle,"timingSafeEqual", { value: (a: Uint8Array,b: Uint8Array) => a.length===b.length && a.every((v,i)=>v===b[i]) });
function object(bytes: Uint8Array) { return { arrayBuffer:async()=>bytes.buffer,text:async()=>new TextDecoder().decode(bytes) }; }
/** Builds the in-memory release bucket and signing key used by these tests. */
async function fixture(version: string) {
 const pair=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
 const raw=new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey));
 const der=new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
 const blob=new Uint8Array(51); blob.set([0,0,0,11]);blob.set(enc.encode("ssh-ed25519"),4);blob.set([0,0,0,32],15);blob.set(raw,19);
 const store=new Map<string,Uint8Array>([[`releases/${version}/VERSION`,enc.encode(version+"\n")],[`releases/${version}/infraternal`,enc.encode("fixture")]]);
 for (const arch of ["x86_64", "aarch64"]) {
  store.set(`releases/${version}/infraternal-${arch}-musl`, enc.encode(`fixture-${arch}-host`));
  store.set(`releases/${version}/infraternal-${arch}-session-musl`, enc.encode(`fixture-${arch}-session`));
 }
 const env={ CALLER_TOKEN:"fixture",SIGNING_KEY:`-----BEGIN PRIVATE KEY-----\n${Buffer.from(der).toString("base64")}\n-----END PRIVATE KEY-----`,PUBLIC_KEY:`ssh-ed25519 ${Buffer.from(blob).toString("base64")}`,
 BUILDS:{head:async(name:string)=>store.has(name),get:async(name:string)=>store.has(name)?object(store.get(name)!):null,list:async({prefix}:{prefix:string})=>({objects:[...store.keys()].filter(k=>k.startsWith(prefix)).map(key=>({key})),truncated:false}),put:async(name:string,body:string)=>{store.set(name,enc.encode(body));}} };
 for (const name of licenseNotices) store.set("releases/" + version + "/" + name,enc.encode("license fixture: " + name));
 return {env,store};
}
for(const [version,channel] of [["0.1.0","stable"],["edge-20261011T071500Z","edge"]]) {
 test(`signs ${channel} and writes its channel pointer`,async()=>{
  const {env,store}=await fixture(version);
  const response=await worker.fetch(new Request("http://127.0.0.1/sign",{method:"POST",headers:{authorization:"Bearer fixture"},body:JSON.stringify({version})}),env);
  expect(response.status).toBe(200);
  const entry=await response.json();expect(entry.channel).toBe(channel);expect(entry.version).toBe(version);
  const pointer=JSON.parse(new TextDecoder().decode(store.get(`releases/channels/${channel}.json`)));
  expect(pointer).toEqual(entry);
  expect(store.has(`releases/${version}/SHA256SUMS.sig`)).toBe(true);
  const sums=new TextDecoder().decode(store.get(`releases/${version}/SHA256SUMS`));
  for (const arch of ["x86_64", "aarch64"]) {
   const name=`infraternal-${arch}-session-musl`;
   const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",store.get(`releases/${version}/${name}`)!));
   const hex=[...digest].map(byte=>byte.toString(16).padStart(2,"0")).join("");
   expect(entry.files).toContain(name);
   expect(sums).toContain(`${hex}  ${name}\n`);
  }
  for (const name of licenseNotices) {
   const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",store.get("releases/" + version + "/" + name)!));
   const hex=[...digest].map(byte=>byte.toString(16).padStart(2,"0")).join("");
   expect(entry.files).toContain(name);
   expect(sums).toContain(hex + "  " + name + "\n");
  }
  expect([...store.keys()].filter(k=>k.startsWith("releases/channels/")).length).toBe(1);
 });
}
test("refuses to sign a release that omits any engine or dependency notice",async()=>{
 const {env,store}=await fixture("0.2.0");
 store.delete("releases/0.2.0/licenses/libghostty-vt/Unicode-3.0.txt");
 const response=await worker.fetch(new Request("http://127.0.0.1/sign",{method:"POST",headers:{authorization:"Bearer fixture"},body:JSON.stringify({version:"0.2.0"})}),env);
 expect(response.status).toBe(409);
 expect(store.has("releases/0.2.0/SHA256SUMS.sig")).toBe(false);
});
test("refuses versions outside stable and UTC edge forms before bucket work",async()=>{
 const {env}=await fixture("0.1.0");
 for (const version of ["1.2.3-rc1","edge-20261011t071500Z","edge-20261011T071500z","../1.2.3"]) {
  const response=await worker.fetch(new Request("http://127.0.0.1/sign",{method:"POST",headers:{authorization:"Bearer fixture"},body:JSON.stringify({version})}),env);
  expect(response.status).toBe(400);
 }
});
