/** Tests the owner-authored channel Worker with an in-memory bucket and ephemeral in-memory signing key [224,226]. */
import { expect, test } from "bun:test";
import worker from "../../apps/release-signer/src/index.js";
const enc = new TextEncoder();
// The Worker runtime supplies this method; the local stand-in compares digests only.
Object.defineProperty(crypto.subtle,"timingSafeEqual", { value: (a: Uint8Array,b: Uint8Array) => a.length===b.length && a.every((v,i)=>v===b[i]) });
function object(bytes: Uint8Array) { return { arrayBuffer:async()=>bytes.buffer,text:async()=>new TextDecoder().decode(bytes) }; }
async function fixture(version: string) {
 const pair=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
 const raw=new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey));
 const der=new Uint8Array(await crypto.subtle.exportKey("pkcs8",pair.privateKey));
 const blob=new Uint8Array(51); blob.set([0,0,0,11]);blob.set(enc.encode("ssh-ed25519"),4);blob.set([0,0,0,32],15);blob.set(raw,19);
 const store=new Map<string,Uint8Array>([[`releases/${version}/VERSION`,enc.encode(version+"\n")],[`releases/${version}/infraternal`,enc.encode("fixture")]]);
 const env={ CALLER_TOKEN:"fixture",SIGNING_KEY:`-----BEGIN PRIVATE KEY-----\n${Buffer.from(der).toString("base64")}\n-----END PRIVATE KEY-----`,PUBLIC_KEY:`ssh-ed25519 ${Buffer.from(blob).toString("base64")}`,
 BUILDS:{head:async(name:string)=>store.has(name),get:async(name:string)=>store.has(name)?object(store.get(name)!):null,list:async({prefix}:{prefix:string})=>({objects:[...store.keys()].filter(k=>k.startsWith(prefix)).map(key=>({key})),truncated:false}),put:async(name:string,body:string)=>{store.set(name,enc.encode(body));}} };
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
  expect([...store.keys()].filter(k=>k.startsWith("releases/channels/")).length).toBe(1);
 });
}
test("refuses versions outside stable and UTC edge forms before bucket work",async()=>{
 const {env}=await fixture("0.1.0");
 for (const version of ["1.2.3-rc1","edge-20261011t071500Z","edge-20261011T071500z","../1.2.3"]) {
  const response=await worker.fetch(new Request("http://127.0.0.1/sign",{method:"POST",headers:{authorization:"Bearer fixture"},body:JSON.stringify({version})}),env);
  expect(response.status).toBe(400);
 }
});
