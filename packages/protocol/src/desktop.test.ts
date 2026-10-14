/** Tests desktop framing limits and hostile fixed-field mutations without browser UI [D12,D232]. */
import {expect,test} from "bun:test";
import {decodeFrame,encodeFrame,WireDecodeError,WireEncodeError,type DesktopMessage} from "./codec";
import { desktopCases } from "./desktop-fixtures";
test("desktop fixed fields and borrowed video roundtrip",()=>{
 for(const message of desktopCases){const wire=encodeFrame({type:"Desktop",message});const decoded=decodeFrame(wire);expect(decoded.frame).toEqual({type:"Desktop",message});
  if(decoded.frame.type==="Desktop"&&(decoded.frame.message.kind==="video"||decoded.frame.message.kind==="fragment"))expect(decoded.frame.message.bytes.buffer).toBe(wire.buffer);
  for(let split=0;split<wire.length;split++){expect(()=>decodeFrame(wire.subarray(0,split))).toThrow(WireDecodeError);}
  if(message.kind!=="video"&&message.kind!=="fragment"){const trailing=new Uint8Array(wire.length+1);trailing.set(wire);trailing[0]!++;expect(()=>decodeFrame(trailing)).toThrow(WireDecodeError);}
 }
});
test("desktop semantics reject nonfinite coordinates and invalid input before encoding",()=>{
 for(const x of [NaN,Infinity,-1,1000001,1.5])expect(()=>encodeFrame({type:"Desktop",message:{kind:"input",input:{kind:"mouse",x,y:0,button:0,state:0,modifiers:0}}})).toThrow(WireEncodeError);
 for(const message of [
  {kind:"video",sequence:0n,captureNs:0n,keyframe:false,bytes:new Uint8Array([1])},
  {kind:"size",width:4096,height:4096,densityMilli:1000},
  {kind:"size",width:3,height:600,densityMilli:2000},
  {kind:"fragment",sessionId:new Uint8Array(16),sequence:1n,captureNs:0n,keyframe:true,total:2048,offset:1,bytes:new Uint8Array(1024)},
 ] as DesktopMessage[])expect(()=>encodeFrame({type:"Desktop",message})).toThrow(WireEncodeError);
 const flag=encodeFrame({type:"Desktop",message:desktopCases.find(m=>m.kind==="video")!});flag[18]=2;expect(()=>decodeFrame(flag)).toThrow(WireDecodeError);
});
test("desktop Rust and TypeScript agree on malformed lengths, flags and mutations",()=>{
 const requests:string[]=[];const expected:unknown[]=[];
 for(const message of desktopCases){const original=encodeFrame({type:"Desktop",message});const candidates:Uint8Array[]=[];
  for(let end=0;end<original.length;end++)candidates.push(original.subarray(0,end));
  for(let offset=0;offset<original.length;offset++)for(const value of [0,1,2,15,127,128,255]){const bytes=original.slice();bytes[offset]=value;candidates.push(bytes);}
  for(const bytes of candidates){let accepted=true;try{decodeFrame(bytes);}catch{accepted=false;}expected.push({accepted});requests.push(JSON.stringify({bytes:Array.from(bytes),probe:true}));}
 }
 const bridge=Bun.spawnSync(["cargo","run","--quiet","-p","infraternal-protocol","--features","desktop","--example","stream_oracle"],{cwd:new URL("../../../",import.meta.url).pathname,stdin:new TextEncoder().encode(requests.join("\n")+"\n"),maxBuffer:128*1024*1024});
 if(bridge.exitCode!==0)throw new Error(new TextDecoder().decode(bridge.stderr));
 expect(new TextDecoder().decode(bridge.stdout).trim().split("\n").map(line=>JSON.parse(line))).toEqual(expected);
 console.log(`desktop rejection differential: ${requests.length} cases, zero divergences`);
});
