/** Shared binary desktop fixtures for semantic and incremental differential tests [D12,D232]. */
import type { DesktopMessage } from "./codec";
export const desktopCases:DesktopMessage[]=[
  {kind:"input",input:{kind:"release"}},
  {kind:"attach",sessionId:new Uint8Array(16).fill(146),delivery:0},
  {kind:"attach",sessionId:new Uint8Array(16).fill(146),delivery:1},
  {kind:"video",sequence:0xffffffffffffffffn,captureNs:0xffffffffffffffffn,keyframe:true,bytes:new Uint8Array([0,0,0,1,0x65])},
  {kind:"size",width:1920,height:1080,densityMilli:2000},
  {kind:"input",input:{kind:"mouse",x:1000000,y:0,button:2,state:2,modifiers:15}},
  {kind:"input",input:{kind:"scroll",x:1,y:2,dx:-2147483648,dy:2147483647,modifiers:15}},
  {kind:"input",input:{kind:"key",keycode:127,down:true,modifiers:15}},
  {kind:"repair",lastSequence:0xffffffffffffffffn},
  {kind:"fragment",sessionId:new Uint8Array(16).fill(146),sequence:1n,captureNs:2n,keyframe:true,total:5,offset:0,bytes:new Uint8Array([0,0,0,1,0x65])},
];
