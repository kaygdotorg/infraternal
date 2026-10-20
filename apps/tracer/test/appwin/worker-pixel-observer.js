/** Role: observe only an armed colour in the benchmark's own worker surface; record the readback cost separately. */
(()=>{
 const palette=[[38,89,204],[38,191,89],[204,64,51],[179,64,191],[38,179,191],[204,166,38],[102,64,204],[191,102,51]];
 let armed,pixel;
 // Each observation reads its own tiny surface. Repeated readback never
 // changes the visible context's acceleration choice.
 const send=self.postMessage.bind(self);
 const draw=OffscreenCanvasRenderingContext2D.prototype.drawImage;
 const getContext=OffscreenCanvas.prototype.getContext;
 let contextReported=false;
 OffscreenCanvas.prototype.getContext=function(kind,options){
  const context=getContext.call(this,kind,kind==='2d'&&self.__benchDesynchronized?{...options,desynchronized:true}:options);
  if(kind==='2d'&&!contextReported){contextReported=true;send({t:'bench-context',attributes:context?.getContextAttributes?.(),requestedDesynchronized:!!self.__benchDesynchronized});}
  return context;
 };
 OffscreenCanvasRenderingContext2D.prototype.drawImage=function(...args){
  const result=draw.apply(this,args);
  pixel=undefined;
  if(armed){
   const begin=performance.timeOrigin+performance.now();
   const probe=new OffscreenCanvas(2,2);
   const probeContext=probe.getContext('2d',{alpha:false});
   draw.call(probeContext,args[0],Math.floor(args[0].displayWidth/2),Math.floor(args[0].displayHeight/2),2,2,0,0,2,2);
   const rgb=probeContext.getImageData(0,0,1,1).data;
   const finished=performance.timeOrigin+performance.now();
   let best=-1,distance=Infinity;
   palette.forEach((p,i)=>{const d=p.reduce((s,v,k)=>s+(v-rgb[k])**2,0);if(d<distance){best=i;distance=d;}});
   pixel={id:armed.id,colour:best,expected:armed.colour,begin,finished,distance,rgb:Array.from(rgb).slice(0,3)};
  }
  return result;
 };
 self.addEventListener('message',e=>{
  if(e.data?.t==='bench-arm')armed={id:e.data.id,colour:e.data.crop.colour};
  if(e.data?.t==='bench-clock')send({t:'bench-clock',id:e.data.id,at:performance.timeOrigin+performance.now()});
 });
 self.postMessage=function(message,...rest){
  send(message,...rest);
  if(message?.t==='trace' && message.frame.outcome==='painted' && pixel)send({t:'bench-observation',...pixel,frame:message.frame});
  if(message?.t==='trace' && message.frame.outcome==='painted' && pixel && pixel.colour===pixel.expected && pixel.distance<2500){
   send({t:'bench-effect',...pixel,frame:message.frame});armed=undefined;pixel=undefined;
  }
 };
})();
