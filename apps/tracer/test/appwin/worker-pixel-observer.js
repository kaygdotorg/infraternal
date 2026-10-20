/** Role: verify armed fixture colours and content sequence markers in the benchmark's own worker surface. */
(()=>{
 const palette=[[38,89,204],[38,191,89],[204,64,51],[179,64,191],[38,179,191],[204,166,38],[102,64,204],[191,102,51]];
 const markerBits=32;
 const markerHeader=0xa5;
 const markerCells=markerBits+8;
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
   const width=args[0].displayWidth,height=args[0].displayHeight;
   if(!Number.isFinite(width)||!Number.isFinite(height)||width<=0||height<=0||!Number.isSafeInteger(armed.sequence))return result;
   const begin=performance.timeOrigin+performance.now();
   const probe=new OffscreenCanvas(markerCells+2,1);
   const probeContext=probe.getContext('2d',{alpha:false});
   // Control clicks place the captured pointer at the centre. The fixture's
   // lower-right background stays clear of that pointer and its text label.
   draw.call(probeContext,args[0],Math.floor(width*.75),Math.floor(height*.75),2,1,0,0,2,1);
   const markerCell=width*.2/markerCells,markerY=Math.floor(height*.7-markerCell/2);
   for(let cell=0;cell<markerCells;cell++){
    const markerX=Math.floor(width*.8+(cell+.5)*markerCell);
    draw.call(probeContext,args[0],markerX,markerY,1,1,cell+2,0,1,1);
   }
   const data=probeContext.getImageData(0,0,markerCells+2,1).data;
   if(data.length<(markerCells+2)*4)return result;
   const rgb=data.slice(0,3);
   let header=0,contentSequence=0;
   for(let bit=0;bit<8;bit++){
    const offset=(bit+2)*4;
    if((data[offset]+data[offset+1]+data[offset+2])/3>127)header=(header|(1<<bit))>>>0;
   }
   for(let bit=0;bit<markerBits;bit++){
    const offset=(bit+10)*4;
    if((data[offset]+data[offset+1]+data[offset+2])/3>127)contentSequence=(contentSequence|(1<<bit))>>>0;
   }
   const finished=performance.timeOrigin+performance.now();
   let best=-1,distance=Infinity;
   palette.forEach((p,i)=>{const d=p.reduce((s,v,k)=>s+(v-rgb[k])**2,0);if(d<distance){best=i;distance=d;}});
   pixel={id:armed.id,colour:best,expected:armed.colour,markerValid:header===markerHeader,contentSequence,expectedSequence:armed.sequence>>>0,begin,finished,distance,rgb:Array.from(rgb)};
  }
  return result;
 };
 self.addEventListener('message',e=>{
  if(e.data?.t==='bench-arm')armed={id:e.data.id,colour:e.data.crop.colour,sequence:e.data.crop.sequence};
  if(e.data?.t==='bench-clock')send({t:'bench-clock',id:e.data.id,at:performance.timeOrigin+performance.now()});
 });
 self.postMessage=function(message,...rest){
  send(message,...rest);
  if(message?.t==='trace' && message.frame.outcome==='painted' && pixel)send({t:'bench-observation',...pixel,frame:message.frame});
  if(message?.t==='trace' && message.frame.outcome==='painted' && pixel && pixel.colour===pixel.expected && pixel.distance<2500 && pixel.markerValid && pixel.contentSequence===pixel.expectedSequence){
   send({t:'bench-effect',...pixel,frame:message.frame});armed=undefined;pixel=undefined;
  }
 };
})();
