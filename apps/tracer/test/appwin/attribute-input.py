"""Role: attribute the isolated Mac input cohort with causal same-host clock bounds and content-free receipts (#146)."""
import json
import math
import pathlib
import re
import statistics
import sys

class InvalidAttributionSample(ValueError):
 """One same-clock input sample contradicts companion execution order."""

def align_ordered(reference,candidates,stamp):
 if len(reference)<3:raise ValueError('too few ordered samples')
 n=len(reference);rank=[]
 for start in range(len(candidates)-n+1):
  values=[stamp(r) for r in candidates[start:start+n]]
  errors=[(values[i]-values[0])-(reference[i]-reference[0]) for i in range(n)]
  centre=statistics.median(errors)
  score=math.sqrt(statistics.mean((v-centre)**2 for v in errors))/1e6
  rank.append((score,start))
 rank.sort()
 if not rank or rank[0][0]>30 or (len(rank)>1 and rank[1][0]<rank[0][0]+5):raise ValueError('ambiguous ordered cohort')
 score,start=rank[0]
 return candidates[start:start+n],score

def align_command_stream(selected, commands, candidates, native_stamp, candidate_stamp):
 """Align every command spanning the measured keyboard inputs.

 Real focus recovery can add mouse commands between sampled keys. Those keys
 are not a contiguous command cohort. Preserve every intervening receipt while
 applying the original spacing/ambiguity guard, then project by native identity.
 Unrelated setup and later stress phases cannot alter this cohort's alignment.
 """
 identities=[int(row['receive_ns']) for row in commands]
 if any(left>=right for left,right in zip(identities,identities[1:])):
  raise ValueError('native command identities are not strictly ordered')
 if not selected or any(int(row['receive_ns']) not in identities for row in selected):
  raise ValueError('sample command is absent from the complete stream')
 lower=min(int(row['receive_ns']) for row in selected)
 upper=max(int(row['receive_ns']) for row in selected)
 cohort=[row for row in commands if lower<=int(row['receive_ns'])<=upper]
 aligned,score=align_ordered([int(row[native_stamp]) for row in cohort],candidates,candidate_stamp)
 by_identity={int(row['receive_ns']):receipt for row,receipt in zip(cohort,aligned)}
 return [by_identity[int(row['receive_ns'])] for row in selected],score

def source_clock_bounds(native_receives, native_finishes, source_receives, source_acks):
 """Bound the source Instant origin in native nanoseconds without wall clocks.

 A command reaches the source before the companion; its acknowledgement follows
 native completion. Intersecting those causal brackets never assumes symmetric
 pipe or network delay. A missing or contradictory cohort must fail analysis.
 """
 if not native_receives or len({len(rows) for rows in (native_receives,native_finishes,source_receives,source_acks)})!=1:raise ValueError('incomplete source clock cohort')
 if any(finished<received or ack<began for received,finished,began,ack in zip(native_receives,native_finishes,source_receives,source_acks)):raise ValueError('reversed local command timestamps')
 lower=max(finished-ack for finished,ack in zip(native_finishes,source_acks))
 upper=min(received-began for received,began in zip(native_receives,source_receives))
 if lower>upper:raise ValueError('noncausal source clock bounds')
 return lower,upper

def source_callback_stages(draw_ns, display_ns, callback_ns, finished_ns, duration_ns):
 """Split actual source work without treating the display stamp as callback time.

 The recorded display stamp can follow its callback. Keep that signed offset;
 clamping it would invent delay and make the source intervals fail to telescope.
 These details subdivide existing phases and never enter the local total twice.
 """
 began_ns=finished_ns-duration_ns
 if callback_ns<=0 or duration_ns<0 or began_ns<callback_ns:raise ValueError('noncausal source callback evidence')
 return {'draw_end_to_callback':(callback_ns-draw_ns)/1e6,
         'display_stamp_to_callback':(callback_ns-display_ns)/1e6,
         'callback_to_encode_begin':(began_ns-callback_ns)/1e6,
         'encode_duration':duration_ns/1e6}

def surface_delivery_stages(delivery, encoded):
 """Partition a fresh frame on one native clock; reject reused or reversed stamps."""
 if delivery.get('fresh')!='true' or delivery['capture_ns']!=encoded['capture_ns']:
  raise ValueError('surface receipt does not identify a fresh encoded frame')
 callback,dequeued,prepared,output_begin,output_end=(int(delivery[name]) for name in
  ('callback_ns','dequeued_ns','prepared_ns','output_begin_ns','output_end_ns'))
 finished=int(encoded['encode_finished_ns']);began=finished-int(encoded['encode_ns'])
 stamps=(callback,dequeued,prepared,began,finished,output_begin,output_end)
 if callback<=0 or any(a>b for a,b in zip(stamps,stamps[1:])):
  raise ValueError('noncausal surface delivery evidence')
 return {'callback_to_dequeue':(dequeued-callback)/1e6,
         'dequeue_to_pixels_ready':(prepared-dequeued)/1e6,
         'pixels_ready_to_encode_begin':(began-prepared)/1e6,
         'encode_duration':(finished-began)/1e6,
         'encoded_to_output_begin':(output_begin-finished)/1e6,
         'native_output_write':(output_end-output_begin)/1e6}

def command_for_post(commands, post_ns):
 """Match on native execution, not a browser window shared by queued mouse input.

 Receive stamps may overlap while commands await the main queue. The actual
 post must lie in exactly one dispatch/completion interval on that same clock.
 """
 received=lambda row:int(row.get('receive_ns',row['dispatch_ns']))
 matches=[row for row in commands if received(row)<=int(row['dispatch_ns'])<=post_ns<=int(row['finished_ns'])]
 if not matches:
  reversed_matches=[row for row in commands if received(row)<=post_ns<int(row['dispatch_ns'])<=int(row['finished_ns'])]
  if len(reversed_matches)==1:raise InvalidAttributionSample('injection precedes companion dispatch')
 if len(matches)!=1:raise ValueError(f'companion dispatch: expected one receipt, found {len(matches)}')
 return matches[0]

def analyze(root, controller):
 rows=[json.loads(line) for line in controller.read_text().splitlines() if line.startswith('{')]
 clock=next(r for r in rows if r.get('kind')=='clocks');timebase=clock['timebase']['numer']/clock['timebase']['denom']
 native_offset=sum(clock['native'][k] for k in ('lower','upper'))/2
 browser_offset=sum(clock['browser'][k] for k in ('lower','upper'))/2
 native_epoch_offset=native_offset-browser_offset
 # Native/browser conversions use the same physical Mac's bracketed clocks.
 # Server wall time is used only to align ordered cohorts; no one-way delay is
 # obtained by subtracting clocks on different machines.
 def native_epoch(ns):return (float(ns)+native_epoch_offset)/1e6
 metrics=[]
 for name in ('helper-metrics.log','native-metrics.log','server-stages.log','companion-metrics.log'):
  # Older receipts share helper stderr; new runs isolate the native appender.
  if name=='companion-metrics.log' and not (root/name).exists():continue
  for line in (root/name).read_text().splitlines():
   if not line.startswith('METRIC '):continue
   fields=dict(re.findall(r'(\w+)=(\S+)',line));fields['metric']=line.split()[1]
   metrics.append(fields)
 
 def server_stamp(row):return int(row['at_ns'])
 def stage(name,kind=None):return [r for r in metrics if r.get('stage')==name and (kind is None or r.get('kind')==str(kind))]
 def exactly(values,label):
  if len(values)!=1:raise ValueError(f'{label}: expected one receipt, found {len(values)}')
  return values[0]
 def between(values, stamp, lo, hi):return [r for r in values if lo<=stamp(r)<=hi]
 def forward(receive,starts,ends,stamp):
  began=min((r for r in starts if stamp(r)>=stamp(receive)),key=stamp)
  ended=min((r for r in ends if stamp(r)>=stamp(began)),key=stamp)
  if stamp(ended)-stamp(receive)>100e6:raise ValueError('ambiguous server forward')
  return began,ended
 
 samples=[];invalid_samples=[]
 for sample in (r for r in rows if r.get('kind')=='input_sample'):
  probe=[v['probe'] for v in sample['events']]
  key=exactly([v for r in probe for v in r['domInputs']],'keydown')
  sent=exactly([v for r in probe for v in r['inputs'] if v['kind'] in ('text','key')],'browser send')
  effect=sample['effect'];lo=key['eventAt'];hi=effect['begin']
  post=exactly(between([r for r in metrics if r['metric']=='native_input_post' and r.get('type')=='10'],lambda r:native_epoch(r['at_ns']),lo,hi),'worker inject')
  try:command=command_for_post(between([r for r in metrics if r['metric']=='native_input'],lambda r:native_epoch(r['receive_ns']),lo,hi),int(post['at_ns']))
  except InvalidAttributionSample:
   invalid_samples.append({'index':sample.get('index'),'reason':'injection_before_dispatch'})
   continue
  if command.get('accepted')!='true':raise ValueError('native input was refused')
  native_event=exactly(between([r for r in json.loads((root/'source-draws.json').read_text()) if r.get('kind')=='input'],lambda r:native_epoch(r['ticks']*timebase),lo,hi),'fixture input')
  draws=[r for r in json.loads((root/'source-draws.json').read_text()) if r.get('kind')=='draw' and r['sequence']==native_event['sequence']]
  draw=min(draws,key=lambda r:r['end_ticks'])
  if int(effect['frame']['captureNs'])<draw['end_ticks']*timebase:raise ValueError('effect predates the fixture draw')
  source_receive=None
  frame=effect['frame'];capture=frame['captureNs']
  encoded=exactly([r for r in metrics if r.get('capture_ns')==capture and 'encode_finished_ns' in r],'encoded frame')
  source_end=exactly([r for r in stage('source_send_end') if r.get('capture_ns')==capture and int(r.get('sequence','0'))==int(frame['sequence'])],'Mac frame sent')
  relay=exactly([r for r in stage('relay_receive') if r.get('capture_ns')==capture and int(r.get('sequence','0'))==int(frame['sequence'])],'server video received')
  video_ends=[r for r in stage('browser_socket_end') if r.get('capture_ns')==capture and int(r.get('sequence','0'))==int(frame['sequence'])]
  # A repaired frame can be forwarded more than once; use the first delivery.
  video_end=min(video_ends,key=server_stamp)
  samples.append({'index':sample['index'],'key':key,'send':sent,'native':command,'post':post,'source_receive':source_receive,'native_event':native_event,'draw':draw,'frame':frame,'effect':effect,'encoded':encoded,'source_end':source_end,'relay':relay,'video_end':video_end})
 
 # Source Instant -> native Mach clock offset is bracketed by each local command:
 # receive precedes companion receive; acknowledgement follows native completion.
 # This avoids wall clocks, which may slew during a run.
 commands=[r for r in metrics if r['metric']=='native_input']
 selected_commands=[s['native'] for s in samples]
 source_receives,_=align_command_stream(selected_commands,commands,stage('source_control_receive',4),'receive_ns',lambda r:int(r['at_ns']))
 source_acks,_=align_command_stream(selected_commands,commands,stage('source_control_ack',67),'finished_ns',lambda r:int(r['at_ns']))
 if len({r['pid'] for r in source_receives+source_acks})!=1:raise ValueError('source clock changed during cohort')
 source_lower,source_upper=source_clock_bounds([int(s['native']['receive_ns']) for s in samples],[int(s['native']['finished_ns']) for s in samples],[int(r['at_ns']) for r in source_receives],[int(r['at_ns']) for r in source_acks])
 source_origin=(source_lower+source_upper)/2
 for sample,receive in zip(samples,source_receives):sample['source_receive']=receive
 # All these stage rows belong to the same source supervisor. Its Instant origin
 # is calibrated directly above; no cross-host wall-clock subtraction is needed.
 def local_epoch(row):return native_epoch(source_origin+int(row['at_ns']))
 
 # Match the full command pattern before selecting quiet keys. Network clocks
 # are never assumed synchronized, including when focus recovery adds mouse input.
 receives=sorted(stage('server_input_receive',4),key=server_stamp)
 if len({r['pid'] for r in receives})!=1:raise ValueError('server clock changed during cohort')
 selected_receives,score=align_command_stream(selected_commands,commands,receives,'receive_ns',server_stamp)
 summary={};events=[];source_details={};source_details_unavailable=[]
 surface_details={};surface_details_unavailable=[]
 for sample,receive in zip(samples,selected_receives):
  began,ended=forward(receive,stage('server_input_write_begin',4),stage('server_input_write_end',4),server_stamp)
  server_local=(server_stamp(ended)-server_stamp(receive))/1e6
  local={
   'browser_keydown_to_send':sample['send']['at']-sample['key']['eventAt'],
   'server_receive_to_forward':server_local,
   'Mac_source_receive_to_companion_receive':native_epoch(sample['native']['receive_ns'])-local_epoch(sample['source_receive']),
   'companion_receive_to_dispatch':(int(sample['native']['dispatch_ns'])-int(sample['native']['receive_ns']))/1e6,
   'companion_dispatch_to_inject':(int(sample['post']['at_ns'])-int(sample['native']['dispatch_ns']))/1e6,
   'inject_to_fixture_keydown':(sample['native_event']['ticks']*timebase-int(sample['post']['at_ns']))/1e6,
   'fixture_keydown_to_draw_end':(sample['draw']['end_ticks']-sample['native_event']['ticks'])*timebase/1e6,
   'draw_end_to_capture':(int(sample['frame']['captureNs'])-sample['draw']['end_ticks']*timebase)/1e6,
   'capture_to_encoded':(int(sample['encoded']['encode_finished_ns'])-int(sample['frame']['captureNs']))/1e6,
   'encoded_to_Mac_send':local_epoch(sample['source_end'])-native_epoch(sample['encoded']['encode_finished_ns']),
   'server_video_receive_to_forward':(server_stamp(sample['video_end'])-server_stamp(sample['relay']))/1e6,
   'browser_receive_to_worker_paint':sample['effect']['begin']-sample['frame']['receivedAt'],
  }
  network={
   'input_two_legs_residual':local_epoch(sample['source_receive'])-sample['send']['at']-server_local,
   'video_two_legs_residual':sample['frame']['receivedAt']-local_epoch(sample['source_end'])-local['server_video_receive_to_forward'],
  }
  callbacks=[r for r in metrics if r['metric']=='source_frame' and r.get('damaged')=='true' and r.get('capture_ns')==sample['frame']['captureNs']]
  if len(callbacks)==1:
   details=source_callback_stages(sample['draw']['end_ticks']*timebase,int(sample['frame']['captureNs']),int(callbacks[0]['callback_ns']),int(sample['encoded']['encode_finished_ns']),int(sample['encoded']['encode_ns']))
   for name,number in details.items():source_details.setdefault(name,[]).append(number)
  else:source_details_unavailable.append(sample['index'])
  deliveries=[r for r in metrics if r['metric']=='surface_delivery' and r.get('capture_ns')==sample['frame']['captureNs'] and r.get('fresh')=='true']
  if len(deliveries)==1:
   for name,number in surface_delivery_stages(deliveries[0],sample['encoded']).items():surface_details.setdefault(name,[]).append(number)
  else:surface_details_unavailable.append(sample['index'])
  mac_names=('Mac_source_receive_to_companion_receive','companion_receive_to_dispatch','companion_dispatch_to_inject','inject_to_fixture_keydown','fixture_keydown_to_draw_end','draw_end_to_capture','capture_to_encoded','encoded_to_Mac_send')
  native_total=sum(local[name] for name in mac_names)
  # The browser is on the same physical Mac as the source. The full Mac
  # budget includes its input and painting, excluding only the server host.
  mac_total=native_total+local['browser_keydown_to_send']+local['browser_receive_to_worker_paint']
  for name,number in {**local,**network,'Mac_native_total':native_total,'Mac_native_non_encode_total':native_total-int(sample['encoded']['encode_ns'])/1e6,'Mac_local_total':mac_total,'Mac_non_encode_total':mac_total-int(sample['encoded']['encode_ns'])/1e6,'input_to_worker':sample['effect']['begin']-sample['key']['eventAt'],'local_total':sum(local.values())}.items():summary.setdefault(name,[]).append(number)
  events.append({'index':sample['index'],'local_ms':local,'network_residual_ms':network,'stamps':sample,'server_input_stamps':{'receive':receive,'forward_begin':began,'forward_end':ended}})
 def quantile(values,p):
  ordered=sorted(values);return ordered[max(0,math.ceil(len(ordered)*p)-1)]
 cohort_start=min(s['key']['eventAt'] for s in samples);cohort_end=max(s['effect']['begin'] for s in samples)
 network_rtts={}
 mac_rtts=[]
 for row in rows:
  if row.get('kind')!='network_leg_rtt':continue
  at=(row['at_perf_ns']-browser_offset)/1e6
  match=re.search(r'time=([0-9.]+) ms',row['raw'])
  if match and cohort_start<=at<=cohort_end:mac_rtts.append(float(match[1]))
 browser_rtts=[r['ms'] for sample in rows if sample.get('kind')=='input_sample' for receipt in sample['events'] for r in receipt['probe']['roundTrips'] if cohort_start<=r['at']<=cohort_end]
 for name,values in [('Mac_server_icmp',mac_rtts),('browser_server_protocol',browser_rtts)]:
  if values:network_rtts[name]={'n':len(values),'p50':statistics.median(values),'p95':quantile(values,.95),'max':max(values)}
 def stats(values):return {'n':len(values),'p50':statistics.median(values),'p95':quantile(values,.95),'max':max(values),'min':min(values)}
 # Callback diagnostics are additive. Never reconstruct an interleaved record
 # or publish quantiles from a smaller cohort; independent input stamps remain
 # complete even when these optional callback details are unavailable.
 report={'concurrent_network_rtt_ms':network_rtts,'source_clock_half_width_ms':(source_upper-source_lower)/2e6,'clock_uncertainty_ms':((clock['native']['upper']-clock['native']['lower'])+(clock['browser']['upper']-clock['browser']['lower']))/2e6,'server_cohort_spacing_rms_ms':score,'valid_sample_count':len(samples),'invalid_sample_count':len(invalid_samples),'invalid_samples':invalid_samples,'metrics':{k:stats(v) for k,v in summary.items()},'source_details_ms':{} if source_details_unavailable else {k:stats(v) for k,v in source_details.items()},'source_details_unavailable_events':source_details_unavailable,'surface_details_ms':{} if surface_details_unavailable else {k:stats(v) for k,v in surface_details.items()},'surface_details_unavailable_events':surface_details_unavailable,'events':events,'note':'Transport residuals include kernel/library queues outside the stamped send/receive boundaries; they are not pure wire time. Cross-host clocks are never subtracted to infer one-way latency. Source details subdivide existing phases; the display stamp may follow its callback and its signed offset is preserved.'}
 return report

if __name__=='__main__':
 if len(sys.argv)!=3:raise SystemExit('usage: attribute-input.py <receipt-directory> <controller-log>')
 print(json.dumps(analyze(pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2])),indent=2))
