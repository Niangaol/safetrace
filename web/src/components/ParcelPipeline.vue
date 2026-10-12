<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import type { ActivityEvent, ActivityStage } from '../activity-types'
import { destination, parcelKey, travelPath, pathLength, pathPoint } from '../parcel-flow'
import { getMotionIntensity, onMotionIntensityChange } from '../effects/motion-prefs'
const props=defineProps<{ events: ActivityEvent[]; paused: boolean }>()
type Parcel={key:string;event:ActivityEvent;stage:ActivityStage|null;x:number;y:number;path:{x:number;y:number}[];progress:number;duration:number;moving:boolean;replay:boolean;settledFor:number}
const parcels=ref<Parcel[]>([]),queue=ref<{event:ActivityEvent;replay:boolean}[]>([]),selected=ref<string|null>(null)
const replay=ref(false),played=ref(0),seen=new Set<number>()
let autoStarted=false,frame:number|undefined,lastTime=0,dispatchWait=0,disposed=false
const motion=ref(getMotionIntensity()),reduced=ref(false)
const media=typeof window==='undefined'?undefined:window.matchMedia('(prefers-reduced-motion: reduce)')
reduced.value=media?.matches??false
const mediaChange=()=>{reduced.value=media?.matches??false};media?.addEventListener('change',mediaChange)
const stopMotion=onMotionIntensityChange(value=>{motion.value=value})
const moving=computed(()=>parcels.value.some(p=>p.moving))
const chosen=computed(()=>parcels.value.find(p=>p.key===selected.value))
const names:Record<ActivityStage,string>={collect:'采集',normalize:'解析',dedupe:'去重',quality:'质量闸门',paper:'论文富化',score:'风险富化',knowledge:'入库',answer:'问答',review:'隔离 / 复核',fallback:'失败 / 降级',assets:'资产扫描'}
const statuses={success:'本阶段通过',running:'处理中',review:'待复核',rejected:'拒收',failed:'失败',degraded:'降级'}
const machines: {stage:ActivityStage;name:string;sub:string;x:number;y:number}[]=[
  {stage:'collect',name:'多源采集',sub:'原文接收',x:110,y:110},{stage:'normalize',name:'解析台',sub:'字段规范化',x:275,y:110},{stage:'dedupe',name:'归并台',sub:'CVE 去重',x:440,y:110},{stage:'quality',name:'质检闸门',sub:'放行 / 隔离',x:600,y:110},
  {stage:'paper',name:'论文工位',sub:'关联证据',x:780,y:55},{stage:'score',name:'风险工位',sub:'CVSS / EPSS',x:780,y:360},{stage:'knowledge',name:'档案仓库',sub:'证据 / 索引',x:925,y:110},{stage:'answer',name:'问答出站',sub:'自然语言引用',x:1040,y:110},
  {stage:'review',name:'隔离待检区',sub:'不自动放行',x:600,y:515},{stage:'fallback',name:'异常收件区',sub:'保留降级原因',x:825,y:515},
]
function label(event:ActivityEvent){return event.intel_id?.replace(/^intel_(nvd|kev)_cve_/,'CVE-').replace(/_/g,'-')??'来源批次'}
function startReplay(){
 queue.value=props.events.slice().sort((a,b)=>a.sequence-b.sequence).map(event=>({event,replay:true}))
 parcels.value=[];selected.value=null;played.value=0;replay.value=true;dispatchWait=0;ensureFrame()
}
function launch(event:ActivityEvent,isReplay:boolean){
 const key=parcelKey(event);let p=parcels.value.find(p=>p.key===key)
 if(p?.moving)return false
 if(!p){
  if(parcels.value.length>=12){const remove=parcels.value.findIndex(p=>!p.moving&&p.key!==selected.value);if(remove<0)return false;parcels.value.splice(remove,1)}
  p={key,event,stage:null,x:18,y:190,path:[],progress:0,duration:0,moving:false,replay:isReplay,settledFor:0};parcels.value.push(p);p=parcels.value[parcels.value.length-1]!
 }
 const stage=destination(event),path=travelPath(p.stage,stage)
 p.event=event;p.replay=isReplay;p.path=path;p.progress=0;p.duration=Math.max(1000,pathLength(path)*7);p.moving=true;p.stage=stage;p.settledFor=0
 played.value++;return true
}
function tick(time:number){
 frame=undefined;if(disposed)return
 const dt=lastTime?Math.min(64,time-lastTime):0;lastTime=time
 const instant=motion.value==='off'||reduced.value
 if(!props.paused){
  dispatchWait-=dt
  if(queue.value.length&&dispatchWait<=0){const next=queue.value[0]!;if(launch(next.event,next.replay)){queue.value.shift();dispatchWait=instant?80:850}}
  for(const p of parcels.value){if(!p.moving){p.settledFor+=dt;continue;}p.progress=instant?1:Math.min(1,p.progress+dt/p.duration);const point=pathPoint(p.path,p.progress);p.x=point.x;p.y=point.y;if(p.progress>=1)p.moving=false}
  parcels.value=parcels.value.filter(p=>p.moving||p.key===selected.value||p.settledFor<2200)
 }
 if(!props.paused&&(queue.value.length||moving.value||parcels.value.some(p=>p.key!==selected.value&&p.settledFor<2200))){frame=requestAnimationFrame(tick)}else{lastTime=0;replay.value=false}
}
function ensureFrame(){if(frame===undefined&&!disposed){lastTime=0;frame=requestAnimationFrame(tick)}}
watch(()=>props.events,events=>{
 if(!events.length){queue.value=[];parcels.value=[];seen.clear();return}
 const incoming=events.filter(event=>!seen.has(event.sequence)).sort((a,b)=>a.sequence-b.sequence)
 for(const event of incoming)seen.add(event.sequence)
 if(seen.size>1500){seen.clear();for(const event of events)seen.add(event.sequence)}
 if(!autoStarted&&incoming.some(e=>e.origin==='recorded')){autoStarted=true;startReplay();return}
 for(const event of incoming){queue.value.push({event,replay:event.origin!=='live'})}
 if(queue.value.length>500)queue.value=queue.value.slice(-500)
 ensureFrame()
},{immediate:true})
watch(()=>props.paused,()=>ensureFrame())
onBeforeUnmount(()=>{disposed=true;if(frame!==undefined)cancelAnimationFrame(frame);media?.removeEventListener('change',mediaChange);stopMotion()})
</script>
<template>
 <section class="parcel-factory" aria-label="拟物情报包裹流水线">
  <header class="factory-header"><div><h3>情报包裹 · 处理流水线</h3><p>一条情报一个包裹，沿轨道运输；经过工位不代表该阶段已通过。</p></div><div class="replay-tools"><span role="status">{{ paused ? '运输暂停' : replay ? '历史记录回放 · 非实时处理' : moving || queue.length ? '事件运输中' : '等待新事件' }}</span><button type="button" :disabled="!events.length || paused" @click="startReplay">重播已有记录</button><small>已展示 {{ played }} 个事件 · 待播 {{ queue.length }}</small></div></header>
  <div class="factory-scroll" tabindex="0" aria-label="包裹传送带，窄屏可横向查看">
    <svg class="factory-floor" viewBox="0 0 1180 640" role="img" aria-label="采集、解析、去重、质检、富化、入库与问答，含隔离和异常轨道" :class="{ transporting:moving && !paused && motion !== 'off' && !reduced }">
     <defs>
      <pattern id="factory-grid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M 28 0 H 0 V 28" fill="none" stroke="#536779" stroke-opacity=".12"/></pattern>
      <linearGradient id="machine-metal" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#6b899d"/><stop offset=".08" stop-color="#3b546b"/><stop offset=".85" stop-color="#1d324a"/><stop offset="1" stop-color="#0f202f"/></linearGradient>
      <linearGradient id="parcel-front"><stop stop-color="#d7ab6f"/><stop offset="1" stop-color="#b58a4d"/></linearGradient>
      <filter id="factory-shadow" x="-40%" y="-40%" width="180%" height="200%"><feDropShadow dx="0" dy="5" stdDeviation="3.2" flood-opacity=".55"/></filter>
     </defs>
     <rect width="1180" height="640" fill="#0b1825"/><rect width="1180" height="640" fill="url(#factory-grid)"/>
     <g class="conveyor" stroke-linejoin="round" stroke-linecap="round">
       <path d="M 40 210 H 620 V 140 H 800 V 210 H 1120 M 620 210 V 295 H 800 V 210 M 540 210 V 470 M 745 210 V 470" class="belt-frame"/>
       <path d="M 40 210 H 620 V 140 H 800 V 210 H 1120 M 620 210 V 295 H 800 V 210 M 540 210 V 470 M 745 210 V 470" class="belt-rubber"/>
       <path d="M 40 210 H 620 V 140 H 800 V 210 H 1120 M 620 210 V 295 H 800 V 210 M 540 210 V 470 M 745 210 V 470" class="belt-rollers"/>
     </g>
     <g v-for="machine in machines" :key="machine.stage" :transform="'translate('+machine.x+' '+machine.y+')'" class="machine" :class="{working:parcels.some(p=>p.moving&&p.stage===machine.stage)}">
      <rect x="-62" y="-28" width="124" height="72" rx="7" fill="url(#machine-metal)" stroke="#7f94a6" filter="url(#factory-shadow)"/>
      <path d="M -62 44 L -52 53 H 72 L 62 44" fill="#0b1d2c" stroke="#45607c"/>
      <circle cx="-51" cy="-18" r="2" fill="#a6bcc9"/><circle cx="51" cy="-18" r="2" fill="#a6bcc9"/>
      <rect x="-46" y="-14" width="92" height="28" rx="3" fill="#0d2031" stroke="#2b4358"/>
      <text text-anchor="middle" y="3" class="machine-title">{{ machine.name }}</text><text text-anchor="middle" y="31" class="machine-sub">{{ machine.sub }}</text><circle cx="48" cy="32" r="3" class="machine-led"/>
      <path v-if="machine.stage==='collect'||machine.stage==='normalize'||machine.stage==='dedupe'" d="M 0 44 V 84" stroke="#45607c" stroke-width="5" opacity=".8"/>
      <path v-if="machine.stage==='paper'||machine.stage==='score'" d="M 0 44 V 90" stroke="#45607c" stroke-width="5" opacity=".8"/>
     </g>
     <text x="550" y="395" class="branch-note">待复核 / 拒收 ↓</text><text x="760" y="395" class="branch-note">失败 / 降级 ↓</text><text x="640" y="245" class="branch-note">富化双工位</text>
     <g v-for="p in parcels" :key="p.key" :data-parcel-key="p.key" :data-x="p.x.toFixed(1)" :data-y="p.y.toFixed(1)" :transform="'translate('+p.x+' '+p.y+')'" class="parcel" :class="[p.event.status,{travelling:p.moving,chosen:selected===p.key}]" role="button" tabindex="0" :aria-label="label(p.event)+'，'+names[p.event.stage]+'，'+statuses[p.event.status]+(p.replay?'，历史回放':'，实时')" @click="selected=selected===p.key?null:p.key" @keydown.enter.prevent="selected=selected===p.key?null:p.key" @keydown.space.prevent="selected=selected===p.key?null:p.key">
      <title>{{ label(p.event) }} · {{ names[p.event.stage] }} · {{ statuses[p.event.status] }} · Trace {{ p.event.trace_id }}</title>
      <ellipse cx="2" cy="10" rx="26" ry="7" fill="#000" opacity=".32"/>
      <g class="parcel-box"><path d="M -25 -18 L -12 -30 L 26 -25 L 14 -14 Z" fill="#edd1a2" stroke="#9a753c"/><path d="M 14 -14 L 26 -25 V 7 L 14 18 Z" fill="#936e38" stroke="#74552f"/><path d="M -25 -18 L 14 -14 V 18 L -25 13 Z" fill="url(#parcel-front)" stroke="#9f7a44"/>
       <path d="M -11 -26 L -5 -25 L -17 -17 L -17 14 L -11 15 V -16 L 5 -23" fill="#f3da9e" opacity=".9"/>
       <rect x="-7" y="-6" width="16" height="14" rx="1" fill="#f1e7cf" transform="rotate(7)"/><path d="M -5 -3 H 8 M -5 0 H 7 M -5 3 H 8" stroke="#7a6a55" stroke-width="1"/>
       <circle cx="10" cy="13" r="3" class="parcel-seal"/>
      </g>
      <text text-anchor="middle" y="36" class="parcel-label">{{ label(p.event).slice(-18) }}</text><text text-anchor="middle" y="49" class="parcel-origin">{{ p.replay ? '历史回放' : '实时' }} · {{ p.moving ? '运输中' : names[p.event.stage] }}</text>
     </g>
   </svg>
  </div>
  <aside v-if="chosen" class="parcel-inspector" aria-label="包裹真实数据详情"><button type="button" class="close-inspector" @click="selected=null" aria-label="关闭包裹详情">×</button><strong>{{ label(chosen.event) }}</strong><span>{{ chosen.replay?'历史回放':'实时事件' }} · {{ names[chosen.event.stage] }} · {{ statuses[chosen.event.status] }}</span><p>{{ chosen.event.details.reason ?? chosen.event.label }}</p><dl><dt>情报 ID</dt><dd>{{ chosen.event.intel_id ?? '来源批次（没有情报 ID）' }}</dd><dt>来源</dt><dd>{{ chosen.event.details.source_id ?? '未报告' }}</dd><dt>Trace</dt><dd>{{ chosen.event.trace_id }}</dd><dt>阶段耗时</dt><dd>{{ chosen.event.details.elapsed_ms===undefined?'未报告':chosen.event.details.elapsed_ms+' ms' }}</dd><dt>事件时间</dt><dd>{{ chosen.event.at }}</dd></dl></aside>
  <p class="factory-footnote">纸箱是情报，工位是处理阶段，滚筒是运输轨道。回放只使用已收到的真实记录；没有记录的阶段不补造处理结果。来源批次单独标注，不当作具体情报。</p>
 </section>
</template>
<style scoped>
.parcel-factory{position:relative;margin-top:20px}.factory-header{display:flex;justify-content:space-between;gap:24px;align-items:start;margin-bottom:18px}.factory-header h3{font-size:19px;color:#e4d8c5;margin:0 0 8px}.factory-header p,.factory-footnote{font-size:12px;line-height:1.8;color:#8fa5b8;margin:0}.replay-tools{display:flex;align-items:center;flex-wrap:wrap;gap:10px;justify-content:flex-end}.replay-tools span{color:#e5bc7e;font-size:12px}.replay-tools small{color:#8a9fb1;font-size:11px}.replay-tools button,.close-inspector{border:1px solid #7c694d;background:linear-gradient(#4c463c,#2c2b2a);color:#efdbb9;padding:8px 12px;border-radius:5px;cursor:pointer}.replay-tools button:disabled{opacity:.45;cursor:default}.factory-scroll{border:1px solid #455766;border-radius:14px;overflow:auto;background:#0b1723;box-shadow:inset 0 0 30px #0008;max-width:100%;padding:12px 12px 4px}.factory-floor{display:block;width:100%;min-width:1100px;height:auto}.belt-frame{fill:none;stroke:#52616c;stroke-width:36;stroke-linejoin:round;stroke-linecap:round;filter:drop-shadow(0 7px 2px #0008)}.belt-rubber{fill:none;stroke:#18232e;stroke-width:27;stroke-linejoin:round;stroke-linecap:round}.belt-rollers{fill:none;stroke:#61717b;stroke-width:23;stroke-dasharray:3 9;opacity:.55;stroke-linejoin:round}.transporting .belt-rollers{animation:rollers .65s linear infinite}@keyframes rollers{to{stroke-dashoffset:-12}}.machine-title{fill:#d8e7e9;font-size:12px;font-weight:600}.machine-sub{fill:#a0b0bc;font-size:9px}.machine-led{fill:#3b665e}.working .machine-led{fill:#8ce5be;filter:drop-shadow(0 0 5px #76e2b6)}.branch-note{fill:#ae997a;font-size:10px}.parcel{cursor:pointer;outline:none}.parcel:focus-visible .parcel-box,.parcel:hover .parcel-box,.parcel.chosen .parcel-box{filter:drop-shadow(0 0 4px #f6d690)}.parcel-box{filter:drop-shadow(0 3px 2px #0005)}.parcel-label{fill:#ede0c9;font:9px monospace;paint-order:stroke;stroke:#0b1723;stroke-width:3px}.parcel-origin{fill:#a3b2bf;font-size:8px;paint-order:stroke;stroke:#0b1723;stroke-width:3px}.parcel-seal{fill:#628864}.failed .parcel-seal,.rejected .parcel-seal{fill:#cf665b}.review .parcel-seal,.degraded .parcel-seal{fill:#e8af4a}.parcel-inspector{position:absolute;right:18px;top:90px;width:min(360px,80%);padding:20px;background:#152330ee;border:1px solid #ac8d5d;border-radius:10px;box-shadow:0 15px 40px #0008;z-index:5;backdrop-filter:blur(10px);color:#dce4ec}.parcel-inspector strong{display:block;padding-right:24px;color:#edcea0}.parcel-inspector span,.parcel-inspector p{font-size:12px;line-height:1.7}.parcel-inspector dl{display:grid;grid-template-columns:65px 1fr;gap:8px;font-size:11px}.parcel-inspector dt{color:#8fa5b8}.parcel-inspector dd{margin:0;overflow-wrap:anywhere}.close-inspector{position:absolute;right:8px;top:8px;padding:2px 8px;font-size:18px}.factory-footnote{margin-top:12px}.factory-scroll:focus-visible{outline:2px solid #d5b279;outline-offset:3px}@media(max-width:700px){.factory-header{flex-direction:column;gap:12px}.replay-tools{justify-content:flex-start}.parcel-inspector{right:5px}}@media(prefers-reduced-motion:reduce){.belt-rollers{animation:none!important}}:global([data-motion="off"]) .belt-rollers{animation:none!important}
</style>
