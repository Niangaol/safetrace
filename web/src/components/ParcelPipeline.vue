<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import type { ActivityEvent, ActivityStage } from '../activity-types'
import { destination, parcelKey, travelPath, pathLength, pathPoint, transportProgress, stationStroke } from '../parcel-flow'
import { getMotionIntensity, onMotionIntensityChange } from '../effects/motion-prefs'
const props=defineProps<{ events: ActivityEvent[]; paused: boolean }>()
type Parcel={key:string;event:ActivityEvent;stage:ActivityStage|null;x:number;y:number;path:{x:number;y:number}[];progress:number;duration:number;moving:boolean;replay:boolean;settledFor:number}
const parcels=ref<Parcel[]>([]),queue=ref<{event:ActivityEvent;replay:boolean}[]>([]),selected=ref<string|null>(null)
const replay=ref(false),played=ref(0),seen=new Set<number>()
let autoStarted=false,frame:number|undefined,lastTime=0,dispatchWait=0,disposed=false
const motion=ref(getMotionIntensity()),reduced=ref(false),beltTime=ref(0)
const motionEnabled=computed(()=>motion.value!=='off'&&!reduced.value)
const motionAmplitude=computed(()=>motion.value==='low'?.45:1)
const media=typeof window==='undefined'?undefined:window.matchMedia('(prefers-reduced-motion: reduce)')
reduced.value=media?.matches??false
const mediaChange=()=>{reduced.value=media?.matches??false};media?.addEventListener('change',mediaChange)
const stopMotion=onMotionIntensityChange(value=>{motion.value=value})
const moving=computed(()=>parcels.value.some(p=>p.moving))
const chosen=computed(()=>parcels.value.find(p=>p.key===selected.value))
const names:Record<ActivityStage,string>={collect:'采集',normalize:'解析',dedupe:'去重',quality:'质量闸门',paper:'论文富化',score:'风险富化',knowledge:'入库',answer:'问答',review:'隔离 / 复核',fallback:'失败 / 降级',assets:'资产扫描'}
const statuses={success:'本阶段通过',running:'处理中',review:'待复核',rejected:'拒收',failed:'失败',degraded:'降级'}
const machines: {stage:ActivityStage;name:string;sub:string;x:number;y:number}[]=[
 {stage:'collect',name:'多源采集',sub:'原文接收',x:80,y:85},{stage:'normalize',name:'解析台',sub:'字段规范化',x:220,y:85},{stage:'dedupe',name:'归并台',sub:'CVE 去重',x:360,y:85},{stage:'quality',name:'质检闸门',sub:'放行 / 隔离',x:500,y:85},
 {stage:'paper',name:'论文工位',sub:'关联证据',x:660,y:40},{stage:'score',name:'风险工位',sub:'CVSS / EPSS',x:660,y:340},{stage:'knowledge',name:'档案仓库',sub:'证据 / 索引',x:840,y:85},{stage:'answer',name:'问答出站',sub:'自然语言引用',x:960,y:85},
 {stage:'assets',name:'资产扫描',sub:'本地快照 / 清单',x:960,y:365},
 {stage:'review',name:'隔离待检区',sub:'不自动放行',x:500,y:505},{stage:'fallback',name:'异常收件区',sub:'保留降级原因',x:710,y:505},
]
function label(event:ActivityEvent){return event.intel_id?.replace(/^intel_(nvd|kev)_cve_/,'CVE-').replace(/_/g,'-')??'来源批次'}
function startReplay(){
 queue.value=props.events.slice().sort((a,b)=>a.sequence-b.sequence).map(event=>({event,replay:true}))
 parcels.value=[];selected.value=null;played.value=0;replay.value=true;dispatchWait=0;ensureFrame()
}
function launch(event:ActivityEvent,isReplay:boolean){
 const key=parcelKey(event);let p=parcels.value.find(p=>p.key===key)
 if(p&&(p.moving||p.settledFor<1000))return false
 if(!p){
  if(parcels.value.length>=12){const remove=parcels.value.findIndex(p=>!p.moving&&p.key!==selected.value);if(remove<0)return false;parcels.value.splice(remove,1)}
  p={key,event,stage:null,x:18,y:190,path:[],progress:0,duration:0,moving:false,replay:isReplay,settledFor:0};parcels.value.push(p);p=parcels.value[parcels.value.length-1]!
 }
 const stage=destination(event),path=travelPath(p.stage,stage)
 p.x=path[0]!.x;p.y=path[0]!.y;
 p.event=event;p.replay=isReplay;p.path=path;p.progress=0;p.duration=Math.max(1000,pathLength(path)*7);p.moving=true;p.stage=stage;p.settledFor=0
 played.value++;return true
}
function tick(time:number){
 frame=undefined;if(disposed)return
 const dt=lastTime?Math.min(64,time-lastTime):0;lastTime=time
 const instant=motion.value==='off'||reduced.value
 if(!props.paused){
  if(motionEnabled.value&&moving.value)beltTime.value+=dt
  dispatchWait-=dt
  if(queue.value.length&&dispatchWait<=0){const next=queue.value[0]!;if(launch(next.event,next.replay)){queue.value.shift();dispatchWait=instant?80:850}}
  for(const p of parcels.value){if(!p.moving){p.settledFor+=dt;continue;}p.progress=instant?1:Math.min(1,p.progress+dt/p.duration);const point=pathPoint(p.path,transportProgress(p.progress));p.x=point.x;p.y=point.y;if(p.progress>=1)p.moving=false}
  parcels.value=parcels.value.filter(p=>p.moving||p.key===selected.value||p.settledFor<2200)
 }
 if(!props.paused&&(queue.value.length||moving.value||parcels.value.some(p=>p.key!==selected.value&&p.settledFor<2200)||parcels.value.some(p=>p.settledFor<1200))){frame=requestAnimationFrame(tick)}else{lastTime=0;if(!props.paused&&!queue.value.length&&!moving.value)replay.value=false}
}
// 工位反馈只对应到站的实时事件；路过、历史回放都不触发机器。
const stationFeedback=computed(()=>Object.fromEntries(machines.map(machine=>{
 const parcel=parcels.value.filter(p=>p.stage===machine.stage&&!p.moving&&!p.replay&&p.event.origin==='live'&&p.settledFor<1200).sort((a,b)=>b.event.sequence-a.event.sequence)[0]
 return [machine.stage,parcel?{sequence:parcel.event.sequence,status:parcel.event.status,stroke:motionEnabled.value?stationStroke(parcel.settledFor)*motionAmplitude.value:0}:undefined]
})))
function feedback(stage:ActivityStage){return stationFeedback.value[stage]}
function stroke(stage:ActivityStage){return feedback(stage)?.stroke??0}
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
   <svg class="factory-floor" viewBox="-48 -10 1136 600" role="img" aria-label="采集、解析、去重、质检、富化、入库与问答，含隔离和异常轨道" :data-motion="motionEnabled ? motion : 'off'" :data-paused="paused">
    <defs>
     <pattern id="factory-grid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M 24 0 H 0 V 24" fill="none" stroke="#536779" stroke-opacity=".12"/></pattern>
     <linearGradient id="machine-metal" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#627a8b"/><stop offset=".08" stop-color="#344a5d"/><stop offset=".85" stop-color="#192e41"/><stop offset="1" stop-color="#0e1e2d"/></linearGradient>
     <linearGradient id="parcel-front"><stop stop-color="#d4a66b"/><stop offset="1" stop-color="#af8047"/></linearGradient>
     <filter id="factory-shadow" x="-40%" y="-40%" width="180%" height="200%"><feDropShadow dx="0" dy="5" stdDeviation="3" flood-opacity=".5"/></filter>
    </defs>
    <rect width="1040" height="570" fill="#0b1723"/><rect width="1040" height="570" fill="url(#factory-grid)"/>
    <g class="conveyor"><path d="M 18 190 H 560 V 120 H 760 V 190 H 990 M 560 190 V 270 H 760 V 190 M 500 190 V 435 M 710 190 V 435 M 840 190 V 320 H 960" class="belt-frame"/><path d="M 18 190 H 560 V 120 H 760 V 190 H 990 M 560 190 V 270 H 760 V 190 M 500 190 V 435 M 710 190 V 435 M 840 190 V 320 H 960" class="belt-rubber"/><path d="M 18 190 H 560 V 120 H 760 V 190 H 990 M 560 190 V 270 H 760 V 190 M 500 190 V 435 M 710 190 V 435 M 840 190 V 320 H 960" class="belt-rollers" :style="{strokeDashoffset:motionEnabled ? -(beltTime / 55) % 12 : 0}"/></g>
    <g v-for="machine in machines" :key="machine.stage" :transform="'translate('+machine.x+' '+machine.y+')'" class="machine" :class="[feedback(machine.stage)?.status,{working:!!feedback(machine.stage)}]" :data-stage="machine.stage" :data-live-sequence="feedback(machine.stage)?.sequence">
     <rect x="-54" y="-25" width="108" height="65" rx="6" fill="url(#machine-metal)" stroke="#6d8595" filter="url(#factory-shadow)"/>
     <path d="M -54 40 L -45 48 H 63 L 54 40" fill="#0a1827" stroke="#3e566b"/><circle cx="-45" cy="-16" r="2" fill="#91a7b5"/><circle cx="45" cy="-16" r="2" fill="#91a7b5"/>
     <rect x="-39" y="-12" width="78" height="25" rx="3" fill="#091b28" stroke="#233f50"/><text text-anchor="middle" y="4" class="machine-title">{{ machine.name }}</text><text text-anchor="middle" y="29" class="machine-sub">{{ machine.sub }}</text><circle cx="42" cy="28" r="3" class="machine-led"/>
     <path v-if="machine.y<190 && machine.stage!=='paper'" d="M -42 48 V 87 M 42 48 V 87" stroke="#3e5566" stroke-width="5"/>
     <!-- 各工位有不同的机械表达；所有行程共用可暂停的 RAF 时钟。 -->
     <g class="station-mechanism" aria-hidden="true">
      <g v-if="machine.stage==='collect'||machine.stage==='normalize'||machine.stage==='assets'" :transform="machine.stage==='assets' ? 'translate(0 -125)' : undefined">
       <path d="M -27 55 V 73 H 27 V 55" class="mechanism-frame"/>
       <path :d="'M -26 '+(58+stroke(machine.stage)*12)+' H 26'" class="scanner-line"/>
       <path d="M -15 80 H -5 M 0 80 H 15" class="mechanism-detail"/>
      </g>
      <g v-else-if="machine.stage==='dedupe'">
       <rect :x="-24+stroke(machine.stage)*12" y="56" width="17" height="20" rx="2" class="mechanism-sheet"/>
       <rect :x="7-stroke(machine.stage)*12" y="61" width="17" height="20" rx="2" class="mechanism-sheet"/>
      </g>
      <g v-else-if="machine.stage==='quality'">
       <path d="M -30 57 V 91 M 30 57 V 91" class="mechanism-frame"/>
       <path :d="'M -27 '+(85-stroke(machine.stage)*22)+' H 27'" class="gate-bar"/>
      </g>
      <g v-else-if="machine.stage==='paper'||machine.stage==='score'" :transform="'translate(0 '+(machine.stage==='paper'?56:-55)+')'">
       <circle r="12" class="mechanism-frame"/>
       <g :transform="'rotate('+stroke(machine.stage)*160+')'" class="mechanism-detail"><path d="M -8 0 H 8 M 0 -8 V 8"/></g>
       <circle r="3" class="mechanism-core"/>
      </g>
      <g v-else-if="machine.stage==='knowledge'||machine.stage==='answer'" :transform="'translate(0 '+stroke(machine.stage)*8+')'">
       <path d="M -24 56 H 24 V 79 H -24 Z M -24 64 H 24 M -24 71 H 24" class="mechanism-frame"/>
       <rect x="-13" y="58" width="26" height="4" class="mechanism-core"/>
      </g>
      <g v-else :transform="'translate(0 '+(-stroke(machine.stage)*6)+')'">
       <path d="M -25 -43 H 25 M -18 -50 V -36 M 18 -50 V -36" class="mechanism-frame"/>
       <path v-if="machine.stage==='review'" d="M -3 -47 V -39 M 3 -47 V -39" class="mechanism-detail"/>
       <path v-else d="M -4 -47 L 4 -39 M 4 -47 L -4 -39" class="mechanism-detail"/>
      </g>
     </g>
    </g>
    <text x="515" y="375" class="branch-note">待复核 / 拒收 ↓</text><text x="725" y="375" class="branch-note">失败 / 降级 ↓</text><text x="578" y="228" class="branch-note">富化双工位</text>
    <g v-for="p in parcels" :key="p.key" :data-parcel-key="p.key" :data-x="p.x.toFixed(1)" :data-y="p.y.toFixed(1)" :transform="'translate('+p.x+' '+p.y+')'" class="parcel" :class="[p.event.status,{travelling:p.moving,chosen:selected===p.key}]" role="button" tabindex="0" :aria-label="label(p.event)+'，'+names[p.event.stage]+'，'+statuses[p.event.status]+(p.replay?'，历史回放':'，实时')" @click="selected=selected===p.key?null:p.key" @keydown.enter.prevent="selected=selected===p.key?null:p.key" @keydown.space.prevent="selected=selected===p.key?null:p.key">
     <title>{{ label(p.event) }} · {{ names[p.event.stage] }} · {{ statuses[p.event.status] }} · Trace {{ p.event.trace_id }}</title>
     <ellipse cx="2" cy="10" rx="24" ry="7" fill="#000" opacity=".35"/>
     <g :transform="'translate(0 '+(motionEnabled && !p.moving ? -Math.sin(Math.PI*Math.min(1,p.settledFor/350))*2*motionAmplitude : 0)+')'" class="parcel-box"><path d="M -23 -17 L -10 -28 L 24 -23 L 12 -12 Z" fill="#ead0a0" stroke="#926739"/><path d="M 12 -12 L 24 -23 V 6 L 12 17 Z" fill="#916135" stroke="#704b2c"/><path d="M -23 -17 L 12 -12 V 17 L -23 12 Z" fill="url(#parcel-front)" stroke="#986c3e"/>
      <path d="M -9 -24 L -3 -23 L -15 -16 L -15 13 L -9 14 V -15 L 3 -22" fill="#f2d89d" opacity=".9"/>
      <rect x="-6" y="-5" width="14" height="13" rx="1" fill="#f1e7cf" transform="rotate(7)"/><path d="M -4 -2 H 6 M -4 1 H 5 M -4 4 H 6" stroke="#776957" stroke-width="1"/>
      <circle cx="8" cy="12" r="3" class="parcel-seal"/>
      <g v-if="!p.moving" class="parcel-status" transform="translate(16 -27)"><circle r="8"/><path v-if="p.event.status==='success'" d="M -4 0 L -1 3 L 4 -3"/><path v-else-if="p.event.status==='failed'||p.event.status==='rejected'" d="M -3 -3 L 3 3 M 3 -3 L -3 3"/><path v-else-if="p.event.status==='review'" d="M -2 -3 V 3 M 2 -3 V 3"/><path v-else d="M 0 -4 V 1 M 0 3 V 4"/></g>
     </g>
     <text text-anchor="middle" y="34" class="parcel-label">{{ label(p.event).slice(-18) }}</text><text text-anchor="middle" y="47" class="parcel-origin">{{ p.replay ? '历史回放' : '实时' }} · {{ p.moving ? '运输中' : names[p.event.stage] }}</text>
    </g>
   </svg>
  </div>
  <aside v-if="chosen" class="parcel-inspector" aria-label="包裹真实数据详情"><button type="button" class="close-inspector" @click="selected=null" aria-label="关闭包裹详情">×</button><strong>{{ label(chosen.event) }}</strong><span>{{ chosen.replay?'历史回放':'实时事件' }} · {{ names[chosen.event.stage] }} · {{ statuses[chosen.event.status] }}</span><p>{{ chosen.event.details.reason ?? chosen.event.label }}</p><dl><dt>情报 ID</dt><dd>{{ chosen.event.intel_id ?? '来源批次（没有情报 ID）' }}</dd><dt>来源</dt><dd>{{ chosen.event.details.source_id ?? '未报告' }}</dd><dt>Trace</dt><dd>{{ chosen.event.trace_id }}</dd><dt>阶段耗时</dt><dd>{{ chosen.event.details.elapsed_ms===undefined?'未报告':chosen.event.details.elapsed_ms+' ms' }}</dd><dt>事件时间</dt><dd>{{ chosen.event.at }}</dd></dl></aside>
  <p class="factory-footnote">纸箱是情报，工位是处理阶段，滚筒是运输轨道。启停与机械行程是事件到达的视觉反馈，不代表后端耗时或处理进度。回放只使用已收到的真实记录；没有记录的阶段不补造处理结果。来源批次单独标注，不当作具体情报。</p>
 </section>
</template>
<style scoped>
.parcel-factory{position:relative;margin-top:20px}
.factory-header{display:flex;justify-content:space-between;gap:24px;align-items:start;margin-bottom:18px}
.factory-header h3{font-size:19px;color:#e4d8c5;margin:0 0 8px}
.factory-header p,.factory-footnote{font-size:12px;line-height:1.8;color:#8fa5b8;margin:0}
.replay-tools{display:flex;align-items:center;flex-wrap:wrap;gap:10px;justify-content:flex-end}
.replay-tools span{color:#e5bc7e;font-size:12px}
.replay-tools small{color:#8a9fb1;font-size:11px}
.replay-tools button,.close-inspector{border:1px solid #7c694d;background:linear-gradient(#4c463c,#2c2b2a);color:#efdbb9;padding:8px 12px;border-radius:5px;cursor:pointer}
.replay-tools button:disabled{opacity:.45;cursor:default}
.factory-scroll{border:1px solid #455766;border-radius:12px;overflow:auto;background:#0b1723;box-shadow:inset 0 0 25px #0007;max-width:100%}
.factory-floor{display:block;width:100%;min-width:1000px;height:auto}
.belt-frame{fill:none;stroke:#52616c;stroke-width:36;stroke-linejoin:round;stroke-linecap:round;filter:drop-shadow(0 7px 2px #0008)}
.belt-rubber{fill:none;stroke:#18232e;stroke-width:27;stroke-linejoin:round;stroke-linecap:round}
.belt-rollers{fill:none;stroke:#61717b;stroke-width:23;stroke-dasharray:3 9;opacity:.55;stroke-linejoin:round}
.machine-title{fill:#d8e7e9;font-size:12px;font-weight:600}
.machine-sub{fill:#a0b0bc;font-size:9px}
.machine-led{fill:#3b665e}
.working .machine-led{fill:#8ce5be;filter:drop-shadow(0 0 5px #76e2b6)}
.branch-note{fill:#ae997a;font-size:10px}
.parcel{cursor:pointer;outline:none}
.parcel:focus-visible .parcel-box,.parcel:hover .parcel-box,.parcel.chosen .parcel-box{filter:drop-shadow(0 0 4px #f6d690)}
.parcel-box{filter:drop-shadow(0 3px 2px #0005)}
.parcel-label{fill:#ede0c9;font:9px monospace;paint-order:stroke;stroke:#0b1723;stroke-width:3px}
.parcel-origin{fill:#a3b2bf;font-size:8px;paint-order:stroke;stroke:#0b1723;stroke-width:3px}
.parcel-seal{fill:#628864}
.failed .parcel-seal,.rejected .parcel-seal{fill:#cf665b}
.review .parcel-seal,.degraded .parcel-seal{fill:#e8af4a}
.parcel-inspector{position:absolute;right:18px;top:90px;width:min(360px,80%);padding:20px;background:#152330ee;border:1px solid #ac8d5d;border-radius:10px;box-shadow:0 15px 40px #0008;z-index:5;backdrop-filter:blur(10px);color:#dce4ec}
.parcel-inspector strong{display:block;padding-right:24px;color:#edcea0}
.parcel-inspector span,.parcel-inspector p{font-size:12px;line-height:1.7}
.parcel-inspector dl{display:grid;grid-template-columns:65px 1fr;gap:8px;font-size:11px}
.parcel-inspector dt{color:#8fa5b8}
.parcel-inspector dd{margin:0;overflow-wrap:anywhere}
.close-inspector{position:absolute;right:8px;top:8px;padding:2px 8px;font-size:18px}
.factory-footnote{margin-top:12px}
.factory-scroll:focus-visible{outline:2px solid #d5b279;outline-offset:3px}@media(max-width:700px){.factory-header{flex-direction:column;gap:12px}
.replay-tools{justify-content:flex-start}
.parcel-inspector{right:5px}}@media(prefers-reduced-motion:reduce){.belt-rollers{animation:none!important}}:global([data-motion="off"]) .belt-rollers{animation:none!important}
/* 不使用独立 CSS 动画：滚筒、扫描与机械动作均由同一时钟更新，暂停不复位。 */
.station-mechanism{color:#739caf}
.mechanism-frame{fill:none;stroke:currentColor;stroke-width:2;stroke-linejoin:round}
.mechanism-detail{fill:none;stroke:#91c4d6;stroke-width:2}
.mechanism-sheet{fill:#152e40;stroke:#80b6ce;stroke-width:1.5}
.mechanism-core{fill:#5caac5}
.scanner-line{fill:none;stroke:#56b7d2;stroke-width:2}
.gate-bar{fill:none;stroke:#8bafbf;stroke-width:5;stroke-linecap:round}
.working .station-mechanism{color:#63b4cb}
.working.failed .station-mechanism,.working.degraded .station-mechanism{color:#df9665}
.working.review .station-mechanism,.working.rejected .station-mechanism{color:#d9b46e}
.working.running .machine-led{fill:#7bc9e5;filter:none}
.working.failed .machine-led,.working.rejected .machine-led{fill:#f08c7b;filter:none}
.working.review .machine-led,.working.degraded .machine-led{fill:#e4bc71;filter:none}
.parcel-status circle{fill:#173d37;stroke:#80c6ab;stroke-width:1.5}
.parcel-status path{fill:none;stroke:#c5f1e1;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.failed .parcel-status circle,.rejected .parcel-status circle{fill:#522e2b;stroke:#e9927f}
.review .parcel-status circle,.degraded .parcel-status circle{fill:#493c25;stroke:#ddbd7b}
.parcel:focus-visible{outline:none}
.parcel:focus-visible .parcel-box{filter:drop-shadow(0 0 5px #9bd5ee)}
</style>
