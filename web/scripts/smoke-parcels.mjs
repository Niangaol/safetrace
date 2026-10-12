import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'
import {parse,compileScript,compileTemplate,compileStyle} from '@vue/compiler-sfc'
const compile=s=>ts.transpileModule(s,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText
const url=s=>'data:text/javascript;base64,'+Buffer.from(s).toString('base64')
const flow=await import(url(compile(readFileSync(new URL('../src/parcel-flow.ts',import.meta.url),'utf8'))))
const event={event:'activity',id:'e',sequence:1,trace_id:'tr',intel_id:'intel-1',stage:'knowledge',status:'success',origin:'recorded',at:'2026-01-01',label:'真实记录',details:{}}
assert.equal(flow.parcelKey(event),flow.parcelKey({...event,trace_id:'other'}),'same data stays one parcel across traces')
assert.notEqual(flow.parcelKey({...event,intel_id:null}),flow.parcelKey({...event,intel_id:null,trace_id:'other'}),'source batches remain distinct')
for(const status of ['review','rejected'])assert.equal(flow.destination({...event,status}),'review')
for(const status of ['failed','degraded'])assert.equal(flow.destination({...event,status}),'fallback')
for(const to of Object.keys(flow.STOPS)){
 const path=flow.travelPath(null,to);assert.deepEqual(flow.pathPoint(path,0),{x:18,y:190});assert.deepEqual(flow.pathPoint(path,1),flow.STOPS[to]);assert.ok(flow.pathLength(path)>0)
 for(let i=1;i<path.length;i++)assert.ok(path[i].x===path[i-1].x||path[i].y===path[i-1].y,'parcel follows conveyor bends, never cuts diagonally')
 const halfway=flow.pathPoint(path,.5);assert.ok(Number.isFinite(halfway.x)&&Number.isFinite(halfway.y))
}
const paper=flow.travelPath('quality','paper');assert.ok(paper.some(p=>p.y===120),'paper branch used')
const score=flow.travelPath('quality','score');assert.ok(score.some(p=>p.y===270),'score branch used')
const text=readFileSync(new URL('../src/components/ParcelPipeline.vue',import.meta.url),'utf8')
const {descriptor,errors}=parse(text);assert.deepEqual(errors,[])
assert.deepEqual(compileTemplate({source:descriptor.template.content,filename:'ParcelPipeline.vue',id:'parcel-test'}).errors,[])
assert.deepEqual(compileStyle({source:descriptor.styles[0].content,filename:'ParcelPipeline.vue',id:'parcel-test',scoped:true}).errors,[])
compileScript(descriptor,{id:'parcel-test'})
assert.ok(text.includes('历史记录回放 · 非实时处理'))
assert.ok(text.includes('cancelAnimationFrame(frame)'))
assert.ok(text.includes("motion.value==='off'||reduced.value"))
assert.ok(text.includes('if(!props.paused&&(queue.value.length||moving.value||parcels.value.some'))
assert.equal(flow.transportProgress(0),0)
assert.equal(flow.transportProgress(1),1)
assert.equal(flow.transportProgress(.5),.5)
assert.ok(flow.transportProgress(.1)<.1,'entry accelerates gently')
assert.ok(flow.transportProgress(.9)>.9,'arrival decelerates gently')
assert.equal(flow.stationStroke(0),0)
assert.equal(flow.stationStroke(500),1)
assert.ok(flow.stationStroke(1000)<1e-12,'single stroke returns to rest')
const hooks={watch:[],unmount:[]}
globalThis.__parcelSmoke=hooks
const runtime=url(`const r=v=>({value:v});export {r as ref};export const computed=f=>({get value(){return f()}});export const defineComponent=v=>v;export const watch=(f,cb,o)=>{globalThis.__parcelSmoke.watch.push([f,cb]);if(o?.immediate)cb(f())};export const onBeforeUnmount=f=>globalThis.__parcelSmoke.unmount.push(f)`)
const prefs=url('export const getMotionIntensity=()=>"full";export const onMotionIntensityChange=()=>()=>{}')
let script=compileScript(descriptor,{id:'parcel-runtime'}).content
script=script.replaceAll("from 'vue'",'from '+JSON.stringify(runtime))
script=script.replaceAll("from '../parcel-flow'",'from '+JSON.stringify(url(compile(readFileSync(new URL('../src/parcel-flow.ts',import.meta.url),'utf8')))))
script=script.replaceAll("from '../effects/motion-prefs'",'from '+JSON.stringify(prefs))
const previousRaf=globalThis.requestAnimationFrame,previousCancel=globalThis.cancelAnimationFrame
let scheduled=0,cancelled=0
globalThis.requestAnimationFrame=()=>++scheduled
globalThis.cancelAnimationFrame=()=>cancelled++
try{
 const component=(await import(url(compile(script)))).default
 const props={events:[],paused:false}
 const state=component.setup(props,{expose(){}})
 assert.equal(state.parcels.value.length,0,'no fabricated parcels without events')
 assert.ok(state.launch({...event,origin:'live',stage:'collect'},false))
 for(let time=100;time<=1400;time+=50)state.tick(time)
 assert.equal(state.parcels.value[0].moving,false)
 assert.equal(state.feedback('collect').sequence,1,'arrival feedback binds real sequence')
 assert.equal(state.launch({...event,origin:'live',stage:'normalize',sequence:2},false),false,'next event waits for current arrival stroke')
 state.parcels.value[0].settledFor=500;state.motion.value='low'
 assert.ok(Math.abs(state.stroke('collect')-.45)<1e-9,'low intensity scales mechanical travel')
 state.motion.value='full'
 const frozen={x:state.parcels.value[0].x,elapsed:state.parcels.value[0].settledFor,belt:state.beltTime.value,stroke:state.stroke('collect')}
 props.paused=true;state.tick(1450);state.tick(1500)
 assert.deepEqual({x:state.parcels.value[0].x,elapsed:state.parcels.value[0].settledFor,belt:state.beltTime.value,stroke:state.stroke('collect')},frozen,'pause freezes mechanics and belt at current frame')
 props.paused=false
 state.selected.value=state.parcels.value[0].key
 const beforeSchedule=scheduled;state.tick(1550)
 assert.ok(scheduled>beforeSchedule,'selected parcel still completes its arrival mechanism')
 state.selected.value=null
 state.parcels.value=[]
 state.launch({...event,stage:'collect'},true)
 for(let time=1600;time<=3000;time+=50)state.tick(time)
 assert.equal(state.feedback('collect'),undefined,'historical replay never activates live machinery')
 state.parcels.value=[];state.motion.value='off'
 state.launch({...event,origin:'live',stage:'quality',status:'rejected',sequence:2},false)
 state.tick(3050)
 assert.equal(state.parcels.value[0].stage,'review')
 assert.equal(state.parcels.value[0].moving,false,'motion off places parcel directly at real destination')
 assert.equal(state.stroke('review'),0,'motion off does not run mechanism')
 for(const hook of hooks.unmount)hook()
 assert.ok(cancelled>0,'unmount releases RAF')
}finally{globalThis.requestAnimationFrame=previousRaf;globalThis.cancelAnimationFrame=previousCancel;delete globalThis.__parcelSmoke}
console.log('Parcel flow: routes, easing, single-stroke machinery, real-sequence arrival, replay isolation, pause freeze, motion off and teardown passed')
