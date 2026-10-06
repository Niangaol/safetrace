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
console.log('Parcel flow: identity, branches, orthogonal paths, interpolation, SFC, replay labels and teardown passed')
