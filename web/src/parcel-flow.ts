import type { ActivityEvent, ActivityStage } from './activity-types'
export type Point = { x: number; y: number }
export const STOPS: Record<ActivityStage, Point> = {
 collect:{x:80,y:190},normalize:{x:220,y:190},dedupe:{x:360,y:190},quality:{x:500,y:190},
 paper:{x:660,y:120},score:{x:660,y:270},knowledge:{x:840,y:190},answer:{x:960,y:190},review:{x:500,y:435},fallback:{x:710,y:435},assets:{x:960,y:320},
}
export function parcelKey(event: ActivityEvent): string { return event.intel_id ? 'intel:'+event.intel_id : 'batch:'+event.trace_id }
export function destination(event: ActivityEvent): ActivityStage {
 if(event.status==='rejected'||event.status==='review')return 'review'
 if(event.status==='failed'||event.status==='degraded')return 'fallback'
 return event.stage
}
// 唯一的运输轨道；经过工位不意味着该工位有成功记录。
const vertices: Record<string,Point>={inlet:{x:18,y:190},...STOPS,split:{x:560,y:190},paperIn:{x:560,y:120},paperOut:{x:760,y:120},scoreIn:{x:560,y:270},scoreOut:{x:760,y:270},merge:{x:760,y:190},exception:{x:710,y:190}}
const edges=[['inlet','collect'],['collect','normalize'],['normalize','dedupe'],['dedupe','quality'],['quality','split'],['split','paperIn'],['paperIn','paper'],['paper','paperOut'],['paperOut','merge'],['split','scoreIn'],['scoreIn','score'],['score','scoreOut'],['scoreOut','merge'],['merge','knowledge'],['knowledge','answer'],['quality','review'],['merge','exception'],['exception','fallback'],['knowledge','assets']]
export function travelPath(from: ActivityStage | null,to: ActivityStage): Point[] {
 const start=from??'inlet', queue=[[start]], seen=new Set([start])
 while(queue.length){const path=queue.shift()!;const tail=path[path.length-1]!
  if(tail===to)return path.map(key=>vertices[key]!)
  for(const [a,b] of edges){const next=a===tail?b:b===tail?a:null;if(next&&!seen.has(next)){seen.add(next);queue.push([...path,next])}}
 }
 return [vertices[start]!,STOPS[to]]
}
export function pathLength(path: readonly Point[]):number {return path.slice(1).reduce((sum,p,i)=>sum+Math.hypot(p.x-path[i]!.x,p.y-path[i]!.y),0)}
export function pathPoint(path: readonly Point[],progress:number):Point {
 let distance=pathLength(path)*Math.max(0,Math.min(1,progress))
 for(let i=1;i<path.length;i++){const a=path[i-1]!,b=path[i]!,length=Math.hypot(b.x-a.x,b.y-a.y)
  if(distance<=length&&length>0)return{x:a.x+(b.x-a.x)*distance/length,y:a.y+(b.y-a.y)*distance/length};distance-=length
 }
 return path[path.length-1]??{x:18,y:190}
}
