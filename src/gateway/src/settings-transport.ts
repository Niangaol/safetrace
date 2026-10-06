import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { SettingsError } from "./runtime-settings-store.js";
export function publicAddress(address:string):boolean {
 if(address.includes(":")){const a=address.toLowerCase();return /^[23][0-9a-f]{3}:/.test(a)&&!a.startsWith("2001:db8:")&&!a.startsWith("2001:0:");}
 const octets=address.split(".").map(Number);if(octets.length!==4||octets.some(n=>!Number.isInteger(n)||n<0||n>255))return false;
 const [a,b]=octets as [number,number,number,number];return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&[0,168].includes(b)||a===100&&b>=64&&b<=127||a===198&&[18,19,51].includes(b)||a===203&&b===0);
}
/** Public DNS is validated and pinned into TLS lookup, so a second DNS lookup cannot rebind the key to a private host. */
export async function pinnedCloudRequest(url:URL,init:RequestInit&{timeoutMs?:number}={}):Promise<Response>{
 const timeout=Math.min(Math.max(Number(init.timeoutMs??30000)||30000,1000),120000);
 const addresses=await lookup(url.hostname,{all:true,verbatim:true});if(!addresses.length||addresses.some(row=>!publicAddress(row.address)))throw new SettingsError(400,"云端域名解析到了不允许的网络地址");const target=addresses[0]!;
 return new Promise<Response>((resolve,reject)=>{
  const req=httpsRequest({protocol:"https:",hostname:url.hostname,port:443,path:url.pathname,method:init.method??"GET",servername:url.hostname,rejectUnauthorized:true,
    lookup:((_host:unknown,_options:unknown,cb:any)=>{if(_options&&typeof _options==="object"&&(_options as {all?:boolean}).all)cb(null,[target]);else cb(null,target.address,target.family);}) as any,
    headers:Object.fromEntries(new Headers(init.headers).entries())},res=>{
    const chunks:Buffer[]=[];let size=0;res.on("data",chunk=>{size+=chunk.length;if(size>1024*1024){req.destroy();reject(new SettingsError(502,"模型响应超过大小限制"));return;}chunks.push(Buffer.from(chunk));});
    res.on("end",()=>{const code=res.statusCode??502;if(code>=300&&code<400){reject(new SettingsError(502,"模型接口不允许重定向"));return;}resolve(new Response(Buffer.concat(chunks),{status:code,headers:{"content-type":String(res.headers["content-type"]??"application/json")}}));});res.on("error",()=>reject(new SettingsError(502,"模型响应传输失败")));
  });
  req.setTimeout(timeout,()=>{req.destroy();reject(new SettingsError(504,"模型连接超时（上限 "+Math.round(timeout/1000)+" 秒）"));});req.on("error",()=>reject(new SettingsError(502,"模型连接失败")));
  const abort=()=>{req.destroy();reject(new SettingsError(499,"模型请求已取消"));};if(init.signal?.aborted){abort();return;}init.signal?.addEventListener("abort",abort,{once:true});req.on("close",()=>init.signal?.removeEventListener("abort",abort));
  if(init.body!==undefined&&init.body!==null){if(typeof init.body!=="string"||Buffer.byteLength(init.body)>65536){req.destroy();reject(new SettingsError(400,"模型请求体无效或过大"));return;}req.write(init.body);}req.end();
 });
}
export interface SettingsFetchOptions { base_url: string; api_key: string; cloud: boolean; testFetch?: typeof fetch; timeoutMs?: number }
function boundedTimeout(value: number | undefined, fallback: number): number { if (value === undefined) return fallback; if (!Number.isFinite(value)) throw new SettingsError(400,"模型请求超时配置无效"); return Math.min(Math.max(Math.round(value), 1000), 120000); }
export function settingsFetch(options:SettingsFetchOptions):typeof fetch {
 const timeout = boundedTimeout(options.timeoutMs, 30000);
 const base=new URL(options.base_url),prefix=base.pathname.replace(/[/]+$/,"");
 return async(input,init={})=>{
  const url=new URL(input instanceof Request?input.url:String(input));if(url.origin!==base.origin||url.search||url.hash||url.username||url.password||![prefix+"/models",prefix+"/chat/completions"].includes(url.pathname))throw new SettingsError(400,"模型请求超出已保存接口范围");
  const headers=new Headers(init.headers);if(options.api_key)headers.set("authorization","Bearer "+options.api_key);else headers.delete("authorization");
  if(options.testFetch)return options.testFetch(url,{...init,headers,redirect:"error"});
  if(options.cloud)return pinnedCloudRequest(url,{...init,headers,timeoutMs:timeout});
  return fetch(url,{...init,headers,redirect:"error",signal:init.signal??AbortSignal.timeout(timeout)});
 };
}
