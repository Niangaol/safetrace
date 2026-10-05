import {randomBytes,createCipheriv,createDecipheriv} from "node:crypto";
import {mkdirSync,readFileSync,writeFileSync,renameSync,existsSync} from "node:fs";
import {join} from "node:path";
export type RuntimeMode="template"|"cloud"|"local";
export interface LocalDraft {connection:"managed"|"existing";base_url:string;model_id:string;selected_file_id:string|null;context_size:number;gpu_layers:number}
export interface CloudDraft {base_url:string;model_id:string;key_cipher:string|null}
export interface AppliedSettings {mode:RuntimeMode;revision:number;cloud:CloudDraft;local:LocalDraft;cloud_consent:boolean}
interface StoredSettings {version:1;revision:number;draft:{cloud:CloudDraft;local:LocalDraft};active:AppliedSettings}
export class SettingsError extends Error {constructor(public status:number,message:string){super(message);}}
export function cloudBase(value:unknown):string {
 if(value==="")return "";if(typeof value!=="string"||value.length>2048||/[\r\n\s]/.test(value))throw new SettingsError(400,"云端地址格式不合法");
 let u:URL;try{u=new URL(value);}catch{throw new SettingsError(400,"云端地址必须是 HTTPS URL");}
 if(u.protocol!=="https:"||u.username||u.password||u.search||u.hash||u.port&&u.port!=="443"||/[%]|(?:^|[/])[.]{1,2}(?:[/]|$)/.test(u.pathname))throw new SettingsError(400,"云端仅支持无凭据、无查询的 HTTPS 公网 API");
 if(u.hostname==="localhost"||u.hostname.endsWith(".localhost")||u.hostname.endsWith(".local")||u.hostname.endsWith(".internal")||/^[0-9.]+$|[:]/.test(u.hostname))throw new SettingsError(400,"云端地址不能指向本机、内网或 IP");return u.href.replace(/[/]+$/,"");
}
export function localBase(value:unknown):string {
 if(typeof value!=="string"||value.length>300)throw new SettingsError(400,"本地地址不合法");let u:URL;try{u=new URL(value);}catch{throw new SettingsError(400,"本地地址不合法");}
 if(!["http:","https:"].includes(u.protocol)||!["127.0.0.1","[::1]"].includes(u.hostname)||u.username||u.password||u.search||u.hash||/[%;]/.test(u.pathname))throw new SettingsError(400,"本地端点必须使用字面量 loopback");
 const port=Number(u.port||(u.protocol==="https:"?443:80));if([6333,8000,19387,5173].includes(port))throw new SettingsError(400,"该端口不是允许的本地模型端点");return u.href.replace(/[/]+$/,"");
}
function model(v:unknown):string {if(v==="")return "";if(typeof v!=="string"||(v.length>512||v.trim().length===0||/[\x00-\x1f\x7f]/.test(v)))throw new SettingsError(400,"模型 ID 不合法");return v;}
function local(v:unknown):LocalDraft {const x=v as LocalDraft;if(!x||!["managed","existing"].includes(x.connection)||!Number.isSafeInteger(x.context_size)||x.context_size<512||x.context_size>16384||!Number.isSafeInteger(x.gpu_layers)||x.gpu_layers<0||x.gpu_layers>99||x.selected_file_id!==null&&(typeof x.selected_file_id!=="string"||! /^[A-Za-z0-9_-]{1,128}$/.test(x.selected_file_id)))throw new SettingsError(400,"本地模型参数不合法");return {connection:x.connection,base_url:x.connection==="managed"?"http://127.0.0.1:8090/v1":localBase(x.base_url),model_id:x.connection==="managed"?"safetrace-local-chat":model(x.model_id),selected_file_id:x.selected_file_id,context_size:x.context_size,gpu_layers:x.gpu_layers};}
function defaults():StoredSettings {const c:CloudDraft={base_url:"",model_id:"",key_cipher:null},l:LocalDraft={connection:"existing",base_url:"http://127.0.0.1:8080/v1",model_id:"",selected_file_id:null,context_size:2048,gpu_layers:0};return {version:1,revision:0,draft:{cloud:c,local:l},active:{mode:"template",revision:0,cloud:c,local:l,cloud_consent:false}};}
/** Private encrypted storage; it is not a vault against somebody who controls the same OS account. */
export class RuntimeSettingsStore {
 private state:StoredSettings;private key:Buffer|undefined;
 constructor(private directory:string){this.state=defaults();const file=join(directory,"models.json");if(existsSync(file)){let s:StoredSettings;try{s=JSON.parse(readFileSync(file,"utf8"));}catch{throw new SettingsError(503,"本机模型设置无法读取");}if(s.version!==1||!Number.isSafeInteger(s.revision)||!s.draft||!s.active||!["template","cloud","local"].includes(s.active.mode))throw new SettingsError(503,"本机设置版本无效");this.state=s;}}
 private master(){if(this.key)return this.key;mkdirSync(this.directory,{recursive:true,mode:0o700});const p=join(this.directory,"master.key");if(existsSync(p)){this.key=readFileSync(p);if(this.key.length!==32)throw new SettingsError(503,"本机密钥存储无效");}else{this.key=randomBytes(32);writeFileSync(p,this.key,{flag:"wx",mode:0o600});}return this.key;}
 private encrypt(value:string){const iv=randomBytes(12),c=createCipheriv("aes-256-gcm",this.master(),iv);const bytes=Buffer.concat([c.update(value,"utf8"),c.final()]);return Buffer.concat([iv,c.getAuthTag(),bytes]).toString("base64");}
 private decrypt(value:string|null){if(!value)return "";try{const b=Buffer.from(value,"base64"),c=createDecipheriv("aes-256-gcm",this.master(),b.subarray(0,12));c.setAuthTag(b.subarray(12,28));return Buffer.concat([c.update(b.subarray(28)),c.final()]).toString("utf8");}catch{throw new SettingsError(503,"本机凭据不可用");}}
 private persist(s:StoredSettings){mkdirSync(this.directory,{recursive:true,mode:0o700});const p=join(this.directory,"models.json"),temp=join(this.directory,"models-"+randomBytes(6).toString("hex")+".tmp");writeFileSync(temp,JSON.stringify(s,null,2),{flag:"wx",mode:0o600});renameSync(temp,p);this.state=s;}
 private revision(value:unknown){if(value!==this.state.revision)throw new SettingsError(409,"设置已变化，请刷新后重试");}
 view(){const s=this.state;return {revision:s.revision,active_mode:s.active.mode,active_revision:s.active.revision,active_model_id:s.active.mode==="cloud"?s.active.cloud.model_id:s.active.mode==="local"?s.active.local.model_id:null,cloud:{base_url:s.draft.cloud.base_url,model_id:s.draft.cloud.model_id,key_configured:!!s.draft.cloud.key_cipher},local:structuredClone(s.draft.local)};}
 save(body:unknown){const v=body as {expected_revision?:unknown;cloud?:{base_url?:unknown;model_id?:unknown;api_key?:unknown;clear_api_key?:unknown};local?:unknown};this.revision(v?.expected_revision);if(!v.cloud||!v.local)throw new SettingsError(400,"配置不完整");const base=cloudBase(v.cloud.base_url),id=model(v.cloud.model_id),l=local(v.local);
  if(v.cloud.api_key!==undefined&&(typeof v.cloud.api_key!=="string"||v.cloud.api_key.length>4096||/[\r\n]/.test(v.cloud.api_key)))throw new SettingsError(400,"API Key 格式不合法");if(v.cloud.clear_api_key!==undefined&&typeof v.cloud.clear_api_key!=="boolean")throw new SettingsError(400,"清除密钥选项无效");if(v.cloud.clear_api_key&&v.cloud.api_key)throw new SettingsError(400,"不能同时清除和设置密钥");
  let cipher=base===this.state.draft.cloud.base_url?this.state.draft.cloud.key_cipher:null;if(v.cloud.api_key)cipher=this.encrypt(v.cloud.api_key);if(v.cloud.clear_api_key)cipher=null;
  const next:StoredSettings={...this.state,revision:this.state.revision+1,draft:{cloud:{base_url:base,model_id:id,key_cipher:cipher},local:l}};
  if(v.cloud.clear_api_key)next.active={...next.active,mode:next.active.mode==="cloud"?"template":next.active.mode,cloud:{...next.active.cloud,key_cipher:null},cloud_consent:false};this.persist(next);return this.view();
 }
 apply(expected:unknown,mode:unknown,confirm:unknown){this.revision(expected);if(!["template","cloud","local"].includes(String(mode)))throw new SettingsError(400,"模型模式不合法");if(mode==="cloud"&&(!this.state.draft.cloud.base_url||!this.state.draft.cloud.model_id||!this.state.draft.cloud.key_cipher||confirm!==true))throw new SettingsError(400,"启用云端需完整配置、密钥和明确计费确认");if(mode==="local"&&!this.state.draft.local.model_id)throw new SettingsError(400,"本地模型 ID 未配置");const s:StoredSettings={...this.state,revision:this.state.revision+1,active:{mode:mode as RuntimeMode,revision:this.state.revision+1,cloud:structuredClone(this.state.draft.cloud),local:structuredClone(this.state.draft.local),cloud_consent:mode==="cloud"}};this.persist(s);return this.view();}
 credentials(target:"cloud"|"local",active=false){const s=active?this.state.active:this.state.draft;return target==="cloud"?{base_url:s.cloud.base_url,model_id:s.cloud.model_id,api_key:this.decrypt(s.cloud.key_cipher)}:{base_url:s.local.base_url,model_id:s.local.model_id,api_key:""};}
 snapshotCredentials(snapshot:AppliedSettings,target:"cloud"|"local"){return target==="cloud"?{base_url:snapshot.cloud.base_url,model_id:snapshot.cloud.model_id,api_key:this.decrypt(snapshot.cloud.key_cipher)}:{base_url:snapshot.local.base_url,model_id:snapshot.local.model_id,api_key:""};}
 active(){return structuredClone(this.state.active);}
}
