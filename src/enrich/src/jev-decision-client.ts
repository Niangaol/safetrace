/**
 * Shared local Open-Jev typed-choice client.
 *
 * Generic over the candidate set: the caller declares the choice criteria, the client
 * validates that the service answered exactly that set with normalized probabilities.
 * No generated JSON, no model-as-fact promotion, loopback-only, provenance-pinnable.
 */
export const DEFAULT_QUESTION_ID="relevance";
export interface JevChoiceAnswer {
  question_id:string;
  /** The candidate the service selected; must be one of the declared criteria keys. */
  choice:string;
  /** Full normalized probability table over the declared candidate set. */
  probabilities:Record<string,number>;
  confidence:number;
}

function criteriaKeys(payload:{state:unknown;questions:Record<string,unknown>}):{questionId:string;keys:string[]} {
  const ids=Object.keys(payload.questions??{});
  if(ids.length!==1)throw new Error("Open-Jev request must carry exactly one question");
  const questionId=ids[0]!;
  if(!/^[A-Za-z0-9_-]{1,64}$/.test(questionId))throw new Error("Open-Jev question id must be 1-64 chars of [A-Za-z0-9_-]");
  const definition=(payload.questions as Record<string,unknown>)[questionId];
  if(!definition||typeof definition!=="object")throw new Error("Open-Jev question definition must be an object");
  const record=definition as Record<string,unknown>;
  if(record.type!=="choice")throw new Error("Open-Jev shared client only supports choice questions");
  const criteria=record.criteria;
  if(!criteria||typeof criteria!=="object"||Array.isArray(criteria))throw new Error("Open-Jev choice requires a criteria object");
  const keys=Object.keys(criteria as Record<string,unknown>);
  if(keys.length<2||keys.length>255)throw new Error("Open-Jev choice requires 2-255 candidates");
  if(new Set(keys).size!==keys.length||keys.some(k=>!/^[A-Za-z0-9_.:-]{1,64}$/.test(k)))throw new Error("Open-Jev candidate keys must be unique and 1-64 chars of [A-Za-z0-9_.:-]");
  return {questionId,keys};
}

/** Response validation: structure, declared candidate set, ranges, normalization, argmax. */
export function parseJevChoiceAnswer(body:unknown,expected:{questionId:string;keys:string[]}):JevChoiceAnswer {
  const answers=(body as {answers?:unknown}|null)?.answers;
  const answer=(answers as Record<string,unknown>|undefined)?.[expected.questionId];
  if(!answer||typeof answer!=="object")throw new Error("Open-Jev response missing answers."+expected.questionId);
  const typed=answer as Record<string,unknown>;
  if(typed.type!=="choice")throw new Error("Open-Jev response is not a choice answer");
  const probabilities=typed.probabilities;
  if(!probabilities||typeof probabilities!=="object"||Array.isArray(probabilities))throw new Error("Open-Jev probabilities missing or malformed");
  const map=probabilities as Record<string,unknown>;
  if(Object.keys(map).length!==expected.keys.length||!expected.keys.every(k=>Object.hasOwn(map,k)))throw new Error("Open-Jev candidate keys do not match the declared candidate set");
  const table:Record<string,number>={};
  for(const key of expected.keys){
    const value=map[key];
    if(typeof value!=="number"||!Number.isFinite(value)||value<0||value>1)throw new Error("Open-Jev probability for "+key+" is not finite in [0,1]");
    table[key]=value;
  }
  const total=Object.values(table).reduce((sum,p)=>sum+p,0);
  if(!Number.isFinite(total)||Math.abs(total-1)>1e-6)throw new Error("Open-Jev probabilities do not sum to one; refusing unnormalized scores");
  const choice=String(typed.choice);
  if(!expected.keys.includes(choice))throw new Error("Open-Jev choice is outside the declared candidate set");
  if(table[choice]!==Math.max(...Object.values(table)))throw new Error("Open-Jev choice contradicts its probabilities");
  if(typeof typed.confidence!=="number"||!Number.isFinite(typed.confidence)||typed.confidence<0||typed.confidence>1)throw new Error("Open-Jev confidence is not finite in [0,1]");
  return {question_id:expected.questionId,choice,probabilities:table,confidence:typed.confidence};
}

export interface JevProvenance {model:string;checkpoint_sha256:string;base_revision:string;code_commit:string;model_revision?:string;device?:string}
export interface JevDecisionOptions {baseUrl?:string;modelId:string;timeoutMs?:number;fetchImpl?:typeof fetch;expectedProvenance?:JevProvenance}
export async function requestJevChoice(payload:{state:unknown;questions:Record<string,unknown>},options:JevDecisionOptions){
  const expected=criteriaKeys(payload);
  const base=(process.env.JEV_BASE_URL?.trim()||options.baseUrl||"http://127.0.0.1:8791").replace(/\/+$/,"");
  const endpoint=new URL(base);
  if(endpoint.protocol!=="http:"||!["127.0.0.1","localhost","[::1]"].includes(endpoint.hostname)||endpoint.username||endpoint.password||endpoint.search||endpoint.hash||endpoint.pathname!=="/")throw new Error("Open-Jev endpoint must be a credential-free loopback HTTP origin");
  const timeout=options.timeoutMs??20000;
  if(!Number.isSafeInteger(timeout)||timeout<1)throw new Error("Open-Jev timeoutMs must be a positive integer");
  const encoded=JSON.stringify(payload);
  if(encoded.length>32000)throw new Error("Open-Jev input exceeds local decision budget");
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
  try{
    let body:{model?:string;metadata?:Record<string,unknown>};
    try{
      const response=await(options.fetchImpl??fetch)(base+"/v1/systemone",{method:"POST",headers:{"content-type":"application/json"},body:encoded,signal:controller.signal,redirect:"error"});
      if(!response.ok)throw new Error("Open-Jev service returned HTTP "+response.status);
      body=await response.json() as {model?:string;metadata?:Record<string,unknown>};
    }catch(error){
      if(error instanceof Error&&error.message.startsWith("Open-Jev service returned HTTP"))throw error;
      throw new Error("Open-Jev decision request failed: "+(error instanceof Error?error.message:String(error)));
    }
    const answer=parseJevChoiceAnswer(body,expected),expectedProv=options.expectedProvenance;
    if(expectedProv){
      if(body.model!==expectedProv.model||body.metadata?.method!=="lora_decision_head")throw new Error("Open-Jev actual model/method mismatch");
      for(const key of ["checkpoint_sha256","base_revision","code_commit","model_revision","device"] as const)if(expectedProv[key]!==undefined&&body.metadata?.[key]!==expectedProv[key])throw new Error("Open-Jev provenance mismatch: "+key);
    }
    return {answer,model:body.model??options.modelId,metadata:body.metadata??{},provenance_verified:!!expectedProv};
  }finally{clearTimeout(timer);}
}