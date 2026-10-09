/**
 * 决策阶梯 LLM 层的本地通道：Open-Jev（GPU 本地推理）。
 *
 * 定位：兜底链的一部分——云 StepFun 不可用（未配置 key / 网络失败 / provider 不匹配）时，
 * 由本机 Open-Jev 继续做「选项选择」，仍不信模型自评概率；服务不可用或低置信度则显式下坠人工层。
 *
 * 纪律（与 StepFun 云通道完全一致，禁砍）：
 *   - 复用同一投影闸门 buildProjection：只有公开结构化事实 + 可信上游校准概率能进模型；
 *   - calibrated_prob 永远来自上游 calibrated_option_probabilities，绝不采用模型自评；
 *   - choice 必须逐字等于给定 option；不确定/低于阈值 → 返回 null 显式下坠，不伪造决策；
 *   - 模型标识必须钉版本；服务端 provenance（checkpoint/base/code/device）不符即拒；
 *   - 只走 loopback HTTP，禁重定向；推理失败抛错由 ladder 转 degraded 后继续下坠。
 */
import type { DecisionReply, EventBus } from "@safetrace/shared";
import { requestJevChoice } from "../../../enrich/src/jev-decision-client.js";
import { buildProjection, writeDecisionLineage } from "./stepfun-decision.js";
import type { DecisionResolution, LadderContext, LlmResolver } from "./decision-ladder.js";

export interface OpenJevDecisionOptions {
  /** 钉死的模型标识（落 lineage）。必填，禁会漂移的别名。 */
  modelId:string;
  /** Open-Jev 服务基地址；缺省读 env JEV_BASE_URL，再缺省 http://127.0.0.1:8791。 */
  baseUrl?:string;
  /** 采纳门槛：上游校准概率 >= 该值才返回决策；默认 0.65（与云通道一致）。 */
  minCalibratedProb?:number;
  /** 期望的服务端 provenance；缺省不核对（不推荐）。 */
  expectedProvenance?:{model:string;checkpoint_sha256:string;base_revision:string;code_commit:string;model_revision?:string;device?:string};
  bus?:EventBus;
  timeoutMs?:number;
  fetchImpl?:typeof fetch;
}

const OPTION_INDEX = /^[1-9][0-9]?$/;

/** 生成本地决策用的 Choice 问题：选项即 typed options，模型只能选其一。 */
export function buildOpenJevDecisionPayload(projection:{kind:string;facts:Record<string,unknown>;question:{q_id:string;options:string[]}}) {
  const state=[
    "Decision kind: "+projection.kind,
    "",
    "Public structured facts (authoritative; do not invent missing values):",
    JSON.stringify(projection.facts,null,1),
  ].join("\n");
  const criteria:Record<string,string>={};
  for(const option of projection.question.options)criteria[option]="Select this option only when the public facts above clearly support it.";
  return {state,questions:{route:{type:"choice",instructions:"Pick the single option best supported by the public facts. If the facts do not clearly support exactly one option, choose uncertain.",criteria:{...criteria,uncertain:"The public facts do not clearly support any single option; abstain rather than guess."}}}};
}

export function createOpenJevDecisionResolver(options:OpenJevDecisionOptions):LlmResolver|undefined {
  if(!options.modelId||options.modelId.trim()==="")throw new Error("Open-Jev decision requires a pinned modelId");
  const minProb=options.minCalibratedProb??0.65;
  if(!Number.isFinite(minProb)||minProb<0||minProb>1)throw new Error("minCalibratedProb must be within 0..1");
  return async (ctx:LadderContext):Promise<DecisionResolution|null> => {
    const projection=buildProjection(ctx);
    if(!projection)return null;
    const payload=buildOpenJevDecisionPayload(projection);
    let answer:{choice:string;probabilities:Record<string,number>};
    try{
      const decision=await requestJevChoice(payload,{baseUrl:options.baseUrl,modelId:options.modelId,timeoutMs:options.timeoutMs,fetchImpl:options.fetchImpl,...(options.expectedProvenance?{expectedProvenance:options.expectedProvenance}:{})});
      answer={choice:decision.answer.choice,probabilities:decision.answer.probabilities};
    }catch(error){
      const message=error instanceof Error?error.message:String(error);
      // 传输类错误统一措辞；校验/provenance 类错误原样透出，保证运维能看到真实原因。
      const wrapped=/^Open-Jev (decision request failed|service returned HTTP|endpoint|input exceeds|timeoutMs)/.test(message)?new Error("Open-Jev decision request failed: "+message):error;
      await writeDecisionLineage(options.bus,ctx,"failed",payload,{failed:true},"openjev",options.modelId,"Local Open-Jev decision failed: "+message,[],"openjev.decision.v1");
      throw wrapped;
    }
    const chosen=answer.choice;
    const modelInput={kind:projection.kind,public_facts:projection.facts,question:{type:"choice" as const,options:projection.question.options}};
    if(chosen==="uncertain"||!projection.question.options.includes(chosen)){
      await writeDecisionLineage(options.bus,ctx,"review",modelInput,{abstained:true,choice:chosen},"openjev",options.modelId,chosen==="uncertain"?"Local Open-Jev abstained; option list unchanged":"Local Open-Jev returned an option outside the typed set",[],"openjev.decision.v1");
      return null;
    }
    const calibrated=projection.calibrated[chosen];
    if(calibrated===undefined||calibrated<minProb){
      await writeDecisionLineage(options.bus,ctx,"review",modelInput,{rejected:true,choice:chosen},"openjev",options.modelId,"Trusted upstream calibrated probability is below the decision threshold",[],"openjev.decision.v1");
      return null;
    }
    const decision:DecisionReply["decision"]={choice:chosen};
    await writeDecisionLineage(options.bus,ctx,"success",modelInput,{decision,calibrated_prob:calibrated},"openjev",options.modelId,"Local Open-Jev selected an allowed option; calibrated_prob came from trusted upstream option probabilities, not model self-rating",[],"openjev.decision.v1");
    return {decision,calibrated_prob:calibrated};
  };
}

/** 多级 LLM 通道按序竞争：前一级返回 null（弃权/未接入）才试下一级；全弃权返回 undefined。 */
export function chainLlmResolvers(...resolvers:(LlmResolver|undefined)[]):LlmResolver|undefined {
  const active=resolvers.filter((r):r is LlmResolver=>typeof r==="function");
  if(active.length===0)return undefined;
  if(active.length===1)return active[0];
  return async (ctx)=>{
    for(const resolver of active){
      const resolved=await resolver(ctx);
      if(resolved)return resolved;
    }
    return null;
  };
}