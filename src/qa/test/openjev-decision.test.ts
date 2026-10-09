import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, SqliteEventStore } from "@safetrace/shared";
import type { DecisionRequest } from "@safetrace/shared";
import { createOpenJevDecisionResolver, chainLlmResolvers, buildOpenJevDecisionPayload } from "../src/ladder/openjev-decision.js";
import { createStepPlanDecisionHandler } from "../src/ladder/stepfun-decision.js";

const PROV={model:"Qwen/Qwen3.5-2B",checkpoint_sha256:"c".repeat(64),base_revision:"15852e8c16360a2fea060d615a32b45270f8a8fc",code_commit:"80ca8e81d08992cb2a4cbb6a0caa1355ad3e5aee",device:"cuda:0"};
const OPTIONS=["impact_high","impact_medium","impact_low"];
function request():DecisionRequest {
  return {decision_id:"dec_1",kind:"y5_triage",trace_id:"tr_oj",schema_version:"1.1",
    state:{data_domain:"public",stepfun_opt_in:true,injection_screened:true,calibration_source:"rule",
      public_facts:{cve_ids:["CVE-2021-44228"],product:"log4j",severity:"critical",cvss_v3_base:10,epss_score:0.97,kev_flag:true},
      calibrated_option_probabilities:{impact_high:0.82,impact_medium:0.12,impact_low:0.06}},
    questions:[{q_id:"impact",type:"choice",options:OPTIONS}]};
}
const answer=(choice:string)=>{const base:Record<string,number>={impact_high:0.04,impact_medium:0.03,impact_low:0.02,uncertain:0.01};for(const k of Object.keys(base))base[k]=0.01;base[choice]=0.97;return {model:PROV.model,metadata:{method:"lora_decision_head",checkpoint_sha256:PROV.checkpoint_sha256,base_revision:PROV.base_revision,code_commit:PROV.code_commit,device:PROV.device},answers:{route:{type:"choice",choice,probabilities:base,confidence:0.9}}};};
/** choice 越界但概率表仍合法：用于验证“选项必须逐字等于 typed option”的分支。 */
const answerWithForeignChoice=()=>({model:PROV.model,metadata:{method:"lora_decision_head",checkpoint_sha256:PROV.checkpoint_sha256,base_revision:PROV.base_revision,code_commit:PROV.code_commit,device:PROV.device},answers:{route:{type:"choice",choice:"not_an_option",probabilities:{impact_high:0.97,impact_medium:0.01,impact_low:0.01,uncertain:0.01},confidence:0.9}}});
async function fixture(){const root=await mkdtemp(join(tmpdir(),"openjev-decision-")),path=join(root,"db.sqlite");const store=new SqliteEventStore(path);const bus=new EventBus({store});return {root,path,bus,close:async()=>{store.close();await rm(root,{recursive:true,force:true});}};}

test("本地通道选中合法选项：calibrated_prob 来自上游而非模型自评",async()=>{
  const f=await fixture();
  try{
    const resolver=createOpenJevDecisionResolver({modelId:"Open-Jev-2B@0c7aa49",expectedProvenance:PROV,bus:f.bus,fetchImpl:(async()=>Response.json(answer("impact_high"))) as typeof fetch});
    const ctx={decision_id:"dec_1",kind:"y5_triage" as const,state:request().state,questions:request().questions,trace_id:"tr_oj"};
    const resolved=await resolver!(ctx);
    assert.ok(resolved && "decision" in resolved);assert.deepEqual(resolved!.decision,{choice:"impact_high"});
    assert.equal(resolved && "calibrated_prob" in resolved ? resolved.calibrated_prob : undefined,0.82,"概率必须来自上游校准表，不是模型 0.9 自评");
    const lineage=await f.bus.readLineage("tr_oj");
    assert.ok(lineage.some(r=>r.stage==="decide.model"&&r.status==="success"&&/not model self-rating/.test(r.decision?.reason??"")));
  }finally{await f.close();}
});

test("模型弃权/越界选项/上游概率不足都返回 null（显式下坠，不伪造决策）",async()=>{
  for(const [name,choice,calibrated] of [["abstain","uncertain",0.82],["low-upstream","impact_high",0.4]] as const){
    const f=await fixture();
    try{
      const req=request();
      if(calibrated!==0.82)(req.state as any).calibrated_option_probabilities={...((req.state as any).calibrated_option_probabilities),impact_high:calibrated};
      const resolver=createOpenJevDecisionResolver({modelId:"Open-Jev-2B@0c7aa49",bus:f.bus,fetchImpl:(async()=>Response.json(answer(choice))) as typeof fetch});
      const ctx={decision_id:"dec_1",kind:"y5_triage" as const,state:req.state,questions:req.questions,trace_id:"tr_oj"};
      assert.equal(await resolver!(ctx),null,name);
    }finally{await f.close();}
  }
});

test("模型返回 typed 选项之外的 choice：客户端即拒（fail-closed），ladder 记 degraded 后下坠",async()=>{
  const f=await fixture();
  try{
    const resolver=createOpenJevDecisionResolver({modelId:"Open-Jev-2B@0c7aa49",bus:f.bus,fetchImpl:(async()=>Response.json(answerWithForeignChoice())) as typeof fetch});
    const ctx={decision_id:"dec_1",kind:"y5_triage" as const,state:request().state,questions:request().questions,trace_id:"tr_oj"};
    await assert.rejects(resolver!(ctx),/outside the declared candidate set/);
    const lineage=await f.bus.readLineage("tr_oj");
    assert.ok(lineage.some(r=>r.stage==="decide.model"&&r.status==="failed"));
  }finally{await f.close();}
});

test("服务不可达/provenance 不符：抛错或拒决，由 ladder 记 degraded 后继续下坠",async()=>{
  const f=await fixture();
  try{
    const ctx={decision_id:"dec_1",kind:"y5_triage" as const,state:request().state,questions:request().questions,trace_id:"tr_oj"};
    await assert.rejects(createOpenJevDecisionResolver({modelId:"pinned",bus:f.bus,fetchImpl:(async()=>{throw new Error("ECONNREFUSED");}) as typeof fetch})!(ctx),/Open-Jev/);
    const mismatch=createOpenJevDecisionResolver({modelId:"pinned",expectedProvenance:{...PROV,checkpoint_sha256:"d".repeat(64)},bus:f.bus,fetchImpl:(async()=>Response.json(answer("impact_high"))) as typeof fetch});
    await assert.rejects(mismatch!(ctx),/provenance/);
  }finally{await f.close();}
});

test("兜底链：云通道弃权后本地接棒；全弃权下坠人工且 decided_by=human",async()=>{
  const f=await fixture();
  try{
    const local=createOpenJevDecisionResolver({modelId:"Open-Jev-2B@0c7aa49",expectedProvenance:PROV,bus:f.bus,fetchImpl:(async()=>Response.json(answer("impact_high"))) as typeof fetch});
    const cloudAbstain=async()=>null;
    const chained=chainLlmResolvers(cloudAbstain,local)!;
    const ctx={decision_id:"dec_1",kind:"y5_triage" as const,state:request().state,questions:request().questions,trace_id:"tr_chain"};
    const chainedResolved=await chained(ctx);assert.ok(chainedResolved && "decision" in chainedResolved);assert.deepEqual(chainedResolved!.decision,{choice:"impact_high"});

    // handler 级：本地也弃权 → 人工层，decided_by=human（不冒充 rule_fallback）
    const handler=createStepPlanDecisionHandler({provider:"stepplan",modelId:"step-3.7-flash",apiKeyConfigured:false,bus:f.bus,
      openjev:{modelId:"Open-Jev-2B@0c7aa49",bus:f.bus,fetchImpl:(async()=>Response.json(answer("uncertain"))) as typeof fetch}});
    const reply=await handler(request());
    assert.equal(reply.decided_by,"human");
    assert.equal(reply.decision.abstain,true);
    assert.match(reply.fallback_reason??"",/阶梯未决|llm/,"全弃权时如实记录挂起原因");
    const lineage=await f.bus.readLineage("tr_oj");
    assert.ok(lineage.some(r=>r.stage==="decide.ladder"&&r.status==="review"));
  }finally{await f.close();}
});

test("投影闸门复用：非 public / 未筛查 / 无上游校准表都不进模型",async()=>{
  const f=await fixture();
  try{
    let calls=0;
    const resolver=createOpenJevDecisionResolver({modelId:"pinned",bus:f.bus,fetchImpl:(async()=>{calls++;return Response.json(answer("impact_high"));}) as typeof fetch});
    const base=request();
    for(const patch of [{data_domain:"private"},{stepfun_opt_in:false},{injection_screened:false},{calibrated_option_probabilities:undefined}] as const){
      const req={...base,state:{...base.state,...patch}};
      const ctx={decision_id:"dec_1",kind:"y5_triage" as const,state:req.state,questions:req.questions,trace_id:"tr_gate"};
      assert.equal(await resolver!(ctx),null);
    }
    assert.equal(calls,0,"闸门不过不得触达模型服务");
  }finally{await f.close();}
});

test("请求体只含公开事实与 typed 选项，并带 uncertain 出口",()=>{
  const payload=buildOpenJevDecisionPayload({kind:"y5_triage",facts:{cve_ids:["CVE-2021-44228"],product:"log4j"},question:{q_id:"impact",options:OPTIONS}});
  assert.match(payload.state,/CVE-2021-44228/);
  assert.equal(payload.questions.route.type,"choice");
  assert.deepEqual(Object.keys(payload.questions.route.criteria),[...OPTIONS,"uncertain"]);
});