/** Model-assisted review is not an independent factual-accuracy guarantee. */
export interface FinalReview {status:"accepted"|"rejected"|"failed"|"skipped";reason:string}
export interface ReviewEvidence {chunk_id:string;quote:string}
export function validateReviewedSummary(raw:unknown,evidence:ReviewEvidence[]):string|null {
 if(!raw||typeof raw!=="object")return null;
 const value=raw as {supported?:unknown;issues?:unknown;claims?:unknown};
 if(value.supported!==true||!Array.isArray(value.issues)||value.issues.length!==0||!Array.isArray(value.claims)||value.claims.length<1||value.claims.length>6)return null;
 const sentences:string[]=[];
 for(const item of value.claims){
  if(!item||typeof item!=="object")return null;
  const claim=item as {text?:unknown;chunk_id?:unknown;quote?:unknown};
  if(typeof claim.text!=="string"||typeof claim.quote!=="string")return null;
  const proof=evidence.find(row=>row.chunk_id===claim.chunk_id);
  const text=claim.text.trim();
  if(!proof||claim.quote.length<10||!proof.quote.includes(claim.quote)||!text||text.length>320)return null;
  if(/[<>\x00-\x1f\x7f]|https?:\/\/|\[[^\]]*\]\(/i.test(text))return null;
  const allowedTokens=new Set((claim.quote.match(/CVE-\d{4}-\d{4,}|\d+(?:\.\d+)?/gi)??[]).map(token=>token.toUpperCase()));
  for(const token of text.match(/CVE-\d{4}-\d{4,}|\d+(?:\.\d+)?/gi)??[])if(!allowedTokens.has(token.toUpperCase()))return null;
  sentences.push(text);
 }
 const summary=sentences.join("\n\n");
 return summary.length>=80&&summary.length<=400?summary:null;
}
