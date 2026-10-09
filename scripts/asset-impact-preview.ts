import {readAssetImpactReceipt} from '../src/enrich/src/asset-extension.js';
import {defaultAssetsDbPath} from '../src/assets/src/config.js';
async function main(){
  const intelId=process.argv.find(a=>a.startsWith('--id='))?.slice('--id='.length);
  if(!intelId||!/^intel_[A-Za-z0-9_-]+$/.test(intelId))throw new Error('Provide --id=<current-intel-id>');
  const assetsPath=process.argv.find(a=>a.startsWith('--assets-db='))?.slice('--assets-db='.length)??defaultAssetsDbPath();
  const result=await readAssetImpactReceipt({sqlitePath:process.env.SQLITE_PATH??'./var/safetrace.sqlite',assetsPath,intelId});
  const counts:Record<string,number>={};for(const a of result.receipt?.artifacts??[])counts[a.status]=(counts[a.status]??0)+1;
  console.log(JSON.stringify({mode:'readonly-asset-impact',intel_id:intelId,status:result.status,receipt_id:result.receipt?.receipt_id??null,asset_scope:result.receipt?.asset_scope??null,by_assessment:counts,business_writes:0,network_calls:0,model_calls:0,validation:'rule-based potential impact; vendor unverified; unknown/absent is not safety'},null,2));
}
void main().catch(error=>{console.error(error);process.exitCode=1});
