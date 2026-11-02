import {execFile} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
const script=fileURLToPath(new URL('./windows-observation.ps1',import.meta.url));
export const sections=['network','firewall','system','application'];
const reasons={UNSUPPORTED_PLATFORM:'Windows에서만 조회할 수 있습니다.',ACCESS_DENIED:'일반 사용자 권한으로 읽을 수 없습니다. 관리자 권한을 요청하지 않습니다.',COMMAND_UNAVAILABLE:'필요한 Windows 조회 명령을 사용할 수 없습니다.',QUERY_FAILED:'Windows 조회에 실패했습니다.',TIMEOUT:'조회 제한 시간(6초)을 초과했습니다.',INVALID_RESPONSE:'조회 결과 형식을 확인할 수 없습니다.',POWERSHELL_UNAVAILABLE:'Windows PowerShell을 실행할 수 없습니다. 실행 정책이나 권한을 변경하지 않습니다.'};
const time=x=>typeof x==='string'&&Number.isFinite(Date.parse(x));
export function unavailable(code,observedAt){return {status:'unavailable',observedAt,reason:code,message:reasons[code]??reasons.QUERY_FAILED};}
export function normalizeObservation(section,raw,observedAt){
 if(!raw||!time(raw.observedAt))return unavailable('INVALID_RESPONSE',observedAt);
 if(raw.status==='unavailable')return unavailable(Object.hasOwn(reasons,raw.reason)?raw.reason:'QUERY_FAILED',raw.observedAt);
 const d=raw.data, strings=x=>Array.isArray(x)&&x.every(v=>typeof v==='string'&&v.length<=300);
 let valid=raw.status==='ok';
 if(section==='network')valid&&=Array.isArray(d)&&d.every(x=>x&&typeof x.name==='string'&&typeof x.status==='string'&&strings(x.addresses)&&strings(x.gateways)&&strings(x.dns));
 else if(section==='firewall')valid&&=Array.isArray(d)&&d.every(x=>x&&['name','enabled','inbound','outbound'].every(k=>typeof x[k]==='string'));
 else valid&&=d&&d.log===(section==='system'?'System':'Application')&&[d.warning,d.error].every(x=>Number.isSafeInteger(x)&&x>=0)&&d.warning+d.error<=5000&&d.unit==='건'&&typeof d.partial==='boolean'&&d.limit===5000&&time(d.startUtc)&&time(d.endUtc)&&Date.parse(d.endUtc)>Date.parse(d.startUtc);
 return valid?{status:'ok',observedAt:raw.observedAt,data:d}:unavailable('INVALID_RESPONSE',observedAt);
}
function runPowerShell(section,start,end){
 // Absolute Windows executable, fixed script/arguments, no shell or elevation. No policy override.
 const executable=join(process.env.SystemRoot??'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe');
 return new Promise((resolve,reject)=>execFile(executable,['-NoLogo','-NoProfile','-NonInteractive','-File',script,'-Section',section,'-StartUtc',start,'-EndUtc',end],{timeout:6000,maxBuffer:1024*1024,windowsHide:true,encoding:'utf8'},(error,stdout)=>error?reject(error):resolve(JSON.parse(stdout.replace(/^\uFEFF/,'')))));
}
export async function collectWindowsObservation({platform=process.platform,now=()=>new Date(),run=runPowerShell}={}){
 const end=now().toISOString(),start=new Date(Date.parse(end)-86400000).toISOString();
 const pairs=await Promise.all(sections.map(async section=>{
  if(platform!=='win32')return [section,unavailable('UNSUPPORTED_PLATFORM',end)];
  try{return [section,normalizeObservation(section,await run(section,start,end),now().toISOString())];}
  catch(e){return [section,unavailable(e.killed||e.code==='ETIMEDOUT'?'TIMEOUT':e.code==='ENOENT'||e.code==='EACCES'||typeof e.code==='number'?'POWERSHELL_UNAVAILABLE':'QUERY_FAILED',now().toISOString())];}
 }));
 return {source:'local-os',platform,checkedAt:now().toISOString(),window:{startUtc:start,endUtc:end},...Object.fromEntries(pairs)};
}
