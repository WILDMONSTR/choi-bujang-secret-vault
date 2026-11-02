import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {collectWindowsObservation,normalizeObservation,sections} from './windows-observation.mjs';
import {createOnServer} from '../src/server.mjs';
const at='2026-11-02T00:00:00.000Z',now=()=>new Date(at);
const counts={log:'System',warning:3,error:2,unit:'건',partial:false,limit:5000,startUtc:'2026-11-01T00:00:00Z',endUtc:at};
test('non-Windows: reports unavailable, never runs PowerShell or invents zero counts',async()=>{
 let calls=0;const x=await collectWindowsObservation({platform:'linux',now,run:()=>calls++});
 assert.equal(calls,0);for(const k of sections){assert.equal(x[k].reason,'UNSUPPORTED_PLATFORM');assert.equal(x[k].data,undefined);}
});
test('normal permissions: sections independently succeed or fail with timestamps',async()=>{
 const x=await collectWindowsObservation({platform:'win32',now,run:async k=>k==='system'?{status:'ok',observedAt:at,data:counts}:k==='application'?{status:'unavailable',observedAt:at,reason:'ACCESS_DENIED'}:{status:'ok',observedAt:at,data:[]}});
 assert.equal(x.system.data.warning,3);assert.equal(x.application.reason,'ACCESS_DENIED');assert.equal(x.network.status,'ok');assert.equal(x.window.endUtc,at);assert.equal(Date.parse(x.window.endUtc)-Date.parse(x.window.startUtc),86400000);
});
test('timeout/missing executable: no elevation or fallback to simulated values',async()=>{
 for(const [error,reason] of [[{killed:true},'TIMEOUT'],[{code:'ENOENT'},'POWERSHELL_UNAVAILABLE'],[{code:1},'POWERSHELL_UNAVAILABLE']]){
  const x=await collectWindowsObservation({platform:'win32',now,run:async()=>{throw error;}});assert.equal(x.system.reason,reason);assert.equal(x.system.data,undefined);
 }
});
test('invalid counts/unit/window are rejected; partial is preserved',()=>{
 for(const patch of [{warning:-1},{error:5001},{unit:'%'},{endUtc:'invalid'},{log:'Security'}])assert.equal(normalizeObservation('system',{status:'ok',observedAt:at,data:{...counts,...patch}},at).status,'unavailable');
 assert.equal(normalizeObservation('system',{status:'ok',observedAt:at,data:{...counts,partial:true}},at).data.partial,true);
});
test('invalid network response is not shown as a successful empty configuration',()=>{
 assert.equal(normalizeObservation('network',{status:'ok',observedAt:at,data:[{name:'fake',status:'Up',addresses:'invalid'}]},at).status,'unavailable');
});
test('PowerShell only uses fixed read commands and does not change policy or elevate',async()=>{
 const ps=await readFile(new URL('./windows-observation.ps1',import.meta.url),'utf8');
 for(const command of ['Get-NetIPConfiguration','Get-NetFirewallProfile','Get-WinEvent'])assert.ok(ps.includes(command));
 assert.doesNotMatch(ps,/\b(?:Set-Net|New-Net|Remove-Net|Clear-EventLog|wevtutil|netsh|RunAs|Start-Process|Set-ExecutionPolicy)/i);
 assert.ok(ps.includes('NoMatchingEventsFound'));assert.ok(ps.includes('-MaxEvents 5001'));
});
test('local API: real runtime PC state and independent SDP disconnected; no-store',async()=>{
 const server=createOnServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const response=await fetch('http://127.0.0.1:'+server.address().port+'/api/local-observation');const x=await response.json();
  assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');assert.equal(x.data.source,'local-os');assert.equal(x.data.platform,process.platform);assert.equal(x.data.sdp.label,'SDP 미연결');
 }finally{await new Promise(r=>server.close(r));}
});
