import {randomUUID} from 'node:crypto';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';import {fixtureRequests} from './fixture-7.mjs';
const keys='decision,reasonCode,requestId,ruleIds,schema';function valid(i,o,ids){return o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===keys&&o.schema==='aleph.decision.v1'&&o.requestId===i.requestId&&['allow','deny','step_up'].includes(o.decision)&&typeof o.reasonCode==='string'&&Array.isArray(o.ruleIds)&&o.ruleIds.length>0&&o.ruleIds.every(x=>ids.includes(x))}
export async function checkDecider({decide,ruleIds}){for(const x of ['device_registered','signal_provenance','resource_scope','instructor_role_required'])if(!ruleIds.includes(x))throw Error('필수 규칙 누락: '+x);const {normal,suspicious}=fixtureRequests(),ann=randomUUID(),checks=[
{name:'등록 기기·허용 경로',r:normal,d:'allow',why:'approved'},
{name:'미등록 기기',r:{...normal,requestId:randomUUID(),deviceRegistered:false},d:'deny',why:'device_not_registered'},
{name:'다른 구역 경로 위조',r:{...normal,requestId:randomUUID(),path:'/api/admin/notes',route:'GET /api/notes'},d:'deny',rule:'resource_scope'},
{name:'동작·경로 불일치',r:{...normal,requestId:randomUUID(),method:'PUT',route:'GET /api/notes/:id'},d:'deny',rule:'resource_scope'},
{name:'주체 누락',r:{...normal,requestId:randomUUID(),subjectId:''},d:'deny',rule:'resource_scope'},
{name:'학생이 역할을 위조해 공지 수정',r:{...normal,requestId:randomUUID(),service:'announcements',method:'PUT',path:`/api/announcements/${ann}`,route:'PUT /api/announcements/:id',role:'instructor'},d:'deny',rule:'instructor_role_required'},
{name:'정상 사건',r:normal,d:'allow'},
{name:'복합 이상 사건',r:suspicious,d:'step_up',why:'step_up_required'},
{name:'클라이언트 헤더를 추가한 요청',r:{...normal,requestId:randomUUID(),headers:{'x-forwarded-for':'127.0.0.1'}},d:'step_up',why:'step_up_required'},
{name:'불명확한 신호 출처',r:{...normal,requestId:randomUUID(),signals:{...normal.signals,source:'x-forwarded-for'}},d:'step_up',why:'step_up_required'},
{name:'지역 정보 누락',r:{...normal,requestId:randomUUID(),signals:{source:'judge_fixture',network:'usual',hour:14}},d:'step_up',why:'step_up_required'},
{name:'시각 정보 누락',r:{...normal,requestId:randomUUID(),signals:{...normal.signals,hour:null}},d:'step_up',why:'step_up_required'},
{name:'행동 정보 누락',r:(()=>{const x={...normal,requestId:randomUUID()};delete x.recentEvents;return x})(),d:'step_up',why:'step_up_required'},
{name:'지역만 다른 정상 요청',r:{...normal,requestId:randomUUID(),signals:{...normal.signals,region:'foreign'}},d:'allow'},
{name:'대량 열람만 발생한 요청',r:{...normal,requestId:randomUUID(),recentEvents:[{kind:'bulk_read',ageSeconds:60,count:20}]},d:'allow'},
{name:'기존 위험 사건',r:{...normal,requestId:randomUUID(),recentEvents:[{kind:'risk_signal',ageSeconds:60,count:20}]},d:'step_up',why:'step_up_required'},
{name:'가상 추가 인증 뒤 복합 이상 재판정',r:{...suspicious,requestId:randomUUID(),stepUp:{verified:true,authAgeSeconds:60}},d:'allow'}];const result=[];for(const x of checks){const o=await decide(x.r);result.push({name:x.name,passed:valid(x.r,o,ruleIds)&&o.decision===x.d&&(!x.why||o.reasonCode===x.why)&&(!x.rule||o.ruleIds.includes(x.rule)),decision:o?.decision})}return result}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{const {decide,RULE_IDS}=await import('../src/decider.mjs'),r=await checkDecider({decide,ruleIds:RULE_IDS});for(const x of r)process.stdout.write(`${x.passed?'통과':'확인 필요'} · ${x.name} · ${x.decision}\n`);process.stdout.write('가상 테스트이며 실제 API 차단 증거는 아닙니다.\n');if(r.some(x=>!x.passed))process.exitCode=1}catch(e){process.stderr.write(e.message+'\n');process.exitCode=1}}