import config from '../aleph.config.json' with {type:'json'};
import {requireResourceIdentity,requireZoneMembership,sendResourceError} from '../src/resource-access.mjs';
import {formatResourceId} from '../src/resource-id.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
function parse(body){
  let value=body;
  if(typeof value==='string'){
    try{value=JSON.parse(value)}catch{return null}
  }
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||typeof value.title!=='string'||!value.title.trim()||value.title.trim().length>200
      ||typeof value.body!=='string'||!value.body.trim()||value.body.length>20000)return null;
  return {title:value.title.trim(),body:value.body};
}
const publish=note=>({
  id:note.id,resourceType:'memo',resourceId:formatResourceId('memo',note.id),
  title:note.title,body:note.content,zoneId:note.zone_id
});

export default async function handler(req,res){
  if(!['GET','POST'].includes(req.method)){
    res.setHeader('Allow','GET, POST');
    return sendResourceError(res,405,'METHOD_NOT_ALLOWED');
  }
  const auth=await requireResourceIdentity(req,res,config);
  if(!auth)return;
  const {supabase:db,identity}=auth;

  try{
    if(req.method==='GET'){
      const zoneId=typeof req.query?.zoneId==='string'?req.query.zoneId:'personal';
      const access=await requireZoneMembership(db,identity.userId,zoneId,{
        roles:['student','instructor']
      });
      if(!access)return sendResourceError(res,403,'ZONE_ACCESS_DENIED');

      const {data,error}=await db.from('learning_notes')
        .select('id,title,content,zone_id,owner_id')
        .eq('owner_id',identity.userId).eq('zone_id',zoneId)
        .order('created_at',{ascending:false});
      if(error||!Array.isArray(data))return sendResourceError(res,502,'NOTES_UNAVAILABLE');

      // Apply the owner + zone scope again to the returned rows, not just the query.
      const owned=data.filter(note=>note.owner_id===identity.userId
        &&note.zone_id===zoneId);
      return res.status(200).json(owned.map(publish));
    }

    const body=req.body&&typeof req.body==='object'&&!Array.isArray(req.body)?req.body:null;
    const note=parse(body);
    if(!note)return sendResourceError(res,400,'INVALID_NOTE');
    const zoneId=body.zoneId===undefined?'personal':body.zoneId;
    const access=await requireZoneMembership(db,identity.userId,zoneId,{
      roles:['student','instructor']
    });
    if(!access)return sendResourceError(res,403,'ZONE_ACCESS_DENIED');
    if(body.id!==undefined&&(typeof body.id!=='string'||!UUID.test(body.id))){
      return sendResourceError(res,400,'INVALID_ID');
    }

    const {data,error}=await db.from('learning_notes').insert({
      ...(body.id?{id:body.id}:{}),
      owner_id:identity.userId,zone_id:zoneId,title:note.title,content:note.body
    }).select('id,owner_id,zone_id').single();
    if(error?.code==='23505')return sendResourceError(res,409,'TITLE_ALREADY_EXISTS');
    if(error||!data?.id)return sendResourceError(res,502,'NOTES_UNAVAILABLE');
    if(data.owner_id!==identity.userId||data.zone_id!==zoneId){
      return sendResourceError(res,502,'NOTES_UNAVAILABLE');
    }
    return res.status(201).json({
      id:data.id,resourceType:'memo',resourceId:formatResourceId('memo',data.id)
    });
  }catch{
    return sendResourceError(res,502,'NOTES_UNAVAILABLE');
  }
}
