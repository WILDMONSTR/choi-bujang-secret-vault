import config from '../../aleph.config.json' with {type:'json'};
import {requireResourceIdentity,requireZoneMembership,sendResourceError} from '../../src/resource-access.mjs';
import {formatResourceId,parseResourceId} from '../../src/resource-id.mjs';

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
  if(!['GET','PUT','DELETE'].includes(req.method)){
    res.setHeader('Allow','GET, PUT, DELETE');
    return sendResourceError(res,405,'METHOD_NOT_ALLOWED');
  }
  const auth=await requireResourceIdentity(req,res,config);
  if(!auth)return;
  const {supabase:db,identity}=auth;
  const id=parseResourceId(req.query?.id,'memo');
  if(!id)return sendResourceError(res,400,'INVALID_ID');

  try{
    const {data:note,error:lookupError}=await db.from('learning_notes')
      .select('id,title,content,zone_id,owner_id')
      .eq('id',id).eq('owner_id',identity.userId).maybeSingle();
    // Keep missing IDs and another user's IDs indistinguishable.
    if(lookupError)return sendResourceError(res,502,'NOTES_UNAVAILABLE');
    if(!note||note.owner_id!==identity.userId)return sendResourceError(res,404,'NOT_FOUND');

    const access=await requireZoneMembership(db,identity.userId,note.zone_id,{
      roles:['student','instructor']
    });
    if(!access||access.zone.zone_id!==note.zone_id)return sendResourceError(res,404,'NOT_FOUND');

    if(req.method==='GET')return res.status(200).json(publish(note));

    if(req.method==='PUT'){
      const value=parse(req.body);
      if(!value)return sendResourceError(res,400,'INVALID_NOTE');
      const {data,error}=await db.from('learning_notes')
        .update({title:value.title,content:value.body})
        .eq('id',id).eq('owner_id',identity.userId).eq('zone_id',note.zone_id)
        .select('id,title,content,zone_id,owner_id').maybeSingle();
      if(error?.code==='23505')return sendResourceError(res,409,'TITLE_ALREADY_EXISTS');
      if(error)return sendResourceError(res,502,'NOTES_UNAVAILABLE');
      if(!data||data.owner_id!==identity.userId||data.zone_id!==note.zone_id){
        return sendResourceError(res,404,'NOT_FOUND');
      }
      return res.status(200).json(publish(data));
    }

    const {data,error}=await db.from('learning_notes')
      .delete().eq('id',id).eq('owner_id',identity.userId).eq('zone_id',note.zone_id)
      .select('id,owner_id,zone_id').maybeSingle();
    if(error)return sendResourceError(res,502,'NOTES_UNAVAILABLE');
    if(!data||data.owner_id!==identity.userId||data.zone_id!==note.zone_id){
      return sendResourceError(res,404,'NOT_FOUND');
    }
    return res.status(204).end();
  }catch{
    return sendResourceError(res,502,'NOTES_UNAVAILABLE');
  }
}
