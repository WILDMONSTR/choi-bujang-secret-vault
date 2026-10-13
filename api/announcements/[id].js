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
      ||typeof value.content!=='string'||!value.content.trim()||value.content.length>20000)return null;
  return {title:value.title.trim(),content:value.content};
}
const publish=announcement=>({
  id:announcement.id,resourceType:'instructor-announcement',
  resourceId:formatResourceId('instructor-announcement',announcement.id),
  zoneId:announcement.zone_id,title:announcement.title,content:announcement.content,
  createdAt:announcement.created_at,updatedAt:announcement.updated_at
});

export default async function handler(req,res){
  if(!['GET','PUT','DELETE'].includes(req.method)){
    res.setHeader('Allow','GET, PUT, DELETE');
    return sendResourceError(res,405,'METHOD_NOT_ALLOWED');
  }
  const auth=await requireResourceIdentity(req,res,config);
  if(!auth)return;
  const {supabase:db,identity}=auth;
  const id=parseResourceId(req.query?.id,'instructor-announcement');
  if(!id)return sendResourceError(res,400,'INVALID_ID');

  try{
    const {data:announcement,error:lookupError}=await db.from('instructor_announcements')
      .select('id,zone_id,title,content,created_by,created_at,updated_at')
      .eq('id',id).maybeSingle();
    if(lookupError)return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
    if(!announcement)return sendResourceError(res,404,'NOT_FOUND');

    // Section membership and role are loaded from the database; request fields are ignored.
    const access=await requireZoneMembership(db,identity.userId,announcement.zone_id,{
      zoneType:'section',roles:['student','instructor']
    });
    // Hide resource existence from anyone outside the section.
    if(!access||access.zone.zone_id!==announcement.zone_id){
      return sendResourceError(res,404,'NOT_FOUND');
    }
    if(req.method==='GET')return res.status(200).json(publish(announcement));

    if(access.membership.role!=='instructor'){
      return sendResourceError(res,403,'INSTRUCTOR_REQUIRED');
    }
    if(announcement.created_by!==identity.userId){
      return sendResourceError(res,403,'ANNOUNCEMENT_OWNER_REQUIRED');
    }

    if(req.method==='PUT'){
      const value=parse(req.body);
      if(!value)return sendResourceError(res,400,'INVALID_ANNOUNCEMENT');
      const {data,error}=await db.from('instructor_announcements')
        .update({title:value.title,content:value.content,updated_at:new Date().toISOString()})
        .eq('id',id).eq('zone_id',announcement.zone_id).eq('created_by',identity.userId)
        .select('id,zone_id,title,content,created_by,created_at,updated_at').maybeSingle();
      if(error)return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
      if(!data||data.zone_id!==announcement.zone_id||data.created_by!==identity.userId){
        return sendResourceError(res,404,'NOT_FOUND');
      }
      return res.status(200).json(publish(data));
    }

    const {data,error}=await db.from('instructor_announcements')
      .delete().eq('id',id).eq('zone_id',announcement.zone_id)
      .eq('created_by',identity.userId)
      .select('id,zone_id,created_by').maybeSingle();
    if(error)return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
    if(!data||data.zone_id!==announcement.zone_id||data.created_by!==identity.userId){
      return sendResourceError(res,404,'NOT_FOUND');
    }
    return res.status(204).end();
  }catch{
    return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
  }
}
