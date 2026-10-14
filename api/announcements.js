import config from '../aleph.config.json' with {type:'json'};
import {requireResourceIdentity,requireZoneMembership,sendResourceError} from '../src/resource-access.mjs';
import {formatResourceId} from '../src/resource-id.mjs';
import {requireApprovedDevice} from '../src/require-approved-device.mjs';

function parse(body){
  let value=body;
  if(typeof value==='string'){
    try{value=JSON.parse(value)}catch{return null}
  }
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||typeof value.zoneId!=='string'||!/^[a-z0-9][a-z0-9_-]{0,63}$/u.test(value.zoneId)
      ||typeof value.title!=='string'||!value.title.trim()||value.title.trim().length>200
      ||typeof value.content!=='string'||!value.content.trim()||value.content.length>20000)return null;
  return {zoneId:value.zoneId,title:value.title.trim(),content:value.content};
}
const publish=announcement=>({
  id:announcement.id,resourceType:'instructor-announcement',
  resourceId:formatResourceId('instructor-announcement',announcement.id),
  zoneId:announcement.zone_id,title:announcement.title,content:announcement.content,
  createdAt:announcement.created_at,updatedAt:announcement.updated_at
});

export default async function handler(req,res){
  if(!['GET','POST'].includes(req.method)){
    res.setHeader('Allow','GET, POST');
    return sendResourceError(res,405,'METHOD_NOT_ALLOWED');
  }
  const auth=await requireResourceIdentity(req,res,config);
  if(!auth)return;
  if(!await requireApprovedDevice(req,res,auth))return;
  const {supabase:db,identity}=auth;

  try{
    if(req.method==='GET'){
      const zoneId=req.query?.zoneId;
      if(typeof zoneId!=='string')return sendResourceError(res,400,'INVALID_ZONE');
      const access=await requireZoneMembership(db,identity.userId,zoneId,{
        zoneType:'section',roles:['student','instructor']
      });
      if(!access)return sendResourceError(res,403,'ZONE_ACCESS_DENIED');

      const {data,error}=await db.from('instructor_announcements')
        .select('id,zone_id,title,content,created_by,created_at,updated_at')
        .eq('zone_id',zoneId).order('created_at',{ascending:false});
      if(error||!Array.isArray(data))return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
      // Do not serialize a row if its stored zone no longer matches the requested section.
      return res.status(200).json(data.filter(item=>item.zone_id===zoneId).map(publish));
    }

    const announcement=parse(req.body);
    if(!announcement)return sendResourceError(res,400,'INVALID_ANNOUNCEMENT');
    const access=await requireZoneMembership(db,identity.userId,announcement.zoneId,{
      zoneType:'section',roles:['instructor']
    });
    if(!access||access.membership.role!=='instructor'){
      return sendResourceError(res,403,'INSTRUCTOR_REQUIRED');
    }

    // Author and role come from the verified token and database membership only.
    const {data,error}=await db.from('instructor_announcements').insert({
      zone_id:announcement.zoneId,created_by:identity.userId,
      title:announcement.title,content:announcement.content
    }).select('id,zone_id,title,content,created_by,created_at,updated_at').single();
    if(error||!data)return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
    if(data.zone_id!==announcement.zoneId||data.created_by!==identity.userId){
      return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
    }
    return res.status(201).json(publish(data));
  }catch{
    return sendResourceError(res,502,'ANNOUNCEMENTS_UNAVAILABLE');
  }
}
