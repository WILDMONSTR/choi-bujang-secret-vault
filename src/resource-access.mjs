import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from './verify-login.mjs';
import {isTrustedBrowserOrigin,readSessionCookies} from './session-cookies.mjs';

let cached;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function sendResourceError(res,status,error){
  return res.status(status).json({error});
}

function validUrl(value){
  try{
    const url=new URL(value);
    return url.protocol==='https:'&&url.pathname==='/'&&!url.search&&!url.hash
      &&!url.username&&!url.password?url.origin:null;
  }catch{return null}
}

function context(config,url,key){
  if(cached?.url===url&&cached?.key===key)return cached;
  const supabase=createClient(url,key,{auth:{
    persistSession:false,autoRefreshToken:false,detectSessionInUrl:false
  }});
  return cached={url,key,supabase,verifyLogin:createLoginVerifier({
    config,supabaseSecretKey:key,supabaseClient:supabase
  })};
}

export async function requireResourceIdentity(req,res,config){
  res.setHeader('Cache-Control','no-store, max-age=0');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');

  let authorization=req.headers?.authorization;
  let cookie=false;
  if(typeof authorization!=='string'||!authorization){
    const session=readSessionCookies(req);
    if(session.accessToken){
      authorization='Bearer '+session.accessToken;
      cookie=true;
    }
  }
  if(typeof authorization!=='string'||!authorization.startsWith('Bearer ')){
    sendResourceError(res,401,'UNAUTHORIZED');
    return null;
  }
  if(cookie&&req.method!=='GET'&&!isTrustedBrowserOrigin(req,config)){
    sendResourceError(res,403,'ORIGIN_NOT_ALLOWED');
    return null;
  }

  const url=validUrl(process.env.SUPABASE_URL);
  const key=process.env.SUPABASE_SECRET_KEY;
  let issuer;
  try{issuer=new URL(config.identityProvider.issuer).origin}
  catch{
    sendResourceError(res,503,'AUTH_NOT_CONFIGURED');
    return null;
  }
  if(!url||url!==issuer||typeof key!=='string'||!key.trim()||key!==key.trim()){
    sendResourceError(res,503,'NOT_CONFIGURED');
    return null;
  }

  let ctx,id;
  try{
    ctx=context(config,url,key);
    id=await ctx.verifyLogin(authorization);
  }catch{
    sendResourceError(res,401,'UNAUTHORIZED');
    return null;
  }
  if(!id||id.kind!=='student'||!UUID.test(id.userId??'')){
    sendResourceError(res,401,'UNAUTHORIZED');
    return null;
  }

  // Confirm that this verified subject is still a real Supabase Auth user.
  // Never accept a user ID or role supplied by the request body.
  try{
    const {data,error}=await ctx.supabase.auth.getUser(authorization.slice(7));
    if(error||data?.user?.id!==id.userId){
      sendResourceError(res,401,'UNAUTHORIZED');
      return null;
    }
  }catch{
    sendResourceError(res,401,'UNAUTHORIZED');
    return null;
  }

  return {supabase:ctx.supabase,identity:id};
}

export async function requireZoneMembership(db,userId,zoneId,options={}){
  if(!UUID.test(userId??'')||typeof zoneId!=='string'
      ||!/^[a-z0-9][a-z0-9_-]{0,63}$/u.test(zoneId))return null;

  const {data:zone,error:zoneError}=await db.from('resource_zones')
    .select('zone_id,zone_type,is_active')
    .eq('zone_id',zoneId).maybeSingle();
  if(zoneError||!zone||zone.zone_id!==zoneId||!zone.is_active
      ||(options.zoneType&&zone.zone_type!==options.zoneType))return null;

  const {data:membership,error:membershipError}=await db.from('resource_zone_memberships')
    .select('user_id,zone_id,role,is_active')
    .eq('user_id',userId).eq('zone_id',zoneId).maybeSingle();
  if(membershipError||!membership||membership.user_id!==userId
      ||membership.zone_id!==zoneId||!membership.is_active
      ||(options.roles&&!options.roles.includes(membership.role)))return null;

  return {zone,membership};
}
