import { createHash, createHmac, randomInt } from "node:crypto";
export const json=(statusCode,body)=>({statusCode,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store, max-age=0","x-content-type-options":"nosniff","referrer-policy":"no-referrer"},body:JSON.stringify(body)});
export function parseBody(event){try{return JSON.parse(event.body||"{}");}catch{return null;}}
export function validEmail(email){return typeof email==="string"&&email.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);}
export function getIp(event){return event.headers?.["x-nf-client-connection-ip"]||event.headers?.["client-ip"]||"unknown";}
const hash=s=>createHash("sha256").update(s).digest("hex");
function redisConfig(){const url=process.env.UPSTASH_REDIS_REST_URL,token=process.env.UPSTASH_REDIS_REST_TOKEN;if(!url||!token)throw new Error("Server storage is not configured. Contact the site administrator.");return {url,token};}
async function redis(command){const {url,token}=redisConfig();const r=await fetch(url,{method:"POST",headers:{authorization:`Bearer ${token}`,"content-type":"application/json"},body:JSON.stringify(command)});if(!r.ok)throw new Error("Secure storage is temporarily unavailable. Try again later.");const d=await r.json();if(d.error)throw new Error("Secure storage request failed.");return d.result;}
export async function validateTurnstile(token,ip){
 const secret=process.env.TURNSTILE_SECRET_KEY;const allowed=(process.env.ALLOWED_HOSTNAMES||"").split(",").map(x=>x.trim().toLowerCase()).filter(Boolean);
 if(!secret||!allowed.length||typeof token!=="string"||token.length>2048)return false;
 const form=new URLSearchParams({secret,response:token});if(ip!=="unknown")form.set("remoteip",ip);
 const response=await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:form});
 if(!response.ok)return false;const result=await response.json();return result.success===true&&allowed.includes(String(result.hostname||"").toLowerCase());
}
export async function rateLimit({email,ip,action}){
 const e=hash(email.toLowerCase()),i=hash(ip),now=new Date(),day=now.toISOString().slice(0,10),month=now.toISOString().slice(0,7);
 const dailyCap=Math.max(1,Number.parseInt(process.env.MFA_DAILY_EMAIL_LIMIT||"100",10)||100),monthlyCap=Math.max(1,Number.parseInt(process.env.MFA_MONTHLY_EMAIL_LIMIT||"3000",10)||3000);
 const rules=action==="start"?[
  {key:`sentinel:email:start:address:${e}`,limit:3,ttl:600},{key:`sentinel:email:start:ip:${i}`,limit:10,ttl:600},
  {key:`sentinel:email:start:address-day:${e}`,limit:8,ttl:86400},{key:`sentinel:email:start:global-day:${day}`,limit:dailyCap,ttl:86400},{key:`sentinel:email:start:global-month:${month}`,limit:monthlyCap,ttl:2678400}
 ]:[{key:`sentinel:email:check:address:${e}`,limit:8,ttl:600},{key:`sentinel:email:check:ip:${i}`,limit:30,ttl:600}];
 const lua="local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]); end; if n>tonumber(ARGV[2]) then return 0 else return 1 end";
 for(const r of rules){const result=await redis(["EVAL",lua,"1",r.key,String(r.ttl),String(r.limit)]);if(Number(result)!==1)return false;}return true;
}
export async function sendCode(email){
 const apiKey=process.env.RESEND_API_KEY,from=process.env.EMAIL_FROM;if(!apiKey||!from)throw new Error("Email sending is not configured. Contact the site administrator.");
 const secret=process.env.OTP_HMAC_SECRET;if(!secret||secret.length<32)throw new Error("OTP security secret is not configured correctly.");
 const code=String(randomInt(0,1000000)).padStart(6,"0"),digest=createHmac("sha256",secret).update(`${email.toLowerCase()}:${code}`).digest("hex"),key=`sentinel:email:otp:${hash(email.toLowerCase())}`;
 await redis(["SET",key,digest,"EX",300]);
 await redis(["DEL",`sentinel:email:attempts:${hash(email.toLowerCase())}`]);
 const html=`<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#142033"><div style="background:#0b1728;padding:28px;border-radius:16px;color:#eef6ff"><p style="color:#59e2df;font-weight:bold;letter-spacing:3px">SENTINEL / MFA</p><h1 style="font-size:24px">Your verification code</h1><p style="color:#b8c9dd">Enter this one-time code to complete your sign-in demonstration.</p><div style="font-size:34px;letter-spacing:9px;font-weight:bold;background:#142b40;padding:18px;border-radius:12px;text-align:center;color:#59e2df">${code}</div><p style="color:#b8c9dd">This code expires in 5 minutes and can only be used once.</p><p style="font-size:12px;color:#8fa5bf">If you did not request this code, you can ignore this email.</p></div></div>`;
 try{const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{authorization:`Bearer ${apiKey}`,"content-type":"application/json"},body:JSON.stringify({from,to:[email],subject:"Your Sentinel MFA verification code",html,text:`Your Sentinel MFA verification code is ${code}. It expires in 5 minutes and can only be used once.`})});const data=await r.json();if(!r.ok)throw new Error("The email provider could not send the message. Check sender-domain verification and account settings.");return data;}
 catch(e){await redis(["DEL",key]);throw e;}
}
export async function verifyCode(email,code){
 const secret=process.env.OTP_HMAC_SECRET;if(!secret||secret.length<32)throw new Error("OTP security secret is not configured correctly.");
 const key=`sentinel:email:otp:${hash(email.toLowerCase())}`,attemptKey=`sentinel:email:attempts:${hash(email.toLowerCase())}`;
 const expected=createHmac("sha256",secret).update(`${email.toLowerCase()}:${code}`).digest("hex");
 const lua="local stored=redis.call('GET',KEYS[1]); if not stored then return -1 end; if stored==ARGV[1] then redis.call('DEL',KEYS[1]); redis.call('DEL',KEYS[2]); return 1 end; local n=redis.call('INCR',KEYS[2]); if n==1 then redis.call('EXPIRE',KEYS[2],300); end; if n>=5 then redis.call('DEL',KEYS[1]); return -2 end; return 0";
 const result=Number(await redis(["EVAL",lua,"2",key,attemptKey,expected]));return result;
}
