import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {randomUUID,createHmac,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import https from 'node:https';
import {rootCertificates} from 'node:tls';

// Дополнительное доверие применяется только к API MAX, не ко всему серверу.
export function createMaxFetch(caPem=''){
  const agent=new https.Agent({ca:[...rootCertificates,...(caPem?[caPem]:[])]});
  return (url,options={})=>new Promise((resolve,reject)=>{
    const target=new URL(url);
    if(target.origin!=='https://platform-api2.max.ru')return reject(Error('Unexpected API host'));
    const request=https.request(target,{method:options.method||'GET',headers:options.headers,signal:options.signal,agent},response=>{
      const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('error',reject);
      response.on('end',()=>resolve({ok:response.statusCode>=200&&response.statusCode<300,status:response.statusCode,json:async()=>JSON.parse(Buffer.concat(chunks).toString('utf8'))}));
    });
    request.on('error',reject);if(options.body)request.write(options.body);request.end();
  });
}

export function validateBrief(data){
  if(!data || typeof data!=='object' || Array.isArray(data)) throw Error('Некорректный бриф');
  const limits={name:120,contact:200,service:120,task:2500,due:30,budget:120};
  const result={};
  for(const [key,max] of Object.entries(limits)){
    if(data[key]!==undefined && typeof data[key]!=='string')throw Error('Проверьте поля брифа');
    result[key]=(data[key]||'').trim();
    if(result[key].length>max)throw Error('Слишком длинное поле: '+key);
  }
  if(!result.name||!result.contact||!result.task)throw Error('Заполните имя, контакт и задачу');
  return result;
}
export function formatBrief(b,id){return ['Новый бриф ОКО · '+id,'Имя: '+b.name,'Контакт: '+b.contact,'Услуга: '+b.service,'','Задача:',b.task,'','Срок: '+(b.due||'уточнить'),'Бюджет: '+(b.budget||'уточнить')].join('\n');}

export function webhookSecret(token){return createHmac('sha256',token).update('oko-max-webhook-v1').digest('hex');}
export function createApp({token='',chatId='',origin='',pairCode='',onBind=id=>console.log('OKO_CHAT_BOUND '+id),fetchImpl=fetch,indexUrl=new URL('./index.html',import.meta.url)}={}){
  const rates=new Map();let sending=false;let lastSent=0;
  let bound=false;
  const json=(res,status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data));};
  return async(req,res)=>{
    try{
      const path=new URL(req.url,'http://localhost').pathname;
      if(req.method==='POST'&&path==='/max/webhook'){
        if(!token)return json(res,503,{error:'Unavailable'});
        const received=Buffer.from(req.headers['x-max-bot-api-secret']||''),expected=Buffer.from(webhookSecret(token));
        if(received.length!==expected.length||!timingSafeEqual(received,expected))return json(res,403,{error:'Forbidden'});
        let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>100000)return json(res,413,{error:'Too large'});}
        let event;try{event=JSON.parse(raw);}catch{return json(res,400,{error:'Invalid JSON'});}
        const message=event.message,recipient=message?.recipient;
        const text=message?.body?.text?.trim()||'';
        const command=new RegExp('^/oko_bind(?:@se14988215_bot)?\\s+'+pairCode+'$');
        if(pairCode&&!chatId&&!bound&&event.update_type==='message_created'&&recipient?.chat_type==='chat'&&!message?.sender?.is_bot&&command.test(text)&&Number.isSafeInteger(recipient.chat_id)){
          bound=true;onBind(String(recipient.chat_id));
        }
        return json(res,200,{ok:true});
      }
      if(req.method==='GET'&&path==='/healthz')return json(res,200,{ok:true});
      if(req.method==='GET'&&path==='/api/status')return json(res,200,{ready:Boolean(token&&/^-?\d+$/.test(chatId))});
      if(req.method==='GET'&&(path==='/'||path==='/index.html')){
        res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"});
        return res.end(await readFile(indexUrl));
      }
      if(path!=='/api/brief'||req.method!=='POST')return json(res,404,{error:'Не найдено'});
      if(!origin||req.headers.origin!==origin)return json(res,403,{error:'Отправка доступна только с сайта ОКО'});
      if(!req.headers['content-type']?.startsWith('application/json'))return json(res,415,{error:'Некорректный формат'});
      if(!token||! /^-?\d+$/.test(chatId))return json(res,503,{error:'Приём заявок ещё не подключён. Сохраните бриф и свяжитесь с ОКО через MAX.'});
      const ip=req.socket.remoteAddress||'unknown',now=Date.now();
      for(const [key,value]of rates)if(now-value.start>600000)rates.delete(key);
      const rate=rates.get(ip)||{start:now,count:0};rate.count++;rates.set(ip,rate);
      if(rate.count>10)return json(res,429,{error:'Слишком много попыток. Попробуйте через 10 минут.'});
      let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>16000)return json(res,413,{error:'Бриф слишком большой'});}
      let b;try{b=validateBrief(JSON.parse(raw));}catch(e){return json(res,400,{error:e.message});}
      if(sending||now-lastSent<600)return json(res,429,{error:'Принимаем предыдущую заявку. Повторите через несколько секунд.'});
      const id=randomUUID().slice(0,8),text=formatBrief(b,id);
      if(text.length>4000)return json(res,400,{error:'Сократите описание задачи'});
      sending=true;lastSent=now;
      try{
        const response=await fetchImpl('https://platform-api2.max.ru/messages?chat_id='+encodeURIComponent(chatId),{method:'POST',headers:{Authorization:token,'Content-Type':'application/json'},body:JSON.stringify({text,notify:true}),signal:AbortSignal.timeout(12000)});
        const result=await response.json().catch(()=>null);
        if(!response.ok||!result?.message?.body?.mid)return json(res,502,{error:'MAX не подтвердил доставку. Сохраните бриф и свяжитесь с ОКО через MAX.'});
        return json(res,200,{ok:true,id});
      }catch{return json(res,502,{error:'Доставка не подтверждена. Бриф сохранён на экране; перед повтором уточните у ОКО, получена ли заявка.'});}
      finally{sending=false;}
    }catch{if(!res.headersSent)json(res,500,{error:'Не удалось обработать запрос'});else res.end();}
  };
}
if(typeof process!=='undefined'&&process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const token=process.env.MAX_BOT_TOKEN||'',origin=process.env.SITE_ORIGIN||'',pairCode=process.env.MAX_PAIR_CODE||'';
  const maxFetch=createMaxFetch(process.env.MAX_CA_PEM||'');
  const app=createApp({token,chatId:process.env.MAX_CHAT_ID,origin,pairCode,fetchImpl:maxFetch});
  http.createServer(app).listen(Number(process.env.PORT)||3000,'0.0.0.0',async()=>{
    console.log('ОКО: веб-сервер запущен');
    if(token&&origin&&pairCode&&!process.env.MAX_CHAT_ID){
      try{
        const response=await maxFetch('https://platform-api2.max.ru/subscriptions',{method:'POST',headers:{Authorization:token,'Content-Type':'application/json'},body:JSON.stringify({url:origin+'/max/webhook',update_types:['message_created'],secret:webhookSecret(token)}),signal:AbortSignal.timeout(15000)});
        const result=await response.json().catch(()=>null);
        console.log(response.ok&&result?.success===true?'OKO_WEBHOOK_READY':'OKO_WEBHOOK_FAILED HTTP '+response.status);
      }catch(error){console.log('OKO_WEBHOOK_FAILED NETWORK '+String(error?.cause?.code||error?.code||error?.name||'UNKNOWN'));}
    }
  });
}
