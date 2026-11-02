import http from 'node:http';
import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const random=()=>randomBytes(32).toString('base64url');
export const hash=s=>createHash('sha256').update(s).digest('base64url');
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status});};
const scopes=['career:read','career:write'];
const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function validRedirect(uri){try{const u=new URL(uri);return u.protocol==='https:'&&!u.username&&!u.password&&!u.hash&&(u.origin==='https://claude.ai'&&['/api/mcp/auth_callback','/api/organizations/mcp/auth_callback'].includes(u.pathname)||/^oauth-redirect(?:-sandbox|-test)?\.googleusercontent\.com$/.test(u.hostname)&&/^\/(r|a)\/[^/]+/.test(u.pathname));}catch{return false;}}
async function body(req){let s='';for await(const b of req){s+=b;if(Buffer.byteLength(s)>60000)fail('Request too large',413);}try{return (req.headers['content-type']||'').includes('application/json')?JSON.parse(s||'{}'):Object.fromEntries(new URLSearchParams(s));}catch{fail('Invalid request body');}}
export function createApplication({origin,siteOrigin,store,call,tools,careerId,now=Date.now}){
  if(!/^https:\/\//.test(origin)||!/^https:\/\//.test(siteOrigin))throw new Error('HTTPS origins required');
  origin=new URL(origin).origin;siteOrigin=new URL(siteOrigin).origin;
  const resource=origin+'/mcp',limits=new Map();
  const json=(res,status,data,headers={})=>{res.writeHead(status,{'content-type':'application/json','Cache-Control':'no-store',...headers});res.end(JSON.stringify(data));};
  const redirect=(res,url,headers={})=>{res.writeHead(303,{Location:url,'Cache-Control':'no-store','Referrer-Policy':'no-referrer',...headers});res.end();};
  const record=async key=>{const r=await store.get(key);return r&&r.data.expires>now()?r:null;};
  const create=async(key,data,ttl)=>store.put(key,{...data,expires:now()+ttl},0);
  const consume=async(key,r)=>store.delete(key,r.revision);
  const checkResource=b=>{if(b.resource!==undefined&&b.resource!==resource)fail('invalid_target');};
  const scopeFor=s=>{const a=(s||'career:read career:write').split(' ').filter(Boolean);if(!a.length||a.some(x=>!scopes.includes(x)))fail('invalid_scope');return [...new Set(a)].join(' ');};
  const rate=(req,kind,max)=>{const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0],key=kind+':'+ip,t=now();let a=limits.get(key);if(!a||t-a.at>3600000)a={at:t,n:0};if(++a.n>max)fail('Too many requests. Try later.',429);limits.set(key,a);if(limits.size>10000)for(const [k,v]of limits)if(t-v.at>3600000)limits.delete(k);};
  const authenticateClient=async(req,b)=>{
    let cid=b.client_id,secret=b.client_secret;
    if(req.headers.authorization?.startsWith('Basic ')){let decoded=Buffer.from(req.headers.authorization.slice(6),'base64').toString(),i=decoded.indexOf(':');cid=decodeURIComponent(decoded.slice(0,i));secret=decodeURIComponent(decoded.slice(i+1));}
    const r=await record('client:'+cid);if(!r)fail('invalid_client',401);
    if(r.data.token_endpoint_auth_method!=='none'&&!equal(hash(secret||''),r.data.secret_hash))fail('invalid_client',401);
    return {cid,client:r.data};
  };
  async function issue(cid,grant,scope){
    const access=random(),refresh=random();
    await create('access:'+hash(access),{client_id:cid,grant,scope,resource},3600000);
    await create('refresh:'+hash(refresh),{client_id:cid,grant,scope,resource},90*86400000);
    return {access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope};
  }
  async function authorized(req){
    const token=req.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1];
    const a=token&&await record('access:'+hash(token));
    if(!a||a.data.resource!==resource)fail('invalid_token',401);
    const grant=await record('grant:'+a.data.grant);if(!grant||grant.data.revoked)fail('invalid_token',401);
    return {...a.data,grant_record:grant};
  }
  return async(req,res)=>{try{
    const u=new URL(req.url,origin),p=u.pathname;
    res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
    if(req.headers.origin&&req.headers.origin!==origin&&!['https://claude.ai','https://gemini.google.com'].includes(req.headers.origin))fail('Origin not permitted',403);
    if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':req.headers.origin||origin,'Access-Control-Allow-Methods':'GET, POST, DELETE, OPTIONS','Access-Control-Allow-Headers':'Authorization, Content-Type, MCP-Protocol-Version','Access-Control-Expose-Headers':'WWW-Authenticate'});return res.end();}
    if(req.method==='GET'&&p==='/health')return json(res,200,{ok:true});
    if(req.method==='GET'&&['/.well-known/oauth-protected-resource','/.well-known/oauth-protected-resource/mcp'].includes(p))return json(res,200,{resource,authorization_servers:[origin],scopes_supported:scopes,bearer_methods_supported:['header']});
    if(req.method==='GET'&&['/.well-known/oauth-authorization-server','/.well-known/openid-configuration'].includes(p))return json(res,200,{issuer:origin,authorization_endpoint:origin+'/oauth/authorize',token_endpoint:origin+'/oauth/token',registration_endpoint:origin+'/oauth/register',revocation_endpoint:origin+'/oauth/revoke',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none','client_secret_post','client_secret_basic'],code_challenge_methods_supported:['S256'],scopes_supported:scopes});
    if(req.method==='POST'&&p==='/oauth/register'){
      rate(req,'register',60);const b=await body(req);
      if(!Array.isArray(b.redirect_uris)||!b.redirect_uris.length||b.redirect_uris.length>8||!b.redirect_uris.every(validRedirect))fail('invalid_redirect_uri');
      const method=b.token_endpoint_auth_method||'client_secret_basic';if(!['none','client_secret_post','client_secret_basic'].includes(method))fail('invalid_client_metadata');
      if(b.grant_types&&(!Array.isArray(b.grant_types)||b.grant_types.some(g=>!['authorization_code','refresh_token'].includes(g))))fail('unsupported_grant_type');
      if(b.response_types&&(!Array.isArray(b.response_types)||b.response_types.some(t=>t!=='code')))fail('unsupported_response_type');
      const cid=random(),secret=method==='none'?null:random();
      const name=b.redirect_uris.every(x=>new URL(x).hostname==='claude.ai')?'Claude':'Gemini';
      const client={client_id:cid,client_name:name,redirect_uris:b.redirect_uris,token_endpoint_auth_method:method,grant_types:['authorization_code','refresh_token'],response_types:['code']};
      await create('client:'+cid,{...client,secret_hash:secret?hash(secret):null},365*86400000);
      return json(res,201,{...client,client_id_issued_at:Math.floor(now()/1000),...(secret?{client_secret:secret,client_secret_expires_at:0}:{})});
    }
    if(req.method==='GET'&&p==='/oauth/authorize'){
      rate(req,'authorize',120);const b=Object.fromEntries(u.searchParams),cr=await record('client:'+b.client_id);
      if(!cr||!cr.data.redirect_uris.includes(b.redirect_uri))fail('Invalid client or redirect');
      if(b.response_type!=='code')fail('unsupported_response_type');
      if(b.code_challenge_method!=='S256'||!/^[A-Za-z0-9_-]{43}$/.test(b.code_challenge||''))fail('S256 PKCE required');
      checkResource(b);const scope=scopeFor(b.scope),id=random(),binding=random();
      await create('request:'+id,{...b,scope,origin,client_name:cr.data.client_name,status:'pending',binding_hash:hash(binding)},600000);
      return redirect(res,siteOrigin+'/external-connect?request='+id,{'Set-Cookie':`rl_${id}=${binding}; Path=/oauth/complete; Secure; HttpOnly; SameSite=Lax; Max-Age=600`});
    }
    if(req.method==='GET'&&p==='/oauth/complete'){
      const id=u.searchParams.get('request'),r=await record('request:'+id);if(!r)fail('Connection request expired');
      const cookie=(req.headers.cookie||'').split('; ').find(x=>x.startsWith('rl_'+id+'='))?.split('=')[1];
      if(!cookie||!equal(hash(cookie),r.data.binding_hash))fail('Connection browser changed; start again',403);
      if(!['approved','denied'].includes(r.data.status))fail('Owner approval required',403);
      await consume('request:'+id,r);const d=r.data,target=new URL(d.redirect_uri);
      if(d.state)target.searchParams.set('state',d.state);
      if(d.status==='denied')target.searchParams.set('error','access_denied');
      else{const code=random();await create('code:'+hash(code),{client_id:d.client_id,redirect_uri:d.redirect_uri,scope:d.scope,code_challenge:d.code_challenge,resource},120000);target.searchParams.set('code',code);}
      return redirect(res,target.toString(),{'Set-Cookie':`rl_${id}=; Path=/oauth/complete; Secure; HttpOnly; SameSite=Lax; Max-Age=0`});
    }
    if(req.method==='POST'&&p==='/oauth/token'){
      rate(req,'token',240);const b=await body(req),{cid}=await authenticateClient(req,b);checkResource(b);
      if(b.grant_type==='authorization_code'){
        const key='code:'+hash(b.code||''),r=await record(key);if(!r||r.data.client_id!==cid||r.data.redirect_uri!==b.redirect_uri||!/^[A-Za-z0-9._~-]{43,128}$/.test(b.code_verifier||'')||!equal(hash(b.code_verifier),r.data.code_challenge))fail('invalid_grant');
        await consume(key,r);const grant=random();await create('grant:'+grant,{client_id:cid,scope:r.data.scope,revoked:false},365*86400000);
        return json(res,200,await issue(cid,grant,r.data.scope));
      }
      if(b.grant_type==='refresh_token'){
        const key='refresh:'+hash(b.refresh_token||''),r=await record(key);if(!r||r.data.client_id!==cid)fail('invalid_grant');
        const grant=await record('grant:'+r.data.grant);if(!grant||grant.data.revoked)fail('invalid_grant');
        if(b.scope&&b.scope.split(' ').some(s=>!r.data.scope.split(' ').includes(s)))fail('invalid_scope');
        await consume(key,r);return json(res,200,await issue(cid,r.data.grant,b.scope||r.data.scope));
      }
      fail('unsupported_grant_type');
    }
    if(req.method==='POST'&&p==='/oauth/revoke'){
      const b=await body(req),{cid}=await authenticateClient(req,b);
      for(const type of ['access','refresh']){const r=await record(type+':'+hash(b.token||''));if(r&&r.data.client_id===cid){const g=await record('grant:'+r.data.grant);if(g)await store.put('grant:'+r.data.grant,{...g.data,revoked:true},g.revision);}}
      return json(res,200,{});
    }
    if(p==='/mcp'){
      const a=await authorized(req);
      if(req.method==='GET'||req.method==='DELETE')return json(res,405,{error:'Stateless server; use POST'},{Allow:'POST'});
      if(req.method!=='POST')fail('Method not allowed',405);
      const rpc=await body(req);if(rpc.jsonrpc!=='2.0'||typeof rpc.method!=='string')fail('Invalid JSON-RPC');
      if(rpc.method.startsWith('notifications/')){res.writeHead(202);return res.end();}
      let result;
      if(rpc.method==='initialize')result={protocolVersion:['2024-11-05','2025-03-26','2025-06-18','2025-11-25'].includes(rpc.params?.protocolVersion)?rpc.params.protocolVersion:'2025-06-18',capabilities:{tools:{}},serverInfo:{name:'Rival Link',version:'1.0.0'},instructions:'Shared career state, not an AI API gateway. Read before writing. Preserve verified stats and currencies; never invent games. No paid rival calls. Claude API participation remains paused.'};
      else if(rpc.method==='ping')result={};
      else if(rpc.method==='tools/list')result={tools:(await tools()).filter(t=>t.name!=='save_context'||a.scope.includes('career:write'))};
      else if(rpc.method==='tools/call'){
        const b=rpc.params||{};
        if(!['get_career','save_context'].includes(b.name)||b.arguments?.career_id!==careerId)fail('Operation outside connected career',403);
        if(b.name==='save_context'&&!a.scope.includes('career:write'))fail('insufficient_scope',403);
        try{result={content:[{type:'text',text:JSON.stringify(await call(b.name,b.arguments))}]};}catch(e){result={isError:true,content:[{type:'text',text:e.status?e.message:'Career service unavailable; no update confirmed. Read again before retrying.'}]};}
      }else return json(res,200,{jsonrpc:'2.0',id:rpc.id??null,error:{code:-32601,message:'Method not found'}});
      return json(res,200,{jsonrpc:'2.0',id:rpc.id??null,result});
    }
    if(req.method==='GET'&&p==='/'){
      res.writeHead(200,{'content-type':'text/html','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'",'Cache-Control':'no-store'});
      return res.end(`<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rival Link</title><style>body{font:18px system-ui;background:#10121a;color:#fafafa;max-width:650px;margin:10vh auto;padding:24px}code{overflow-wrap:anywhere;color:#b6f36a}p{line-height:1.6}</style><h1>One career. Connected chats.</h1><p>Add this server in Gemini’s Custom apps or Claude’s Connectors, then approve access in your existing Rival Link account.</p><code>${escape(resource)}</code><p>Your career remains private. This connection can read and update the linked save; it cannot run paid rival models or read API keys.</p><p>Career: ${escape(careerId)}</p></html>`);
    }
    return json(res,404,{error:'Not found'});
  }catch(e){return json(res,e.status||503,{error:e.status?e.message:'Service temporarily unavailable'},e.status===401?{'WWW-Authenticate':`Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`}:{});}};
}
export function productionApplication(env=process.env){
  const origin=env.PUBLIC_ORIGIN||env.RENDER_EXTERNAL_URL;
  for(const k of ['UPSTREAM_SITE_ORIGIN','UPSTREAM_ACCESS_TOKEN','UPSTREAM_BRIDGE_SECRET','CAREER_ID'])if(!env[k])throw new Error('Missing required configuration: '+k);
  const bridge=async b=>{
    const res=await fetch(env.UPSTREAM_SITE_ORIGIN+'/api/external-bridge',{method:'POST',headers:{'content-type':'application/json','Authorization':'Bearer '+env.UPSTREAM_BRIDGE_SECRET,'OAI-Sites-Authorization':'Bearer '+env.UPSTREAM_ACCESS_TOKEN},body:JSON.stringify(b),signal:AbortSignal.timeout(20000),redirect:'error'});
    const d=await res.json();if(!res.ok)fail(d.error||'Upstream unavailable',res.status);return d;
  };
  return createApplication({origin,siteOrigin:env.UPSTREAM_SITE_ORIGIN,careerId:env.CAREER_ID,store:{get:key=>bridge({op:'get',key}),put:(key,data,revision)=>bridge({op:'put',key,data,revision}),delete:(key,revision)=>bridge({op:'delete',key,revision})},tools:()=>bridge({op:'tools'}),call:(name,args)=>bridge({op:'call',name,args})});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const handler=productionApplication();http.createServer(handler).listen(Number(process.env.PORT||10000),'0.0.0.0',()=>console.log('Rival Link connector listening'));
}
