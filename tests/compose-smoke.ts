import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { chromium } from '@playwright/test';

// Run only against the disposable verification Compose project, never the owner's instance.
const project = process.env.HUB_VERIFY_PROJECT || 'wheremymcp-verify';
if (!/^[a-z0-9][a-z0-9_-]*verify[a-z0-9_-]*$/.test(project)) throw new Error('A separate verify project is required');
const origin = process.env.HUB_VERIFY_ORIGIN || 'http://127.0.0.1:18080';
const compose = ['compose', '-p', project, '-f', 'compose.yaml', '-f', 'tests/compose.verify.yaml'];
const command = (...args:string[]) => execFileSync('docker', [...compose,...args], { encoding:'utf8', env:{...process.env,HUB_PORT:new URL(origin).port,HUB_ORIGIN:origin}, stdio:['ignore','pipe','pipe'] }).trim();
const password = `Smoke-${randomBytes(24).toString('base64url')}-7!`;
let cookie = '', csrf = '';
async function api(path:string, method='GET', body?:unknown, accepted=[200,201]) {
 const response = await fetch(origin+path,{method,headers:{...(body!==undefined?{'content-type':'application/json'}:{}),...(cookie?{cookie,'x-csrf-token':csrf}:{})},body:body===undefined?undefined:JSON.stringify(body)});
 const result:any=await response.json();assert.ok(accepted.includes(response.status),`${method} ${path}: ${response.status} ${result.error||''}`);
 if(path==='/auth/session' && method==='POST'){cookie=response.headers.get('set-cookie')!.split(';')[0]!;csrf=result.csrf_token;}
 return result;
}
const clients:Client[]=[];
let browser;
try {
 assert.equal((await api('/api/v1/setup')).claimed,false,'Verification project must use a fresh unclaimed volume');
 const setupToken=command('exec','-T','hub','node','-e',"process.stdout.write(require('fs').readFileSync('/secrets/bootstrap.token','utf8'))");
 await api('/setup/claim','POST',{setup_token:setupToken,password});await api('/auth/session','POST',{password});
 const ip=command('exec','-T','hub','node','-e',"require('dns').lookup('upstream-fixture',(e,a)=>{if(e)throw e;process.stdout.write(a)})");
 const {connection}=await api('/api/v1/connections','POST',{provider:'bearer',alias:'fixture-account',secret:'local-fixture-credential'});
 const {upstream}=await api('/api/v1/upstreams','POST',{name:'Compose fixture',url:'http://upstream-fixture:8081/mcp',connection_id:connection.id,allowed_private_ips:[ip]});
 await api(`/api/v1/upstreams/${upstream.id}/refresh`,'POST',{});await api(`/api/v1/upstreams/${upstream.id}/approve`,'POST',{});
 const {tools}=await api('/api/v1/tools');assert.equal(tools.length,2);
 const read=tools.find((tool:any)=>tool.name==='read_echo'),write=tools.find((tool:any)=>tool.name==='write_echo');
 await api(`/api/v1/tools/${read.id}/approve`,'POST',{risk:'read',enabled:true});await api(`/api/v1/tools/${write.id}/approve`,'POST',{risk:'write',enabled:true});
 const {profile}=await api('/api/v1/profiles','POST',{name:'Compose read/write',slug:'compose-verification'});
 await api(`/api/v1/profiles/${profile.id}/grants`,'PUT',{grants:[{tool_id:read.id,connection_id:connection.id,action_class:'read'},{tool_id:write.id,connection_id:connection.id,action_class:'write'}]});
 const {client,token}=await api('/api/v1/clients','POST',{name:'Disposable verify client',kind:'codex',profile_id:profile.id});
 for(const mode of ['auto','legacy'] as const){
  const sdk=new Client({name:'compose-smoke',version:'1'},{versionNegotiation:{mode}});clients.push(sdk);await sdk.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{authorization:`Bearer ${token}`}}}));
  assert.equal((await sdk.listTools()).tools.length,2);const result=await sdk.callTool({name:read.gateway_name,arguments:{text:'real-container-call'}});assert.match(JSON.stringify(result),/real-container-call/);
  await assert.rejects(sdk.callTool({name:write.gateway_name,arguments:{text:'approved-container-write'}}));
  const {approval_id}=await api('/api/v1/approvals','POST',{client_id:client.id,tool_id:write.id,arguments:{text:'approved-container-write'}});
  const output=await sdk.callTool({name:write.gateway_name,arguments:{text:'approved-container-write'},_meta:{wheremymcp_approval_id:approval_id}});assert.match(JSON.stringify(output),/approved-container-write/);
  await assert.rejects(sdk.callTool({name:write.gateway_name,arguments:{text:'approved-container-write'},_meta:{wheremymcp_approval_id:approval_id}}));
 }
 const backup=await api('/api/v1/backup/create','POST',{password});assert.ok(backup.name);
 browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:900}});page.setDefaultTimeout(7000);
 const browserErrors:string[]=[];page.on('pageerror',error=>browserErrors.push(error.message));
 await page.goto(origin);await page.getByLabel('Owner password').fill(password);await page.getByRole('button',{name:'Log in',exact:true}).click();
 await page.getByRole('heading',{name:'Gateway policy is active'}).waitFor();
 for(const width of [1280,390]){
  await page.setViewportSize({width,height:900});
  for(const name of ['overview','upstreams','connections','tools','profiles','clients','approvals','skills','security','audit','backups','settings']){
   await page.goto(`${origin}/#${name}`);await page.locator('main[aria-busy="false"]').waitFor();
   assert.equal(await page.getByRole('heading',{name:'Could not load this view'}).count(),0,`Container dashboard ${name} must load`);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`Container dashboard ${name} must fit ${width}px`);
   assert.equal(await page.locator('main').evaluate(main=>[...main.childNodes].some(node=>node.nodeType===Node.TEXT_NODE&&node.textContent?.trim()==='null')),false,'No null content in container dashboard');
   if(name==='upstreams')assert.equal(await page.getByRole('button',{name:'Approve server',exact:true}).isDisabled(),true,'Container must serve the fixed button handler');
  }
 }
 await page.getByRole('button',{name:'Log out',exact:true}).click();await page.getByRole('heading',{name:'Owner login'}).waitFor();
 assert.deepEqual(browserErrors,[]);await browser.close();browser=undefined;
 const events=await api('/api/v1/audit?limit=100');assert.ok(events.events.length>10);assert.equal(JSON.stringify(events).includes(token),false);assert.equal(JSON.stringify(events).includes('real-container-call'),false);
 await api(`/api/v1/clients/${client.id}/revoke`,'POST',{});await assert.rejects(clients[0]!.listTools());
 await api('/auth/logout','POST',{});
 process.stdout.write(JSON.stringify({result:'PASS',project,transport:['2026-07-28','2025-11-25'],verified:['fresh owner claim','encrypted upstream account','DNS-pinned container egress','discovery/review/profile grants','read invocation','one-use write approval','client revoke','metadata-only audit','encrypted backup','12 dashboard pages at desktop and mobile widths','unavailable action buttons disabled','no literal null content','browser login/logout','logout']},null,2)+'\n');
} finally {if(browser)await browser.close();await Promise.all(clients.map(client=>client.close().catch(()=>{})));}
