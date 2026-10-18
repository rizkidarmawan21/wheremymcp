import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { Agent, fetch as undiciFetch, type RequestInit as UndiciRequestInit } from 'undici';

export interface FetchPolicy {
  allowedPrivateIps?: string[];
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowedOrigin?: string;
  allowQuery?: boolean;
}
const private4 = new BlockList();
for (const [address,prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]] as const) private4.addSubnet(address,prefix,'ipv4');
const global6 = new BlockList(); global6.addSubnet('2000::',3,'ipv6');
const reserved6 = new BlockList();
for(const [address,prefix] of [['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20]] as const) reserved6.addSubnet(address,prefix,'ipv6');

function normalize(address: string): string {
  if (!isIP(address) || address.includes('%')) throw new Error('invalid_address');
  if (isIP(address) === 4) return address;
  const host = new URL(`http://[${address}]/`).hostname.slice(1,-1);
  if(host.startsWith('::ffff:')) {
    const parts=host.slice(7).split(':');
    if(parts.length===2) {
      const value=parseInt(parts[0]!,16)*65536+parseInt(parts[1]!,16);
      return [value>>>24,(value>>>16)&255,(value>>>8)&255,value&255].join('.');
    }
  }
  return host;
}
function metadata(address:string): boolean {
  return address.startsWith('169.254.') || address === '100.100.100.200' || address === 'fd00:ec2::254' || address === 'fd20:ce::254';
}
export function isAllowedAddress(address:string,allowedPrivateIps:string[]=[]):boolean {
  try {
    const normalized=normalize(address);
    if(metadata(normalized)) return false;
    if(allowedPrivateIps.some(ip=>normalize(ip)===normalized)) return true;
    return isIP(normalized)===4 ? !private4.check(normalized,'ipv4') : global6.check(normalized,'ipv6') && !reserved6.check(normalized,'ipv6');
  } catch { return false; }
}
async function resolveAddresses(hostname:string):Promise<{address:string;family:number}[]> {
 let timer:NodeJS.Timeout|undefined;try{return await Promise.race([lookup(hostname,{all:true,verbatim:true}),new Promise<never>((_resolve,reject)=>{timer=setTimeout(()=>reject(new Error('dns_timeout')),5000);timer.unref();})]);}finally{if(timer)clearTimeout(timer);}
}
export async function validateTarget(input:string|URL,allowedPrivateIps:string[]=[],allowQuery=false):Promise<{url:URL;addresses:{address:string;family:number}[]}> {
  if(allowedPrivateIps.length>16 || allowedPrivateIps.some(ip=>!isIP(ip)||metadata(normalize(ip)))) throw new Error('invalid_private_exception');
  const url=new URL(input);
  if(!['http:','https:'].includes(url.protocol)||url.username||url.password||(!allowQuery&&url.search)||url.hash) throw new Error('invalid_target');
  const hostname=url.hostname.replace(/^\[|\]$/g,'');
  const addresses=isIP(hostname)?[{address:hostname,family:isIP(hostname)}]:await resolveAddresses(hostname);
  if(!addresses.length||addresses.length>32||addresses.some(({address})=>!isAllowedAddress(address,allowedPrivateIps))) throw new Error('blocked_target');
  if(url.protocol!=='https:' && !addresses.every(({address})=>allowedPrivateIps.some(ip=>normalize(ip)===normalize(address)))) throw new Error('https_required');
  return {url,addresses};
}

export function pinnedLookup(address:{address:string;family:number}) {
  return (_hostname:string,options:{all?:boolean},callback:(...args:any[])=>void):void=>{
    if(options.all)callback(null,[address]);else callback(null,address.address,address.family);
  };
}

export async function safeFetch(input:string|URL|Request,init:RequestInit={},policy:FetchPolicy={}):Promise<Response> {
  const timeout=AbortSignal.timeout(Math.min(Math.max(policy.timeoutMs??15_000,1),60_000));
  const signal=AbortSignal.any([timeout,...(init.signal?[init.signal]:[]),...(input instanceof Request?[input.signal]:[])]);
  let agent:Agent|undefined;
  try {
    const {url,addresses}=await Promise.race([validateTarget(input instanceof Request?input.url:input,policy.allowedPrivateIps,policy.allowQuery),new Promise<never>((_resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('outbound_timeout')),{once:true}))]);
    signal.throwIfAborted();
    if(policy.allowedOrigin && url.origin!==policy.allowedOrigin) throw new Error('credential_origin_mismatch');
    const address=addresses[0]!;
    agent=new Agent({connect:{lookup:pinnedLookup(address)}});
    const request=input instanceof Request?input:undefined;
    const headers=new Headers(init.headers??request?.headers);
    headers.delete('host');headers.delete('cookie');headers.delete('proxy-authorization');
    headers.set('accept-encoding','identity');
    const response=await undiciFetch(url,{...init,method:init.method??request?.method,body:init.body??(request?.body as never),headers:Object.fromEntries(headers),duplex:'half',redirect:'manual',signal,dispatcher:agent} as UndiciRequestInit);
    if(response.status>=300&&response.status<400) throw new Error('redirect_forbidden');
    const limit=Math.min(Math.max(policy.maxResponseBytes??1_048_576,1),4_194_304);
    if(Number(response.headers.get('content-length'))>limit) throw new Error('response_too_large');
    const chunks:Uint8Array[]=[];let size=0;let events=0;let previous=0;const eventStream=response.headers.get('content-type')?.includes('text/event-stream');
    if(response.body) for await(const chunk of response.body){size+=chunk.byteLength;if(eventStream)for(const byte of chunk){if(byte===10&&previous===10&&++events>2048)throw new Error('too_many_events');if(byte!==13)previous=byte;}if(size>limit) throw new Error('response_too_large');chunks.push(chunk);}
    const body=new Uint8Array(size);let offset=0;for(const chunk of chunks){body.set(chunk,offset);offset+=chunk.length;}
    const outHeaders=new Headers([...response.headers]);outHeaders.delete('content-encoding');outHeaders.delete('content-length');outHeaders.delete('set-cookie');
    return new Response([204,205,304].includes(response.status)?null:body,{status:response.status,statusText:response.statusText,headers:outHeaders});
  } catch { throw new Error('outbound_request_rejected'); }
  finally {if(agent) await agent.destroy();}
}
