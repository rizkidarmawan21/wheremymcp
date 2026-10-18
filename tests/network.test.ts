import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { safeFetch, validateTarget, isAllowedAddress, pinnedLookup } from '../src/gateway/network.js';

test('egress blocks private, metadata, unusual IP and mapped IPv6 addresses', async () => {
  for (const address of ['127.0.0.1','10.0.0.1','192.168.1.1','172.16.0.1','169.254.169.254','100.100.100.200','::1','fc00::1','fe80::1','::ffff:127.0.0.1','::ffff:169.254.169.254','0.0.0.0','224.0.0.1']) {
    assert.equal(isAllowedAddress(address, []), false, address);
  }
  assert.equal(isAllowedAddress('8.8.8.8', []), true);
  assert.equal(isAllowedAddress('2606:4700:4700::1111', []), true);
  assert.equal(isAllowedAddress('127.0.0.1', ['127.0.0.1']), true);
  assert.equal(isAllowedAddress('127.0.0.2', ['127.0.0.1']), false);
  for (const address of ['169.254.169.254','100.100.100.200','fd00:ec2::254','fd20:ce::254','::ffff:169.254.169.254']) assert.equal(isAllowedAddress(address,[address]),false);
  for (const url of ['http://127.1','http://2130706433','http://user:pass@example.com','https://example.com/?token=x','file:///etc/passwd','http://[::ffff:127.0.0.1]']) await assert.rejects(validateTarget(url));
});

test('explicit local exception works; redirect, oversized body and timeout fail closed', async t => {
  let seen = 0;
  const server = createServer((req,res) => {
    seen++;
    if (req.url === '/redirect') {res.writeHead(302,{location:'/ok'});res.end();}
    else if (req.url === '/large') res.end('x'.repeat(4096));
    else if (req.url === '/hang') setTimeout(() => res.end('late'),150);
    else res.end('ok');
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>{server.closeAllConnections();server.close();});
  const url = `http://127.0.0.1:${(server.address() as any).port}`;
  await assert.rejects(safeFetch(url));
  const policy={allowedPrivateIps:['127.0.0.1']};
  assert.equal(await (await safeFetch(url+'/ok',{},policy)).text(),'ok');
  await assert.rejects(safeFetch(url+'/redirect',{headers:{authorization:'secret'}},policy));
  assert.equal(seen,2,'redirect never followed');
  await assert.rejects(safeFetch(url+'/ok?page=2',{},policy));
  assert.equal(await (await safeFetch(url+'/ok?page=2',{}, {...policy,allowQuery:true})).text(),'ok');
  await assert.rejects(safeFetch(url+'/large',{}, {...policy,maxResponseBytes:100}));
  await assert.rejects(safeFetch(url+'/hang',{}, {...policy,timeoutMs:20}));
  await assert.rejects(validateTarget(url,['127.0.0.0/8']));
});


test('socket DNS lookup stays pinned when hostname resolution could rebind',()=>{
 const lookup=pinnedLookup({address:'8.8.8.8',family:4});
 const observed:any[]=[];
 for(const hostname of ['public.example','public.example','127.0.0.1'])lookup(hostname,{},(error,address,family)=>{assert.equal(error,null);observed.push({address,family});});
 assert.deepEqual(observed,[{address:'8.8.8.8',family:4},{address:'8.8.8.8',family:4},{address:'8.8.8.8',family:4}]);
 lookup('public.example',{all:true},(error,addresses)=>{assert.equal(error,null);assert.deepEqual(addresses,[{address:'8.8.8.8',family:4}]);});
});
