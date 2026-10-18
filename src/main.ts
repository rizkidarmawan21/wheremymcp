import { readFile, mkdir, open, unlink, access } from 'node:fs/promises';
import { join } from 'node:path';
import { loadConfig } from './config.js';
import { Hub } from './core.js';
import { createApp } from './app.js';
import { withOperationLock, acquireRuntimeLease } from './backup.js';

async function main(){
 const config=loadConfig();await mkdir(config.dataDir,{recursive:true,mode:0o700});let hub!:Hub;
 const lock=join(config.dataDir,'runtime.lock');let ownsLock=false;let releaseLease:(()=>void)|undefined;
 await withOperationLock(config.dataDir,false,async()=>{
  try{await access(join(config.dataDir,'rotation.pending.json'));throw new Error('An interrupted key rotation requires CLI rotate-key --recover before startup');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  releaseLease=acquireRuntimeLease(config.dataDir);
  try{
    const handle=await open(lock,'w',0o600);await handle.writeFile(String(process.pid));await handle.close();ownsLock=true;
    const key=await readFile(config.masterKeyFile);try{hub=new Hub(join(config.dataDir,'hub.sqlite'),key,config);}finally{key.fill(0);}
  }catch(e){await unlink(lock).catch(()=>{});ownsLock=false;releaseLease();releaseLease=undefined;throw e;}
 });
 try{
  const app=await createApp(hub);await app.listen({host:config.host,port:config.port});
  process.stdout.write(`WhereMyMCP listening on ${config.origin}; mode=${config.publicMode?'public':'local'}\n`);
  let stopping=false;const shutdown=async()=>{if(stopping)return;stopping=true;const deadline=setTimeout(()=>process.exit(1),20000);deadline.unref();let status=0;try{await app.close();hub.db.pragma('wal_checkpoint(TRUNCATE)');hub.close();if(ownsLock)await unlink(lock);}catch{status=1;}finally{releaseLease?.();clearTimeout(deadline);process.exit(status);}};
  process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
 }catch(e){hub?.close();if(ownsLock)await unlink(lock);releaseLease?.();throw e;}
}
main().catch(error=>{process.stderr.write(`Startup failed: ${error instanceof Error?error.message:'invalid configuration'}\n`);process.exitCode=1;});
