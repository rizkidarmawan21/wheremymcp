import { parseArgs } from 'node:util';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile, stat, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Hub } from './core.js';
import { loadConfig } from './config.js';
import { createEncryptedBackup, restoreBackup, rotateMasterKey, recoverMasterKeyRotation, withOperationLock } from './backup.js';
import { planSkillSync, applySkillSync, type SyncPlan } from './skills.js';

export async function runCli(argv:string[]=process.argv.slice(2)) {
  const {positionals,values}=parseArgs({args:argv,allowPositionals:true,options:{
    file:{type:'string'},target:{type:'string'},'key-file':{type:'string'},'new-key-file':{type:'string'},id:{type:'string'},out:{type:'string'},plan:{type:'string'},apply:{type:'boolean'},recover:{type:'boolean'},'invalidate-clients':{type:'boolean'},'keep-sessions':{type:'boolean'},help:{type:'boolean'},
  }});
  const [command,subcommand]=positionals;const config=loadConfig();
  const required=(value:string|undefined,name:string)=>{if(!value)throw new Error(`${name} required`);return value;};
  if(values.help||!command){return {usage:['init','bootstrap-reset','backup','restore --file BACKUP --target EMPTY_DIR [--key-file KEY] [--invalidate-clients] [--keep-sessions]','rotate-key --new-key-file KEY | --recover','skills plan --id ID --target ABSOLUTE_DIR --out PLAN.json','skills sync --plan PLAN.json --apply'],note:'Master key and bootstrap token are never printed. Set HUB_DATA_DIR and HUB_MASTER_KEY_FILE before use.'};}
  if(command==='init') {
    return withOperationLock(config.dataDir,true,async()=>{
      await mkdir(dirname(config.masterKeyFile),{recursive:true,mode:0o700});await mkdir(dirname(config.bootstrapTokenFile),{recursive:true,mode:0o700});
      // Exclusive creation preserves an existing installation when Compose reruns init.
      try{await writeFile(config.masterKeyFile,randomBytes(32),{flag:'wx',mode:0o600});}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}
      const file=await open(config.masterKeyFile,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);let key:Buffer;
      try{const info=await file.stat();if(!info.isFile()||info.size!==32)throw new Error('Master key must be a regular file containing 32 raw bytes');key=await file.readFile();}
      finally{await file.close();}
      const hub=new Hub(join(config.dataDir,'hub.sqlite'),key,config);
      try{if(!hub.db.prepare('SELECT id FROM owner WHERE id=1').get()) {
        try{await writeFile(config.bootstrapTokenFile,`${randomBytes(32).toString('base64url')}\n`,{flag:'wx',mode:0o600});}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}
      }}finally{hub.close();}
      return {initialized:true,master_key_file:config.masterKeyFile,bootstrap_token_file:config.bootstrapTokenFile,note:'Read the bootstrap token from its protected file. Back up the master key separately.'};
    });
  }
  if(command==='bootstrap-reset') {
    return withOperationLock(config.dataDir,true,async()=>{
      const hub=new Hub(join(config.dataDir,'hub.sqlite'),await readFile(config.masterKeyFile),config);
      try{if(hub.db.prepare('SELECT id FROM owner WHERE id=1').get())throw new Error('Owner already claimed; bootstrap cannot reopen');
        await writeFile(config.bootstrapTokenFile,`${randomBytes(32).toString('base64url')}\n`,{mode:0o600});
        return {reset:true,bootstrap_token_file:config.bootstrapTokenFile};
      }finally{hub.close();}
    });
  }
  if(command==='restore')return restoreBackup(required(values.file,'--file'),await readFile(values['key-file']||config.masterKeyFile),required(values.target,'--target'),{invalidateClients:values['invalidate-clients'],invalidateSessions:!values['keep-sessions']});
  if(command==='rotate-key'&&values.recover)return recoverMasterKeyRotation(config);
  try{await stat(join(config.dataDir,'rotation.pending.json'));throw new Error('Incomplete rotation: stop the app and run rotate-key --recover');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
  await stat(join(config.dataDir,'hub.sqlite'));const hub=new Hub(join(config.dataDir,'hub.sqlite'),await readFile(config.masterKeyFile),config);
  try{
    if(command==='backup')return await createEncryptedBackup(hub);
    if(command==='rotate-key')return await rotateMasterKey(hub,required(values['new-key-file'],'--new-key-file'));
    if(command==='skills'&&subcommand==='plan') {
      const plan=await planSkillSync(hub,required(values.id,'--id'),required(values.target,'--target'));const out=resolve(required(values.out,'--out'));
      await writeFile(out,JSON.stringify(plan,null,2),{flag:'wx',mode:0o600});return {...plan,plan_file:out,note:'Review every change; sync requires --apply.'};
    }
    if(command==='skills'&&subcommand==='sync') {
      if(!values.apply)throw new Error('Explicit --apply and a saved reviewed plan required');const plan=JSON.parse(await readFile(required(values.plan,'--plan'),'utf8')) as SyncPlan;
      return await withOperationLock(config.dataDir,false,()=>applySkillSync(hub,plan));
    }
    throw new Error('Unknown command; use --help');
  }finally{if(hub.db.open)hub.close();}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  runCli().then(result=>{process.stdout.write(`${JSON.stringify(result,null,2)}\n`);}).catch(error=>{process.stderr.write(`${error instanceof Error?error.message:'Operation failed'}\n`);process.exitCode=1;});
}
