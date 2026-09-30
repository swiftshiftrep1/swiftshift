const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const root = __dirname;
if (process.versions.node.split('.')[0] < 22) throw new Error('Node 22+ is required.');
for (const file of ['server.js','public/app.js']) {
  const { spawnSync } = require('child_process');
  const r = spawnSync(process.execPath,['--check',path.join(root,file)],{encoding:'utf8'});
  if(r.status!==0) throw new Error(`${file} syntax check failed: ${r.stderr}`);
}
const tmp=path.join(root,'data','smoke.sqlite');fs.mkdirSync(path.dirname(tmp),{recursive:true});try{fs.rmSync(tmp,{force:true});const db=new DatabaseSync(tmp);db.exec('CREATE TABLE test(id INTEGER PRIMARY KEY, name TEXT);');db.prepare('INSERT INTO test(name) VALUES(?)').run('ok');if(db.prepare('SELECT COUNT(*) c FROM test').get().c!==1)throw new Error('SQLite smoke test failed');db.close();console.log('SwiftShift static + SQLite smoke test passed.');}finally{fs.rmSync(tmp,{force:true});}
