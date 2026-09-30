const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, 'data');
const PRIVATE_DIR = path.join(DATA_DIR, 'private');
const DB_FILE = path.join(DATA_DIR, 'swiftshift.sqlite');
fs.mkdirSync(PRIVATE_DIR, { recursive: true });

const now = () => new Date().toISOString();
const clean = (v, max) => typeof v === 'string' ? v.trim().slice(0, max) : '';
const uid = () => crypto.randomUUID();
const money = v => Math.round((Number(v) || 0) * 100) / 100;
const json = v => JSON.stringify(v ?? null);
const parseJson = v => { try { return v ? JSON.parse(v) : null; } catch { return null; } };

const db = new DatabaseSync(DB_FILE);
db.exec(`
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 student_card TEXT, role TEXT NOT NULL DEFAULT 'user', verification_status TEXT NOT NULL DEFAULT 'PENDING',
 availability INTEGER NOT NULL DEFAULT 1, terms_accepted_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verification_requests (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 student_card TEXT, id_document_name TEXT, encrypted_path TEXT, status TEXT NOT NULL DEFAULT 'PENDING',
 created_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by TEXT
);
CREATE TABLE IF NOT EXISTS jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, requester_id TEXT NOT NULL REFERENCES users(id), runner_id TEXT REFERENCES users(id),
 title TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, pickup TEXT NOT NULL, destination TEXT,
 urgency TEXT NOT NULL, scheduled_for TEXT, material_cost REAL NOT NULL DEFAULT 0, base REAL NOT NULL,
 distance_fee REAL NOT NULL, complexity REAL NOT NULL, urgency_fee REAL NOT NULL, platform_fee REAL NOT NULL,
 total_price REAL NOT NULL, runner_earnings REAL NOT NULL, status TEXT NOT NULL, payment_status TEXT NOT NULL,
 payment_provider TEXT, payment_reference TEXT, paid_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 pickup_lat REAL, pickup_lng REAL, destination_lat REAL, destination_lng REAL
);
CREATE TABLE IF NOT EXISTS job_events (
 id TEXT PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, actor_id TEXT REFERENCES users(id),
 type TEXT NOT NULL, from_status TEXT, to_status TEXT, lat REAL, lng REAL, metadata TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id),
 body TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL,
 title TEXT NOT NULL, body TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payouts (
 id TEXT PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id), runner_id TEXT NOT NULL REFERENCES users(id),
 amount REAL NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, released_at TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
 id TEXT PRIMARY KEY, reporter_id TEXT NOT NULL REFERENCES users(id), job_id INTEGER REFERENCES jobs(id),
 type TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN', created_at TEXT NOT NULL, resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS disputes (
 id TEXT PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id), opened_by TEXT NOT NULL REFERENCES users(id),
 reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN', created_at TEXT NOT NULL, resolved_at TEXT, resolved_by TEXT, decision TEXT
);
CREATE TABLE IF NOT EXISTS reviews (
 id TEXT PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id), reviewer_id TEXT NOT NULL REFERENCES users(id),
 reviewee_id TEXT NOT NULL REFERENCES users(id), rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5), comment TEXT, created_at TEXT NOT NULL,
 UNIQUE(job_id, reviewer_id, reviewee_id)
);
CREATE TABLE IF NOT EXISTS audit (
 id TEXT PRIMARY KEY, actor_id TEXT, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT,
 metadata TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_messages_job ON messages(job_id, created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read_at);
CREATE INDEX IF NOT EXISTS idx_reviews_reviewee ON reviews(reviewee_id);
`);

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : false);
app.use(express.json({ limit: '6mb' }));
app.use(express.urlencoded({ extended: false, limit: '6mb' }));
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','geolocation=(self), camera=(), microphone=()');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  next();
});

const rate = new Map();
setInterval(()=>{ const cutoff=Date.now()-10*60_000; for(const [k,v] of rate) if(v.t < cutoff) rate.delete(k); }, 5*60_000).unref();
function rateLimit(windowMs=60_000,max=120){ return (req,res,next)=>{ const key=`${req.ip}:${Math.floor(Date.now()/windowMs)}`; const x=rate.get(key)||{c:0,t:Date.now()}; x.c++; rate.set(key,x); if(x.c>max) return res.status(429).json({error:'Too many requests. Please try again shortly.'}); next(); }; }
app.use('/api', rateLimit());
app.use('/api',(req,res,next)=>{
  if(['GET','HEAD','OPTIONS'].includes(req.method) || req.path==='/payments/payfast/itn' || req.path==='/payments/webhook') return next();
  const origin=req.headers.origin;
  if(origin){
    const expected=`${req.protocol}://${req.get('host')}`;
    if(origin!==expected) return res.status(403).json({error:'Cross-origin request blocked.'});
  }
  next();
});

if(process.env.NODE_ENV==='production' && (!process.env.DOCUMENT_ENCRYPTION_KEY || process.env.DOCUMENT_ENCRYPTION_KEY==='replace-with-a-long-random-secret' || process.env.DOCUMENT_ENCRYPTION_KEY==='CHANGE_ME_BEFORE_PRODUCTION')){
  throw new Error('DOCUMENT_ENCRYPTION_KEY must be configured before starting SwiftShift in production.');
}

const CATEGORIES=['Printing','Pickup & Delivery','Food','Shopping','Admin','Academic','Documents','Other'];
const URGENCIES=['ASAP','Today','Schedule'];
const STATUSES=['SEARCHING','ACCEPTED','HEADING_TO_PICKUP','ARRIVED','IN_PROGRESS','HEADING_TO_DESTINATION','DELIVERED','COMPLETED','CANCELLED','DISPUTED'];

function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){ return `${salt}:${crypto.scryptSync(password,salt,64).toString('hex')}`; }
function verifyPassword(password,stored){ const [salt,expected]=String(stored||'').split(':'); if(!salt||!expected)return false; const actual=crypto.scryptSync(password,salt,64).toString('hex'); return actual.length===expected.length && crypto.timingSafeEqual(Buffer.from(actual),Buffer.from(expected)); }
function tokenHash(token){return crypto.createHash('sha256').update(token).digest('hex');}
function q(sql,args=[]){return db.prepare(sql).all(...args);}
function one(sql,args=[]){return db.prepare(sql).get(...args)||null;}
function run(sql,args=[]){return db.prepare(sql).run(...args);}
function tx(fn){ db.exec('BEGIN IMMEDIATE'); try{const out=fn();db.exec('COMMIT');return out;}catch(e){try{db.exec('ROLLBACK')}catch{};throw e;} }
function audit(actorId,action,entityType,entityId,metadata={}){run('INSERT INTO audit(id,actor_id,action,entity_type,entity_id,metadata,created_at) VALUES(?,?,?,?,?,?,?)',[uid(),actorId,action,entityType,String(entityId??''),json(metadata),now()]);}
function notify(userId,type,title,body){if(!userId)return;run('INSERT INTO notifications(id,user_id,type,title,body,created_at) VALUES(?,?,?,?,?,?)',[uid(),userId,type,title,body,now()]);}
function userRow(id){return one('SELECT * FROM users WHERE id=?',[id]);}
function safeUser(u){return u?{id:u.id,name:u.name,email:u.email,role:u.role,verificationStatus:u.verification_status,verified:u.verification_status==='APPROVED',availability:!!u.availability,termsAcceptedAt:u.terms_accepted_at}:null;}
function sessionUser(req){const c=String(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('swiftshift_session='));if(!c)return null;const raw=c.slice('swiftshift_session='.length);const s=one('SELECT * FROM sessions WHERE token_hash=? AND expires_at>?',[tokenHash(raw),now()]);return s?userRow(s.user_id):null;}
function cookieOptions(maxAge){return `HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAge}${process.env.NODE_ENV==='production'?'; Secure':''}`;}
function setSession(res,userId){const raw=crypto.randomBytes(32).toString('hex');run('DELETE FROM sessions WHERE expires_at<=?',[now()]);run('INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)',[tokenHash(raw),userId,now(),new Date(Date.now()+7*864e5).toISOString()]);res.setHeader('Set-Cookie',`swiftshift_session=${raw}; ${cookieOptions(7*86400)}`);}
function clearSession(res){res.setHeader('Set-Cookie',`swiftshift_session=; ${cookieOptions(0)}`);}
function requireUser(req,res){const u=sessionUser(req);if(!u){res.status(401).json({error:'Please log in.'});return null;}return u;}
function requireVerified(req,res){const u=requireUser(req,res);if(!u)return null;if(u.verification_status!=='APPROVED'){res.status(403).json({error:'Your account must be verified before using jobs.'});return null;}return u;}
function requireAdmin(req,res){const u=requireUser(req,res);if(!u)return null;if(!['admin','safety_admin'].includes(u.role)){res.status(403).json({error:'Admin access required.'});return null;}return u;}

function prohibited(text){const s=String(text||'').toLowerCase();const rules=[[/\b(weapon|firearm|gun|ammunition|explosive|grenade)\b/,'Weapons and explosives are prohibited.'],[/\b(cocaine|heroin|meth|fentanyl|illegal drugs?)\b/,'Illegal drugs are prohibited.'],[/\b(suicide|self[- ]?harm)\b/,'Tasks involving self-harm are prohibited.'],[/\b(write|submit|take|sit).{0,35}\b(exam|test)\b|\bdo\s+my\s+assignment\b/,'Academic cheating and impersonation are prohibited.'],[/\b(steal|stolen|counterfeit|fake\s+id)\b/,'Illegal or fraudulent activity is prohibited.'],[/\b(poison|toxic chemical|corrosive)\b/,'Dangerous chemicals are prohibited.']];for(const [re,msg] of rules)if(re.test(s))return msg;return null;}

function calculatePrice({category,pickup,destination,urgency,materialCost=0,demand=0,availableRunners=0}){
  const base=category==='Other'?12:10;
  const distanceFee=pickup&&destination?8:0;
  const complexity=['Admin','Academic'].includes(category)?5:4;
  const urgencyFee=urgency==='ASAP'?5:urgency==='Today'?3:0;
  const materials=Math.min(5000,Math.max(0,Number(materialCost)||0));
  const demandFee=(urgency==='ASAP'&&demand>=3&&availableRunners<=2)?Math.min(12,4+Math.max(0,demand-3)*2):0;
  const subtotal=base+distanceFee+complexity+urgencyFee+demandFee+materials;
  const platformFee=Math.max(5,Math.round(subtotal*0.15));
  return {base,distanceFee,complexity,urgencyFee,demandFee,materials,platformFee,total:money(subtotal+platformFee),runnerEarnings:money(subtotal)};
}
function priceContext(){return {demand:q("SELECT COUNT(*) c FROM jobs WHERE status='SEARCHING'")[0].c,availableRunners:q("SELECT COUNT(*) c FROM users WHERE verification_status='APPROVED' AND availability=1 AND role='user'")[0].c};}
function priceForInput(b){return calculatePrice({...b,...priceContext()});}

function jobView(j){
  const requester=userRow(j.requester_id), runner=j.runner_id?userRow(j.runner_id):null;
  const avg=runner?one('SELECT ROUND(AVG(rating),1) avg, COUNT(*) count FROM reviews WHERE reviewee_id=?',[runner.id]):null;
  return {id:j.id,requesterId:j.requester_id,runnerId:j.runner_id,title:j.title,category:j.category,description:j.description,pickup:j.pickup,destination:j.destination,urgency:j.urgency,scheduledFor:j.scheduled_for,materialCost:j.material_cost,base:j.base,distanceFee:j.distance_fee,complexity:j.complexity,urgencyFee:j.urgency_fee,demandFee:j.demand_fee,platformFee:j.platform_fee,totalPrice:j.total_price,runnerEarnings:j.runner_earnings,status:j.status,paymentStatus:j.payment_status,paymentProvider:j.payment_provider,paymentReference:j.payment_reference,createdAt:j.created_at,updatedAt:j.updated_at,requester:requester?.name||'',runner:runner?.name||null,runnerRating:avg?.avg??null,runnerReviewCount:avg?.count??0,pickupLat:j.pickup_lat,pickupLng:j.pickup_lng,destinationLat:j.destination_lat,destinationLng:j.destination_lng};
}
function allowedNext(j,actor){if(actor==='runner'){const m={ACCEPTED:['HEADING_TO_PICKUP'],HEADING_TO_PICKUP:['ARRIVED'],ARRIVED:['IN_PROGRESS'],IN_PROGRESS:[j.destination?'HEADING_TO_DESTINATION':'DELIVERED'],HEADING_TO_DESTINATION:['DELIVERED']};return m[j.status]||[];}return {DELIVERED:['COMPLETED'],SEARCHING:['CANCELLED'],ACCEPTED:['CANCELLED']}[j.status]||[];}
function assertJobParticipant(u,j){return j&&[j.requester_id,j.runner_id].includes(u.id);}

// Auth
app.get('/api/auth/me',(req,res)=>res.json({user:safeUser(sessionUser(req))}));
app.post('/api/auth/signup',(req,res)=>{
  const b=req.body||{},name=clean(b.name,80),email=clean(b.email,120).toLowerCase(),password=String(b.password||''),studentCard=clean(b.studentCard,40),idDocument=String(b.idDocumentData||''),idDocumentName=clean(b.idDocumentName,150);
  if(!name||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<10||!studentCard||!idDocument||!idDocumentName||b.termsAccepted!==true)return res.status(400).json({error:'Provide a valid name, email, password (10+ characters), student card, ID document and accept the terms.'});
  if(one('SELECT id FROM users WHERE email=?',[email]))return res.status(409).json({error:'An account with that email already exists. Log in instead.'});
  if(Buffer.byteLength(idDocument,'base64')>5.5*1024*1024)return res.status(400).json({error:'ID document is too large.'});
  const userId=uid(),t=now();const status=process.env.DEMO_MODE==='true'?'APPROVED':'PENDING';
  const ext=path.extname(idDocumentName).toLowerCase().replace(/[^a-z0-9.]/g,'').slice(0,10)||'.bin';
  const encPath=path.join(PRIVATE_DIR,`${userId}${ext}.enc`);const key=crypto.createHash('sha256').update(process.env.DOCUMENT_ENCRYPTION_KEY||'CHANGE_ME_BEFORE_PRODUCTION').digest();const iv=crypto.randomBytes(12);const cipher=crypto.createCipheriv('aes-256-gcm',key,iv);const encrypted=Buffer.concat([cipher.update(Buffer.from(idDocument,'base64')),cipher.final()]);fs.writeFileSync(encPath,Buffer.concat([iv,cipher.getAuthTag(),encrypted]));
  tx(()=>{run('INSERT INTO users(id,name,email,password_hash,student_card,role,verification_status,terms_accepted_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)',[userId,name,email,hashPassword(password),studentCard,'user',status,t,t]);run('INSERT INTO verification_requests(id,user_id,student_card,id_document_name,encrypted_path,status,created_at) VALUES(?,?,?,?,?,?,?)',[uid(),userId,studentCard,idDocumentName,encPath,status==='APPROVED'?'APPROVED':'PENDING',t]);audit(userId,'VERIFICATION_SUBMITTED','user',userId);});
  setSession(res,userId);res.status(201).json({user:safeUser(userRow(userId)),message:status==='APPROVED'?'Demo verification approved.':'Verification submitted for review.'});
});
app.post('/api/auth/login',(req,res)=>{const email=clean(req.body?.email,120).toLowerCase(),password=String(req.body?.password||'');const u=userRow(one('SELECT id FROM users WHERE email=?',[email])?.id);if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({error:'Invalid email or password.'});setSession(res,u.id);res.json({user:safeUser(u)});});
app.post('/api/auth/logout',(req,res)=>{const c=String(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('swiftshift_session='));if(c)run('DELETE FROM sessions WHERE token_hash=?',[tokenHash(c.slice('swiftshift_session='.length))]);clearSession(res);res.json({ok:true});});
app.post('/api/auth/availability',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const available=!!req.body?.available;run('UPDATE users SET availability=? WHERE id=?',[available?1:0,u.id]);res.json({available});});

// Pricing/jobs
app.post('/api/jobs/estimate',(req,res)=>{const b=req.body||{};if(!CATEGORIES.includes(b.category)||!URGENCIES.includes(b.urgency))return res.status(400).json({error:'Invalid category or urgency.'});res.json(priceForInput(b));});
app.get('/api/jobs',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const rows=q("SELECT * FROM jobs WHERE status NOT IN ('CANCELLED') ORDER BY created_at DESC LIMIT 200");res.json(rows.map(jobView));});
app.get('/api/jobs/:id',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.params.id)]);if(!j||!assertJobParticipant(u,j))return res.status(404).json({error:'Job not found.'});res.json(jobView(j));});
app.post('/api/jobs',(req,res)=>{
  const u=requireVerified(req,res),b=req.body||{};if(!u)return;const title=clean(b.title,80),category=clean(b.category,40),description=clean(b.description,500),pickup=clean(b.pickup,120),destination=clean(b.destination,120),urgency=clean(b.urgency,20),scheduledFor=clean(b.scheduledFor,40);const bad=prohibited(`${title} ${description} ${pickup} ${destination}`);
  if(!title||!CATEGORIES.includes(category)||!description||!pickup||!URGENCIES.includes(urgency)||bad)return res.status(400).json({error:bad||'Complete all required job fields.'});
  if(urgency==='Schedule'&&(!scheduledFor||new Date(scheduledFor)<=new Date()))return res.status(400).json({error:'Scheduled jobs must have a future date and time.'});
  const p=priceForInput({category,pickup,destination,urgency,materialCost:b.materialCost});const paymentStatus=process.env.DEMO_MODE==='true'?'PAID_CONFIRMED':'PENDING_PAYMENT';const t=now();
  let jobId;tx(()=>{const r=run(`INSERT INTO jobs(requester_id,title,category,description,pickup,destination,urgency,scheduled_for,material_cost,base,distance_fee,complexity,urgency_fee,platform_fee,total_price,runner_earnings,status,payment_status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,[u.id,title,category,description,pickup,destination,urgency,scheduledFor||null,p.materials,p.base,p.distanceFee,p.complexity,p.urgencyFee,p.platformFee,p.total,p.runnerEarnings,'SEARCHING',paymentStatus,t,t]);jobId=Number(r.lastInsertRowid);audit(u.id,'JOB_CREATED','job',jobId,{price:p});});
  res.status(201).json(jobView(one('SELECT * FROM jobs WHERE id=?',[jobId])));
});
app.post('/api/jobs/:id/accept',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.params.id)]);if(!j)return res.status(404).json({error:'Job not found.'});if(j.requester_id===u.id)return res.status(400).json({error:'You cannot accept your own job.'});if(j.status!=='SEARCHING'||j.payment_status!=='PAID_CONFIRMED')return res.status(409).json({error:'This job is not currently available.'});const changed=tx(()=>{const r=run("UPDATE jobs SET runner_id=?,status='ACCEPTED',updated_at=? WHERE id=? AND status='SEARCHING' AND runner_id IS NULL",[u.id,now(),j.id]);if(r.changes!==1)throw Object.assign(new Error('Job was just accepted by another runner.'),{status:409});run('INSERT INTO job_events(id,job_id,actor_id,type,to_status,created_at) VALUES(?,?,?,?,?,?)',[uid(),j.id,u.id,'STATUS','ACCEPTED',now()]);notify(j.requester_id,'JOB_ACCEPTED','Runner accepted your job',`${u.name} accepted Job #${j.id}.`);notify(u.id,'JOB_ASSIGNED','Job accepted',`You are now the runner for Job #${j.id}.`);audit(u.id,'JOB_ACCEPTED','job',j.id);return true;});res.json(jobView(one('SELECT * FROM jobs WHERE id=?',[j.id])));});
app.post('/api/jobs/:id/status',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.params.id)]);if(!j)return res.status(404).json({error:'Job not found.'});const actor=req.body?.actor,status=String(req.body?.status||'');if(actor==='runner'&&j.runner_id!==u.id)return res.status(403).json({error:'Only the assigned runner can do that.'});if(actor==='requester'&&j.requester_id!==u.id)return res.status(403).json({error:'Only the requester can do that.'});if(!allowedNext(j,actor).includes(status))return res.status(409).json({error:`Cannot move a job from ${j.status} to ${status}.`});const previous=j.status;tx(()=>{run('UPDATE jobs SET status=?,updated_at=? WHERE id=?',[status,now(),j.id]);run('INSERT INTO job_events(id,job_id,actor_id,type,from_status,to_status,created_at) VALUES(?,?,?,?,?,?,?)',[uid(),j.id,u.id,'STATUS',previous,status,now()]);if(status==='COMPLETED'){run('INSERT INTO payouts(id,job_id,runner_id,amount,status,created_at) VALUES(?,?,?,?,?,?)',[uid(),j.id,j.runner_id,j.runner_earnings,'PENDING_PROVIDER',now()]);notify(j.runner_id,'PAYOUT_PENDING','Job completed',`Job #${j.id} is complete. Your ${money(j.runner_earnings).toFixed(2)} payout is pending release.`);notify(j.requester_id,'JOB_COMPLETED','Job completed',`Job #${j.id} is complete.`);}if(status==='CANCELLED')notify(j.runner_id,'JOB_CANCELLED','Job cancelled',`Job #${j.id} was cancelled.`);audit(u.id,'JOB_STATUS_CHANGED','job',j.id,{from:previous,to:status});});res.json(jobView(one('SELECT * FROM jobs WHERE id=?',[j.id])));});

// Location tracking: only active participants may share a location; frontend should request browser permission.
app.post('/api/jobs/:id/location',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.params.id)]);if(!j||j.runner_id!==u.id)return res.status(403).json({error:'Only the active runner can share location.'});if(!['ACCEPTED','HEADING_TO_PICKUP','ARRIVED','IN_PROGRESS','HEADING_TO_DESTINATION'].includes(j.status))return res.status(409).json({error:'Location sharing is only available during an active job.'});const lat=Number(req.body?.lat),lng=Number(req.body?.lng);if(!Number.isFinite(lat)||!Number.isFinite(lng)||Math.abs(lat)>90||Math.abs(lng)>180)return res.status(400).json({error:'Invalid coordinates.'});run('INSERT INTO job_events(id,job_id,actor_id,type,lat,lng,created_at) VALUES(?,?,?,?,?,?,?)',[uid(),j.id,u.id,'LOCATION',lat,lng,now()]);res.json({ok:true});});
app.get('/api/jobs/:id/location',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.params.id)]);if(!j||!assertJobParticipant(u,j))return res.status(404).json({error:'Job not found.'});const x=one("SELECT lat,lng,created_at FROM job_events WHERE job_id=? AND type='LOCATION' ORDER BY created_at DESC LIMIT 1",[j.id]);res.json(x||null);});

// Chat
app.get('/api/jobs/:id/messages',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.params.id)]);if(!j||!assertJobParticipant(u,j))return res.status(404).json({error:'Job not found.'});const rows=q('SELECT m.id,m.body,m.created_at,m.sender_id,u.name sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.job_id=? ORDER BY m.created_at ASC LIMIT 200',[j.id]);res.json(rows.map(m=>({id:m.id,body:m.body,createdAt:m.created_at,senderId:m.sender_id,sender:m.sender})));});
app.post('/api/jobs/:id/messages',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.params.id)]);if(!j||!assertJobParticipant(u,j))return res.status(404).json({error:'Job not found.'});const body=clean(req.body?.body,500);const bad=prohibited(body);if(!body||bad)return res.status(400).json({error:bad||'Message cannot be empty.'});const m={id:uid(),jobId:j.id,senderId:u.id,body,createdAt:now()};const other=u.id===j.requester_id?j.runner_id:j.requester_id;if(!other)return res.status(409).json({error:'A runner has not accepted this job yet.'});tx(()=>{run('INSERT INTO messages(id,job_id,sender_id,body,created_at) VALUES(?,?,?,?,?)',[m.id,j.id,u.id,body,m.createdAt]);notify(other,'MESSAGE','New SwiftShift message',`${u.name}: ${body}`);audit(u.id,'MESSAGE_SENT','job',j.id);});res.status(201).json(m);});

// Notifications
app.get('/api/notifications',(req,res)=>{const u=requireUser(req,res);if(!u)return;const rows=q('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50',[u.id]);res.json(rows.map(n=>({id:n.id,type:n.type,title:n.title,body:n.body,readAt:n.read_at,createdAt:n.created_at})));});
app.post('/api/notifications/:id/read',(req,res)=>{const u=requireUser(req,res);if(!u)return;run('UPDATE notifications SET read_at=? WHERE id=? AND user_id=?',[now(),req.params.id,u.id]);res.json({ok:true});});

// Reviews / reputation
app.get('/api/users/:id/reputation',(req,res)=>{const u=requireUser(req,res);if(!u)return;const target=userRow(req.params.id);if(!target)return res.status(404).json({error:'User not found.'});const stats=one('SELECT ROUND(AVG(rating),1) avg,COUNT(*) count FROM reviews WHERE reviewee_id=?',[target.id]);const counts=one("SELECT COUNT(*) completed FROM jobs WHERE runner_id=? AND status='COMPLETED'",[target.id]);res.json({user:{id:target.id,name:target.name,verified:target.verification_status==='APPROVED'},average:stats?.avg??null,reviews:stats?.count??0,completedJobs:counts?.completed??0});});
app.post('/api/reviews',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.body?.jobId)]);const rating=Number(req.body?.rating),comment=clean(req.body?.comment,500);if(!j||j.status!=='COMPLETED'||!assertJobParticipant(u,j)||!j.runner_id)return res.status(400).json({error:'You can only review a completed job you participated in.'});const reviewee=u.id===j.requester_id?j.runner_id:j.requester_id;if(reviewee===u.id)return res.status(400).json({error:'You cannot review yourself.'});if(!Number.isInteger(rating)||rating<1||rating>5)return res.status(400).json({error:'Rating must be 1 to 5.'});try{tx(()=>{run('INSERT INTO reviews(id,job_id,reviewer_id,reviewee_id,rating,comment,created_at) VALUES(?,?,?,?,?,?,?)',[uid(),j.id,u.id,reviewee,rating,comment,now()]);notify(reviewee,'REVIEW','New review',`${u.name} left you a ${rating}-star review.`);audit(u.id,'REVIEW_CREATED','job',j.id,{rating});});res.status(201).json({ok:true});}catch(e){if(String(e.message).includes('UNIQUE'))return res.status(409).json({error:'You already reviewed this job.'});throw e;}});

// Safety/disputes
app.post('/api/incidents',(req,res)=>{const u=requireUser(req,res);if(!u)return;const description=clean(req.body?.description,1000),type=clean(req.body?.type,40)||'OTHER';const jobId=req.body?.jobId?Number(req.body.jobId):null;if(!description)return res.status(400).json({error:'Describe the incident.'});if(jobId){const j=one('SELECT * FROM jobs WHERE id=?',[jobId]);if(!j||!assertJobParticipant(u,j))return res.status(404).json({error:'Job not found.'});}const incident={id:uid(),reporterId:u.id,jobId,type,description,status:'OPEN',createdAt:now()};run('INSERT INTO incidents(id,reporter_id,job_id,type,description,status,created_at) VALUES(?,?,?,?,?,?,?)',[incident.id,u.id,jobId,type,description,'OPEN',incident.createdAt]);audit(u.id,'INCIDENT_REPORTED','incident',incident.id,{jobId});res.status(201).json({ok:true,incidentId:incident.id});});
app.post('/api/disputes',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=?',[Number(req.body?.jobId)]),reason=clean(req.body?.reason,1000);if(!j||!assertJobParticipant(u,j))return res.status(404).json({error:'Job not found.'});if(!reason)return res.status(400).json({error:'Give a reason for the dispute.'});if(['COMPLETED','CANCELLED','DISPUTED'].includes(j.status))return res.status(409).json({error:'This job cannot be disputed now.'});const d={id:uid(),jobId:j.id,openedBy:u.id,reason,status:'OPEN',createdAt:now()};tx(()=>{run('INSERT INTO disputes(id,job_id,opened_by,reason,status,created_at) VALUES(?,?,?,?,?,?)',[d.id,j.id,u.id,reason,'OPEN',d.createdAt]);run("UPDATE jobs SET status='DISPUTED',payment_status='DISPUTED',updated_at=? WHERE id=?",[now(),j.id]);notify(j.requester_id===u.id?j.runner_id:j.requester_id,'DISPUTE','Job dispute opened',`A dispute was opened for Job #${j.id}.`);audit(u.id,'DISPUTE_OPENED','dispute',d.id,{jobId:j.id});});res.status(201).json(d);});

// Payments
app.get('/api/payments/status',(req,res)=>res.json({enabled:process.env.PAYMENTS_ENABLED==='true',provider:process.env.PAYMENT_PROVIDER||null,mode:process.env.PAYMENT_MODE||'sandbox'}));
function payfastSignature(data,passphrase){const ordered=Object.entries(data).filter(([k,v])=>k!=='signature'&&k!=='setup'&&v!==''&&v!=null).map(([k,v])=>`${k}=${encodeURIComponent(String(v).trim()).replace(/%20/g,'+')}`).join('&');const source=passphrase?`${ordered}&passphrase=${encodeURIComponent(passphrase.trim()).replace(/%20/g,'+')}`:ordered;return crypto.createHash('md5').update(source).digest('hex');}
app.post('/api/payments/create',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const j=one('SELECT * FROM jobs WHERE id=? AND requester_id=?',[Number(req.body?.jobId),u.id]);if(!j)return res.status(404).json({error:'Job not found.'});if(process.env.PAYMENTS_ENABLED!=='true')return res.status(503).json({error:'Payments are not configured.'});if(j.payment_status!=='PENDING_PAYMENT')return res.status(409).json({error:'This job does not need payment.'});if((process.env.PAYMENT_PROVIDER||'').toLowerCase()!=='payfast')return res.status(503).json({error:'No supported checkout provider is configured.'});const {PAYFAST_MERCHANT_ID:merchantId,PAYFAST_MERCHANT_KEY:merchantKey,PAYFAST_PASSPHRASE:passphrase,PUBLIC_BASE_URL:baseUrl}=process.env;if(!merchantId||!merchantKey||!passphrase||!baseUrl)return res.status(503).json({error:'PayFast credentials are incomplete.'});const buyer=u.name.split(/\s+/);const data={merchant_id:merchantId,merchant_key:merchantKey,return_url:`${baseUrl}/?payment=success`,cancel_url:`${baseUrl}/?payment=cancelled`,notify_url:`${baseUrl}/api/payments/payfast/itn`,name_first:buyer[0]||u.name,name_last:buyer.slice(1).join(' '),email_address:u.email,m_payment_id:`job-${j.id}`,amount:Number(j.total_price).toFixed(2),item_name:`SwiftShift Job #${j.id}`,item_description:j.title,custom_int1:j.id};data.signature=payfastSignature(data,passphrase);res.json({provider:'payfast',action:process.env.PAYMENT_MODE==='live'?'https://www.payfast.co.za/eng/process':'https://sandbox.payfast.co.za/eng/process',fields:data});});
app.post('/api/payments/payfast/itn',(req,res)=>{const d=req.body||{},jId=String(d.m_payment_id||'').replace(/^job-/,'');const j=one('SELECT * FROM jobs WHERE id=?',[Number(jId)]);if(!j)return res.status(404).send('');if(!process.env.PAYFAST_PASSPHRASE||d.merchant_id!==process.env.PAYFAST_MERCHANT_ID||d.signature!==payfastSignature(d,process.env.PAYFAST_PASSPHRASE))return res.status(401).send('');if(d.payment_status!=='COMPLETE')return res.status(200).send('OK');if(Number(j.total_price).toFixed(2)!==Number(d.amount_gross||0).toFixed(2))return res.status(400).send('');if(j.payment_status==='PAID_CONFIRMED')return res.status(200).send('OK');run("UPDATE jobs SET payment_status='PAID_CONFIRMED',payment_provider='payfast',payment_reference=?,paid_at=?,updated_at=? WHERE id=?",[clean(d.pf_payment_id,100),now(),now(),j.id]);notify(j.requester_id,'PAYMENT','Payment confirmed',`Payment for Job #${j.id} was confirmed.`);audit(null,'PAYFAST_PAYMENT_CONFIRMED','job',j.id,{reference:d.pf_payment_id});res.status(200).send('OK');});

// Payouts
app.get('/api/payouts',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const rows=q('SELECT * FROM payouts WHERE runner_id=? ORDER BY created_at DESC',[u.id]);res.json(rows.map(p=>({id:p.id,jobId:p.job_id,amount:p.amount,status:p.status,createdAt:p.created_at,releasedAt:p.released_at})));});
app.post('/api/payouts/request',(req,res)=>{const u=requireVerified(req,res);if(!u)return;const pending=q("SELECT * FROM payouts WHERE runner_id=? AND status='PENDING_PROVIDER'",[u.id]);if(!pending.length)return res.status(409).json({error:'No payout is currently ready.'});res.status(501).json({error:'Payout execution still requires an approved payout provider and verified bank-account flow.'});});

// Admin dashboard / operations
app.get('/api/admin/overview',(req,res)=>{const admin=requireAdmin(req,res);if(!admin)return;const metrics={users:one('SELECT COUNT(*) c FROM users').c,verifiedUsers:one("SELECT COUNT(*) c FROM users WHERE verification_status='APPROVED'").c,openJobs:one("SELECT COUNT(*) c FROM jobs WHERE status='SEARCHING'").c,activeJobs:one("SELECT COUNT(*) c FROM jobs WHERE status IN ('ACCEPTED','HEADING_TO_PICKUP','ARRIVED','IN_PROGRESS','HEADING_TO_DESTINATION')").c,completedJobs:one("SELECT COUNT(*) c FROM jobs WHERE status='COMPLETED'").c,openDisputes:one("SELECT COUNT(*) c FROM disputes WHERE status='OPEN'").c,openIncidents:one("SELECT COUNT(*) c FROM incidents WHERE status='OPEN'").c,revenue:one("SELECT COALESCE(SUM(platform_fee),0) n FROM jobs WHERE status='COMPLETED'").n};const ver=q("SELECT v.*,u.name,u.email FROM verification_requests v JOIN users u ON u.id=v.user_id WHERE v.status='PENDING' ORDER BY v.created_at");const disputes=q("SELECT d.*,j.title,u.name opener FROM disputes d JOIN jobs j ON j.id=d.job_id JOIN users u ON u.id=d.opened_by WHERE d.status='OPEN' ORDER BY d.created_at");const incidents=q("SELECT i.*,u.name reporter FROM incidents i JOIN users u ON u.id=i.reporter_id WHERE i.status='OPEN' ORDER BY i.created_at");const jobs=q('SELECT * FROM jobs ORDER BY created_at DESC LIMIT 50').map(jobView);const users=q('SELECT id,name,email,role,verification_status,availability,created_at FROM users ORDER BY created_at DESC LIMIT 100').map(u=>({id:u.id,name:u.name,email:u.email,role:u.role,verificationStatus:u.verification_status,availability:!!u.availability,createdAt:u.created_at}));res.json({metrics,verificationRequests:ver,disputes,incidents,jobs,users,audit:q('SELECT * FROM audit ORDER BY created_at DESC LIMIT 100').map(a=>({...a,metadata:parseJson(a.metadata)}))});});
app.post('/api/admin/verifications/:id',(req,res)=>{const admin=requireAdmin(req,res);if(!admin)return;const v=one('SELECT * FROM verification_requests WHERE id=?',[req.params.id]);if(!v)return res.status(404).json({error:'Verification request not found.'});const decision=req.body?.decision;if(!['APPROVED','REJECTED'].includes(decision))return res.status(400).json({error:'Invalid decision.'});tx(()=>{run('UPDATE verification_requests SET status=?,reviewed_at=?,reviewed_by=? WHERE id=?',[decision,now(),admin.id,v.id]);run('UPDATE users SET verification_status=? WHERE id=?',[decision,v.user_id]);notify(v.user_id,'VERIFICATION',`Verification ${decision.toLowerCase()}`,decision==='APPROVED'?'Your SwiftShift account is verified.':'Your verification was rejected. Please contact support.');audit(admin.id,`VERIFICATION_${decision}`,'verification',v.id,{userId:v.user_id});});res.json({ok:true});});
app.post('/api/admin/disputes/:id',(req,res)=>{const admin=requireAdmin(req,res);if(!admin)return;const d=one('SELECT * FROM disputes WHERE id=?',[req.params.id]);if(!d)return res.status(404).json({error:'Dispute not found.'});const decision=req.body?.decision;if(!['REFUND_REQUESTER','RELEASE_RUNNER'].includes(decision))return res.status(400).json({error:'Invalid decision.'});const j=one('SELECT * FROM jobs WHERE id=?',[d.job_id]);tx(()=>{run('UPDATE disputes SET status=?,resolved_at=?,resolved_by=?,decision=? WHERE id=?',['RESOLVED',now(),admin.id,decision,d.id]);run('UPDATE jobs SET status=?,payment_status=?,updated_at=? WHERE id=?',['COMPLETED',decision==='REFUND_REQUESTER'?'REFUND_PENDING':'RELEASE_PENDING',now(),j.id]);notify(j.requester_id,'DISPUTE_RESOLVED','Dispute resolved',`Job #${j.id}: ${decision.replaceAll('_',' ').toLowerCase()}.`);if(j.runner_id)notify(j.runner_id,'DISPUTE_RESOLVED','Dispute resolved',`Job #${j.id}: ${decision.replaceAll('_',' ').toLowerCase()}.`);audit(admin.id,'DISPUTE_RESOLVED','dispute',d.id,{decision});});res.json({ok:true});});
app.post('/api/admin/incidents/:id/resolve',(req,res)=>{const admin=requireAdmin(req,res);if(!admin)return;run("UPDATE incidents SET status='RESOLVED',resolved_at=? WHERE id=? AND status='OPEN'",[now(),req.params.id]);audit(admin.id,'INCIDENT_RESOLVED','incident',req.params.id);res.json({ok:true});});

app.use('/api',(req,res)=>res.status(404).json({error:'Not found.'}));
app.use((err,req,res,next)=>{if(res.headersSent)return next(err);res.status(err.status||500).json({error:err.status===400?'Invalid request.':'Server error.'});});
app.use(express.static(path.join(__dirname,'public')));
app.get('/*splat',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

if(process.env.BOOTSTRAP_ADMIN_EMAIL&&process.env.BOOTSTRAP_ADMIN_PASSWORD&&!one('SELECT id FROM users WHERE email=?',[process.env.BOOTSTRAP_ADMIN_EMAIL.toLowerCase()])){
  run('INSERT INTO users(id,name,email,password_hash,role,verification_status,terms_accepted_at,created_at) VALUES(?,?,?,?,?,?,?,?)',[uid(),'SwiftShift Admin',process.env.BOOTSTRAP_ADMIN_EMAIL.toLowerCase(),hashPassword(process.env.BOOTSTRAP_ADMIN_PASSWORD),'admin','APPROVED',now(),now()]);
}

app.listen(PORT,()=>console.log(`SwiftShift running at http://localhost:${PORT}`));
