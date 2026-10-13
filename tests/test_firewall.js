/* Offline test harness. No Google API calls. Run: node tests/test_firewall.js */
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const code = fs.readFileSync(__dirname+'/../Code.gs','utf8');
const addonCode = fs.readFileSync(__dirname+'/../GmailAddon.gs','utf8');
function env() {
  const properties = new Map(), byID = new Map(), labelByName = new Map(), messages = new Map();
  let sheetIndex=0;
  class Sheet {
    constructor(name){this.name=name;this.rows=[];}
    getName(){return this.name;}
    setName(s){this.name=s;}
    appendRow(v){this.rows.push(v);}
    getLastRow(){return this.rows.length;}
    getRange(r,c,rs,cs){return {getValues:()=>Array.from({length:rs},(_,i)=>Array.from({length:cs},(_,j)=>(this.rows[r-1+i]||[])[c-1+j]??'')),setValues:(data)=>{data.forEach((v,i)=>{this.rows[r-1+i] ||= [];v.forEach((val,j)=>this.rows[r-1+i][c-1+j]=val);});}};}
    getDataRange(){const sh=this; return {getValues:()=>sh.rows.map(x=>x.slice())};}
    deleteRow(i){this.rows.splice(i-1,1);}
  }
  class Book{constructor(id){this.id=id;this.sheets=[new Sheet('Sheet1')];}
    getSheets(){return this.sheets;}getSheetByName(name){return this.sheets.find(x=>x.name===name)||null;}
    insertSheet(name){const x=new Sheet(name);this.sheets.push(x);return x;}getId(){return this.id;}}
  const parent='ZZ', oldParent='ZZ-Firewall';
  const aliases={AF_AI_NOISE:'AF_N',AF_AI_KEEP:'AF_K',AF_FORCE_BLOCK:'AF_FB',
    AF_ALLOW:'AF_A',AF_ALLOWED_DONE:'AF_AD',AF_CHECKED:'AF_C',AF_SUPPRESSED:'AF_S',
    AF_REVIEW:'AF_R',AF_PRIORITY_REVIEW:'AF_PR',AF_PENDING:'AF_P',
    AF_RULE_NOISE:'AF_RN',AF_KEEP_AUDITED:'AF_KA'};
  const reverse=Object.fromEntries(Object.entries(aliases).map(([k,v])=>[v,k]));
  const vis=new Map();
  const resolveName=(name)=>{
    if(name.startsWith(oldParent+'-'))name=oldParent+'/'+name.slice(oldParent.length+1);
    else if(!name.startsWith(oldParent+'/') && name.startsWith(parent+'-'))name=parent+'/'+name.slice(parent.length+1);
    if(name.startsWith('AF_')) {
      for(const n of [parent+'/'+aliases[name],oldParent+'/'+name,name])
        if(labelByName.has(n))return n;
    }
    return name;
  };
  const getLabel=(name)=>{
    const effective=resolveName(name);
    if(!labelByName.has(effective)) {
      const tail=effective.split('/').pop();
      const logical=reverse[tail]||tail;
      const base='LBL-'+logical;
      const id=[...labelByName.values()].includes(base)?base+'-DUP-'+labelByName.size:base;
      labelByName.set(effective,id);
    }
    return labelByName.get(effective);
  };
  const gmail={Users:{Labels:{
    list:()=>({labels:Array.from(labelByName,([name,id])=>({name,id,...(vis.get(id)||{})}))}),
    create:(args)=>{
      const id=getLabel(args.name);vis.set(id,{messageListVisibility:args.messageListVisibility||'show',labelListVisibility:args.labelListVisibility||'labelShow'});
      return {id,name:args.name};
    },
    patch:(args,_user,id)=>{
      const entry=[...labelByName.entries()].find(([k,v])=>v===id);
      if(!entry)throw Error('Missing original label ID '+id);
      const next=args.name||entry[0];
      if(next!==entry[0]&&labelByName.has(next))throw Error('Duplicate target label '+next);
      if(next!==entry[0]){labelByName.delete(entry[0]);labelByName.set(next,id);}
      vis.set(id,{...(vis.get(id)||{}),...(args.messageListVisibility?{messageListVisibility:args.messageListVisibility}:{}),
        ...(args.labelListVisibility?{labelListVisibility:args.labelListVisibility}:{}),
        ...(args.color?{color:{...args.color}}:{})});
      return {name:next,id};
    }
  },Messages:{
    list:(_user,{q='',maxResults,labelIds=[]})=>{const terms=(q.match(/(?:\S*\"[^\"]*\"\S*|\S+)/g)||[]); const ids=[...messages.values()].filter(m=>{
      return labelIds.every(id=>m.labelIds.includes(id)) && terms.every(t=>{
      if(t==='in:inbox')return m.labelIds.includes('INBOX');
      if(t.startsWith('label:'))return m.labelIds.includes(getLabel(t.slice(6)));
      if(t.startsWith('-label:'))return !m.labelIds.includes(getLabel(t.slice(7)));
      if(t.startsWith('newer_than:'))return true;
      return true;});}).slice(0,maxResults).map(m=>({id:m.id}));return {messages:ids};},
    get:(_u,id,{format})=>{const m=messages.get(id);if(!m)throw Error('No message '+id);return {...m,payload:{headers:m.headers, ...(format==='full'?{mimeType:'text/plain',body:{data:Buffer.from(m.body||'').toString('base64url')}}:{})}};},
    modify:({addLabelIds=[],removeLabelIds=[]},_u,id)=>{const m=messages.get(id);if(!m)throw Error('no message');m.labelIds=[...new Set([...m.labelIds.filter(x=>!removeLabelIds.includes(x)),...addLabelIds])];}
  }}};
  gmail.Users.Threads={get:(_u,threadId,_options)=>({id:threadId,messages:[...messages.values()].filter(m=>m.threadId===threadId).map(m=>({...m,payload:{headers:m.headers}}))})};
  const props={getProperty:(k)=>properties.get(k)||null,setProperty:(k,v)=>properties.set(k,String(v)),deleteProperty:(k)=>properties.delete(k)};
  const logs=[];
  const context={console:{log:s=>logs.push(s),warn:s=>logs.push(s),error:s=>logs.push(s)},
    Gmail:gmail,GmailApp:{setCurrentMessageAccessToken:()=>{},getMessageById:id=>{const m=messages.get(id);if(!m)throw Error('No message '+id);return {getId:()=>id,getPlainBody:()=>m.body||'',getThread:()=>({getId:()=>m.threadId,getMessages:()=>[...messages.values()].filter(x=>x.threadId===m.threadId).map(x=>({getId:()=>x.id}))})};}},
    SpreadsheetApp:{create:()=>{const b=new Book('ledger'+(++sheetIndex));byID.set(b.id,b);return b;},openById:id=>byID.get(id)},
    PropertiesService:{getScriptProperties:()=>props},
    ScriptApp:{getProjectTriggers:()=>[],newTrigger:()=>({timeBased:()=>({everyMinutes:()=>({create:()=>{}})})}),deleteTrigger:()=>{}},
    LockService:{getScriptLock:()=>({tryLock:()=>true,releaseLock:()=>{}})},
    Utilities:{formatDate:()=>('2026-10-10'),newBlob:(buf)=>({getDataAsString:()=>Buffer.from(buf).toString('utf8')}),
      base64Decode:v=>{ if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v))
          throw Error('Could not decode string.'); return Buffer.from(v,'base64');},
      base64EncodeWebSafe:v=>Buffer.from(v).toString('base64url')},
    UrlFetchApp:{fetch:()=>{throw Error('No external requests allowed in v1.2');}},
    Date,Set,Map,JSON,RegExp,String,Number,Array,Math,Error,parseInt,Boolean};
  vm.createContext(context);vm.runInContext(code,context);vm.runInContext(addonCode,context);
  const call=(name,...args)=>vm.runInContext(name,context)(...args);
  const mk=(id,{subject='Re: Invitation to a Conversation on ...',labels=['INBOX'],thread='thread-'+id,messageId='<'+id+'@example.edu>',inReplyTo='',refs='',body='Hello.',sender='news@example.edu'}={})=>{
    const m={id,threadId:thread,labelIds:labels.map(n=>['INBOX','UNREAD','TRASH','SPAM'].includes(n)?n:getLabel(n)),internalDate:String(Date.now()-3600000),headers:[
      {name:'Subject',value:subject},{name:'From',value:sender},{name:'To',value:'faculty@lists.example.edu'},
      {name:'Message-ID',value:messageId},{name:'In-Reply-To',value:inReplyTo},{name:'References',value:refs}],body};messages.set(id,m);return m;};
  const has=(m,l)=>m.labelIds.includes(['INBOX','UNREAD','TRASH','SPAM'].includes(l)?l:getLabel(l));
  const sheet=n=>byID.get(props.getProperty('AF_DB_ID')).getSheetByName(n);
  return {call,mk,has,sheet,props,logs,messages,context,getLabel,labelByName,vis,aliases};
}
let count=0;
function test(name,fn){try{fn();console.log('PASS',name);count++;}catch(e){console.error('FAIL',name,e);process.exitCode=1;}}
test('Migration renames existing labels into one parent without losing IDs or mail',()=>{
 const e=env();
 const m=e.mk('legacy-before-setup',{labels:['INBOX','AF_AI_NOISE']});
 const idBefore=e.getLabel('AF_AI_NOISE');
 e.call('setupFirewall');
 assert.equal(e.getLabel('AF_AI_NOISE'),idBefore);
 assert(e.labelByName.has('ZZ/AF_N'));
 assert(!e.labelByName.has('AF_AI_NOISE'));
 assert(e.has(m,'AF_AI_NOISE'));
 e.call('organizeFirewallLabels');
 assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
 assert.equal(e.props.getProperty('AF_LABEL_LAYOUT'),'COMPACT');
 e.call('scanMailbox');
 assert(e.has(m,'AF_REVIEW'));
 e.call('checkNestedLabelSearch');
});
test('All 12 firewall labels are nested, with no duplicated flat labels',()=>{
 const e=env();e.call('setupFirewall');
 assert.equal([...e.labelByName.keys()].filter(k=>k.startsWith('ZZ/')).length,12);
 assert.equal([...e.labelByName.keys()].filter(k=>k.startsWith('AF_')).length,0);
 e.call('setupFirewall');
 assert.equal([...e.labelByName.keys()].filter(k=>k.startsWith('ZZ/')).length,12);
});
test('Noise label is red by default; another label color is left unchanged',()=>{
 const e=env();e.call('setupFirewall');
 const noise=e.getLabel('AF_AI_NOISE'), keep=e.getLabel('AF_AI_KEEP');
 assert.equal(e.vis.get(noise).color.backgroundColor,'#cc3a21');
 assert.equal(e.vis.get(noise).color.textColor,'#ffffff');
 assert.equal(e.vis.get(keep).color,undefined);
 e.call('setNoiseLabelRed');
 assert(e.logs.some(line=>String(line).includes('now red')));
 assert.equal(e.vis.get(keep).color,undefined);
});
test('Existing AF_CHECKED from legacy Studio flow becomes AF_PENDING rather than approved',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('older',{labels:['INBOX','AF_CHECKED']});e.call('scanMailbox');assert(e.has(m,'AF_PENDING'));assert(!e.has(m,'AF_REVIEW'));assert.equal(e.sheet('Pending').getLastRow(),2);
 e.call('scanMailbox');assert.equal(e.sheet('Pending').getLastRow(),2);});
test('Shared announcement address is not blanket-blocked; unclassified remains pending',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('notice',{subject:'Important administrative announcement',sender:'announcement@lists.example.edu'});
 e.call('scanMailbox');assert(e.has(m,'AF_PENDING'));assert(e.has(m,'INBOX'));});
test('Studio KEEP protects required workshop from university shared sender',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('mandatory',{subject:'Mandatory Example University training workshop',labels:['INBOX','AF_AI_KEEP'],sender:'announcement@lists.example.edu'});
 e.call('scanMailbox');assert(e.has(m,'INBOX'));assert(!e.has(m,'AF_REVIEW'));});
test('Studio NOISE is labeled AF_REVIEW with no archiving in DRY_RUN',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('invite',{subject:'Invitation to voluntary yoga program',labels:['INBOX','AF_AI_NOISE']});e.call('scanMailbox');assert(e.has(m,'AF_REVIEW'));assert(e.has(m,'INBOX'));assert(e.sheet('Audit').rows.some(r=>r[1]==='WOULD_ARCHIVE'));});
test('Manual FORCE_BLOCK dry-run adds review without persisting keys',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('forced',{labels:['INBOX','AF_FORCE_BLOCK']});e.call('scanMailbox');assert(e.has(m,'AF_REVIEW'));assert.equal(e.sheet('BlockedKeys').getLastRow(),1);});
test('LIVE: suppressed original is remembered; reply with new Gmail thread ID matches RFC chain',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');const orig=e.mk('orig',{labels:['INBOX','AF_FORCE_BLOCK'],thread:'t-old',messageId:'<orig-123@example.edu>'});e.call('scanMailbox');assert(!e.has(orig,'INBOX'));assert(e.sheet('BlockedKeys').getLastRow()>1);e.messages.delete('orig');
 const reply=e.mk('later',{labels:['INBOX'],thread:'t-new',messageId:'<later-456@example.edu>',inReplyTo:'<orig-123@example.edu>',refs:'<orig-123@example.edu>',subject:'Re: Cultural invitation'});
 e.call('scanMailbox');assert(!e.has(reply,'INBOX'));assert(e.has(reply,'AF_SUPPRESSED'));});
test('Protected subject overrides an AI noise decision',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');const m=e.mk('exam',{subject:'CSE221 final exam schedule',labels:['INBOX','AF_AI_NOISE']});e.call('scanMailbox');assert(e.has(m,'INBOX'));assert(e.has(m,'AF_PRIORITY_REVIEW'));});
test('v1.2 automatically disables and removes Gemini key on upgrade',()=>{
 const e=env();e.call('setupFirewall');e.props.setProperty('AF_GEMINI_API_KEY','OLD_KEY');e.props.setProperty('AF_FALLBACK_ENABLED','true');
 e.call('goLive');e.call('upgradeFirewallV12');
 assert.equal(e.props.getProperty('AF_GEMINI_API_KEY'),null);assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
 assert.equal(e.props.getProperty('AF_FALLBACK_ENABLED'),'false');
});
test('Rule matches the exact feminism invitation sample',()=>{
 const e=env();e.call('setupFirewall');e.call('testFreeRules');
});
test('Old pending event is classified locally without external API, dry-run only',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('feminism',{subject:'Invitation to a Conversation on Transitional Feminism & Women’s Mobilization to Claim Justice',
   labels:['INBOX','AF_CHECKED'],to:'all@example.edu',body:'Dear colleagues, the Department of English and Humanities is delighted to invite you to an upcoming event. Date: October 12, 2026. Time: 3:30 PM. Venue: Classroom. Speaker bios: ...'});
 e.call('scanMailbox');assert(e.has(m,'AF_PENDING'));
 const pending=e.sheet('Pending');pending.rows[1][1]=new Date(Date.now()-15*60000);
 e.call('scanMailbox');assert(e.has(m,'AF_RULE_NOISE'));assert(e.has(m,'AF_REVIEW'));assert(e.has(m,'INBOX'));
 assert(e.sheet('Audit').rows.some(r=>r[1]==='WOULD_ARCHIVE' && r[2]==='RULE_OPTIONAL_BROADCAST_EVENT'));
});
test('Important policy from same mailing list never rule-suppressed',()=>{
 const e=env();e.call('setupFirewall');
 const m=e.mk('official',{subject:'Mandatory university policy training workshop',labels:['INBOX','AF_CHECKED'],sender:'announcement@lists.example.edu',
 body:'Dear colleagues, required attendance for official university policy. Date: Oct 16. Venue: campus.'});
 e.call('scanMailbox');assert(e.has(m,'INBOX'));assert(!e.has(m,'AF_RULE_NOISE'));
});
test('Optional event to one recipient is held pending, not auto-hidden',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('one',{subject:'Invitation to our theatre performance',labels:['INBOX'],sender:'colleague@example.edu',
 body:'You are cordially invited! Venue: Campus auditorium.'});
 m.headers.find(x=>x.name==='To').value='lecturer@example.edu';
 e.call('scanMailbox');const pending=e.sheet('Pending');pending.rows[1][1]=new Date(Date.now()-15*60000);
 e.call('scanMailbox');assert(e.has(m,'INBOX'));assert(!e.has(m,'AF_RULE_NOISE'));
});
test('Studio KEEP corrects a local rule flag in dry-run',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('correction',{subject:'Yoga and cultural night',labels:['INBOX'],body:'Dear colleagues, join us at the event. Date: Friday. Venue: Auditorium.'});
 e.call('scanMailbox');e.sheet('Pending').rows[1][1]=new Date(Date.now()-15*60000);e.call('scanMailbox');assert(e.has(m,'AF_RULE_NOISE'));
 m.labelIds.push('LBL-AF_AI_KEEP');e.call('scanMailbox');assert(!e.has(m,'AF_RULE_NOISE'));assert(!e.has(m,'AF_REVIEW'));assert(e.has(m,'INBOX'));
});
test('No classification becomes pending rather than being falsely classified as keep/noise',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('unknown',{subject:'Hello',labels:['INBOX','AF_CHECKED'],body:'Dear colleague, can you spare time to discuss a matter?'});
 e.call('scanMailbox');assert(e.has(m,'AF_PENDING'));assert(!e.has(m,'AF_RULE_NOISE'));
});
test('LIVE rule-based suppression remembers identifiers for deleted-original replies',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const orig=e.mk('eventOrig',{subject:'Invitation to a Conversation on Transitional Feminism',labels:['INBOX'],thread:'event-t1',
   messageId:'<optional-event-123@example.edu>',body:'Dear colleagues, we are delighted to invite you to an upcoming event. Date: 12 Oct. Time: 3PM. Venue: Auditorium.'});
 e.call('scanMailbox');e.sheet('Pending').rows[1][1]=new Date(Date.now()-15*60000);
 e.call('scanMailbox');assert(!e.has(orig,'INBOX'));assert(e.has(orig,'AF_RULE_NOISE'));
 assert(e.sheet('BlockedKeys').getLastRow()>1);e.messages.delete('eventOrig');
 const reply=e.mk('eventReply',{subject:'Re: Invitation to a Conversation on Transitional Feminism',labels:['INBOX'],thread:'event-t2',
   messageId:'<event-followup-456@example.edu>',inReplyTo:'<optional-event-123@example.edu>',refs:'<optional-event-123@example.edu>',body:'Thank you for the invitation.'});
 e.call('scanMailbox');assert(!e.has(reply,'INBOX'));assert(e.has(reply,'AF_SUPPRESSED'));
});
test('Later Studio KEEP can stop an important message on a known blocked thread',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const first=e.mk('unwanted',{subject:'Cultural Night',labels:['INBOX','AF_FORCE_BLOCK'],thread:'same',messageId:'<first@example.edu>'});
 e.call('scanMailbox');
 const m=e.mk('importantLater',{subject:'CSE221 exam schedule',labels:['INBOX','AF_AI_KEEP'],thread:'different',
   inReplyTo:'<first@example.edu>',refs:'<first@example.edu>'});
 e.call('scanMailbox');assert(e.has(m,'INBOX'));assert(!e.has(m,'AF_SUPPRESSED'));
});
test('After goLive, already reviewed rule noise is archived on next scan',()=>{
 const e=env();e.call('setupFirewall');const m=e.mk('drySeen',{subject:'Yoga and cultural night',labels:['INBOX'],
 body:'Dear colleagues, join us at the event. Date: Friday. Venue: Auditorium.'});
 e.call('scanMailbox');e.sheet('Pending').rows[1][1]=new Date(Date.now()-15*60000);e.call('scanMailbox');
 assert(e.has(m,'AF_REVIEW'));assert(e.has(m,'INBOX'));e.call('goLive');e.call('scanMailbox');assert(!e.has(m,'INBOX'));
});
test('Rule function never marks direct academic research invitation as NOISE',()=>{
 const e=env();e.call('setupFirewall');
 const m={subject:'Invitation to a CSE software engineering collaboration workshop',to:'faculty@lists.example.edu',
 body:'Dear colleagues, we invite you to join us for research collaboration. Date: Monday. Venue: Seminar Room.'};
 assert.equal(e.call('freeRuleDecision_',m).decision,'PENDING');
});
test('Gmail MIME decoder handles unpadded URL-safe Base64 and Bangla body',()=>{
  const e=env();e.call('testGmailMimeDecoding');
});
test('Malformed Gmail MIME body stays pending and never gets RULE_NOISE',()=>{
  const e=env();e.call('setupFirewall');const m=e.mk('malformed',{subject:'Invitation to Drama Night',
    body:'Dear colleagues, join us. Date: Monday. Venue: Auditorium.'});
  e.call('scanMailbox');e.sheet('Pending').rows[1][1]=new Date(Date.now()-15*60000);
  const old=e.context.Gmail.Users.Messages.get;
  e.context.Gmail.Users.Messages.get=(_u,id,options)=>{
    const r=old(_u,id,options);
    if(options.format==='full')r.payload.body.data='bad*base64!';
    return r;
  };
  e.call('scanMailbox');assert(e.has(m,'AF_PENDING'));assert(!e.has(m,'AF_RULE_NOISE'));
  assert.equal(e.sheet('Pending').rows[1][4],'RETRY_RULE_ERROR');
});
test('Hotfix only resets failed decode attempts and stays DRY_RUN',()=>{
  const e=env();e.call('setupFirewall');const m=e.mk('retry');e.call('scanMailbox');
  const sh=e.sheet('Pending');sh.rows[1][2]=new Date();sh.rows[1][4]='RETRY_RULE_ERROR';
  e.call('goLive');e.call('upgradeFirewallV121');
  assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
  assert.equal(sh.rows[1][2],'');
  assert.equal(sh.rows[1][4],'PENDING_LOCAL_RULE');
});

const keepCases = [
 ['ceremony','Invitation to the Inauguration Ceremony | Example University Silver Jubilee National Career Fair 2026',
  'Dear Distinguished Guests, Warm greetings from the Office. You are cordially invited to the opening ceremony. Date: 11 October. Venue: Auditorium.'],
 ['lecture','Invitation: Public lecture on “Transitional Feminism & Women’s Mobilization to Claim Justice” by ENH',
  'Dear students and faculty members, The Department of English and Humanities is delighted to invite you. Time: 3:30 PM. Venue: Classroom.'],
 ['condolence','Condolence message',
  'Dear All, It is with deep sorrow that we announce the passing of a colleague’s family member. We extend our sincere condolences.'],
 ['workshop','Invitation: Workshop on Standard Bangla Pronunciation | 15 October 2026',
  'Dear Faculty Members, Greetings from the School of General Education. You are cordially invited to a workshop. Date: 15 October, Venue: Auditorium.']
];
for (const [id,subject,body] of keepCases) test('Studio KEEP mistake corrected: '+id,()=>{
 const e=env();e.call('setupFirewall');e.call('upgradeFirewallV123');
 const m=e.mk(id,{subject,body,labels:['INBOX','AF_AI_KEEP'],sender:'announcement@lists.example.edu'});
 e.call('scanMailbox');
 assert(!e.has(m,'AF_AI_KEEP'));
 assert(e.has(m,'AF_RULE_NOISE'));
 assert(e.has(m,'AF_REVIEW'));
 assert(e.has(m,'AF_KEEP_AUDITED'));
 assert(e.has(m,'INBOX'));
 assert(e.sheet('Audit').rows.some(r=>r[1]==='WOULD_ARCHIVE'));
});
test('Unrelated important administration from shared sender stays KEEP',()=>{
 const e=env();e.call('setupFirewall');e.call('upgradeFirewallV123');
 const m=e.mk('policy',{subject:'Mandatory faculty training - new examination policy',
  body:'Dear Faculty Members, attendance is mandatory for all faculty. Please complete required training by Monday. Venue: Auditorium.',
  labels:['INBOX','AF_AI_KEEP'],sender:'announcement@lists.example.edu'});
 e.call('scanMailbox');
 assert(e.has(m,'AF_AI_KEEP'));assert(!e.has(m,'AF_RULE_NOISE'));assert(e.has(m,'INBOX'));
});
test('CSE student advising message stays KEEP',()=>{
 const e=env();e.call('setupFirewall');e.call('upgradeFirewallV123');
 const m=e.mk('student',{subject:'CSE221 student advising: workshop on retake procedures',
  body:'Dear faculty, students must submit retake applications. Mandatory advising meeting.',
  labels:['INBOX','AF_AI_KEEP']});
 e.call('scanMailbox');
 assert(e.has(m,'AF_AI_KEEP'));assert(!e.has(m,'AF_RULE_NOISE'));
});
test('LIVE second opinion archives misclassified invitation and remembers it',()=>{
 const e=env();e.call('setupFirewall');e.call('upgradeFirewallV123');e.call('goLive');
 const m=e.mk('invite123',{subject:'Invitation: Workshop on Standard Bangla Pronunciation',
  body:'Dear Faculty Members, you are cordially invited. Time: 3 PM. Venue: Auditorium.',
  labels:['INBOX','AF_AI_KEEP'],messageId:'<optional123@example.edu>'});
 e.call('scanMailbox');
 assert(!e.has(m,'INBOX'));assert(e.has(m,'AF_SUPPRESSED'));
 assert(e.sheet('BlockedKeys').getLastRow()>1);
});
test('Upgrade v1.2.3 preserves existing ledger and resets to DRY_RUN',()=>{
 const e=env();e.call('setupFirewall');
 const id=e.props.getProperty('AF_DB_ID');
 e.call('goLive');e.call('upgradeFirewallV123');
 assert.equal(e.props.getProperty('AF_DB_ID'),id);
 assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
});

test('Trash message is skipped before KEEP MIME decode even if search returns it',()=>{
 const e=env();e.call('setupFirewall');e.call('upgradeFirewallV124');
 const m=e.mk('trashedKeep',{subject:'Invitation: Public lecture',labels:['TRASH','AF_AI_KEEP'],
  body:'Dear all, you are invited. Time: Monday. Venue: Auditorium.'});
 const originalList=e.context.Gmail.Users.Messages.list;
 e.context.Gmail.Users.Messages.list=(u,opts)=>{
  if ((opts.q||'').includes('ZZ-AF_K') && (opts.q||'').includes('in:inbox'))return {messages:[{id:m.id}]};
  return originalList(u,opts);
 };
 const get=e.context.Gmail.Users.Messages.get;
 e.context.Gmail.Users.Messages.get=(u,id,o)=>{
   const val=get(u,id,o);
   if(id===m.id&&o.format==='full')val.payload.body.data='bad*base64';
   return val;
 };
 e.call('scanMailbox');
 assert(!e.has(m,'AF_RULE_NOISE'));assert(!e.has(m,'AF_KEEP_AUDITED'));
 assert.equal(e.sheet('Audit').getLastRow(),1);
});
test('LIVE never changes a trashed manual-block message or remembers its keys',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('trashedBlock',{labels:['TRASH','AF_FORCE_BLOCK'],messageId:'<trash@example.edu>'});
 e.call('scanMailbox');assert(e.has(m,'TRASH'));assert(!e.has(m,'AF_SUPPRESSED'));
 assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('Message moved to Trash while pending has technical pending flag cleaned',()=>{
 const e=env();e.call('setupFirewall');
 const m=e.mk('pendingTrash',{subject:'Unknown message',labels:['INBOX'],body:'Hello.'});
 e.call('scanMailbox');assert(e.has(m,'AF_PENDING'));
 m.labelIds=m.labelIds.filter(x=>x!=='INBOX');m.labelIds.push('TRASH');
 e.sheet('Pending').rows[1][1]=new Date(Date.now()-15*60000);
 e.call('scanMailbox');assert.equal(e.sheet('Pending').rows[1][4],'DONE_DISCARDED');
 assert(!e.has(m,'AF_PENDING'));assert(e.has(m,'TRASH'));
});
test('Upgrade v1.2.4 preserves ledger and returns to DRY_RUN',()=>{
 const e=env();e.call('setupFirewall');const db=e.props.getProperty('AF_DB_ID');
 e.call('goLive');e.call('upgradeFirewallV124');
 assert.equal(e.props.getProperty('AF_DB_ID'),db);
 assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
});

test('Apps Script Byte[] MIME: decoded signed UTF-8 Bangla bytes read without Base64',()=>{
  const e=env();e.call('testGmailMimeDecoding');
});
test('KEEP second-opinion: Byte[] message gets ruled NOISE in DRY_RUN',()=>{
  const e=env();e.call('setupFirewall');
  const body='Dear students and faculty members, you are cordially invited to a public lecture. Venue: Auditorium. Time: 3:30 PM.';
  const m=e.mk('keep-byte-array',{subject:'Invitation: Public lecture on Transitional Feminism',labels:['INBOX','AF_AI_KEEP'],body});
  const get=e.context.Gmail.Users.Messages.get;
  e.context.Gmail.Users.Messages.get=(u,id,options)=>{
    const r=get(u,id,options);
    if(options.format==='full' && id==='keep-byte-array') {
      const bytes=Buffer.from(body,'utf8');
      r.payload.body={data:Array.from(bytes,b=>b>127?b-256:b),size:bytes.length};
    }
    return r;
  };
  e.call('scanMailbox');
  assert(e.has(m,'AF_RULE_NOISE'));
  assert(e.has(m,'AF_REVIEW'));
  assert(!e.has(m,'AF_AI_KEEP'));
  assert(e.has(m,'INBOX'));
  assert(!e.logs.some(x=>String(x).includes('KEEP audit failed')));
});
test('KEEP second-opinion: Byte[] mandatory notices remain protected',()=>{
  const e=env();e.call('setupFirewall');
  const body='Dear colleagues, Mandatory training required for faculty. Attendance is required. Venue: Auditorium, Date: Monday.';
  const m=e.mk('keep-mandatory-byte',{subject:'Mandatory Example University faculty policy workshop',labels:['INBOX','AF_AI_KEEP'],body});
  const get=e.context.Gmail.Users.Messages.get;
  e.context.Gmail.Users.Messages.get=(u,id,options)=>{
    const r=get(u,id,options);
    if(options.format==='full' && id==='keep-mandatory-byte') {
      const bytes=Buffer.from(body,'utf8');
      r.payload.body={data:Array.from(bytes,b=>b>127?b-256:b),size:bytes.length};
    }
    return r;
  };
  e.call('scanMailbox');
  assert(!e.has(m,'AF_RULE_NOISE'));
  assert(e.has(m,'AF_AI_KEEP'));
  assert(e.has(m,'INBOX'));
});
test('v1.2.5 migration preserves ledger but resets decode retries and goes DRY_RUN',()=>{
  const e=env();e.call('setupFirewall');
  e.mk('retry-bytes',{labels:['INBOX']});
  e.call('scanMailbox');
  const dbid=e.props.getProperty('AF_DB_ID');
  const sh=e.sheet('Pending');
  sh.rows[1][2]=new Date();sh.rows[1][4]='RETRY_RULE_ERROR';
  e.call('goLive');e.call('upgradeFirewallV125');
  assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
  assert.equal(e.props.getProperty('AF_DB_ID'),dbid);
  assert.equal(sh.rows[1][2],'');
  assert.equal(sh.rows[1][4],'PENDING_LOCAL_RULE');
});

test('Compact labels preserve 12 message IDs during migration from nested old parent',()=>{
 const e=env();
 const names=Object.keys(e.aliases);
 const before={};
 names.forEach(n=>{before[n]=e.getLabel('ZZ-Firewall/'+n);});
 e.props.setProperty('AF_LABEL_IDS', JSON.stringify(before));
 const m=e.mk('keeplegacy',{labels:['INBOX','AF_AI_KEEP']});
 e.call('setupFirewall');
 assert.equal(e.getLabel('AF_AI_KEEP'),before['AF_AI_KEEP']);
 assert(e.has(m,'AF_AI_KEEP'));
 assert.equal(e.labelByName.size,13); // ZZ + 12 short labels; parent in Gmail auto-created, mock does not
 for(const n of names){
   const id=e.getLabel(n);
   assert.equal(id,before[n]);
   assert(e.labelByName.has('ZZ/'+e.aliases[n]));
   const shouldShow=(n==='AF_AI_KEEP'||n==='AF_AI_NOISE');
   assert.equal(e.vis.get(id).messageListVisibility,shouldShow?'show':'hide');
 }
 e.call('checkNestedLabelSearch');
});
test('Migration refuses duplicate labels rather than changing or losing existing IDs',()=>{
 const e=env();
 e.getLabel('ZZ-Firewall/AF_AI_NOISE');e.getLabel('ZZ/AF_N');
 assert.throws(()=>e.call('setupFirewall'),/Conflicting old and new Gmail labels/);
 assert(e.labelByName.has('ZZ-Firewall/AF_AI_NOISE'));
 assert(e.labelByName.has('ZZ/AF_N'));
});
test('Compact mode translates all rules and checks without changing old internal keys',()=>{
 const e=env();e.call('setupFirewall');
 assert.equal(e.call('searchLabelQuery_', 'label:AF_AI_NOISE -label:AF_AI_KEEP'),
  'label:ZZ-AF_N -label:ZZ-AF_K');
 const m=e.mk('keep',{subject:'Important faculty policy',labels:['INBOX','AF_AI_KEEP']});
 e.call('scanMailbox');assert(e.has(m,'AF_AI_KEEP'));
 assert.equal(e.props.getProperty('AF_LABEL_LAYOUT'),'COMPACT');
});
test('Compact re-run does not create new labels or clear LIVE in Gmail unexpectedly',()=>{
 const e=env();e.call('setupFirewall');const before=new Map(e.labelByName);
 e.call('goLive');e.call('compactFirewallLabels');
 assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
 for(const [n,id] of before)assert.equal(e.labelByName.get(n),id);
 assert.equal(e.labelByName.size,before.size);
});
console.log(`Local mocked tests passed: ${count}`);

// v1.2.7: regression cases for optional broadcasts previously marked KEEP.
test('v1.2.7: career fair special sessions invitation is NOISE',()=>{
 const e=env(); const d=e.call('freeRuleDecision_',{
   subject:'Invitation to Special Career Sessions | Example University Silver Jubilee National Career Fair 2026',
   to:'Example University All <campus-all@example.edu>',
   body:'Dear All, Warm greetings from the Office of Career Services & Alumni Relations (Career Office), Example University. As part of the Example University Silver Jubilee National Career Fair 2026, we are pleased to invite you all and encourage you to join our special career sessions featuring experienced professionals and industry leaders. The sessions will offer valuable insights into AI and the future of work, interview preparation, CV development, leadership and career growth. Please find attached the career session posters for the speakers, venues, timings and registration details. We warmly encourage you to join the sessions that interest you and take this opportunity to engage with industry professionals.'});
 assert.equal(d.decision,'NOISE');
 assert.equal(d.reason,'OPTIONAL_CAREER_SESSION_INVITE');
});
test('v1.2.7: required faculty career fair work is protected',()=>{
 const e=env();const d=e.call('freeRuleDecision_',{
  subject:'Invitation to Special Career Sessions | National Career Fair 2026',
  to:'campus-all@example.edu',
  body:'Dear All, attendance is mandatory for assigned CSE faculty. Please register by 12 October and supervise student booths. Event time and venue details enclosed.'});
 assert.equal(d.decision,'PENDING');
});
test('v1.2.7: direct student job request is protected',()=>{
 const e=env();const d=e.call('freeRuleDecision_',{
  subject:'CSE221 student career opportunities and advising',
  to:'lecturer@example.edu',
  body:'Sir, would you review my CV and give advice on internships?'});
 assert.equal(d.decision,'PENDING');
});
test('v1.2.7: generic yoga event is NOISE and official sender alone not blocked',()=>{
 const e=env();const d=e.call('freeRuleDecision_',{
  subject:'Invitation to Yoga Wellness Session',
  sender:'announcement@lists.example.edu',to:'campus-all@example.edu',
  body:'Dear All, You are cordially invited to the yoga wellness session. Time: 3 PM. Venue: Multipurpose Hall.'});
 assert.equal(d.decision,'NOISE');
});
test('v1.2.7: migration resets audited invitation and scanner reclassifies K as RN',()=>{
 const e=env();e.call('setupFirewall');
 const m=e.mk('old-career',{labels:['INBOX','AF_AI_KEEP','AF_KEEP_AUDITED'],
  subject:'Invitation to Special Career Sessions | Example University Silver Jubilee National Career Fair 2026',
  body:'Dear All, we warmly encourage you to join the sessions. Career session posters, speakers, venues, timings and registration details are attached.'});
 assert(e.has(m,'AF_KEEP_AUDITED'));
 e.call('upgradeFirewallV127');
 assert(!e.has(m,'AF_KEEP_AUDITED'));
 assert(e.has(m,'AF_AI_KEEP'));
 assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
 e.call('scanMailbox');
 assert(e.has(m,'AF_RULE_NOISE'));
 assert(e.has(m,'AF_REVIEW'));
 assert(!e.has(m,'AF_AI_KEEP'));
 assert(e.has(m,'INBOX'));
});
test('v1.2.7: migration does not disturb unrelated KEEP email',()=>{
 const e=env();e.call('setupFirewall');
 const m=e.mk('real-office',{labels:['INBOX','AF_AI_KEEP','AF_KEEP_AUDITED'],
  subject:'CSE221 Final Examination invigilation instructions'});
 e.call('upgradeFirewallV127');
 assert(e.has(m,'AF_AI_KEEP'));
 assert(e.has(m,'AF_KEEP_AUDITED'));
 assert(e.has(m,'INBOX'));
});
console.log('Total v1.2.7 mocked tests:',count);

// v1.2.8 regression: admission-test and invigilation duties are revenue-relevant
// even when invitations never mention payment, and MUST NOT be auto-archived.
test('v1.2.8: subject and body protection includes English and Bangla, never requiring payment wording',()=>{
 const e=env(); e.call('testProtectedDutyRules');
 for(const [s,b] of [
   ['Invitation for Admission Test Invigilation','You may volunteer if interested.'],
   ['Example University Admission Test','Dear colleagues, please register if available.'],
   ['General invitation','Please volunteer to act as an invigilator.'],
   ['Admission test: exam duty roster','Dear faculty, please fill up your availability.'],
   ['ভর্তি পরীক্ষায় দায়িত্ব পালনের আমন্ত্রণ','আপনাদের অংশগ্রহণ কামনা করি।'],
 ]) {
   const result=e.call('freeRuleDecision_',{subject:s,body:b,to:'faculty@example.edu'});
   assert.notEqual(result.decision,'NOISE',s);
 }
});
test('v1.2.8: LIVE Studio AI_NOISE admission-test invitation is not archived, blocked or force-blocked',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('a-duty',{labels:['INBOX','AF_AI_NOISE','AF_FORCE_BLOCK','AF_RULE_NOISE'],
   subject:'Admission Test Duty Invitation - Example University',
   messageId:'<invite-duty@example.edu>',body:'Interested faculty please fill out the form. No payment mentioned.'});
 e.call('scanMailbox');
 assert(e.has(m,'INBOX'));assert(e.has(m,'AF_PRIORITY_REVIEW'));
 for(const label of ['AF_AI_NOISE','AF_FORCE_BLOCK','AF_RULE_NOISE','AF_REVIEW']) assert(!e.has(m,label),label);
 assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
 assert(e.sheet('AllowedKeys').rows.some(r=>r[0]==='RFC:<invite-duty@example.edu>'));
});
test('v1.2.8: protected invitation inside BODY defeats a Studio NOISE decision in LIVE mode',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('body-duty',{labels:['INBOX','AF_AI_NOISE'],subject:'Invitation for faculty volunteers',
   body:'Dear faculty, this is an optional call for invigilators for upcoming exams. Please confirm availability. Venue: campus.'});
 e.call('scanMailbox');assert(e.has(m,'INBOX'));
 assert(e.has(m,'AF_PRIORITY_REVIEW'));assert(!e.has(m,'AF_AI_NOISE'));
 assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('v1.2.8: Studio KEEP admission-test message gets audited and its reply chain anchored',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('duty-keep',{labels:['INBOX','AF_AI_KEEP'],subject:'Invitation to volunteer in admission test duty',
  messageId:'<keep-duty@example.edu>',body:'Please let us know your availability.'});
 e.call('scanMailbox');assert(e.has(m,'INBOX'));assert(e.has(m,'AF_AI_KEEP'));
 assert(e.has(m,'AF_PRIORITY_REVIEW'));assert(e.sheet('AllowedKeys').rows.some(r=>r[0]==='RFC:<keep-duty@example.edu>'));
});
test('v1.2.8: a reply saying only “Available” is kept even if Studio calls it NOISE',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 e.mk('protected-original',{labels:['INBOX','AF_AI_NOISE'],subject:'Invigilation Duty Invitation',
   messageId:'<protected-invig@example.edu>',body:'Faculty may volunteer at the exam center.'});
 e.call('scanMailbox');
 const reply=e.mk('reply-no-context',{labels:['INBOX','AF_AI_NOISE'],subject:'Re: Faculty availability',
    thread:'another-thread-id',messageId:'<available@example.edu>',inReplyTo:'<protected-invig@example.edu>',
    refs:'<protected-invig@example.edu>',body:'I am available. Thanks.'});
 e.call('scanMailbox');
 assert(e.has(reply,'INBOX'));assert(!e.has(reply,'AF_SUPPRESSED'));
 assert(e.sheet('AllowedKeys').rows.some(r=>r[0]==='RFC:<available@example.edu>'));
});
test('v1.2.8: admission-duty invitation survives even when its RFC ancestor belongs to a blocked noise thread',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 e.mk('old-nuisance',{labels:['INBOX','AF_FORCE_BLOCK'],subject:'Yoga and cultural evening',
  messageId:'<old-noise@example.edu>',body:'Dear colleagues, join us for yoga. Date: Friday. Venue: Hall.'});
 e.call('scanMailbox');
 const duty=e.mk('new-duty-inside-blocked',{labels:['INBOX','AF_AI_NOISE'],subject:'Re: Invitation',
  messageId:'<important-duty@example.edu>',inReplyTo:'<old-noise@example.edu>',
  refs:'<old-noise@example.edu>',body:'Please volunteer for admission test invigilation duties on the upcoming examination day.'});
 e.call('scanMailbox');assert(e.has(duty,'INBOX'));assert(e.has(duty,'AF_PRIORITY_REVIEW'));
 assert(!e.has(duty,'AF_SUPPRESSED'));
});
test('v1.2.8: unreadable body never leads to automatic archiving even when Gemini says NOISE',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('unreadable',{labels:['INBOX','AF_AI_NOISE'],subject:'General invitation',
    body:'Invitation to join us at an event, speaker details enclosed.'});
 const old=e.context.Gmail.Users.Messages.get;
 e.context.Gmail.Users.Messages.get=(_u,id,opt)=>{
   const r=old(_u,id,opt);
   if(id==='unreadable'&&opt.format==='full')r.payload.body.data='bad$BASE64';
   return r;
 };
 e.call('scanMailbox'); assert(e.has(m,'INBOX'));assert(e.has(m,'AF_PRIORITY_REVIEW'));
 assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('v1.2.8: clear recreational studio noise still archives normally in LIVE mode',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('clear-noise',{labels:['INBOX','AF_AI_NOISE'],subject:'Invitation to Yoga Session',
   body:'Dear colleagues, we warmly invite you to the yoga program. Time: 4PM. Venue: Auditorium.'});
 e.call('scanMailbox');assert(!e.has(m,'INBOX'));assert(e.has(m,'AF_SUPPRESSED'));
});
test('v1.2.8: upgrade sets DRY_RUN and preserves existing blocked/allowed records',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('before',{labels:['INBOX','AF_FORCE_BLOCK'],subject:'Drama Invitation',body:'Join our stage performance.'});
 e.call('scanMailbox');const originalCount=e.sheet('BlockedKeys').getLastRow();
 e.call('upgradeFirewallV128');
 assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
 assert.equal(e.sheet('BlockedKeys').getLastRow(),originalCount);
});
console.log('Total v1.2.8 mocked tests:',count);


// v1.3.0 add-on: direct action from selected Gmail message, no URL parsing.
test('v1.3.0: direct block previews only in DRY_RUN',()=>{
 const e=env();e.call('setupFirewall');
 const m=e.mk('1a12a9e1c0ffee11',{thread:'1a12a9e1c0ffee11',subject:'Yoga session invitation',body:'Join the voluntary yoga class.'});
 const r=e.call('af130BlockByMessageId_',m.id,m.threadId);
 assert.equal(r.mode,'DRY_RUN');assert.equal(r.inboxCount,1);assert(e.has(m,'INBOX'));
 assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('v1.3.0: LIVE one-click block archives mistaken AI_KEEP and remembers IDs',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('1a12a9e1c0ffee12',{labels:['INBOX','AF_AI_KEEP','UNREAD'],thread:'1a12a9e1c0ffee12',
   messageId:'<one-click@example.edu>',subject:'Optional concert',body:'Come to a voluntary campus concert.'});
 const out=e.call('af130BlockByMessageId_',m.id,m.threadId);
 assert.equal(out.archived,1);assert(!e.has(m,'INBOX'));assert(!e.has(m,'UNREAD'));
 assert(e.has(m,'AF_SUPPRESSED'));assert(!e.has(m,'AF_AI_KEEP'));
 assert(e.sheet('BlockedKeys').rows.some(r=>r[0]==='RFC:<one-click@example.edu>'));
 assert(e.sheet('Audit').rows.some(r=>r[2]==='GMAIL_ONE_CLICK_BLOCK'));
});
test('v1.3.0: related reply is recognized after original is permanently deleted',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('1a12a9e1c0ffee13',{thread:'1a12a9e1c0ffee13',messageId:'<removed-event@example.edu>',
   subject:'Drama night',body:'Voluntary drama session.'});
 e.call('af130BlockByMessageId_',m.id,m.threadId);e.messages.delete(m.id);
 const reply=e.mk('reply-130',{thread:'new-gmail-thread',subject:'Re: Drama night',
   messageId:'<new-reply@example.edu>',inReplyTo:'<removed-event@example.edu>',
   refs:'<removed-event@example.edu>',body:'Lovely show, thanks.'});
 e.call('scanMailbox');assert(!e.has(reply,'INBOX'));
});
test('v1.3.0: hard duty protected despite user click',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('1a12a9e1c0ffee14',{thread:'1a12a9e1c0ffee14',subject:'Volunteer for invigilation',
   body:'Open to all faculty members; honorarium not mentioned.'});
 assert.throws(()=>e.call('af130BlockByMessageId_',m.id,m.threadId),/Protected/);
 assert(e.has(m,'INBOX'));assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('v1.3.0: protects admission duty appearing only in email body',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('1a12a9e1c0ffee15',{thread:'1a12a9e1c0ffee15',subject:'Special Invitation',
   body:'We invite faculty to support admission test duty.'});
 assert.throws(()=>e.call('af130BlockByMessageId_',m.id,m.threadId),/admission-test|invigilation duty/i);
 assert(e.has(m,'INBOX'));
});
test('v1.3.0: mixed thread with protected message blocks nothing',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const one=e.mk('1a12a9e1c0ffee16',{thread:'mix-130',subject:'Concert Invitation',body:'Welcome to the concert!'});
 const two=e.mk('1a12a9e1c0ffee17',{thread:'mix-130',subject:'Re: Concert Invitation',body:'Please also volunteer for the upcoming admission test.'});
 assert.throws(()=>e.call('af130BlockByMessageId_',one.id,one.threadId),/admission-test|invigilation duty/);
 assert(e.has(one,'INBOX'));assert(e.has(two,'INBOX'));assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('v1.3.0: manually allowed message blocks nothing',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('1a12a9e1c0ffee18',{thread:'1a12a9e1c0ffee18',labels:['INBOX','AF_ALLOW'],
   subject:'Book launch',body:'Optional book publication launch.'});
 assert.throws(()=>e.call('af130BlockByMessageId_',m.id,m.threadId),/protected|allowed/i);
 assert(e.has(m,'INBOX'));
});
test('v1.3.0: rejects stale context when selected message changed',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('1a12a9e1c0ffee19',{thread:'1a12a9e1c0ffee19',subject:'Drama Event',body:'Please join my drama.'});
 assert.throws(()=>e.call('af130BlockByMessageId_',m.id,'different-thread'),/changed/);
 assert(e.has(m,'INBOX'));
});
test('v1.3.0: upgrade never accidentally enables LIVE',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');e.call('upgradeFirewallV130');
 assert.equal(e.props.getProperty('AF_MODE'),'DRY_RUN');
});
test('v1.3.0: one-click button preview uses real event Gmail messageId',()=>{
 const e=env();e.call('setupFirewall');
 const m=e.mk('1a12a9e1c0ffee20',{thread:'1a12a9e1c0ffee20',subject:'Drama invitation',body:'Welcome to my theater show.'});
 // Stub the CardService UI enough to confirm that a Gmail event can open.
 const fake = () => new Proxy({}, {get(_t,k){return k==='build'?()=>({built:true}):()=>fake();}});
 e.context.CardService={newCardBuilder:fake,newCardHeader:fake,newCardSection:fake,newTextParagraph:fake,
  newDecoratedText:fake,newTextButton:fake,newAction:fake};
 const cards=e.call('af130OpenMessage',{gmail:{messageId:m.id,accessToken:'temporary-token'}});
 assert.equal(cards.length,1);assert.equal(cards[0].built,true);
});
console.log('v1.3.0 additional add-on tests completed.');

test('v1.3.2: selected message absent from API thread list recovered via GmailApp',()=>{
 const e=env();e.call('setupFirewall');const t='t-multi';
 const original=e.mk('origin',{thread:t,subject:'Invitation to Drama night',body:'Join our celebration'});
 const reply=e.mk('reply',{thread:t,subject:'Re: Invitation to Drama night',body:'Congratulations'});
 const getter=e.context.Gmail.Users.Threads.get;
 e.context.Gmail.Users.Threads.get=(u,tid,o)=>{const r=getter(u,tid,o);return {...r,messages:r.messages.filter(x=>x.id!=='reply')};};
 const out=e.call('af130BlockByMessageId_',reply.id,t);
 assert.equal(out.mode,'DRY_RUN');assert.equal(out.inboxCount,2);
 assert(e.logs.some(v=>String(v).includes('recovered missing API message')));
});
test('v1.3.2: any protected duty email vetoes recovered thread in LIVE',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');const t='t-protected';
 const original=e.mk('a',{thread:t,subject:'Invitation to Drama night',body:'Please come to our show'});
 const duty=e.mk('b',{thread:t,subject:'Invigilation duty invitation — Example University admission test',body:'Kindly register for duty'});
 const getter=e.context.Gmail.Users.Threads.get;
 e.context.Gmail.Users.Threads.get=(u,tid,o)=>{const r=getter(u,tid,o);return {...r,messages:r.messages.filter(x=>x.id!=='a')};};
 assert.throws(()=>e.call('af130BlockByMessageId_',original.id,t),/Protected academic\/duty/);
 assert(e.has(original,'INBOX'));assert(e.has(duty,'INBOX'));assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('v1.3.2: API and GmailApp thread disagreement refuses block without side effects',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('bad',{subject:'Invitation to Drama night',body:'Please attend'});
 e.context.Gmail.Users.Threads.get=()=>({id:m.threadId,messages:[]});
 e.context.GmailApp.getMessageById=()=>({getThread:()=>({getId:()=>m.threadId,getMessages:()=>[{getId:()=>m.id},{getId:()=> 'wrong-thread-msg'}]})});
 e.mk('wrong-thread-msg',{thread:'other-thread',body:'Hello'});
 assert.throws(()=>e.call('af130BlockByMessageId_',m.id,m.threadId),/membership changed|disagrees/);
 assert(e.has(m,'INBOX'));assert.equal(e.sheet('BlockedKeys').getLastRow(),1);
});
test('v1.3.2: cannot verify selected message in either service fails safe',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const m=e.mk('unmatched',{subject:'Invitation to Drama night'});
 e.context.Gmail.Users.Threads.get=()=>({id:m.threadId,messages:[]});
 e.context.GmailApp.getMessageById=()=>({getThread:()=>({getId:()=>m.threadId,getMessages:()=>[]})});
 assert.throws(()=>e.call('af130BlockByMessageId_',m.id,m.threadId),/Cannot verify selected message/);
 assert(e.has(m,'INBOX'));
});

test('v1.3.3: later reply classified AI_KEEP is archived by remembered RFC ancestry',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const original=e.mk('manual-original',{thread:'blocked-first-thread',subject:'Drama invitation',body:'All staff are welcome to our performance',messageId:'<block-parent@example.edu>'});
 e.call('af130BlockByMessageId_',original.id,original.threadId);
 assert(!e.has(original,'INBOX'));assert(e.sheet('BlockedKeys').getLastRow()>1);
 e.messages.delete(original.id);
 const reply=e.mk('new-later-reply',{thread:'new-thread-after-delete',subject:'Re: Drama invitation',
   messageId:'<late-reply@example.edu>',inReplyTo:'<block-parent@example.edu>',
   refs:'<block-parent@example.edu>',body:'Congratulations!',labels:['INBOX','UNREAD','AF_AI_KEEP']});
 e.call('scanMailbox');
 assert(!e.has(reply,'INBOX'),'remembered reply should no longer be in inbox');
 assert(!e.has(reply,'AF_AI_KEEP'));
 assert(e.has(reply,'AF_SUPPRESSED'));
});
test('v1.3.3: admission duty in new reply remains protected despite blocked ancestry and AI_KEEP',()=>{
 const e=env();e.call('setupFirewall');e.call('goLive');
 const original=e.mk('manual-parent',{thread:'t-original',subject:'Drama invitation',body:'Welcome',messageId:'<block-parent2@example.edu>'});
 e.call('af130BlockByMessageId_',original.id,original.threadId);
 const duty=e.mk('new-duty-reply',{thread:'new-gmail-thread',subject:'Re: Drama invitation',
   inReplyTo:'<block-parent2@example.edu>',refs:'<block-parent2@example.edu>',
   messageId:'<protected-response@example.edu>',body:'Please register to invigilate the admission test',labels:['INBOX','AF_AI_KEEP']});
 e.call('scanMailbox');
 assert(e.has(duty,'INBOX'),'duty must stay in Inbox');
 assert(e.has(duty,'AF_PRIORITY_REVIEW'),'duty must be marked for attention');
});
console.log('v1.3.3 targeted protected-lineage tests completed.');
