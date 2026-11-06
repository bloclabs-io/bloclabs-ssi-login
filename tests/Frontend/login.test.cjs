const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync(require('node:path').resolve(__dirname,'../../assets/js/login.js'),'utf8');

test('oversize QR retains wallet link and polling; a lost binding clears both affordances',async()=>{
 const timers=[],elements={};
 for(const key of ['start','panel','qr','open','status','cancel']) elements[key]={hidden:false,disabled:false,children:[],replaceChildren(){this.children=[]},appendChild(x){this.children.push(x)},removeAttribute(k){delete this[k]},addEventListener(event,fn){this[event]=fn}};
 const root={querySelector:s=>elements[s.match(/data-ssi-(\w+)/)[1]]};
 const wallet='openid4vp://authorize?request='+ 'x'.repeat(3000);
 let calls=0;
 const fetch=async()=>({ok:calls++===0,status:calls===1?200:404,json:async()=>calls===1?{wallet_url:wallet,attempt:'a'}:{}});
 const window={fetch,bloclabsSsi:{restBase:'https://example.test/api/',i18n:{waiting:'waiting',error:'error'}},setTimeout:fn=>timers.push(fn),qrcode:()=>({addData(){},make(){throw Error('QR overflow')}})};
 vm.runInNewContext(source,{window,document:{getElementById:()=>root,createElement:()=>({})},fetch,URL});
 elements.start.click();
 await new Promise(setImmediate);
 assert.equal(elements.open.href,wallet);
 assert.equal(elements.open.hidden,false);
 assert.equal(elements.qr.hidden,true);
 assert.equal(timers.length,1);
 timers.shift()();
 await new Promise(setImmediate);
 assert.equal(elements.open.href,undefined);
 assert.equal(elements.open.hidden,true);
 assert.deepEqual(elements.qr.children,[]);
 assert.equal(elements.start.hidden,false);
 assert.equal(timers.length,0);
});

// --- The Digital Credentials API path (issue #76) ---------------------------------------------

const WALLET='openid4vp://authorize?client_id=x&request_uri=https%3A%2F%2Fverifier.example%2Fr';
const RESPONSE_URL='https://verifier.example/verification-session/dc1/response';
const DC_API={requests:[{protocol:'openid4vp-v1-unsigned',data:{response_mode:'dc_api',nonce:'n',dcql_query:{credentials:[]}}}],response_url:RESPONSE_URL};
const ANSWER={protocol:'openid4vp-v1-unsigned',data:{vp_token:{login:['sd-jwt~kb-jwt']}}};

/**
 * A login page with the script loaded: WordPress answers come from `wp` (initiate, then status),
 * the verifier's response route from `verifier`, the browser's credential prompt from `get`.
 */
function page(options={}){
 const timers=[],elements={},calls=[];
 for(const key of ['start','panel','hint','qr','open','status','cancel']) elements[key]={hidden:false,disabled:false,children:[],replaceChildren(){this.children=[]},appendChild(x){this.children.push(x)},removeAttribute(k){delete this[k]},addEventListener(event,fn){this[event]=fn}};
 const root={querySelector:s=>elements[s.match(/data-ssi-(\w+)/)[1]]};
 const wp=options.wp||[{ok:true,status:201,body:{wallet_url:WALLET,attempt:'a',dc_api:'dcApi' in options?options.dcApi:DC_API}},{ok:true,status:200,body:{status:'pending',poll_after:2}}];
 const verifier=options.verifier||{ok:true,status:200,body:{}};
 const fetch=async(url,init)=>{
  calls.push({url,init});
  if(url.startsWith('https://example.test/api/')){const a=wp.length>1?wp.shift():wp[0];return {ok:a.ok,status:a.status,json:async()=>a.body};}
  if(verifier.reject) throw new Error('network');
  return {ok:verifier.ok,status:verifier.status,json:async()=>verifier.body};
 };
 const credentials={calls:[],get(opts){this.calls.push(opts);return options.get?options.get(opts):Promise.resolve(ANSWER);}};
 const assigned=[],replaced=[];
 const window={fetch,bloclabsSsi:{restBase:'https://example.test/api/',resumeParam:'bloclabs_ssi_attempt',i18n:{starting:'starting',waiting:'waiting',resuming:'resuming',verified:'verified',unknown:'unknown',failed:'failed',expired:'expired',error:'error'}},setTimeout:fn=>timers.push(fn),isSecureContext:options.secure!==false,location:{protocol:options.pageProtocol||'https:',href:options.href,assign:(url)=>assigned.push(url)},history:'history' in options?options.history:{state:null,replaceState(state,title,url){replaced.push(url);}},navigator:{credentials}};
 if(options.browser!==false) window.DigitalCredential=options.DigitalCredential||function DigitalCredential(){};
 vm.runInNewContext(source,{window,document:{getElementById:()=>root,createElement:()=>({})},fetch,URL,AbortController});
 const verifierPosts=()=>calls.filter(c=>!c.url.startsWith('https://example.test/api/'));
 return {elements,timers,calls,credentials,verifierPosts,window,assigned,replaced};
}
const flush=()=>new Promise(setImmediate);
// Objects built inside the script's realm have another Object.prototype: compare by value.
const plain=(x)=>JSON.parse(JSON.stringify(x));

test('asks the wallet through the browser when the bridge offers a request and the browser supports it',async()=>{
 const p=page();
 p.elements.start.click();
 await flush();
 assert.equal(p.credentials.calls.length,1,'navigator.credentials.get called once');
 const opts=p.credentials.calls[0];
 assert.deepEqual(plain(opts.digital),{requests:DC_API.requests});
 assert.ok(opts.signal&&opts.signal.aborted===false,'a cancel signal is passed');
 // The wallet's answer goes to the verifier as {protocol, data}, with nothing of this site attached.
 const posts=p.verifierPosts();
 assert.equal(posts.length,1);
 assert.equal(posts[0].url,RESPONSE_URL);
 assert.equal(posts[0].init.method,'POST');
 assert.equal(posts[0].init.credentials,'omit');
 assert.equal(posts[0].init.mode,'cors');
 assert.equal(posts[0].init.redirect,'error');
 assert.equal(posts[0].init.headers['Content-Type'],'application/json');
 assert.deepEqual(JSON.parse(posts[0].init.body),ANSWER);
 // No QR code or wallet link while the browser is in charge, and the poller is running.
 assert.equal(p.elements.qr.hidden,true);
 assert.deepEqual(p.elements.qr.children,[]);
 assert.equal(p.elements.open.hidden,true);
 assert.equal(p.elements.open.href,undefined);
 assert.equal(p.elements.hint.hidden,true);
 assert.equal(p.elements.status.textContent,'waiting');
 assert.equal(p.timers.length,1,'status polling started');
 assert.equal(p.elements.start.hidden,true);
});

test('an answer the browser hands over as JSON text is parsed before it is posted',async()=>{
 const p=page({get:async()=>({protocol:'openid4vp-v1-unsigned',data:JSON.stringify(ANSWER.data)})});
 p.elements.start.click();
 await flush();
 assert.deepEqual(JSON.parse(p.verifierPosts()[0].init.body),ANSWER);
});

test('falls back to the QR code and wallet link when the holder dismisses the browser prompt',async()=>{
 const p=page({get:()=>Promise.reject(new Error('NotAllowedError'))});
 p.elements.start.click();
 await flush();
 assert.equal(p.credentials.calls.length,1);
 assert.equal(p.verifierPosts().length,0,'nothing to post');
 assert.equal(p.elements.open.href,WALLET);
 assert.equal(p.elements.open.hidden,false);
 assert.equal(p.elements.hint.hidden,false);
 assert.equal(p.elements.status.textContent,'waiting');
 assert.equal(p.timers.length,1,'the same poller keeps going');
});

test('falls back when the verifier refuses the answer or cannot be reached',async()=>{
 for(const verifier of [{ok:false,status:400,body:{}},{reject:true}]){
  const p=page({verifier});
  p.elements.start.click();
  await flush();
  assert.equal(p.verifierPosts().length,1);
  assert.equal(p.elements.open.href,WALLET,JSON.stringify(verifier));
  assert.equal(p.elements.open.hidden,false);
 }
});

test('uses the QR code and wallet link alone when the browser or the offer cannot be used',async()=>{
 const cases={
  'no Digital Credentials API':{browser:false},
  'no offer from the bridge':{dcApi:null},
  'an offer that is not an object':{dcApi:'yes'},
  'an offer without requests':{dcApi:{requests:[],response_url:RESPONSE_URL}},
  'a malformed request':{dcApi:{requests:[{protocol:'',data:{}}],response_url:RESPONSE_URL}},
  'an insecure page':{secure:false},
  'a plain-http response route on an https page':{dcApi:{...DC_API,response_url:'http://verifier.example/verification-session/dc1/response'}},
  'a javascript: response route':{dcApi:{...DC_API,response_url:'javascript:alert(1)'}},
  'a protocol this browser refuses':{DigitalCredential:Object.assign(function(){},{userAgentAllowsProtocol:()=>false})},
 };
 for(const [name,options] of Object.entries(cases)){
  const p=page(options);
  p.elements.start.click();
  await flush();
  assert.equal(p.credentials.calls.length,0,`${name}: the browser is not asked`);
  assert.equal(p.verifierPosts().length,0,`${name}: nothing is posted`);
  assert.equal(p.elements.open.href,WALLET,`${name}: the wallet link is shown`);
  assert.equal(p.elements.open.hidden,false,name);
  assert.equal(p.elements.hint.hidden,false,name);
  assert.equal(p.timers.length,1,`${name}: polling started`);
 }
 // A localhost test stack: plain http on both sides is allowed.
 const local=page({pageProtocol:'http:',dcApi:{...DC_API,response_url:'http://localhost:7004/verification-session/dc1/response'}});
 local.elements.start.click();
 await flush();
 assert.equal(local.credentials.calls.length,1);
 assert.equal(local.verifierPosts()[0].url,'http://localhost:7004/verification-session/dc1/response');
});

test('keeps only the requests the browser allows',async()=>{
 const offer={requests:[{protocol:'org-iso-mdoc',data:{}},DC_API.requests[0]],response_url:RESPONSE_URL};
 const p=page({dcApi:offer,DigitalCredential:Object.assign(function(){},{userAgentAllowsProtocol:(x)=>x==='openid4vp-v1-unsigned'})});
 p.elements.start.click();
 await flush();
 assert.deepEqual(plain(p.credentials.calls[0].digital.requests),DC_API.requests);
});

test('cancel aborts the open browser prompt and shows nothing afterwards',async()=>{
 let rejectPrompt;
 const p=page({get:(opts)=>new Promise((resolve,reject)=>{rejectPrompt=reject;opts.signal.addEventListener?.('abort',()=>reject(new Error('AbortError')));})});
 p.elements.start.click();
 await flush();
 const signal=p.credentials.calls[0].signal;
 assert.equal(signal.aborted,false);
 p.elements.cancel.click();
 assert.equal(signal.aborted,true,'the prompt is aborted');
 assert.equal(p.elements.panel.hidden,true);
 assert.equal(p.elements.start.hidden,false);
 rejectPrompt(new Error('AbortError'));
 await flush();
 assert.equal(p.elements.open.hidden,true,'no fallback for a cancelled attempt');
 assert.deepEqual(p.elements.qr.children,[]);
 assert.equal(p.verifierPosts().length,0);
 p.timers.shift()();
 await flush();
 assert.equal(p.calls.filter(c=>c.url.includes('status/')).length,0,'the stale poller stopped');
});

test('an answer that arrives after cancel is dropped',async()=>{
 let resolvePrompt;
 const p=page({get:()=>new Promise((resolve)=>{resolvePrompt=resolve;})});
 p.elements.start.click();
 await flush();
 p.elements.cancel.click();
 resolvePrompt(ANSWER);
 await flush();
 assert.equal(p.verifierPosts().length,0,'nothing is posted for a cancelled attempt');
});

// --- The same-device return (issue #96) --------------------------------------------------------

const ATTEMPT='a'.repeat(32);
const RETURN_PAGE='https://example.test/wp-login.php?redirect_to=https%3A%2F%2Fexample.test%2Fwp-admin%2Fedit.php';

test('finishes the attempt a wallet on this device sent the holder back to, and drops it from the address at once',async()=>{
 const p=page({href:RETURN_PAGE+'&bloclabs_ssi_attempt='+ATTEMPT+'&response_code=c0ffee',wp:[{ok:true,status:200,body:{status:'verified'}},{ok:true,status:200,body:{redirect_to:'https://example.test/wp-admin/edit.php'}}]});
 assert.deepEqual(p.replaced,[RETURN_PAGE],'the attempt and the verifier\'s response code leave the address before anything else');
 assert.equal(p.elements.start.hidden,true,'no new request is offered');
 assert.equal(p.elements.panel.hidden,false);
 assert.equal(p.elements.cancel.disabled,false);
 assert.equal(p.elements.qr.hidden,true);
 assert.deepEqual(p.elements.qr.children,[]);
 assert.equal(p.elements.open.hidden,true);
 assert.equal(p.elements.hint.hidden,true);
 assert.equal(p.elements.status.textContent,'resuming');
 assert.equal(p.calls.length,0,'nothing is initiated: the attempt exists');
 assert.equal(p.credentials.calls.length,0,'the wallet is not asked again');
 assert.equal(p.timers.length,1,'the attempt is polled');
 p.timers.shift()();
 await flush();
 assert.equal(p.calls[0].url,'https://example.test/api/status/'+ATTEMPT);
 assert.equal(p.calls[0].init.credentials,'same-origin','the binding cookie decides, as for every poll');
 assert.equal(p.elements.status.textContent,'verified');
 assert.equal(p.calls[1].url,'https://example.test/api/complete');
 assert.deepEqual(JSON.parse(p.calls[1].init.body),{attempt:ATTEMPT});
 assert.deepEqual(p.assigned,['https://example.test/wp-admin/edit.php'],'logged in, and on to the redirect the attempt stored');
});

test('a returned attempt this browser does not hold says so and offers a fresh start',async()=>{
 const p=page({href:'https://example.test/wp-login.php?bloclabs_ssi_attempt='+'b'.repeat(32),wp:[{ok:false,status:404,body:{code:'bloclabs_ssi_unknown',message:'Unknown login request.'}}]});
 p.timers.shift()();
 await flush();
 assert.equal(p.elements.status.textContent,'unknown');
 assert.equal(p.elements.start.hidden,false);
 assert.equal(p.elements.open.hidden,true);
 assert.equal(p.assigned.length,0);
 assert.equal(p.timers.length,0,'nothing left to poll');
 // A page that started its own attempt keeps the plain message for a lost binding.
 const own=page({wp:[{ok:true,status:201,body:{wallet_url:WALLET,attempt:'a',dc_api:null}},{ok:false,status:404,body:{code:'bloclabs_ssi_unknown'}}]});
 own.elements.start.click();
 await flush();
 own.timers.shift()();
 await flush();
 assert.equal(own.elements.status.textContent,'error');
});

test('a returned attempt the chain refused or that expired reads like any other',async()=>{
 for(const [status,message] of [['failed','failed'],['expired','expired']]){
  const p=page({href:'https://example.test/wp-login.php?bloclabs_ssi_attempt='+ATTEMPT,wp:[{ok:true,status:200,body:{status}}]});
  p.timers.shift()();
  await flush();
  assert.equal(p.elements.status.textContent,message);
  assert.equal(p.elements.start.hidden,false);
 }
});

test('an address without a well-formed attempt starts nothing',async()=>{
 const cases=[
  ['https://example.test/wp-login.php',[]],
  ['https://example.test/wp-login.php?redirect_to=x',[]],
  ['https://example.test/wp-login.php?bloclabs_ssi_attempt=../x',['https://example.test/wp-login.php']],
  ['https://example.test/wp-login.php?bloclabs_ssi_attempt='+'A'.repeat(32),['https://example.test/wp-login.php']],
  ['https://example.test/wp-login.php?bloclabs_ssi_attempt=',['https://example.test/wp-login.php']],
  [undefined,[]],
 ];
 for(const [href,replaced] of cases){
  const p=page({href});
  assert.deepEqual(p.replaced,replaced,String(href));
  assert.equal(p.timers.length,0,`${href}: no polling`);
  assert.equal(p.calls.length,0,`${href}: no request`);
  assert.equal(p.elements.start.hidden,false,String(href));
 }
 // Without a history to rewrite, a well-formed attempt is not resumed either: the address would replay it.
 const fixed=page({href:'https://example.test/wp-login.php?bloclabs_ssi_attempt='+ATTEMPT,history:null});
 assert.equal(fixed.timers.length,0,'no polling without a history to drop the parameter from');
 assert.equal(fixed.calls.length,0);
 assert.equal(fixed.elements.start.hidden,false);
});

test('cancel during a returned attempt stops it',async()=>{
 const p=page({href:'https://example.test/wp-login.php?bloclabs_ssi_attempt='+ATTEMPT});
 p.elements.cancel.click();
 assert.equal(p.elements.panel.hidden,true);
 assert.equal(p.elements.start.hidden,false);
 p.timers.shift()();
 await flush();
 assert.equal(p.calls.length,0,'the stale poller stopped');
});

