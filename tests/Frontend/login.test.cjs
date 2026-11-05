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
