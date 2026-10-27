import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareSite, prepareConfig, setField, updateHandler, handlerConfig, changeHandler, updateItem, addRoute } from '../ui/config-model.js';

const sites = [
  { name:'demo', hosts:['demo.sczh.cc'], routes:[{ respond:{body:'ok'} }] },
  { name:'derp', hosts:['derp.sczh.cc'], routes:[{ proxy:{upstream:'http://127.0.0.1:3340'} }] },
  { name:'admin', hosts:['admin.sczh.cc'], routes:[{ proxy:{upstream:'http://127.0.0.1:8080'} }] },
];
for (const site of sites) test(`${site.name}: form and JSON round trips preserve the full site`, () => {
  assert.deepEqual(prepareSite(site),site);
  assert.deepEqual(prepareSite(JSON.parse(JSON.stringify(prepareSite(site)))),site);
});

test('editing one proxy field preserves unshown options and other routes', () => {
  const site={name:'mixed',hosts:['example.com'],listeners:['https'],policies:['public'],allow_http:false,routes:[
    {name:'app',path:'/app/',method:'GET',policies:['private'],proxy:{upstream:'http://old',host_header:'internal',dial_timeout:'7s',max_conns:0,insecure_skip_verify:false,future_option:{nested:[1,null,false]}}},
    {path:'/worker/',worker:{script:'worker.js',env:{PRESERVE:'yes'}}},
  ]};
  const edited=updateItem(prepareSite(site),'routes',0,updateHandler(site.routes[0],'proxy','upstream','http://new'));
  const expected=structuredClone(site);
  expected.routes[0].proxy.upstream='http://new';
  assert.deepEqual(edited,expected);
  assert.deepEqual(site.routes[0].proxy.upstream,'http://old');
});

test('editing site metadata preserves custom extension handlers', () => {
  const site={hosts:['example.com'],worker:{script:'worker.js',env:{KEEP:'yes',EMPTY:''}},listeners:[]};
  assert.deepEqual(setField(prepareSite(site),'allow_http',true),{...site,allow_http:true});
});

test('string shorthand expands only the handler being edited', () => {
  const route={path:'/app/',proxy:'http://old',policies:['keep']};
  assert.deepEqual(handlerConfig(route,'proxy'),{upstream:'http://old'});
  assert.deepEqual(updateHandler(route,'proxy','host_header','internal'),{...route,proxy:{upstream:'http://old',host_header:'internal'}});
  assert.deepEqual(prepareSite({hosts:['x'],routes:[route]}).routes[0],route);
});

test('adding a route preserves an existing shorthand handler and its options', () => {
  const site={name:'shorthand',hosts:['x'],listeners:['https'],policies:['p'],allow_http:false,proxy:{upstream:'http://old',future:{keep:true}}};
  const next=addRoute(site);
  assert.deepEqual(next.routes[0],{proxy:site.proxy});
  assert.equal(next.routes[1].path,'/api/');
  assert.equal(next.name,site.name);
  assert.deepEqual(next.listeners,site.listeners);
  assert.deepEqual(next.policies,site.policies);
  assert.equal(next.allow_http,false);
  assert.equal(Object.hasOwn(next,'proxy'),false);
  assert.equal(Object.hasOwn(site,'proxy'),true);
});

test('changing a route handler preserves routing metadata', () => {
  const route={name:'app',method:'GET',path:'/app/',policies:['p'],proxy:{upstream:'http://old'}};
  assert.deepEqual(changeHandler(route,'respond',true),{name:'app',method:'GET',path:'/app/',policies:['p'],respond:{body:''}});
});

test('configuration round trips keep fields at every unshown level', () => {
  const config={version:1,server:{read_header_timeout:'10s',future:{keep:[null,false,0,'']}},tls:{min_version:'1.2',future:[1]},
    listeners:[{name:'https',address:':443',tls:true,trusted_proxies:['127.0.0.1'],future:{keep:1}}],
    policies:[{name:'p',request:{timeout:'30s',future:{keep:2}},rate_limit:{requests_per_second:1.5,burst:2,future:[3]},future:'keep'}],
    sites:[...sites,{hosts:['worker.example.com'],worker:{script:'worker.js',env:{KEEP:'yes'}}}],future:{nested:[{keep:true}]} };
  assert.deepEqual(prepareConfig(config),config);
  const draft=prepareConfig(JSON.parse(JSON.stringify(prepareConfig(config))));
  const next={...draft,server:setField(draft.server,'read_header_timeout','15s')};
  const expected=structuredClone(config);expected.server.read_header_timeout='15s';
  assert.deepEqual(next,expected);
});

test('editing listener address keeps TLS, policies and unknown listener fields', () => {
  const config={listeners:[{name:'https',address:':443',tls:true,policies:['keep'],future:{keep:true}}],sites};
  const next=updateItem(prepareConfig(config),'listeners',0,setField(config.listeners[0],'address',':8443'));
  const expected=structuredClone(config);expected.listeners[0].address=':8443';
  assert.deepEqual(next,expected);
});

test('editing policy limits keeps all unshown policy settings', () => {
  const config={policies:[{name:'p',request:{timeout:'30s',future:true},rate_limit:{requests_per_second:3,burst:5},future:[1]}],sites};
  const next=updateItem(config,'policies',0,{...config.policies[0],request:setField(config.policies[0].request,'timeout','60s')});
  const expected=structuredClone(config);expected.policies[0].request.timeout='60s';
  assert.deepEqual(next,expected);
});

test('empty values are changed only at the explicitly edited field', () => {
  const value={zero:0,disabled:false,empty:'',nil:null,unknown:{a:1},edited:'old'};
  assert.deepEqual(setField(value,'edited',''),{zero:0,disabled:false,empty:'',nil:null,unknown:{a:1}});
});

test('unsupported shapes are rejected without mutating the JSON source', () => {
  const site={hosts:['example.com'],routes:{future:true}};
  assert.throws(()=>prepareSite(site),/Routes must be an array/);
  assert.deepEqual(site,{hosts:['example.com'],routes:{future:true}});
  assert.throws(()=>prepareConfig({listeners:{unknown:1}}),/Listeners must be an array/);
  assert.throws(()=>prepareConfig([]),/must be a JSON object/);
});
