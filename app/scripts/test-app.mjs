import assert from 'node:assert/strict';
import { createServer } from 'vite';
const server = await createServer({server:{middlewareMode:true},appType:'custom',optimizeDeps:{noDiscovery:true,include:[]}});
class FakeSource {
  static current;
  handlers = new Map();
  constructor() { FakeSource.current = this; }
  addEventListener(name, fn) { this.handlers.set(name, fn); }
  close() {}
  emit(name, data) { this.handlers.get(name)?.({data:JSON.stringify(data)}); }
}
globalThis.EventSource = FakeSource;
globalThis.fetch = async () => ({ok:true,json:async()=>({ok:true,data:{revision:0,lines:[]}})});
try {
  const events = await server.ssrLoadModule('/src/lib/events.ts');
  const {useOutput} = await server.ssrLoadModule('/src/store/output.ts');
  const {useWatch} = await server.ssrLoadModule('/src/store/watch.ts');
  events.connect();
  const send = (name, data) => FakeSource.current.emit(name, data);
  let detach = useOutput.getState().attach();
  detach(); detach = useOutput.getState().attach();
  for(let seq=1;seq<=5000;seq++) send('output',{seq,ms:seq,text:`line ${seq}`});
  assert.equal(useOutput.getState().lines.length,4096);
  assert.equal(useOutput.getState().lines[0].seq,905);
  send('output',{seq:5000,ms:0,text:'duplicate'});
  assert.equal(useOutput.getState().lines.at(-1).text,'line 5000');
  detach();
  send('output',{seq:5001,ms:0,text:'detached'});
  assert.equal(useOutput.getState().revision,5000);
  let notifications = 0;
  const stop = useWatch.subscribe(()=>notifications++);
  let off = useWatch.getState().attach(); off(); off=useWatch.getState().attach();
  send('watch.values',{attached:true,values:[]});
  assert.equal(notifications,1);
  off(); send('watch.values',{attached:false,values:[]});
  assert.equal(notifications,1); stop();

  // Function list must fill in once background (hyperion) analysis completes.
  // At load the list is seeded from the fast native index; for a .NET/IL image
  // that index holds only the entry stub, and every managed method appears only
  // after analysis finishes and the engine streams hype.progress ready=true.
  // Regression guard for the "shows 1 function" .NET bug.
  {
    const {useDisasm} = await server.ssrLoadModule('/src/store/disasm.ts');
    let analysisReady = false;
    const nativeOnly = {functions:[{va:0x1000,size:6,name:'entry_point'}],total:1};
    const managed = {functions:[
      {va:0x1000,size:6,name:'entry_point'},
      {va:0x2000,size:10,name:'App::Main'},
      {va:0x3000,size:10,name:'App::Run'},
    ],total:3};
    const reply = (data) => ({ok:true,json:async()=>({ok:true,data})});
    globalThis.fetch = async (url, opts) => {
      if (String(url).endsWith('/health')) return {ok:true,json:async()=>({ok:true})};
      const {tool,action} = JSON.parse(opts.body);
      if (tool==='disasm' && action==='load') return reply({ok:true,ready:true});
      if (tool==='disasm' && action==='loaded') return reply({
        ready:true,name:'net.exe',entry_va:0x1000,
        functions:analysisReady?3:1,
        hype:{available:true,ready:analysisReady,progress:analysisReady?1:0.5},
      });
      if (tool==='disasm' && action==='functions') return reply(analysisReady?managed:nativeOnly);
      if (tool==='disasm' && action==='disassemble') return reply({instructions:[]});
      return reply({});
    };

    await useDisasm.getState().loadFile('net.exe');
    // Analysis still running: only the native entry stub is known.
    assert.equal(useDisasm.getState().functions.length,1);
    assert.equal(useDisasm.getState().total,1);

    // Engine reports analysis complete; the store must re-pull the full list.
    analysisReady = true;
    useDisasm.getState().onHypeProgress(true,true);
    for (let i=0;i<50 && useDisasm.getState().total!==3;i++) await new Promise((r)=>setTimeout(r,0));
    assert.equal(useDisasm.getState().total,3);
    assert.equal(useDisasm.getState().functions.length,3);

    // A second ready event on the same edge must not thrash / re-fetch.
    let calls=0; const base=globalThis.fetch;
    globalThis.fetch = async (u,o)=>{calls++;return base(u,o);};
    useDisasm.getState().onHypeProgress(true,true);
    await new Promise((r)=>setTimeout(r,0));
    assert.equal(calls,0);
  }

  // .NET explorer store: refresh builds the namespace/type tree, toggleType
  // lazy-loads a type's members exactly once, selectMethod pulls C#+IL, and a
  // native image collapses to a clean not-managed state.
  {
    const {useDotnet} = await server.ssrLoadModule('/src/store/dotnet.ts');
    let managedImage = true;
    let typeCalls = 0;
    const reply = (data) => ({ok:true,json:async()=>({ok:true,data})});
    globalThis.fetch = async (url, opts) => {
      const {tool,action} = JSON.parse(opts.body);
      if (tool!=='dotnet') return reply({});
      if (action==='status') return reply(managedImage
        ? {managed:true,assembly:'App',runtime:'v4.0.30319',types:2,methods:3,fields:1,properties:0}
        : {managed:false,note:'not a managed image'});
      if (action==='tree') return reply({namespaces:[
        {name:'App',types:[
          {token:0x02000001,token_hex:'02000001',name:'Program',full_name:'App.Program',
           kind:'class',visibility:'public',counts:{fields:1,properties:0,events:0,methods:2,nested:0}},
        ]},
      ]});
      if (action==='type') { typeCalls++; return reply({
        token:0x02000001,name:'Program',namespace:'App',full_name:'App.Program',kind:'class',
        visibility:'public',abstract:false,sealed:false,static:false,
        fields:[{token:0x04000001,name:'count',type:'int',visibility:'private',static:false}],
        properties:[],events:[],
        methods:[{token:0x06000001,token_hex:'06000001',name:'Main',signature:'static void Main()',
                  visibility:'public',ret:'void',static:true,has_body:true,il_count:4}],
      }); }
      if (action==='source') return reply({csharp:'public class Program\n{\n}\n'});
      if (action==='method') return reply({
        token:0x06000001,name:'Main',full_name:'App.Program::Main',signature:'static void Main()',
        decl_type:'App.Program',visibility:'public',ret:'void',static:true,max_stack:8,code_size:4,
        entry:0x2000,params:[],locals:[],handlers:[],
        il:[{offset:0,offset_label:'IL_0000',va:0x2000,size:1,mnemonic:'ret',flow:'return'}],
        il_text:'.method static void Main()\n  IL_0000: ret\n',
        csharp:'return;\n',csharp_structured:true,
      });
      return reply({});
    };

    await useDotnet.getState().refresh();
    assert.equal(useDotnet.getState().status.managed,true);
    assert.equal(useDotnet.getState().namespaces.length,1);
    assert.equal(useDotnet.getState().namespaces[0].types[0].name,'Program');

    // First expand fetches the detail; a second expand/collapse must not refetch.
    await useDotnet.getState().toggleType(0x02000001);
    assert.equal(typeCalls,1);
    assert.ok(useDotnet.getState().details[0x02000001]);
    assert.equal(useDotnet.getState().details[0x02000001].methods[0].name,'Main');
    await useDotnet.getState().toggleType(0x02000001); // collapse
    await useDotnet.getState().toggleType(0x02000001); // re-open, cached
    assert.equal(typeCalls,1);

    // Selecting a method loads both renderings and exposes an entry VA.
    await useDotnet.getState().selectMethod(0x06000001,'Main');
    assert.equal(useDotnet.getState().method.entry,0x2000);
    assert.equal(useDotnet.getState().ilText.includes('IL_0000'),true);
    assert.equal(useDotnet.getState().csharp,'return;\n');

    // A native image: refresh must land on a clean not-managed state, no throw.
    managedImage = false;
    await useDotnet.getState().refresh();
    assert.equal(useDotnet.getState().status.managed,false);
    assert.equal(useDotnet.getState().namespaces.length,0);
  }

  events.disconnect();
  console.log('PASS: bounded output, duplicate frames, output/watch teardown and remount, dotnet function-list refresh on analysis-complete, dotnet explorer tree/lazy-load/select');
} finally {await server.close();}
