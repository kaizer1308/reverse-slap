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
  events.disconnect();
  console.log('PASS: bounded output, duplicate frames, output/watch teardown and remount');
} finally {await server.close();}
