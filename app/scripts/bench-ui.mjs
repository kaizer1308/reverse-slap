import { createServer } from 'vite';
import React from 'react';
import { renderToString } from 'react-dom/server';
import { writeFileSync } from 'node:fs';
const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', optimizeDeps: { noDiscovery: true, include: [] } });
try {
  const { useOutput } = await server.ssrLoadModule('/src/store/output.ts');
  const { default: OutputPanel } = await server.ssrLoadModule('/src/components/panels/OutputPanel.tsx');
  const lines = Array.from({length:4096}, (_,i) => ({seq:i+1,ms:1700000000000+i,text:`line ${i} ${'x'.repeat(80)}`}));
  useOutput.setState({lines,revision:4096});
  Object.assign(useOutput.getInitialState(), {lines,revision:4096});
  const run = () => renderToString(React.createElement(OutputPanel));
  run(); const samples=[]; let html;
  for(let i=0;i<7;i++){const start=performance.now(); html=run(); samples.push(performance.now()-start);}
  const result={workload:'output_4096_rows_ssr',median_ms:[...samples].sort((a,b)=>a-b)[3],samples_ms:samples,html_bytes:Buffer.byteLength(html),rendered_rows:(html.match(/class="log-row"/g)||[]).length,note:'SSR component work only, not browser frame time or RSS'};
  console.log(JSON.stringify(result,null,2));
  if(process.argv[2]) writeFileSync(process.argv[2],JSON.stringify(result,null,2)+'\n');
} finally {await server.close();}
