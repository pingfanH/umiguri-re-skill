#!/usr/bin/env node
// dump-cdp.js - 通过 Chrome DevTools Protocol dump UMIGURI renderer 源码
//
// 原理: 定制 Electron 禁用 --inspect(主进程),但渲染进程的 remote debugging 可用。
//       游戏前端是 Web(THREE+Effekseer+逻辑 IIFE),直接从 renderer dump 即可。
//
// 前置: 游戏以 --remote-debugging-port=<port> 启动(或用 Frida spawn 时注入该参数)。
// 运行: node dump-cdp.js [port=9222] [outDir=cdp_sources]
//
// 依赖 Node 18+(global fetch)+ WebSocket(优先 npm `ws`,否则用 global WebSocket,需 Node 21+)。

const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.argv[2] || '9222', 10);
const OUT = process.argv[3] || 'cdp_sources';

let WebSocketImpl = global.WebSocket;
try { WebSocketImpl = require('ws'); } catch { /* fall back to global */ }
if (!WebSocketImpl) {
  console.error('需要 WebSocket: 安装 `npm i ws` 或使用 Node 21+ (global WebSocket)');
  process.exit(1);
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  // 1) 枚举 targets,找 renderer page
  const targets = await fetch(`http://127.0.0.1:${PORT}/json/list`).then(r => r.json());
  console.log('targets:', targets.map(t => `${t.type}:${t.url}`).join('\n          '));
  const page = targets.find(t => t.type === 'page');
  if (!page) { console.error('未找到 page target(renderer)'); process.exit(1); }
  console.log('连接:', page.url);

  const ws = new WebSocketImpl(page.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  const scripts = new Map(); // scriptId -> { url }

  const send = (method, params) => new Promise((res) => {
    const mid = ++id;
    pending.set(mid, res);
    ws.send(JSON.stringify({ id: mid, method, params }));
  });

  ws.on('message', async (data) => {
    const msg = JSON.parse(data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg.result); pending.delete(msg.id); return; }
    if (msg.method === 'Debugger.scriptParsed') {
      const { scriptId, url } = msg.params;
      scripts.set(scriptId, { url });
    }
  });

  await new Promise((res) => ws.on('open', res));

  // 2) 开 Debugger,收集所有已解析脚本
  await send('Debugger.enable');
  await new Promise(r => setTimeout(r, 1500)); // 等 scriptParsed 事件

  console.log('已发现脚本:', scripts.size);

  // 3) 逐个 getScriptSource 落盘
  let n = 0, total = 0;
  for (const [scriptId, { url }] of scripts) {
    const r = await send('Debugger.getScriptSource', { scriptId });
    if (!r || r.scriptSource == null) continue;
    // 文件名: 用 url 的最后一段,无 url 则用 scriptId
    let name = 'script_' + scriptId;
    if (url) {
      try { name = decodeURIComponent(url.split('/').pop() || name).replace(/[\\:*?"<>|]/g, '_'); }
      catch { /* keep */ }
    }
    const file = path.join(OUT, name);
    fs.writeFileSync(file, r.scriptSource);
    console.log('  ✓', name, (r.scriptSource.length / 1024).toFixed(1) + 'KB', url || '');
    n++; total += r.scriptSource.length;
  }
  console.log(`完成: ${n} 个脚本, ${(total / 1048576).toFixed(2)} MB -> ${OUT}`);

  // 备用: 直接让页面自身 fetch(asar 映射到 file:///,返回解密后的原始文件)
  // await send('Runtime.evaluate', { expression: "fetch('/main.js').then(r=>r.text())", awaitPromise: true });

  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
