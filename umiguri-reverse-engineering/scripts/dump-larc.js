#!/usr/bin/env node
// dump-larc.js - 通过 CDP 从运行中的 UMIGURI 提取 app.larc 里「解密后的前端文件」
//
// 背景: .larc 是 asar 变体(魔数 Re=L),解密在 app.exe 的 native
//       electron_common_asar Archive 类里,算法未逆向 → 没有离线解密脚本。
//       但游戏运行时,asar 内容被透明解密并映射到 renderer 的 file:///,
//       所以 renderer 里 fetch('/main.js') 能拿到「解密后的原文」。
//
// 前置: 游戏以 --remote-debugging-port=<port> 启动,且 app.larc 已由 --app-path 加载。
// 运行: node dump-larc.js [port=9222] [outDir=larc_out] [路径1 路径2 ...]
//
// 限制: 只能拿经 file:// 暴露给 renderer 的文件(前端 index.html/main.css/main.js 等)。
//       主进程 index.js/package.json/node_modules 通常不暴露,拿不到(需逆向 native)。
//
// 依赖 Node 18+(global fetch)+ WebSocket(优先 npm `ws`,否则 global WebSocket,Node 21+)。

const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.argv[2] || '9222', 10);
const OUT = process.argv[3] || 'larc_out';
const EXTRA = process.argv.slice(4);

// 默认尝试的路径(按需增删;游戏前端入口一般是 index.html)
const DEFAULT_PATHS = [
  '/index.html',
  '/index.css',
  '/main.css',
  '/main.js',
  '/renderer.js',
  '/preload.js',
  '/package.json',
];

let WebSocketImpl = global.WebSocket;
try { WebSocketImpl = require('ws'); } catch { /* fall back to global */ }
if (!WebSocketImpl) {
  console.error('需要 WebSocket: 安装 `npm i ws` 或使用 Node 21+ (global WebSocket)');
  process.exit(1);
}

// 在 renderer 里执行: fetch(path) -> base64(二进制安全,分块避免栈溢出)
function fetchExpr(p) {
  return `(async () => {
    try {
      const r = await fetch(${JSON.stringify(p)});
      if (!r.ok) return { ok: false, status: r.status, path: ${JSON.stringify(p)} };
      const buf = new Uint8Array(await r.arrayBuffer());
      let s = '';
      for (let i = 0; i < buf.length; i += 8192) s += String.fromCharCode.apply(null, buf.subarray(i, i + 8192));
      return { ok: true, status: r.status, path: ${JSON.stringify(p)}, size: buf.length, b64: btoa(s) };
    } catch (e) {
      return { ok: false, error: String(e), path: ${JSON.stringify(p)} };
    }
  })()`;
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  const targets = await fetch(`http://127.0.0.1:${PORT}/json/list`).then(r => r.json());
  const page = targets.find(t => t.type === 'page');
  if (!page) { console.error('未找到 page target(renderer);targets:', targets.map(t => t.type)); process.exit(1); }
  console.log('连接 renderer:', page.url);

  const ws = new WebSocketImpl(page.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  ws.on('message', (data) => {
    const msg = JSON.parse(data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  });
  const send = (method, params) => new Promise((res) => {
    const mid = ++id; pending.set(mid, res);
    ws.send(JSON.stringify({ id: mid, method, params }));
  });
  await new Promise((res) => ws.on('open', res));

  await send('Runtime.enable', {});

  const paths = [...DEFAULT_PATHS, ...EXTRA];
  for (const p of paths) {
    const r = await send('Runtime.evaluate', {
      expression: fetchExpr(p),
      awaitPromise: true,
      returnByValue: true,
    });
    const v = r.result && r.result.result && r.result.result.value;
    if (!v || !v.ok) {
      console.log('  ✗', p, v ? (v.error || ('HTTP ' + v.status)) : 'no result');
      continue;
    }
    const rel = p.replace(/^\/+/, '');
    const out = path.join(OUT, rel);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, Buffer.from(v.b64, 'base64'));
    console.log('  ✓', rel, '(' + v.size + 'B)');
  }
  console.log('完成 ->', OUT);
  ws.close();
}

main().catch(e => { console.error(e); process.exit(1); });
