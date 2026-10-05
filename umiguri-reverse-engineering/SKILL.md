---
name: umiguri-reverse-engineering
description: Use when analyzing or reverse-engineering UMIGURI (inonote 音游 v2.x), decrypting its .arc/.una/.larc encrypted resource archives, recovering its Electron renderer source via CDP, deobfuscating terser output, or working with the umgr-re recovered code / Electron/Tauri/Capacitor shells. Trigger keywords: UARC, UNA, Re=L, .larc, .arc, .una, decrypt_arc, game_logic.deobf, game_main.original, umgr_elc, handshake, 音游逆向, 资源解密.
---

# UMIGURI 逆向工程 skill

UMIGURI 逆向全流程沉淀:目标概况 → 分析方法论 → 文件格式 → 加密/解密算法 → 解密后结构 → 脚本 → 运行时桥 → 坑与验证。

Base directory 下的 `scripts/` 含可运行脚本:`decrypt_arc.js`(归档解密器)、`dump-cdp.js`(renderer 源码 dump)。

---

## 0. 目标概况

| 项 | 值 |
|----|----|
| 名称 | UMIGURI(街机音游,maimai 类) |
| 作者/版权 | inonote,(c) 2025,inonote |
| 版本 | v2.01 |
| 运行时 | **定制 Electron 25**(Chromium 113),前端 = 纯 Web(HTML + JS + WebGL) |
| 3D/特效 | THREE.js **r137** + Effekseer 粒子 |
| 主程序 | `core/bin/app.exe`(约 161MB,内含 native asar 解密) |
| 代码归档 | `core/bin/app.larc`(asar 变体,魔数 `Re=L`) |
| 外设 | Amusement IC 读卡器 / LED 灯板 / VFD 屏 / COM 串口(Di8 输入板) |

前端指 `game_main.original.js`(3.75MB)= THREE + Effekseer + 字符映射表 + 游戏主逻辑 IIFE。

---

## 1. 分析方法论(怎么分析)

### 1.1 识别与分类(第一步)

1. 看文件结构:出现 `*.asar`/`*.larc`、`resources/`、`locales/`、`chrome_*.pak` → Electron。
2. 看主程序大小:161MB 左右、含 `v8_context_snapshot.bin` / `snapshot_blob.bin` → 打包的 Electron。
3. 看前端:game 逻辑是 Web → 用 **CDP**(Chrome DevTools Protocol)从 renderer 直接 dump 源码,**最优路径**。

### 1.2 renderer 源码恢复(CDP —— 核心手法)

Electron 27+ 默认禁用了 `--inspect`,但**渲染进程的 remote debugging 仍可用**:

```bash
# 启动时附加远程调试端口(或 Frida spawn 时注入)
app.exe --remote-debugging-port=9222
# 也可用 Frida spawn 后追加
```

连接与 dump:

```js
// scripts/dump-cdp.js 的核心逻辑
const targets = await fetch('http://127.0.0.1:9222/json/list').then(r => r.json());
const page = targets.find(t => t.type === 'page');           // renderer
const ws = new WebSocket(page.webSocketDebuggerUrl);
// 1) Debugger.enable → 监听 Debugger.scriptParsed 收集所有脚本 id
// 2) 对每个 id 发 Debugger.getScriptSource → 拿源码
// 3) 或直接用 Runtime.evaluate 触发页面自身 fetch:
//    fetch('/main.js').then(r=>r.text())  // 相对路径经 file:// 映射返回解密后的原始文件
```

关键点:
- **相对路径 fetch 能拿到解密后的原文**:`app.larc` 通过 `--app-path=app.larc` 加载,asar 内容映射到 `file:///`,所以 renderer 里 `fetch('/main.css')` / `fetch('/main.js')` 返回**解密后的原始文件**(不需要逆向 native)。
- 主进程 `index.js` / `package.json` / `node_modules` **不通过 file:// 暴露**给 renderer,拿不到。

### 1.3 主进程(native asar)分析

- Electron Fuse 禁用了 Node inspector → 主进程 JS **无法用 CDP** 拿。
- 手法:**Frida** 定位 `electron_common_asar` 的 node_module → **扫描主进程内存字节码常量池**,提取全部字符串字面量(`mainproc_strings.txt`)。逻辑无法逐行还原,但**功能完全清楚**(API 路径、配置键、服务器地址、录像工具等)。
- native 解密函数(Archive 类)在 `app.exe` 里 → **Ghidra**(配 JDK 21)反汇编。反汇编易被 V8 字符串处理淹没,hook `ReadFile`/`NtReadFile`/`MapViewOfFile` 也未必捕获 `.larc` 读取。

### 1.4 反混淆(前端主逻辑)

`game_main.original.js` 后段是 terser 压缩的 IIFE(327万~384万偏移)。产物:
- `game_logic.min.js` —— 切出的原始压缩版
- `game_logic.deobf.js` —— 反混淆版

反混淆内容:
1. **变量名**:7692 个 terser 短名 → `m_*`(模块级)/`v_*_位置`(局部),消除同名冲突。
2. **枚举语义化**:`fe→JUDGE_JUSTICE_CRITICAL`、`w0→JUDGE_JUSTICE`、`_e→JUDGE_ATTACK`、`he→JUDGE_MISS`。
3. 格式化 + 可解析验证。

**诚实边界**(信息论上不可逆):
- terser 的**对象属性名**(`Fi`/`Be`/`Wt`)原始名已永久丢弃,只能靠上下文 + 字符串常量 + 明文数据推断。
- 局部临时变量原始名(单字母 `t/i/e` 复用)同样丢失。

### 1.5 字符串常量池

从 bundle 提取全部 2086 个字符串常量(`string_constants.txt`),是理解逻辑的"地图";核心判定/血条/计分片段见 `core_logic.snippets.txt`。

---

## 2. 文件格式与魔数

| 格式 | 魔数(bytes) | ASCII | 说明 |
|------|-------------|-------|------|
| `.arc` | `55 41 52 43` | `UARC` | 资源归档(图片/音频/文本打包) |
| `.una` | `55 4E 41 20` | `UNA ` | 语言包(字体/着色器/纹理/字符串表) |
| `.larc` | `52 65 3D 4C`,byte4=`26` | `Re=L` | asar 变体,**代码归档**,加密算法与 .arc/.una 不同,未逆向 |
| `.krtbl` | `4B 52 53 4D` | `KRSM` | 存档表(明文,直接可读) |
| `.dds` | `44 44 53 20` | `DDS ` | 纹理(BC1/BC3/RGB/RGBA) |
| `.rgf` | `52 47 46 30` | `RGF0` | 字体字形数据 |
| `.rvs` | `52 56 53 54` | `RVST` | 版本/表数据 |
| `.rsb` | `52 53 42 46` | `RSBF` | UI 布局/字符串表 |
| `.glb` | `67 6C 54 46` | `glTF` | 3D 模型 |
| `.ugc` | 文本 | — | 谱面(header + 音符行) |
| `.ucsl` | 文本 | — | 技能 DSL(官方有规格) |
| `.upm` | 文本 | — | 场景模型(官方有规格,GLSL) |

**共同头**(UARC/UNA):
- byte[0..4] = 魔数
- byte[4] = **flags**:`M2 = (flags & 0x01)` = 是否 gzip 压缩,`R2 = (flags & 0x02)` = 是否加密。实际样本 flags=`0x03`(两者都开)。

---

## 3. 加密/解密算法(完整逆向)

> 算法从**渲染端反混淆代码**提取(前端 `m_vs` 归档解析 + `m_$a`/`m_Na`/`m_Gi`),并用 `decrypt_arc.js` 批量验证(DDS/KRSM/RVST/RGF0 魔数全部正确)。

### 3.1 旋转右移 rotr(`m_$a`)

```js
// 与游戏 m_$a 语义一致(rotate right,无符号)
function rotr(state, shift) {
  return state >>> shift | (state & -1 >>> 32 - shift) << 32 - shift;
}
```

### 3.2 条目表偏移

```js
const magic = 281266680;                       // 0x10C3C9F8
// 只读 5 字节头里的 u32(offset 5,小端),异或 magic 后取负
let offset = -1 - ((magic ^ dv.getUint32(5, true)) | 0) + 5;
```

### 3.3 条目表解析(PRNG + XOR)

```js
let t = 3125038119, e = 452525368, n = 3518972124, r = 1813668011; // 4 状态
while (offset < dv.byteLength) {
  t = rotr(t, 2); e = rotr(e, 3); n = rotr(n, 5);
  const fileOffset = (dv.getUint32(offset,     true) ^ t) >>> 0;
  const fileSize   = (dv.getUint32(offset + 4, true) ^ e) >>> 0;
  const nameLen    = dv.getUint8(offset + 8) ^ (n & 255);
  offset += 9;
  let name = "";
  for (let i = 0; i < nameLen && i + offset < dv.byteLength; ++i) {
    r = rotr(r, 3);
    name += String.fromCharCode(dv.getUint8(i + offset) ^ (r & 255));
  }
  offset += nameLen;
  files.push({ name, fileOffset, fileSize });
}
```
每条目 stride = `9 + nameLen`。

### 3.4 文件数据解密

数据位于 `fileOffset + 5`,长度 `fileSize`。三步:

```js
// 1) XOR 表(位置相关)  table 由 P2 选择(见 3.6)
for (let i = fileOffset; i < buf.length + fileOffset; ++i) {
  buf[i - fileOffset] ^= table[(31 & i) << 1];   // 索引 = (31 & 绝对偏移) << 1,即 0,2,...,62
}
// 2) mNa 位置流 XOR
mNa(buf);
// 3) gzip 解压(M2 时)
if (M2) buf = zlib.gunzipSync(buf.subarray(1)); // 跳过 1 字节头
if (P2 === 2) buf = buf.subarray(1);            // .una 再跳 1 字节
```

**mNa**(位置相关 XOR 流):

```js
function mNa(buf) {
  let v = 250, e = 0, n = 0, r;
  for (let t = 0; t < buf.length; ++t) {
    r = n; n = buf[t];
    if      (t % 5  === 0) buf[t] ^= 105;
    else if (t % 19 === 0) buf[t] ^= 209;
    else if (t % 83 === 0) buf[t] ^= 72;
    else if (t % 97 === 0) buf[t] ^= 2;
    else                   buf[t] ^= v;
    buf[t] ^= (117 & r) | (72 & e);
    v -= t % 3;
    if (v < 0) v = 255;
    e = buf[t];
  }
}
```

### 3.5 XOR 表(两份,按 P2 选)

`VA_TABLE`(P2=0)与 `WA_TABLE`(P2=1/2),各 64 字节。游戏里 `m_Gi = [m_Va, m_Wa, m_Wa]` 即 P2=0 用 VA,P2=1/2 用 WA。

```js
const VA_TABLE = [168,220,89,53,219,151,160,26,53,145,237,161,148,35,123,1,157,54,121,110,229,160,93,18,129,35,179,28,127,161,220,148,112,95,35,237,192,127,26,71,50,224,1,60,41,28,247,220,71,208,54,75,75,179,151,193,236,1,95,121,18,121,245,95];
const WA_TABLE = [252,113,113,161,156,129,155,251,255,156,249,43,162,156,245,100,242,193,193,117,75,117,10,129,214,113,144,179,43,100,144,100,203,88,251,161,210,245,71,144,100,249,247,255,124,245,53,10,14,155,113,113,152,255,245,179,148,225,178,251,179,71,154,242];
```

### 3.6 P2 参数(归档类型)

游戏 `new m_ds(path, 0, P2)` 的 P2 决定表 + 尾部处理:

| P2 | 归档 | XOR 表 | 尾部 |
|----|------|--------|------|
| 0 | 旧变体 | `VA_TABLE` | 无 |
| 1 | `.arc`(UARC) | `WA_TABLE` | 无 |
| 2 | `.una`(UNA ) | `WA_TABLE` | 再 `subarray(1)` 跳 1 字节 |

> **经验**:无脑跑 `P2=1` 对 `.arc`/`.una` 都能出正确魔数(DDS/KRSM/RVST/RGF0),`.una` 需 P2=2 才对(游戏代码里 `.una` 用 P2=2)。批量脚本里统一用 1 也可以,尾字节差异不影响内容识别。

---

## 4. 解密后结构与扩展名推断

### 4.1 扩展名推断(`guessExt`,按魔数)

| 魔数 | 扩展 |
|------|------|
| `89 50 4E 47` | `.png` |
| `44 44 53 20` | `.dds` |
| `52 49 46 46` | `.wav` |
| `52 47 46 30` | `.rgf` |
| `4B 52 53 4D` | `.krtbl` |
| `52 56 53 54` | `.rvs` |
| `52 53 42 46` | `.rsb` |
| `FF D8` | `.jpg` |
| `1F 8B` | `.gz` |
| `67 6C 54 46` | `.glb` |
| `4F 67 67 53` | `.ogg` |
| 文本(可打印 >50%) | `.txt`,若含 `//`/`function`/`window.`/`var ` → `.js` |

### 4.2 解包后的目录结构

```
解码输出/<相对归档路径>/<条目名><推断扩展名>
```
例:
- `data/characters/touhou/000/data.arc` → `image_0_lg.dds`, `image_0_md.dds`, `image_0_sm.dds`
- `core/una/hiiragi.una` → 191 个文件:`fonts/*.rgf`、`shaders/*.krtbl`、`ui/*.rsb`、`ui/*.js`、`tables/*.rvs`、`_VERSION.txt`

### 4.3 明文数据(直接可读,无需解密)

- `data/music/<id>/` —— `j.png`/`bg.png`(封面)、`*.ugc`(谱面)、`track.mp3`、`mas.ugc`
- `data/nameplates/<id>/` —— `image.png` + `meta.txt`
- `data/characters/<group>/<id>/` —— `data.arc` + `meta.txt`
- `core/config/` —— `game.json`、`se.json`、`default_order_*.txt`、`*.krtbl`
- `core/sounds/` —— 音效 `.wav`/`.mp3`

---

## 5. 脚本

### 5.1 `scripts/decrypt_arc.js`(归档批量解密器)

```
用法:
  单个: node decrypt_arc.js <data.arc> [输出目录] [P2]
  批量: node decrypt_arc.js --batch <根目录> [输出目录] [P2]
```
- 递归查找所有 `.arc`/`.una`
- 逐条目解密 → 按魔数补扩展名 → 写出
- 已批量验证 331 文件(196 dds + 42 js + 42 rsb + 21 wav + 11 rgf + 5 krtbl + 2 rvs)

### 5.2 `scripts/dump-cdp.js`(renderer 源码 dump)

```
用法: node dump-cdp.js [端口=9222] [输出目录=cdp_sources]
```
连接 CDP `/json/list` → page target → `Debugger.enable` → 收集 `scriptParsed` → `Debugger.getScriptSource` 落盘。

### 5.3 `scripts/dump-larc.js`(`app.larc` 运行时提取)

`.larc` 是 asar 变体(魔数 `Re=L`),解密在 `app.exe` 的 native `electron_common_asar` Archive 类里,**算法未逆向 → 没有离线解密脚本**。可行路径是**运行时提取**:

```
用法: node dump-larc.js [端口=9222] [输出目录=larc_out] [额外路径...]
```

**流程**:
1. 游戏以 `--remote-debugging-port=9222` 启动(`app.larc` 经 `--app-path` 加载)。
2. native asar Archive 透明解密 `.larc`,内容映射到 renderer 的 `file:///`。
3. CDP `Runtime.evaluate` 在 renderer 里执行 `fetch('/main.js')` 等,返回**解密后的原文**。
4. 结果 base64 传回 Node 落盘(二进制安全)。

**限制**:只有经 `file://` 暴露给 renderer 的前端文件能拿(`index.html`/`main.css`/`main.js`);主进程 `index.js`/`package.json`/`node_modules` 拿不到。

**要拿全**(含主进程)需逆向 native Archive 类:Ghidra 反汇编 `app.exe` 定位 `Archive::Init`/`ReadFile`(先用 `Re=L`/asar 常量交叉引用锚定),或 Frida hook 更底层(Electron asar 读取路径 / `uv_fs_read`),拿到密钥/流密码后按 asar 结构重写。这是唯一未攻克的硬骨头。

### 5.4 源码保护(逆向项目自建,非游戏原生)

项目里 `main.js` 用 **AES-256-CBC** 加密成 `main.js.enc`,运行时解密注入:
- KEY = `umiguri-2025-inonote-16bytes-key`(32B)
- IV  = `umiguri-iv-16byt`(16B)

---

## 6. 运行时桥(umgr_elc)与虚拟路径

前端通过 preload 注入的 `window.umgr_elc` 读文件(IPC 到主进程 / Rust / WebView)。

### 6.1 handshake(`umgr_elc._`)

```js
{
  O: { ct, B, p9 },              // 授权/构建信息
  fe: 'A1B2C3D4E5F6G7H8I9J0K;L\'M,N.O/P-RSTUWY', // 38 字符键盘布局!
  W: true,                        // true=Di8 街机输入板, false=键盘
  I4: 'ja-JP', g1: [语言包列表], ...
}
```
关键:`m_ye.rm.dm = m_Hl.fe`(布局)、`m_ye.rm.wm = m_Hl.W`(Di8 开关)。

### 6.2 文件 API(`umgr_elc.st`)

| 方法 | 用途 | 返回 |
|------|------|------|
| `zu(path)` | 列目录 | `{ status, data: FileEntry[] }` |
| `sn(path)` | 读整个文件 | `{ status, data: Uint8Array }` |
| `_2(path)` | 文件大小 | `{ status, data: { val } }` |
| `xl(path, off, size)` | 读切片 | `{ status, data: { buf, br } }` |
| `Qf()` | 磁盘空间 | `{ status, data }` |
| `Xu()` | 写 | `{ status, data: { entry, writer } }` |

**`FileEntry` 必须是 camelCase**:`{ fullPath, isDirectory, isFile, name }`。若序列化成 snake_case(`is_directory`),前端 `isDirectory` 恒为 undefined,**目录递归会静默失效**(角色/乐曲/姓名牌都不加载)。这是重写壳最容易踩的坑。

### 6.3 虚拟路径映射

| 虚拟 | 真实 |
|------|------|
| `/chara/` | `data/characters/` |
| `/music/` | `data/music/` |
| `/voices/` | `data/voices/` |
| `/skills/` | `data/skills/` |
| `/courses/` | `data/courses/` |
| `/player_scenes/` | `data/player_scenes/` |
| `/nameplates/` | `data/nameplates/` |
| `/titles/` | `data/titles/` |
| `/textures/` | `core/textures/` |
| `/una/` | `core/una/` |
| `/sounds/` | `core/sounds/` |
| `/config/` | `core/config/` |
| `/extra/` | `core/extra/` |

### 6.4 输入

- 键盘函数:`kbdStart(keys)`/`kbdUpdate`/`kbdHeld(vk)`/`kbdUni2Virt(ch)`;Di8:`di8KbdStart/Update/Held/Shutdown`。
- 游戏 `m_mi` 用的是 **DirectInput(DIK)键码**,不是 evdev:方向键是 `DIK_UP=200 / LEFT=203 / RIGHT=205 / DOWN=208`(易误写成 evdev 的 103/105/106/108)。
- 打击音变体列表 `m_f0 = ["default","clap","rain","woodblock","bell","kick","shortclap","taiko","mai","ong"]` → `notes/Tap_<v>.wav`。

---

## 7. 关键坑与验证

1. **FileEntry 字段名**:camelCase(`isDirectory`/`isFile`/`fullPath`),否则目录遍历静默失效。
2. **URL 编码**:资源路径含空格/日文(如 `000308 Back 2 Back`、`少女レイ`),自定义协议 fetch 前必须 `encodeURI`,Rust 端 `percent_decode`。
3. **query string**:音频路径带 `?v=0`(变体),解析路径前要剥离 `?`。
4. **双斜杠**:游戏会传 `/config//default_order_music.txt`,路径拼接要 `trim_start_matches('/')`。
5. **Image.src 相对路径**:前端 `new Image().src = "/music/..."` 请求的是页面 origin,需转成自定义协议 URL(如 `https://umg.localhost/...`)。
6. **`.larc` 与 `.arc`/`.una` 算法不同**:别把 `.arc` 的解密套到 `.larc`(header offset 会 > 文件大小)。
7. **rotr 方向**:是 rotate **right**;写成 rotate left 会导致条目表全是乱码。
8. **验证**:解密后检查前 4 字节魔数(DDS/KRSM/RVST/RGF0/PNG)。批量跑完统计成功数。
9. **缺失资源**:打击音变体(`Tap_clap` 等)、`license.xml`、`Screenshot.wav` 可能本地数据不含(服务器下发),用 `fix-missing-assets.js` 生成占位即可,游戏会回退。
10. **静音角色**:`voices/_0000000_sys_silence` 无 `data.arc`,其语音加载失败是**预期**。

---

## 8. 官方规格(优先参考)

逆向前先查作者是否公开了格式:
- UCSL 技能语言:`https://gist.github.com/inonote/d4f9a1ee84da849b5b8962db13d42220`
- UPM 场景模型:`https://gist.github.com/inonote/4d100277f797b55581d4317ffb4f2ce0`
- 规格索引:`https://new.umgr.inonote.jp/docs/docs`

`.arc`/`.una`/`.larc` 的加密算法作者**未公开**(规格列表只有 UCSL/UPM/LED 三种数据格式)。

---

## 9. 复刻:Electron 壳(完整可运行)

把恢复出来的前端 + 原始数据,用**官方 Electron** 重新装载,复刻原生运行环境。

### 9.1 思路

- 前端 3 个文件(`index.html`/`main.css`/`main.js`)从 `app.larc` 恢复(§5.3)。
- 原生主进程那套(`umgr_elc`/键盘/串口)**拿不到**,需**自己实现**。
- 数据目录直接用原始 `UMIGURI_NEXT`(加密 `.arc`/`.una` 由前端自带算法解密)。

### 9.2 目录结构(`desktop/`)

```
desktop/
├── package.json     # main → app-main.js;build.extraResources 打包数据
├── app-main.js      # 主进程: 窗口 + IPC 文件系统 + file:// 协议拦截 + main.js AES 解密
├── preload.js       # contextBridge 注入 umgr_elc + 键盘 + 串口 mock
├── index.html       # 前端入口(<script src="main.js">)
├── main.js          # 前端逻辑(明文;或替换为 main.js.enc 密文)
└── main.css
```

### 9.3 `app-main.js` 要点

1. `ROOT` = 数据根目录:打包后 `process.resourcesPath/game_data`,开发用 `UMIGURI_DATA_DIR` 或默认路径。
2. `PATH_MAP` 虚拟路径映射(同 §6.3);`virtualToReal(vpath)`:先匹配 PATH_MAP,再判盘符/绝对路径,否则拼 ROOT。
3. **IPC handler**:`handshake` / `fs:list` / `fs:file` / `fs:size` / `fs:read`。
   - `fs:list` 必须返回 **camelCase** FileEntry:`{ fullPath, isDirectory, isFile, name }`(见 §7.1)。
   - `fs:file` 返回 `{ status, data: Buffer }`;`fs:read` 返回 `{ status, data: { buf, br } }`。
4. **`protocol.handle('file', ...)`** —— 复刻关键:拦截 `file://` 请求
   - 去盘符前缀:`vpath.match(/^\/[a-zA-Z]:(.*)$/)` → `drive='D:'`, `vpath='/xxx'`。
   - 虚拟路径(`/nameplates/` 等)走 `virtualToReal`;否则 `drive + vpath`。
   - `/main.js` 特殊:返回 **AES 解密后的明文**(源码保护,见 §5.4)。
   - 按扩展名给 MIME(`.html/.css/.js/.png/.dds/.wav/.mp3/.wasm/.xml` …)。
5. 窗口:

```js
const win = new BrowserWindow({
  width: 1280, height: 720, useContentSize: true,
  webPreferences: { preload: path.join(__dirname, 'preload.js'),
    contextIsolation: true, nodeIntegration: false },
});
win.loadFile('index.html');
```

### 9.4 `preload.js` 要点

- `contextBridge.exposeInMainWorld('umgr_elc', { enable, _, st, si, g4 })`,`st.zu/sn/_2/xl` → `ipcRenderer.invoke('fs:*')`,其余返回 `{status:-1}` 占位。
- **键盘**:`codeToVk(e.code → VK)` + `keydown/keyup` 维护 `keyState`;`kbdHeld(vk)`、`kbdUni2Virt(charCode)`(含符号键 `CHAR_TO_VK`)。
- **Di8**:`di8KbdHeld(dik)` 用 **DIK→VK** 映射(方向键 `200/203/205/208`,见 §6.4/§7);`di8KbdStart/Update/Shutdown` 返回 0 让前端走键盘分支。
- **串口 mock**:`ugSerialCreate/Open/Write/Pop/Close/Destroy` 全返回失败/空。
- `getCurrentProcessId` / `kbdStart` / `kbdUpdate`。

### 9.5 运行

```bash
# 用官方 Electron(不是游戏的 app.exe);Electron 二进制见项目 electron41/
electron41/electron.exe desktop/
# 或: cd desktop && npm install && npm start   (start = electron .)
```

### 9.6 打包(electron-builder)

```jsonc
// package.json
"build": {
  "appId": "jp.inonote.umiguri", "productName": "UMIGURI",
  "extraResources": [
    { "from": "../../data", "to": "game_data/data" },
    { "from": "../../core", "to": "game_data/core" }   // 打包后 app-main.js 从 process.resourcesPath/game_data 读
  ],
  "win": { "target": "nsis" }, "mac": { "target": "dmg" }, "linux": { "target": ["AppImage","deb"] }
}
```

```
npm run dist:win / dist:mac / dist:linux
```
跨平台限制:**mac(dmg)只能在 macOS 打包**(签名限制),win/linux 可在 Windows 交叉。

### 9.7 与 Tauri 壳的关键差异(踩坑对照)

| 点 | Electron 壳 | Tauri 壳 |
|----|------------|----------|
| FileEntry 字段 | `app-main.js` 直接返回 camelCase,不踩坑 | Rust serde 默认 snake_case,必须 `#[serde(rename_all="camelCase")]` |
| 封面 `Image.src` 相对路径 | `protocol.handle('file')` 自动兜底 | 需转自定义协议 / monkey-patch `Image` |
| 二进制传输 | IPC 结构化克隆(Buffer),天然快 | `invoke` 返 `Vec<u8>` 走 JSON 极慢,需自定义 protocol |
| 路径编码 | `decodeURIComponent` | 前端 `encodeURI` + Rust `percent_decode` |

### 9.8 诚实边界:「完美运行」其实没达到

- **做到了**:启动 → 数据加载完整(音乐/课程/角色/技能/称号/语言/铭牌/语音)→ THREE canvas 1920x1080 → `.una` 前端解密。
- **没做到**:数据加载后**场景 UI 不显示**(卡 `m_Hr.ef` 完成链,`div=3`),未进主界面。
- 主进程原生(`app.larc/index.js`)未恢复;`.larc` 未离线解密。
- 准确说法:**「跑通到数据加载+渲染」**,不是「完美运行」。

---

## 10. 未完成 / 已知边界

- `.larc` 解密算法(native `electron_common_asar` Archive 类,未逆向)。运行时提取见 §5.3 `dump-larc.js`(仅前端文件)。
- 前端场景 UI 异步完成链卡点(`m_Hr.ef` 等,headless/壳环境限制)。
- `game_logic.deobf.js` 是**分析产物**;游戏实际运行的是原始 `main.js`(AES 加密的 `main.js.enc`),两者语义一致,但反混淆的遍历函数(`m_De` 的 `&&` vs `if` 返回值)可能有细微差异——分析时注意。
