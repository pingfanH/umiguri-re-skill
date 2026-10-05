# umiguri-re-skill

UMIGURI(inonote 音游 v2.x)逆向工程 skill 仓库。

> 把 UMIGURI 的分析与逆向全过程沉淀为可复用的 opencode skill:
> 分析方法论 / 文件格式 / 加解密算法 / 解密后结构 / 可运行脚本 / 踩坑与验证。

## 内容

```
umiguri-re-skill/
└── umiguri-reverse-engineering/
    ├── SKILL.md                 # 主文档(全流程)
    └── scripts/
        ├── decrypt_arc.js       # .arc/.una 归档批量解密器
        ├── dump-cdp.js          # CDP dump renderer 源码
        └── dump-larc.js         # app.larc(.larc) 运行时提取(解密后的前端文件)
```

## SKILL.md 覆盖

| 章节 | 内容 |
|------|------|
| 目标概况 | 定制 Electron 25 / THREE r137 / Effekseer / app.exe / app.larc |
| 分析方法论 | 识别分类、CDP dump、Frida 主进程、Ghidra native、terser 反混淆 |
| 文件格式 | `.arc`(UARC) `.una`(UNA ) `.larc`(Re=L) `.krtbl` `.dds` `.rgf` `.rvs` `.rsb` `.glb` |
| 加解密算法 | 条目表偏移、PRNG 4 状态 rotr、XOR 表(VA/WA)、mNa 位置流、gzip、P2 参数 |
| 解密后结构 | 扩展名推断、目录结构、明文数据 |
| 运行时桥 | umgr_elc API、handshake、虚拟路径映射、DIK 键码 |
| 复刻:Electron 壳 | 目录结构 / 主进程 `protocol.handle('file')` 拦截 / IPC / preload / 运行 / 打包 / 与 Tauri 差异 |
| 踩坑 | FileEntry camelCase、URL 编码、query、双斜杠、Image.src、rotr 方向 |

## 使用

### 作为 opencode skill

放到 opencode 扫描路径之一:

```
.opencode/skills/umiguri-reverse-engineering/SKILL.md
~/.config/opencode/skills/umiguri-reverse-engineering/SKILL.md
```

或在 `opencode.json` 里注册:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "skills": { "paths": ["./path/to/umiguri-re-skill"] }
}
```

> 修改配置后需重启 opencode。

### 解密归档

```bash
# 单个
node umiguri-reverse-engineering/scripts/decrypt_arc.js <data.arc> [输出目录] [P2]
# 批量(递归)
node umiguri-reverse-engineering/scripts/decrypt_arc.js --batch <根目录> [输出目录] [P2]
```

### dump renderer 源码

```bash
# 游戏以 --remote-debugging-port=9222 启动后
node umiguri-reverse-engineering/scripts/dump-cdp.js 9222 cdp_sources
```

### 提取 app.larc(.larc)内容

`.larc` 解密算法未逆向(native asar),用运行时提取:游戏以 `--remote-debugging-port=9222` 启动后,从 renderer `fetch` 解密后的原文。

```bash
node umiguri-reverse-engineering/scripts/dump-larc.js 9222 larc_out
# 也可追加额外路径: node .../dump-larc.js 9222 larc_out /some/path.js
```

> 只能拿经 `file://` 暴露的前端文件(index.html/main.css/main.js);主进程 JS/node_modules 拿不到。

## 声明

仅供学习与互操作研究。游戏版权归 inonote 所有((c) 2025 inonote)。
