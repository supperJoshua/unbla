# unbla

[![ci](https://github.com/supperJoshua/unbla/actions/workflows/ci.yml/badge.svg)](https://github.com/supperJoshua/unbla/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

**剥掉 BLA 类「反 AI 逆向」防护层，还你一个能读、能跑、体积正常的产物。**

`unbla` 不是一个「一键还原源码」的工具。它只做一件事：把投毒层里**可以证明删了不改变行为**的那部分拆掉，剩下的明确告诉你在哪、为什么不能动。

---
## 1. 它面对的是什么

上游项目 [BLA](https://github.com/qybaihe/bla)（npm 包 `bla-agents`，本文实测版本 **3.2.4**）在打包产物里注入让 AI 逆向 agent 空转的「诱饵」，把逆向成本推到不可接受。三招：

| 招式 | 做法 | 后果 |
|---|---|---|
| 投毒诱饵 | 注入语法合法、语义无效的代码与注释 | agent 读进上下文、浪费 token |
| 超限轰炸 | 往 `.asar` 头部塞几千条假 inventory 分片 | 头部逼近 16 MiB 准入上限，解析器直接崩 |
| 诱导误判 | 伪造 sourcemap、假 TEE/enclave 模块、给模型看的「权威说明」 | agent 得出错误结论 |

`unbla` 的工作是从**产物结构**上把这些层识别出来，并且只删能证明安全的部分。

## 2. 实测（真实 BLA 产物，非模拟）

靶子：一个 7 文件的 Electron 应用，`resources/app.asar` 原始 **3 705 B**。
用 `bla-agents@3.2.4` 以 `--intensity bankrupt` 加固后，再跑 `unbla`：

| 指标 | 加固后 | unbla 处理后 | 变化 |
|---|---|---|---|
| `app.asar` | 18 436 082 B（17.58 MiB） | **682 280 B（0.65 MiB）** | **−96.3%** |
| asar 头部 | 16.64 MiB（17 445 012 B） | **0.00 MiB（2 100 B）** | 降到 0 |
| 整棵产物树 | 19 119 081 B | **1 337 800 B** | **−93.0%** |
| asar 条目 | 4 008（含 4 000 诱饵） | **8** | 删 4 000 诱饵 |
| `billing.js` | 136 572 B | 131 036 B | −4.1% |

**行为保持性（`unbla verify`）**：8 个真实条目全部存在，SHA-256 逐字节一致，`node --check` 通过 → `PASS`。
**第三方交叉验证**：官方 `@electron/asar@4.3.1` 的 `listPackage()` 正常加载剥离后的包（10 条目），`extractFile('billing.js')` 读出 136 104 B。

> 数字可复现，步骤见 [docs/EVIDENCE.md](docs/EVIDENCE.md)；另一组同结构样本的数字与差异原因见该文件第 6 节。

## 3. 能力矩阵：什么删、什么不删

| 防护层 | 识别 | 处理 | 为什么 |
|---|---|---|---|
| asar 头部超限诱饵（`enclave/shards/ring0-slot-*`） | critical | **删除** | 纯合成条目，无任何真实代码引用 |
| 内联伪造 sourcemap | critical | **删除** | 只影响调试信息，删除不改变运行 |
| 独立伪造 `.map` 文件 | critical | **丢弃** | 假来源信息比没有更糟 |
| 注入语料符号（`_interlockSafetyCorpus_*` 等） | warn | **默认保留** | 见下节，多数已被织进真实调用链 |
| 给模型看的注入话术 | warn | 只报告 | 是注释/字符串，删不删都有争议 |
| canary GUID 水印 | info | 只报告 | 用于溯源，删除会破坏审计价值 |
| 假 enclave 模块（`enclave/hardware-tee-bridge.js`） | warn | **不删** | 真实代码可能 `import` 它，删了会断 |
| AST 级函数重命名 | — | **无法还原** | 原符号名在编译期已丢失，不可逆 |

### 为什么 JS 层只降 4.1%

这是本项目最重要的一条实测结论。BLA 把诱饵语料和摘要函数**互相引用，并接进真实函数**：

```
runtimeSeedPrimaryPolicy_5a85        <- 重命名后的真实业务函数（原 seatCost）
  └─ _deriveContainmentCorpusDigest_0c43   <- 诱饵摘要
       └─ _interlockSafetyCorpus_0c43      <- 诱饵语料
```

两端都是诱饵命名，中间夹着真实逻辑。任何「未被引用即删除」的朴素死代码策略都会把这个簇判成死的，一删就破坏运行。`unbla` 因此改成**从非诱饵语句出发做可达性闭包**：只要这个簇能从活代码走到，就整体判定 `removable=False`，只报告不动刀。

真正能安全删的 JS 部分，只有内联的假 sourcemap（就是那 4.1%）。

## 4. 判据：三层，全部可指向证据

1. **结构指纹**——路径形状 + body 三键（`shardId` / `enclaveCid` / `attestationHash`）。常量直接读自 BLA 源码 `src/shields/exhaustion/asar-header-amplifier.ts`，不是猜的。
2. **拓扑可达性**——从非诱饵语句出发的闭包传播，判断注入符号是否被活代码使用。
3. **语义一致性**——sourcemap 判据要求**至少命中 2 条**才判伪造：合成 scheme 的 `sourceRoot`、全部 sources 落在 enclave/TEE 路径、`sourcesContent` 全是短 stub、≥40 段映射里 distinct ≤3。单条命中不算，避免误伤。

## 5. 用法

```bash
pip install -e .          # 或直接用 PYTHONPATH=src python -m unbla.cli
unbla scan  dist/         # 只报告，不改动；有 critical 时退出码 1
unbla strip dist/ -o out/ # 输出一份剥离后的副本
unbla verify dist/ out/   # 校验：导出名 / node --check / asar 逐条目哈希
```

零运行时依赖，纯 Python 标准库。`verify` 的 parse 检查需要本机有 `node`，没有就跳过并注明。

MCP / CI 场景：`scan --json -o report.json` 输出机器可读报告。

## 6. 局限（写清楚，不粉饰）

- **不还原源码**：函数名、变量名不可逆，`unbla` 不做也不假装做这件事。
- **不删 woven 诱饵**：宁可留着也不冒险破坏运行。
- **只看结构**：不做语义级反编译，不判断「这段业务逻辑对不对」。
- **攻防是动态的**：BLA 换诱发方式，判据就要跟着改。当前常量对应 3.2.4。

## 7. 项目结构

```
src/unbla/
  asar.py       # 双 Pickle 头的 asar 读写，零依赖
  jsast.py      # 顶层语句 span 扫描（跳过字符串/模板/注释）
  sourcemap.py  # VLQ 解码 + 伪造判据 + 内联 map 提取
  shields.py    # 5 个检测器 + 2 个安全剥离器
  verify.py     # 导出名 / node --check / 逐条目哈希
  cli.py        # scan | strip | verify
tests/test_unbla.py   # 13 项，全部内联构造
docs/EVIDENCE.md      # 每个数字的出处与复现步骤
```

## 8. 验证

发布前从零重跑一遍（BLA 3.2.4 / `@electron/asar` 4.3.1 / Node 22.23.2 / Python 3.12.11）：

| 测试 | 结果 |
|---|---|
| 单元测试 | 13/13 通过 |
| 真实加固产物的 `scan` | 6 critical / 11 warning，exit 1 |
| `strip` | 删 4 000 条目 / 0 语句 / 5 个内联假 map |
| `verify` | PASS，8 个真实条目逐字节一致，`node --check` 全过 |
| 官方库加载剥离产物 | 10 条目，`extractFile('billing.js')` = 136 104 B |
| **行为等价** | 原始 / 加固 / 剥离 / 解包后 4 个构建、8 条断言结果全等 |
| **反向验证** | 删掉一个真实条目 → FAIL；翻转 1 个字节 → FAIL |
| 未加固产物 | 0 findings（无假阳性） |
| 幂等性 | 再 strip 一次，SHA-256 不变 |

## 9. 合法使用

仅用于**你自己拥有或已获授权**的产物，用于安全审计、取证分析、恶意投毒检测、教学研究。详见 [DISCLAIMER.md](DISCLAIMER.md)。

贡献代码请先读 [CONTRIBUTING.md](CONTRIBUTING.md)；版本变更见 [CHANGELOG.md](CHANGELOG.md)；安全问题按 [SECURITY.md](SECURITY.md) 私下报告，不要开公开 issue。

## License

MIT
