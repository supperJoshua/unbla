# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.1.0] - 2026-11-11

首个可用版本。目标版本：BLA `bla-agents@3.2.4`（npm）。

### Added

- `unbla scan`：只读检测，`--json` 输出机器可读报告，存在 `critical` 时退出码 1。
- `unbla strip`：输出剥离副本，不动原件。
- `unbla verify`：导出名一致性 + `node --check` + 逐条目 SHA-256 三重校验。
- 5 个检测器：
  - `asar-header-amplification`（超限诱饵分片）
  - `honey-sourcemap` / `honey-sourcemap-inline`（伪造 sourcemap）
  - `cognitive-armor-corpus`（注入语料符号，含可达性判定）
  - `model-directed-payload`（给模型看的注入话术）
  - `canary-marker`（canary/评测水印）
- 2 个安全剥离器：asar 诱饵条目重写、内联伪造 sourcemap 移除。
- 双 Pickle 头的 `.asar` 读写实现，零依赖。

### Known limitations

- AST 级函数重命名**不可逆**，不提供源码还原。
- 已被织入真实调用链的诱饵（woven）只报告，不删除。
- 常量对应 BLA 3.2.4；上游改变注入结构后需同步更新判据。
