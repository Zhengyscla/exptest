# HONOR OXF-AN00 (Kirin 990 / HarmonyOS 4.2) 提权实验记录

> 时间：2026-11-27
> 目标机：HONOR OXF-AN00（`HWOXF` / kirin990），HarmonyOS `4.2.0.125(C00E121R5P4)`
> 内核：`5.10.43 #1 SMP PREEMPT Tue Sep 22 09:21:41 CST 2026`
> 工具：LSPosed/LSPrivilege（GhostLock-APP）

## 一句话结论

**这台机器无法用 LSPrivilege 提权。** 不是 profile 填错，而是内核把 SELinux 编译成
`CONFIG_SECURITY_SELINUX_DEVELOP=n`：`/sys/fs/selinux/enforce` 恒返回 `"1"`、
`selinux_state` 里没有 `enforcing` 字段，而 LSPrivilege 的 W1 阶段硬性要求该文件读到 `'0'`。
把它强行跳过之后，W2 依赖的 `mm_struct` 泄漏在本内核上拿不到可信地址，写下去就 panic。

## 本次产出的可复用价值

1. **完整的内核符号表**：从 `BOOT.img` 解出与设备运行内核逐字一致的内核镜像，
   用 kallsyms 恢复 206,378 个符号，`_text = 0xffffffc010000000`（见 [kernel/symbols.txt](kernel/symbols.txt)）。
2. **一份静态核对过的 profile**：`offset` 段全部对齐真实符号，`task_struct`/`cred` 偏移全部用
   反汇编和数据交叉验证（见 [02-结构与关键函数.md](02-结构与关键函数.md)）。
3. **一套可复现的 native 构建链路**：NDK r30 + 响应文件编译，绕开本机 `make`/MSYS 不可用的问题
   （见 [04-复现指南.md](04-复现指南.md)）。
4. **四条失败路径的定量数据**：足以说明哪些参数可以排除（见 [03-实验记录.md](03-实验记录.md)）。

## 目录

| 文件 | 内容 |
|---|---|
| [01-内核取证.md](01-内核取证.md) | `BOOT.img` 归属验证、kallsyms 恢复、符号偏移表、设备侧取证限制 |
| [02-结构与关键函数.md](02-结构与关键函数.md) | `task_struct` / `cred` / `rt_mutex_waiter` 偏移及其证据；SELinux 结论的证据链 |
| [03-实验记录.md](03-实验记录.md) | 7 次运行的日志要点、`mm_struct_sz` 四组数据、panic 归因 |
| [04-复现指南.md](04-复现指南.md) | 编译、部署、运行、profile blob 变体生成、已知坑 |
| `kernel/` | `symbols.txt`（符号表）、`evidence-disasm.txt`（关键函数反汇编原文） |
| `profiles/` | 各版 HOCON profile 与 APP 编译出的 PRIV1 blob |
| `logs/` | 全部原始日志（APP 侧 6 份 + 自建 native 6 份） |
| `patches/` | 相对上游的实验补丁（仅 1 处） |
| `tools/` | 符号/反汇编/交叉引用/blob 补丁/构建脚本 |

## 文件清单（43 个文件，145 KB）

| 路径 | 字节 |
|---|---|
| `README.md` | 3272 |
| `01-内核取证.md` | 3886 |
| `02-结构与关键函数.md` | 5272 |
| `03-实验记录.md` | 5132 |
| `04-复现指南.md` | 4304 |
| `kernel/symbols.txt` | 5192 |
| `kernel/evidence-disasm.txt` | 9134 |
| `logs/` 12 份 | 4.0K–24K |
| `profiles/*.conf` 4 份 | 1.9K–4.7K |
| `profiles/blobs/*.bin` 4 份 | 1925 各 |
| `patches/cve_2026_43499_backend.cpp.patch` | 1065 |
| `tools/` 14 个脚本 | 0.4K–2.5K |

## 不建议继续的方向

- 换 `mm_struct_sz`（936 / 960 / 1024 / 1280 都试过，详见 03）：能泄漏的必崩，不崩的泄漏不到。
- 用 `--force-attack` 绕过 W1：该参数只跳过「已有 KernelSU root 就别再打」，源码
  `cve_2026_43499_backend.cpp:449` 已确认。
- 让 APP 自己跑：APP 的 W1 判定在 native 里，无 UI 开关。

## 如果将来还要碰

优先解决 **可信的 `mm_struct` 定位**（读 `kernelsnitch.h` 的扫描假设，与本内核 SLUB 的
`order` / `objects_per_slab` / `s->size` 对齐），因为 `sel_read_enforce` 这条路在
非 DEVELOP 内核上没有解。两者都满足的工具才可能在这台机器上工作。
