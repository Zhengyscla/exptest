# HONOR V30 (OXF-AN00) GhostLock/提权研究复盘

日期：2026-11-26
设备：HONOR V30 (OXF-AN00)，Kirin 990 5G，HarmonyOS 4.2.0.125 (C00E121R5P4)
内核：Linux 5.10.43 #1 SMP PREEMPT Tue Sep 22 09:21:41 CST 2026 aarch64
启动状态：Bootloader Locked，Verified Boot Green，SELinux Enforcing，user/release-keys

## 一、漏洞确认（来自解密 boot.img）

BOOT.img 为标准 Android boot v2（可被 `ghostlock-extract` 之外的常规工具处理；
直接喂解压后的 arm64 Image 给 extractor 即可）。内核 gzip 解出 73,216,524 字节。

1. **CVE-2026-43499 (GhostLock) 未修**：
   `remove_waiter@0x19d860`（image 相对偏移）开头 `mrs x19, sp_el0`，仍用 `current`
   而非 `waiter->task`（上游修复 commit 3bfdc63）。extractor 亦确认
   "CVE-2026-43499 primitive present (remove_waiter@0x19d860 still uses current)"。
2. **CVE-2026-99491 未修**：`wacom_remove_shared_data@0x110c9080` 直接 `kfree`，
   无 `synchronize_rcu`；`wacom_report_touch_mute` 符号不存在。
   攻击面已实测可达：shell（含 uhid/input 组）可通过 `/dev/uhid` 创建
   vendor 0x056a 虚拟 Wacom 设备，wacom 驱动绑定并生成 evdev 节点（无需实体外设）。
3. CVE-2026-98499（同 wacom 面）未单独反汇编确认，按修复时间推断同样未修。

## 二、本机内核关键偏移（全部证据化，可直接复用）

### task_struct
| 字段 | 偏移 | 依据 |
|---|---|---|
| prio | 0x120 (288) | set_user_nice / __sched_setscheduler |
| normal_prio | 0x124 (292) | __sched_setscheduler 加载（推断，未运行时验证） |
| sched_task_group | 0x2c0 (704) | sched_move_task（推断） |
| pi_lock | 0x8d4 (2260) | remove_waiter 自旋锁 |
| pi_waiters | 0x8e8 (2280) | remove_waiter rb_erase |
| pi_top_task | 0x8f8 (2296) | pi 布局 |
| pi_blocked_on | 0x900 (2304) | remove_waiter `str xzr,[task,#0x900]` |
| pid / tgid | 0x640 / 0x644 | P40 对照 |
| atomic_flags | 0x608 (1544) | init_task 静态数据：restart_block.fn 于 0x610 |
| real_cred / cred | 0x7f8 / 0x800 | commit_creds 直接确认 |
| comm | 0x810 (2064) | init_task "swapper" @0x810（0x808 是 cached_requested_key） |
| tasks | 0x538 (1336) | release_task 的 list_del |
| seccomp | 0x8b0 (2224) | __secure_computing 读取 current+0x8b0 |

### cred（5.10 布局，与 5.10.236 profile + P40 security@0x78 一致）
copy_size=168, usage@0=1, caps@40×5=-1,
ref0/1/2 = user/user_ns/group_info @128/136/144

### cred 引用绝对地址（image）
- root_user     = 0xffffffc0134a3500
- init_user_ns  = 0xffffffc0134a32e8
- init_groups   = 0xffffffc0134a4748
- init_cred     = 0xffffffc0134a46a0（与 P40 复盘完全相同）
- selinux_state = 0xffffffc013e13ac8（与 P40 完全相同）
- remove_waiter = image+0x19d860（P40 为 0x19d830，差 +0x30）

### rt_mutex_waiter（厂商改版）
task@0x30, lock@0x38, +0x40 起为厂商 qos/flag，prio@0x48，deadline@0x50，无 ww_ctx。

## 三、GhostLock profile 与运行结果

`profile_5.10.43.draft.conf` 已通过 GhostLock App（com.ghostlock.app 1.2）校验，
主页显示"受支持"。route=multicast_waiter（extractor 建议；select_stack 亦可用）。

**关键修正：`kernel_phys_offset = 0`**（Kirin DRAM 基址为 0，不是 native 默认的
0x80000000）。不加此值时 direct map alias/slide 全为 0，W1 直接放弃；
加入后 alias/slide/init_task/root_tg 全部正确解析，W1 真正开始执行，
KernelSnitch 成功找到 futex collisions。

**最终壁垒（结构性）**：堆喷页面准备好（"payload ready"）后，
`Write 1`（对 selinux_state 的受限写）每次都失败——与 P40 复盘一致：
华为内核 selinux_state 受 prmem/HKIP 保护，所有 SELinux 路线判死；
W2/W3 依赖 W1 窗口，整链在 W1 断裂。约 7 次运行全部安全失败，
无 panic、无重启、SELinux 保持 Enforcing。

native（无论 com.ghostlock.app 1.2 还是月虹 1.2+160）将本机识别为
`soc: qcom/other` 并硬编码 `label=ghostlock_oplus slide=pselect main=pselect`，
profile 的 route 亦被其覆盖。

## 四、文件清单

- `README.md` — 本复盘
- `profile_5.10.43.draft.conf` — 通过 App 校验的完整 profile（HOCON v2）
- `glk_v_po0.bin` — GLK1 v2 二进制，kernel_phys_offset=0（地址解析正确的变体）
- `glk_v_po0_he12.bin` — 同上 + heap.prepare_max_attempts=12
- `image/kernel-5.10.43_Image.bin` — 从 BOOT.img 解出的 arm64 内核 Image（73,216,524B）
- `image/kernel-5.10.43_Image.gz` — BOOT.img 内的 gzip 内核载荷（24,506,078B）
- `disasm/remove_waiter_0x19d860.txt` — GhostLock 未修证据（`mrs x19, sp_el0`）
- `disasm/wacom_remove_shared_data_0x110c9080.txt` — 99491 未修证据（kfree、无 synchronize_rcu）
- `disasm/commit_creds_0x114e10.txt` — real_cred/cred=0x7f8/0x800 证据
- `disasm/init_task_fielddump.txt` — init_task 静态数据（restart_block.fn@0x610 ⇒
  atomic_flags=0x608；"swapper"@0x810 ⇒ comm=0x810）
- `device-glk/` — 设备 `/data/local/tmp/glk/` 全量 + 运行痕迹：
  - 各 profile（HOCON/JSON/GLK1 bin）与 extractor 输出
  - `.ghostlock_root.sh` — native 写入的 root 脚本（W1 成功后才会执行）
  - `ghostlock-app/.ghostlock_native.log` / `.ghostlock_root.sh` — 第二次运行（po0）痕迹
- `logs/ghostlock-shizuku-0.log.txt` — 第一次 App 运行日志（失败：W1 target 0）
- `logs/profile.conf` / `logs/profile.bin` — App 实际合并导出的 profile
- 设备端另有：`/data/local/tmp/glk/`（已归档为 device-glk/）、
  `/sdcard/Download/ghostlock-debug-log/`

## 五、复现命令

```sh
# native 变体运行（shell 权限即可，无需 Shizuku）
adb push glk_v_po0.bin /data/local/tmp/glk/profile_po0.bin
adb shell chmod 644 /data/local/tmp/glk/profile_po0.bin
adb shell /data/local/tmp/ghostlock-native --load-prebuilt-profile \
      /data/local/tmp/glk/profile_po0.bin
```

## 六、结论与剩余路径

- 公开 GhostLock App/native 无法在本机实现临时 root：W1 在华为 prmem/HKIP 上判死，
  与 P40 (ELS-AN00) 复盘"7 条 SELinux/HKIP 候选全灭"一致。
- 剩余路径：按 P40 方法自写 exploit（perf 泄 KASLR + 随机/uuid ctl_table 读原语 +
  rtmutex 栈 UAF 写原语；产出为 shell 域 uid0，非完整 root）、
  等待针对 Kirin 的私有 PoC、或接受 Shizuku 方案。
- BL 解锁在本机不可行（fastboot oem unlock 为假解锁，flash.locked 恒为 1）。
