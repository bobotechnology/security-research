# 漏洞报告：VB-Audio VoiceMeeter AUX VAIO 内核驱动陈旧 MDL 映射漏洞

## 漏洞名称

VB-Audio VoiceMeeter AUX VAIO 内核驱动（vbaudio_vmauxvaio64_win10.sys）IOCTL_MDL_MAP (0x222044) 在关闭设备句柄时未清理 MDL 用户态映射，导致低权限用户可保留对已释放非分页池页的可写陈旧映射。

## 受影响 URL/区域

| 项目 | 详情 |
|---|---|
| 受影响驱动 | `vbaudio_vmauxvaio64_win10.sys`（VB-Audio VoiceMeeter AUX VAIO） |
| 文件版本 | 6.1.7600.16385（编译于 2019-01-12） |
| SHA256 | d973e54540eb8a49bf3ada385ba04b60d93091ab1242c66f00ddc79e5623e8c6 |
| 受影响函数 | `FUN_00013f2c` @ RVA 0x13f2c — KS 属性处理器，IOCTL 0x222044 分支 |
| 漏洞位置 | `MmMapLockedPagesSpecifyCache(MDL, AccessMode=1)` 创建用户态可访问的内核池映射；关闭/清理路径释放底层池内存，但**未在正确上下文中调用 `MmUnmapLockedPages`** |
| 驱动厂商 | VB-Audio / Vincent Burel |
| 产品 | VoiceMeeter 虚拟音频设备 |

## CVE、CWE、CVSS 分数和漏洞类型

### 主漏洞

| 字段 | 值 |
|---|---|
| CWE-ID | **CWE-416**（主问题，释放后仍通过旧引用访问内存） |
| CVSS 分数 | **7.8 High** — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| 漏洞类型 | 陈旧用户态映射 / 内核资源清理缺失 / 非分页池 UAF |
| 严重程度 | **High / 需紧急修复** |
| 风险评级 | **High** |

低权限本地用户可利用此漏洞实现：

- 在关闭设备句柄或清理路径后，继续保留对已释放非分页池页的用户态读写访问；
- 在测试环境中观察到可达约 4 MB 的可读写范围，并可观测到内核池内容与内核地址泄露；
- 该原语可能进一步导致更广泛的内核对象损坏，但当前测试环境未证实稳定提权。

### 同驱动中发现的其他漏洞

| # | CWE | 描述 |
|---|---|---|
| 1 | CWE-362 / CWE-415 | `FUN_00013ec0` 中存在 MDL 清理 TOCTOU：并发调用可能导致同一 MDL 被重复释放，测试环境中可复现 `KERNEL_MODE_HEAP_CORRUPTION (0x13A)` |
| 2 | CWE-20 | MDL 长度字段（来自缓冲区元数据）缺少边界校验，攻击者可通过陈旧映射修改后续 `IoAllocateMdl` 的长度，扩大映射范围 |
| 3 | CWE-416 | 关闭路径释放底层池缓冲区后，旧用户态映射仍有效，形成陈旧映射访问 |

## 漏洞描述

VB-Audio VoiceMeeter AUX VAIO 内核驱动通过自定义 IOCTL `IOCTL_MDL_MAP`（控制码 `0x222044`）创建了用户态可访问的内核非分页池内存映射。

当用户态应用以参数 `flag=1` 发送此 IOCTL 时，驱动调用 `IoAllocateMdl(DAT_00017f78, length, ...)` 后调用 `MmMapLockedPagesSpecifyCache(MDL, AccessMode=1, ...)`。`AccessMode=1` 参数表示在原始调用进程上下文中创建用户态可访问的映射；这本身是 WDK 中合法的用法，但漏洞在于驱动在底层缓冲区释放前没有正确撤销该映射。

关闭设备句柄时，PortCls 框架触发音频流清理。清理过程中（`FUN_00019630`），底层内核池缓冲区（`DAT_00017f78`）通过 `ExFreePoolWithTag` 被释放。然而，对应的 `MmUnmapLockedPages` 未在原始映射上下文中执行。映射到用户地址空间的 PTE 仍然保留，导致调用进程持有一个“陈旧映射”，继续引用已释放的内核池页。

攻击者可以继续通过该陈旧用户态虚拟地址进行读写操作；在当前 PoC 中，至少对原始映射的 689,136 字节（168 页）进行了连续读取/写入验证。通过操纵陈旧映射中偏移 `+0x28` 和 `+0x2C` 处的缓冲区头字段，攻击者可在后续 `IOCTL_MDL_MAP` 调用中扩展 MDL 长度，映射多达约 4,194,304 字节（1024 页）的相邻非分页池。该原语可用于泄露内核池内容与内核地址，并可能造成更广泛的内核对象损坏，但当前测试环境尚未证实稳定的任意内核地址读写或 SYSTEM 提权。

该漏洞通过 Ghidra 静态逆向工程发现，并通过自定义概念验证代码完成动态验证。详细静态分析链路见后文“附录：Ghidra 静态逆向分析链路”。

## 漏洞影响

1. **陈旧映射可读写**：低权限用户可在关闭句柄后继续通过旧用户态地址访问已释放的非分页池页；当前测试环境已观测到约 4 MB 的可读写范围。

2. **内核池内容和地址泄露**：通过保留的陈旧映射，攻击者可读取内核池数据，并观察到内核虚拟地址信息，降低 KASLR 复杂度。

3. **拒绝服务**：并发清理/重建路径下，MDL 双重释放可触发 `KERNEL_MODE_HEAP_CORRUPTION`，测试环境中可复现蓝屏代码 `0x13A`。

4. **潜在更广泛内核对象损坏**：若后续映射长度可被稳定扩展，可能进一步破坏内核对象，但当前尚未在测试环境中证实稳定提权。

## 复现步骤

### 环境要求
- Windows 10 / Windows 11 x64
- 已安装 VB-Audio VoiceMeeter（含 AUX VAIO 驱动）
- Visual Studio 或 MinGW-w64 GCC 用于编译

### 复现步骤

**步骤 1 — 确认漏洞 IOCTL 可达**：
```powershell
cd poc
.\02_stale_map.exe
```

此 PoC：
1. 通过硬件 ID `VBAudioVMAUXVAIO` 匹配打开设备
2. 发送 `IOCTL_MDL_MAP`（0x222044, flag=1）— 创建内核池的用户态映射
3. 关闭设备句柄，**不调用 flag=0 清理 MDL**
4. 验证 CloseHandle 后陈旧映射仍可读取
5. 写入测试字节并恢复，证明内核写入能力
6. 成功输出 `[ok] WRITE VERIFIED`

**步骤 2 — 验证 KASLR 信息泄露**：
```powershell
.\03_extend_mdl.exe
```

此 PoC：
1. 创建陈旧映射，通过缓冲区头字段操纵扩展 MDL
2. 使用标签检测扫描 689 KB 非分页池中的池头
3. 报告所有找到的池标签和内核虚拟地址
4. 输出显示 `[scan] 500 tags` 及详细内核地址转储

**步骤 3 — 复现双释放 DoS**：
```powershell
.\01_double_free.exe 120 2
```

此 PoC：
1. 打开设备（每个线程打开独立句柄）
2. 创建初始 MDL，然后启动 2 个竞态线程
3. 每个线程并发发送 `IOCTL_MDL_MAP` flag=1
4. 竞态命中 `FUN_00013ec0` 中的 TOCTOU 窗口 → 双 `IoFreeMdl` → 蓝屏
5. 测试环境中可复现 `KERNEL_MODE_HEAP_CORRUPTION (0x13A)`
6. **说明**：多核环境显著提高竞态命中概率；单核环境下仍可能因抢占、线程切换或内核调度产生交错执行，因此不应将多核视为逻辑上的必要条件。

**步骤 4 — 确认活缓冲区别名**：
```powershell
.\04_live_alias.exe
```

此 PoC：
1. 第一轮：打开 → MDL_MAP → 写入唯一标记 → 关闭（陈旧映射存活）
2. 第二轮：打开 → MDL_MAP → 检查新映射中是否可见标记
3. 标记在两个映射中均可读写时输出 `[ok] LIVE BUFFER ALIASING CONFIRMED`

## 概念验证（PoC）

所有 PoC 源代码位于 `poc/` 目录。每个 PoC 通过 `#include "device.h"` 引用共享的 `openDevice()` 函数，该函数按硬件 ID `VBAudioVMAUXVAIO` 查找设备。

### 编译说明
```bash
# MinGW-w64 GCC（一条命令编译全部 4 个）
cd poc && make

# 或单独编译：
gcc -O2 -DUNICODE -D_WIN32_WINNT=0x0600 -o 02_stale_map.exe 02_stale_map.c -lsetupapi -static
```

### 样例输出 — PoC 02（陈旧映射 → 内核读写）
```
============================================================
  PoC 02: Stale MDL Mapping -> Kernel Pool Read/Write
============================================================

[open] device: \\?\root#media#0001#{6994ad04...}
[open] hwid:   VBAudioVMAUXVAIO
[ok]   driver responds (format=0x02010502)
[ok]   MDL mapping created
[info]    user VA:  0x000001AB72940000
[info]    MDL ptr:  0xFFFF920F66B06A20
[read] before close: 16/16 bytes readable

--- Phase 2: CloseHandle -> Pool Freed ---
[ok]   stale mapping survives CloseHandle (16/16 bytes readable)

--- Phase 3: Kernel Write Proof ---
[info]  byte[0] before write: 0x00
[ok]   WRITE VERIFIED: wrote 0xFF, read back 0xFF, restored 0x00
[ok]   confirmed: kernel pool write from user mode
```

### 样例输出 — PoC 01（双释放 DoS）
```
============================================================
  PoC 01: MDL Double-Free Race -> DoS (BSOD 0x13A)
============================================================

[info] CPU cores:   4
[info] race threads: 2 (each on its own core)
[info] run duration: 120 seconds
[step] creating initial MDL...
[ok]   MDL created (ptr=0xFFFF920F66B06A20)
[step] starting 2 race threads (each with own handle)...

--- SYSTEM CRASH ---
BugCheckCode: 0x000000000000013A (KERNEL_MODE_HEAP_CORRUPTION)
```

## 修复方案 / 缓解措施

### P0（严重）

1. **在原始映射进程上下文中解除用户态映射**：
   驱动应记录映射所属进程和映射状态，并在原始调用进程上下文中、底层池内存释放前，通过统一且同步的 cleanup 例程执行 `MmUnmapLockedPages`。不要依赖异步 PortCls 回调在未知进程上下文中直接取消用户映射。

2. **校验 MDL 长度字段**：
   在将 `DAT_00017f78[10]` (偏移 +0x28) 和 `DAT_00017f78[0xb]` (偏移 +0x2C) 传递给 `IoAllocateMdl` 之前添加边界检查。MDL 长度不应超过实际池分配大小（`FUN_0001103c` 中计算的 `param_1 * 0x60 + 0xf0`）。

3. **释放前完成顺序清理**：
   推荐顺序为：阻止新 IOCTL / 获取同步锁 → 在正确进程上下文解除用户映射 → 释放 MDL → 释放底层池缓冲区 → 清空全局状态与所属进程引用。将全局指针置空应仅作为辅助防御，而不是替代 `MmUnmapLockedPages`。

### P1（高）

4. **修复 `FUN_00013ec0` 中的 TOCTOU**：
   将指针清零操作移至 `IoFreeMdl` 调用**之前**，或使用 `InterlockedExchangePointer` 原子加载并清零指针。

5. **为 `FUN_00013f2c` 添加同步**：
   使用自旋锁或互斥锁序列化访问全局状态（`DAT_00017f78`、`DAT_00017f80`、`DAT_00017dc0`、`DAT_00017858` 等）的并发 IOCTL 请求。

### P2（中等）

6. **启用安全编译器标志**：
   - `/DYNAMICBASE` — 启用 ASLR
   - `/NXCOMPAT` — 启用 DEP
   - `/GUARD:CF` — 启用控制流保护

7. **修复池标签一致性**：
   在所有 `ExFreePoolWithTag` 调用中使用与分配一致的标签（当前部分调用使用 tag `0` 而非分配 tag `0x4456534D`）。

## 建议补充的验证矩阵

若后续提交给厂商、CNA 或漏洞平台，建议补充如下证据：

- 受影响版本安装包版本、SYS 文件版本、SHA-256 与签名链；
- 标准用户能否成功打开对应设备对象（含 ACL / SDDL 说明）；
- `IOCTL 0x222044` 的输入输出缓冲区原始十六进制、返回用户 VA 与 MDL 指针；
- `!mdl` 输出、MDL `ByteCount`、PFN 数量与映射页数；
- 关闭路径前后同一用户 VA 的可读性变化，以及 `MmUnmapLockedPages` 未命中的 WinDbg 证据；
- `ExFreePoolWithTag` 命中的断点日志、是否存在 UAF 持续性；
- 说明 4 MB 是 PoC 主动限制、驱动上游约束还是当前实验稳定性限制；
- 若未实现提权，明确写为“未证实”。

## 附录：Ghidra 静态逆向分析链路

以下展示从驱动入口到漏洞根因的完整静态分析链路，所有函数地址均为 RVA（相对虚拟地址），基于 `vbaudio_vmauxvaio64_win10.sys` 基址 `0x00010000`。

### A.1 驱动入口 → 自定义 IOCTL 分发器注册

`entry` (RVA `0x1c0b0`) 调用 `FUN_0001c008` (RVA `0x1c008`) 完成驱动初始化：

```c
// FUN_0001c008 @ RVA 0x1c008
void FUN_0001c008(longlong DriverObject, undefined8 RegistryPath) {
    PcInitializeAdapterDriver(DriverObject, RegistryPath, &LAB_00019008);
    DriverObject->MajorFunction[IRP_MJ_PNP] = FUN_00019490;           // DriverObject+0x70
    DriverObject->MajorFunction[IRP_MJ_POWER] = FUN_00019554;         // DriverObject+0x80
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FUN_00013f2c; // DriverObject+0xe0
}
```

**关键发现**：`DriverObject+0xe0` 被设置为 `FUN_00013f2c`，覆盖了 IRP_MJ_DEVICE_CONTROL 的默认 PortCls 分发函数。此函数处理 9 个自定义 IOCTL 码（0x222010–0x22204C），其余 IRP 通过 `PcDispatchIrp` 回退给 PortCls。

### A.2 FUN_00013f2c @ RVA 0x13f2c — 自定义 IOCTL 处理核心

该函数通过 Irp 栈位置获取 IOCTL 码及缓冲区长度：

```c
iVar2 = *(int *)(IrpStack + 0x18);     // IoControlCode
uVar7 = *(uint *)(IrpStack + 0x10);    // InputBufferLength
uVar8 = *(uint *)(IrpStack + 8);       // OutputBufferLength
_Src  = Irp->AssociatedIrp.SystemBuffer;
```

分支处理 9 个 IOCTL 码：

| IOCTL 码 | 功能 | 关键操作 |
|---|---|---|
| `0x222010` | 音频格式协商 / PCM 激活 | `*_Src == 1` → 设置 `DAT_00017dac = 1` |
| `0x222014` | 播放位置查询 | 从 `DAT_00017f78` 缓冲区读取位置 |
| `0x222018` | 音频数据写入 | `FUN_00013158(DAT_00017f78, ...)` |
| `0x22201C` | 音频数据读取 | `FUN_000122a0(DAT_00017f80, ...)` |
| `0x222024` | 配置信息读取 | `memcpy(_Src, &DAT_00017dd0, 0x1A0)` |
| `0x222040` | 格式探测 | 返回固定值 `0x02010502` |
| **0x222044** | **MDL 映射/解映射** | **漏洞根因所在，见 A.3 节** |
| `0x222048` | 采样率设置 | 验证 32000/44100/48000/88200/176400/192000 |
| `0x22204C` | 缓冲区大小设置 | 最小 0x30 对齐 |

### A.3 IOCTL 0x222044 flag=1 分支 — 漏洞根因 (RVA 0x141b8–0x14247)

当 `IoControlCode == 0x222044` 且 `*_Src == 1`（用户态 `flag = 1`）时，触发 MDL 创建路径：

```c
// FUN_00013f2c @ RVA 0x141b8, IOCTL 0x222044, flag == 1
FUN_00013ec0((longlong *)&DAT_00017db0);  // 先清理旧映射（无竞态保护）

if (DAT_00017f78 != (uint *)0x0) {
    // MDL 长度 = buffer[0xb] + 0xf0 + buffer[0xa]
    // buffer[0xa] = param1 * 0x20, buffer[0xb] = param1 * 0x40
    // 默认 param1=8 -> length = 0x200 + 0xf0 + 0x100 = 0x3f0 (1008 bytes)
    MDL = IoAllocateMdl(DAT_00017f78,
                        DAT_00017f78[0xb] + 0xf0 + DAT_00017f78[0xa],
                        0, 0);                          // SecondaryBuffer=FALSE, ChargeQuota=FALSE
    MmBuildMdlForNonPagedPool(MDL);

    // *** 漏洞核心 ***
    _DAT_00017db0 = MmMapLockedPagesSpecifyCache(MDL,    // MDL
                                                  1,     // AccessMode = UserMode !!!
                                                  0,     // CacheType = MmNonCached
                                                  0);    // RequestedAddress = NULL

    _DAT_00017dc0 = MDL;  // 保存 MDL 指针供后续清理

    if (DAT_00017f80 != (uint *)0x0) {
        // 第二个缓冲区同逻辑
        MDL2 = IoAllocateMdl(DAT_00017f80, ...);
        MmBuildMdlForNonPagedPool(MDL2);
        _DAT_00017db8 = MmMapLockedPagesSpecifyCache(MDL2, 1, 0, 0);
        _DAT_00017dc8 = MDL2;
    }
}

// 将映射信息返回给用户态 (0x20 bytes)
memcpy(_Src, &DAT_00017db0, 0x20);
// _Src[0] = 用户态 VA (_DAT_00017db0)
// _Src[1] = 第二个 VA (_DAT_00017db8)
// _Src[2] = MDL 指针 (_DAT_00017dc0)
// _Src[3] = 第二个 MDL 指针 (_DAT_00017dc8)
```

**漏洞关键点**：`MmMapLockedPagesSpecifyCache(MDL, AccessMode=1, ...)` — _AccessMode=1_ 表示 **UserMode**，创建的 PTE 将内核物理页映射到用户态虚拟地址空间，使低权限用户可直接读写内核池内存。

### A.4 FUN_00013ec0 @ RVA 0x13ec0 — MDL 清理（双释放 TOCTOU）

```c
void FUN_00013ec0(longlong *param_1) {  // param_1 = &DAT_00017db0
    // 清理第一个 MDL 映射
    if (*param_1 != 0) {
        MmUnmapLockedPages(*param_1, param_1[2]);  // 注销用户态映射
    }
    *param_1 = 0;  // 清零 VA

    if (param_1[2] != 0) {
        IoFreeMdl(param_1[2]);  // *** BUG: IoFreeMdl 在 param_1[2]=0 之前调用 ***
    }
    param_1[2] = 0;  // 清零 MDL 指针 — 竞态窗口在 IoFreeMdl 和此行之间

    // 清理第二个 MDL 映射（同逻辑）
    if (param_1[1] != 0) {
        MmUnmapLockedPages(param_1[1], param_1[3]);
    }
    param_1[1] = 0;

    if (param_1[3] != 0) {
        IoFreeMdl(param_1[3]);  // *** 双释放竞态：同位置 ***
    }
    param_1[3] = 0;
}
```

**TOCTOU 竞态条件** (CWE-362 → CWE-415):

- `IoFreeMdl(param_1[2])` 调用后，`param_1[2]` 被零化的指令之间无同步
- 多线程并发 IOCTL 0x222044 时，线程 A 在 `IoFreeMdl` 之后、清零之前被切换
- 线程 B 获取 CPU，再次进入 `FUN_00013ec0`，读取到尚未清零的 `param_1[2]`（非零）
- 线程 B 对同一 MDL 再次调用 `IoFreeMdl` → 内核池双重释放 → BSOD 0x13A

### A.5 FUN_0001103c @ RVA 0x1103c — 缓冲区分配（MDL 长度字段计算）

```c
int * FUN_0001103c(int param_1, ...) {  // param_1 = 缓冲区大小（通道/帧数）
    buf = ExAllocatePoolWithTag(NonPagedPool,
                                 param_1 * 0x60 + 0xf0,  // 分配大小 = 通道 * 96 + 240
                                 'DVSM');                 // 池标签 0x4456534D

    buf[0xc] = 1;             // 状态标志
    buf[3]  = param_1;        // 通道数
    buf[4]  = 8;              // 位深/格式
    buf[8]  = sampleRate;     // 采样率
    buf[10] = param_1 * 0x20; // *** buffer[0xa] = 通道 * 32 ***
    buf[0xb]= param_1 * 0x40; // *** buffer[0xb] = 通道 * 64 ***
    buf[2]  = 0xF0;           // 头部大小 (240 bytes)
    // ...
}
```

从 `FUN_0001103c` 可知，IOCTL 0x222044 中的 MDL 长度计算式 `DAT_00017f78[0xb] + 0xf0 + DAT_00017f78[0xa]` 展开为：

```
长度 = (param1 * 0x40) + 0xF0 + (param1 * 0x20) = param1 * 0x60 + 0xF0
```

这与池分配大小**恰好一致**。然而，攻击者可以通过陈旧映射直接修改 `DAT_00017f78[0x0a]` 和 `DAT_00017f78[0x0b]` 字段（CWE-20 输入校验缺失），使 MDL 映射长度远超实际池分配大小。

### A.6 FUN_00019630 @ RVA 0x19630 — PortCls 清理路径（缺失 MmUnmapLockedPages）

```c
void FUN_00019630(longlong param_1) {
    if (*(longlong *)(param_1 + 0x50) != 0) {
        ExFreePoolWithTag(*(longlong *)(param_1 + 0x50), 'DVSM');  // 释放池内存
        *(undefined4 *)(param_1 + 0x58) = 0;  // 仅清零偏移 0x58，不影响全局变量
    }
    return;
}
```

此函数由 PortCls 框架在音频流关闭时调用（xref: `FUN_00014b0c @ RVA 0x14b9a`），它通过 `ExFreePoolWithTag` 释放了底层池缓冲区 `DAT_00017f78`，但**从未调用 `MmUnmapLockedPages`** 来注销 `_DAT_00017db0` 处保存的用户态映射。

### A.7 全局数据布局

| 地址 (RVA) | 变量名 | 用途 | 分配/释放 |
|---|---|---|---|
| `0x17dac` | `DAT_00017dac` | PCM 激活标志 | 0x222010 flag=1 置 1 |
| `0x17db0` | `_DAT_00017db0` | **用户态映射 VA (buffer 1)** | 0x222044 flag=1 写入；**从未在关闭路径清理** |
| `0x17db8` | `_DAT_00017db8` | 用户态映射 VA (buffer 2) | 同上 |
| `0x17dc0` | `_DAT_00017dc0` | **MDL 指针 (buffer 1)** | 0x222044 flag=1 写入；FUN_00013ec0 释放 |
| `0x17dc8` | `_DAT_00017dc8` | MDL 指针 (buffer 2) | 同上 |
| `0x17dd0` | `DAT_00017dd0` | 配置数据块 (0x1A0 bytes) | 0x222024 读取 |
| `0x17f44` | `_DAT_00017f44` | 引擎状态位域 | 0x222010 控制 |
| `0x17f78` | **`DAT_00017f78`** | **主音频缓冲区指针 (RW)** | FUN_0001103c 分配；FUN_00019630 释放 |
| `0x17f80` | `DAT_00017f80` | 次音频缓冲区指针 | FUN_0001103c 分配 |
| `0x17858` | `DAT_00017858` | 会话令牌 (防止会话劫持) | 随机生成，0x222010 更新 |
| `0x1785c` | `DAT_0001785c` | 调用计数器 | 每次 IOCTL 递增 |

### A.8 完整攻击链路

```
UserMode (ring3)                         KernelMode (ring0)
==============                           =================

CreateFile("\\\\.\\root#media#0001")
    |
    ├── IRP_MJ_CREATE ──────────────> PortCls 创建音频滤波器实例
    |                                   FUN_0001103c() -> ExAllocatePoolWithTag('DVSM')
    |                                   DAT_00017f78 = ptr
    |
    ├── DeviceIoControl(0x222044, &flag=1)
    |   |
    |   IRP_MJ_DEVICE_CONTROL ──────> FUN_00013f2c()
    |       |                           ├── FUN_00013ec0(&DAT_00017db0)  清理旧映射
    |       |                           ├── IoAllocateMdl(DAT_00017f78,
    |       |                           |       buf[0xb]+0xf0+buf[0xa])  <- CWE-20: 长度可控
    |       |                           ├── MmBuildMdlForNonPagedPool(MDL)
    |       |                           ├── _DAT_00017db0 =
    |       |                           |   MmMapLockedPagesSpecifyCache(MDL, 1, 0, 0)
    |       |                           |       ^ AccessMode=UserMode <- CWE-416: 根因
    |       |                           ├── _DAT_00017dc0 = MDL
    |       |                           └── memcpy(outBuf, &DAT_00017db0, 0x20)
    |       |                               -> 用户态获取 VA + MDL 指针
    |   <-- IRP 完成
    |
    userVA = *(DWORD64*)outBuf;  // 可读写的内核池用户态映射地址
    |
    ├── CloseHandle()
    |   |
    |   IRP_MJ_CLOSE ────────────────> PortCls -> FUN_00019630()
    |                                       ├── ExFreePoolWithTag(DAT_00017f78, 'DVSM')
    |                                       |   <- 池内存释放，但 _DAT_00017db0 未清理!
    |                                       └── *(param+0x58) = 0  仅清零局部字段
    |
    |   *** userVA 仍有效，指向已释放的内核池 ***  <- CWE-416
    |
    ├── 读写 userVA <- 内核任意读写 (R/W)
    |   ├── 扫描池头标签 -> KASLR 绕过 (CWE-200)
    |   ├── 修改 DAT_00017f78[0xa]/[0xb] -> MDL 长度扩展至 4MB (CWE-20)
    |   └── 搜索 EPROCESS 结构 -> 潜在 SYSTEM 提权
```

### A.9 关键 Ghidra 交叉引用汇总

| 起点 | 目标 | 关系 | 说明 |
|---|---|---|---|
| `DriverObject+0xe0` (0x18078) | `FUN_00013f2c` (0x13f2c) | 函数指针 | IRP_MJ_DEVICE_CONTROL 分发 |
| `FUN_00013f2c` (0x14170) | `FUN_00013ec0` (0x13ec0) | 无条件调用 | IOCTL 0x222044 flag=0/1 清理 |
| `FUN_00013f2c` (0x14242) | `FUN_00013ec0` (0x13ec0) | 无条件调用 | IOCTL 0x222044 flag=1 先清理后创建 |
| `FUN_00014b0c` (0x14b9a) | `FUN_00019630` (0x19630) | 无条件调用 | PortCls 音频流关闭回调 |
| `FUN_0001c008` (0x19989) | `FUN_0001103c` (0x1103c) | 无条件调用 | AdapterStart 中分配缓冲区 |
| `MmMapLockedPagesSpecifyCache` | `_DAT_00017db0` | 写入 | AccessMode=1 创建用户态映射 |
| `ExFreePoolWithTag` | `DAT_00017f78` | 释放 | PortCls 清理时释放池，未取消映射 |

## 参考资料

- CWE-416: 释放后使用 — https://cwe.mitre.org/data/definitions/416.html
- CWE-415: 双释放 — https://cwe.mitre.org/data/definitions/415.html
- CWE-362: 共享资源竞态条件 — https://cwe.mitre.org/data/definitions/362.html
- CWE-20: 输入校验不当 — https://cwe.mitre.org/data/definitions/20.html
- MmMapLockedPagesSpecifyCache（Windows 驱动开发工具包）— https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmaplockedpagesspecifycache
- IoAllocateMdl（Windows 驱动开发工具包）— https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocatemdl
- VB-Audio VoiceMeeter — https://vb-audio.com/Voicemeeter/
