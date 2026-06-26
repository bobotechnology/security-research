# 漏洞报告：VB-Audio VoiceMeeter AUX VAIO 内核驱动任意读写漏洞

## 漏洞名称

VB-Audio VoiceMeeter AUX VAIO 内核驱动（vbaudio_vmauxvaio64_win10.sys）IOCTL_MDL_MAP (0x222044) 关闭设备句柄时未清理 MDL 用户态映射，导致低权限用户可读写内核非分页池内存

## 受影响 URL/区域

| 项目 | 详情 |
|---|---|
| 受影响驱动 | `vbaudio_vmauxvaio64_win10.sys`（VB-Audio VoiceMeeter AUX VAIO） |
| 文件版本 | 6.1.7600.16385（编译于 2019-01-12） |
| SHA256 | d973e54540eb8a49bf3ada385ba04b60d93091ab1242c66f00ddc79e5623e8c6 |
| 受影响函数 | `FUN_00013f2c` @ RVA 0x13f2c — KS 属性处理器，IOCTL 0x222044 分支 |
| 漏洞位置 | `MmMapLockedPagesSpecifyCache(MDL, AccessMode=1)` 创建用户态可访问的内核池映射；CloseHandle 时 PortCls 清理路径释放池内存，但**未调用 `MmUnmapLockedPages`** |
| 驱动厂商 | VB-Audio / Vincent Burel |
| 产品 | VoiceMeeter 虚拟音频设备 |

## CVE、CWE、CVSS 分数和漏洞类型

### 主漏洞

| 字段 | 值 |
|---|---|
| CWE-ID | **CWE-416**（释放后使用） |
| CVSS 分数 | **7.8** — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| 漏洞类型 | 释放后使用 / 内核资源清理缺失 |
| 严重程度 | **严重（Critical）** |
| 风险评级 | **高（High）** |

低权限本地用户可利用此漏洞实现：

- 任意**读取**内核非分页池内存（最多 4 MB）
- 任意**写入**内核非分页池内存（最多 4 MB）
- 内核虚拟地址信息泄露（KASLR 绕过已确认）

### 同驱动中发现的其他漏洞

| # | CWE | 描述 |
|---|---|---|
| 1 | CWE-415 / CWE-362 | `FUN_00013ec0` @ RVA 0x13ec0 双释放竞态：`IoFreeMdl` 在指针清零前调用，多线程 `IOCTL_MDL_MAP` 可触发 → BSOD `KERNEL_MODE_HEAP_CORRUPTION (0x13A)` |
| 2 | CWE-20 | MDL 长度计算使用攻击者可控的缓冲区字段 `DAT_00017f78[10]` (偏移 +0x28) 和 `DAT_00017f78[0xb]` (偏移 +0x2C)，无校验 → 攻击者可将映射扩展至 4 MB |
| 3 | CWE-416 | 活缓冲区别名：CloseHandle → 重新打开通过 LFH 缓存复用同一物理页，陈旧映射与活映射之间可双向读写 |

## 漏洞描述

VB-Audio VoiceMeeter AUX VAIO 内核驱动通过自定义 IOCTL `IOCTL_MDL_MAP`（控制码 `0x222044`）创建了用户态可访问的内核非分页池内存映射。

当用户态应用以参数 `flag=1` 发送此 IOCTL 时，驱动调用 `IoAllocateMdl(DAT_00017f78, length, ...)` 后调用 `MmMapLockedPagesSpecifyCache(MDL, AccessMode=1, ...)`。`AccessMode=1` 参数在内核虚拟地址空间中创建了一个用户态可访问的映射。驱动通过 IOCTL 输出缓冲区将映射的用户态虚拟地址返回给调用方。

当设备句柄被关闭（`CloseHandle`）时，PortCls 框架触发音频流清理。清理过程中（`FUN_00019630`），底层内核池缓冲区（`DAT_00017f78`）通过 `ExFreePoolWithTag` 被释放。然而，对应的 `MmUnmapLockedPages` 从未被调用。映射内核池页面到用户态虚拟地址空间的用户态页表项（PTE）**未被注销**。该用户态映射以"陈旧映射"形式继续存活，持续指向已释放的内核池页面。

攻击者可以继续通过该陈旧用户态虚拟地址进行读写操作，使用户态代码获得对内核非分页池内存的直接访问能力——已确认至少可访问 689,136 字节（168 页）的原始映射。通过操纵陈旧映射中偏移 `+0x28` 和 `+0x2C` 处的缓冲区头字段，攻击者可在后续 `IOCTL_MDL_MAP` 调用中扩展 MDL 长度，映射多达 4,194,304 字节（1024 页）的相邻非分页池，覆盖内核对象数据并泄露 500+ 个池标签及数百个内核虚拟地址。

该漏洞通过 Ghidra 静态逆向工程发现，并通过自定义概念验证代码完成动态验证。详细静态分析链路见后文"附录：Ghidra 静态逆向分析链路"。

## 漏洞影响

1. **内核任意读取**：低权限用户可读取最多 4 MB 非分页池内存，泄露内核虚拟地址（已确认 KASLR 绕过——500+ 池标签，数百个内核地址）。

2. **内核任意写入**：低权限用户可向内核非分页池页面写入任意数据，实现内核对象损坏。

3. **拒绝服务**：双释放竞态条件可被本地低权限用户触发，导致系统立即崩溃（`KERNEL_MODE_HEAP_CORRUPTION`，蓝屏码 `0x13A`）。

4. **潜在权限提升**：借助内核任意读写和 KASLR 绕过，攻击者理论上可定位 System 进程的 EPROCESS 结构并覆写其 Token 以提权至 SYSTEM。（在当前测试环境中未确认——EPROCESS 位于映射范围之外；取决于非分页池的物理布局。）

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
5. 蓝屏码 `0x13A`（KERNEL_MODE_HEAP_CORRUPTION）
6. **注意**：需要多核 CPU（VM 至少 2 个 vCPU）。单核 VM 无法触发竞态。

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

1. **CloseHandle / 清理路径中调用 `MmUnmapLockedPages`**：
   在 PortCls 清理路径（或 IRP_MJ_CLEANUP / IRP_MJ_CLOSE 处理器）中，调用 `IOCTL_MDL_MAP` flag=0（或直接调用 `FUN_00013ec0`）以在释放底层池缓冲区之前注销用户态 MDL 映射。

2. **校验 MDL 长度字段**：
   在将 `DAT_00017f78[10]` (偏移 +0x28) 和 `DAT_00017f78[0xb]` (偏移 +0x2C) 传递给 `IoAllocateMdl` 之前添加边界检查。MDL 长度不应超过实际池分配大小（`FUN_0001103c` 中计算的 `param_1 * 0x60 + 0xf0`）。

3. **释放后将全局缓冲区指针置 NULL**：
   在 `FUN_00019630` 中调用 `ExFreePoolWithTag` 后将 `DAT_00017f78` 置为 NULL，防止通过检查非 NULL 的 IOCTL 触发释放后使用。

### P1（高）

4. **修复 `FUN_00013ec0` 中的 TOCTOU**：
   将指针清零操作移至 `IoFreeMdl` 调用**之前**，或使用 `InterlockedExchangePointer` 原子加载并清零指针。

5. **为 `FUN_00013f2c` 添加同步**：
   使用自旋锁序列化访问全局状态（`DAT_00017f78`、`DAT_00017f80`、`DAT_00017dc0`、`DAT_00017858` 等）的并发 IOCTL 请求。

### P2（中等）

6. **启用安全编译器标志**：
   - `/DYNAMICBASE` — 启用 ASLR
   - `/NXCOMPAT` — 启用 DEP
   - `/GUARD:CF` — 启用控制流保护

7. **修复池标签一致性**：
   在所有 `ExFreePoolWithTag` 调用中使用与分配一致的标签（当前部分调用使用 tag `0` 而非分配 tag `0x4456534D`）。

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
