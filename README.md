# Windows 锁屏界面用户输入检测深度技术方案

#### 注：测试环境为win11 专业工作站版 25h2 26200.7462 UAC为关闭状态

## 1. 核心挑战与安全背景

在现代 Windows 安全架构中，锁屏界面（Lock Screen）受到多重保护。要实现对其输入的检测，必须跨越以下三道关卡：

### 1.1 Session 0 隔离 (Session 0 Isolation)
自 Windows Vista 以来，系统服务运行在 Session 0，而用户交互发生在 Session 1 或更高。Session 0 没有任何交互式界面，也无法直接接收 Session 1 的键盘/鼠标消息流。

### 1.2 窗口站与桌面隔离 (Window Station & Desktop Isolation)
Windows 的 GUI 层次结构为：**Window Station (窗口站) -> Desktop (桌面)**。
*   交互式窗口站名为 `WinSta0`。
*   用户平常工作的环境是 `Default` 桌面。
*   锁屏界面、登录界面、UAC 提示界面运行在 `Winlogon` 桌面。
**安全规则**：一个进程安装的 Windows 钩子（Hooks）只能作用于其所在的桌面。运行在 `Default` 桌面的进程对 `Winlogon` 桌面是“盲”的。

---

## 2. 整体技术架构：父子进程迁移模型

本程序通过“父进程引导，子进程监控”的模式突破限制：

1.  **引导阶段 (Parent - Session 0)**：以 SYSTEM 权限运行，负责寻找活跃用户会话并“克隆”其安全令牌。
2.  **执行阶段 (Child - Session 1)**：在目标用户会话中启动，继承 SYSTEM 权限但具备交互能力。
3.  **捕获阶段 (Monitor - Winlogon)**：子进程主动切换到 `Winlogon` 桌面并安装低级钩子（Low-Level Hooks）。

---

## 3. 核心实现细节与代码

### 3.1 跨 Session 令牌克隆 (Token Stealing)
为了让程序从 Session 0 “跃迁”到 Session 1，我们需要获取一个已经在 Session 1 中且具有 `SYSTEM` 权限的进程令牌。`winlogon.exe` 是该 Session 的管理进程，是最佳目标。

#### 关键步骤：
1.  **获取会话 ID**：使用 `WTSGetActiveConsoleSessionId` 确定当前锁屏的物理会话。
2.  **获取进程句柄**：通过 `OpenProcess` 获取 `winlogon.exe` 的句柄。
3.  **克隆令牌**：使用 `OpenProcessToken` 和 `DuplicateTokenEx` 创建一个新的主令牌（Primary Token）。

```csharp
// 核心逻辑片段
int activeSessionId = (int)NativeMethods.WTSGetActiveConsoleSessionId();
Process targetWinlogon = Process.GetProcessesByName("winlogon")
                            .FirstOrDefault(p => p.SessionId == activeSessionId);

// 获取并克隆令牌
if (NativeMethods.OpenProcessToken(targetWinlogon.Handle, TOKEN_ALL_ACCESS, out hToken)) {
    NativeMethods.DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, 
                                 SecurityImpersonation, TokenPrimary, out hNewToken);
    
    // 强制设置 SessionId（可选，通常 Duplicate 已处理）
    uint sessionId = (uint)activeSessionId;
    NativeMethods.SetTokenInformation(hNewToken, TokenSessionId, ref sessionId, sizeof(uint));
}
```

### 3.2 穿透启动 (CreateProcessAsUser)
有了 Session 1 的令牌后，使用 `CreateProcessAsUser` 启动监控子进程。

```csharp
NativeMethods.STARTUPINFO si = new NativeMethods.STARTUPINFO();
si.cb = Marshal.SizeOf(si);
si.lpDesktop = null; // 关键：启动时不强制桌面，防止安全拒绝

// 创建环境块，确保子进程能正确加载 .NET 运行库
NativeMethods.CreateEnvironmentBlock(out lpEnvironment, hNewToken, false);

string cmdLine = $"\"C:\\Program Files\\dotnet\\dotnet.exe\" \"{dllPath}\" --child";
NativeMethods.CreateProcessAsUser(
    hNewToken, 
    null, 
    cmdLine, 
    IntPtr.Zero, 
    IntPtr.Zero, 
    false, 
    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, 
    lpEnvironment, 
    workDir, 
    ref si, 
    out pi);
```

### 3.3 桌面动态附加 (Desktop Attachment)
子进程启动后，它位于 Session 1，但默认不在 `Winlogon` 桌面。它必须通过以下 API “强行”进入锁屏桌面。

```csharp
// 尝试打开并切换桌面
IntPtr hDesktop = NativeMethods.OpenDesktop("Winlogon", 0, false, DESKTOP_ALL_ACCESS);
if (hDesktop != IntPtr.Zero) {
    // 将当前线程挂载到 Winlogon 桌面，这是安装钩子的前提
    if (NativeMethods.SetThreadDesktop(hDesktop)) {
        Log("Successfully attached to Winlogon desktop.");
    }
}
```

### 3.4 全局输入钩子 (WH_KEYBOARD_LL / WH_MOUSE_LL)
使用低级钩子（Low-Level Hooks）的优势在于它们不需要 DLL 注入，由操作系统直接回调。

```csharp
// 安装键盘钩子
_hookIDKeyboard = NativeMethods.SetWindowsHookEx(WH_KEYBOARD_LL, _procKeyboard, hMod, 0);

// 安装鼠标钩子（包含移动检测）
_hookIDMouse = NativeMethods.SetWindowsHookEx(WH_MOUSE_LL, _procMouse, hMod, 0);

// 鼠标回调逻辑
private static IntPtr HookCallbackMouse(int nCode, IntPtr wParam, IntPtr lParam) {
    if (nCode >= 0) {
        int msg = (int)wParam;
        // 监控鼠标移动 (0x0200) 以及各类点击事件
        if (msg == 0x0200 || msg == 0x0201 || msg == 0x0204 || msg == 0x0207) {
            CheckActivity("Mouse");
        }
    }
    return NativeMethods.CallNextHookEx(_hookIDMouse, nCode, wParam, lParam);
}
```

---

## 4. 健壮性设计

### 4.1 消息循环
由于钩子依赖于 Windows 消息机制，子进程必须运行一个消息泵：
```csharp
System.Windows.Forms.Application.Run();
```

### 4.2 诊断日志系统
在 `Winlogon` 桌面下，传统调试器无法工作。程序实现了以下诊断机制：
*   **OutputDebugString**：将信息发送到系统内核调试流，可通过 `DebugView` 工具捕获。
*   **分离式重试日志**：父子进程写入不同文件，并带有 5 次重试的指数退避逻辑，防止文件锁定。

### 4.3 权限提升 (Privilege Adjusting)
在窃取令牌前，程序会自动提升自身的 `SeDebugPrivilege` 权限，以确保能够打开 `winlogon.exe` 这种系统关键进程。

---

## 5. 运行流程总结
1.  **Service**: 捕获 `SessionLock` 信号。
2.  **Task Scheduler**: 以最高权限拉起 `Monitor.exe` (Parent)。
3.  **Parent**: 提权 -> 找 Winlogon -> 复制令牌 -> 启动 `Monitor.exe` (Child)。
4.  **Child**: 打开 Winlogon 桌面 -> 挂载线程 -> 安装 LL 钩子 -> 开启消息泵。
5.  **Event**: 用户移动鼠标或敲击键盘 -> 钩子回调 -> 记录活动 -> 触发后续验证。

---
