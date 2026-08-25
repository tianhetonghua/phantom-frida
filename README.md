# phantom-frida

基于 Frida 17.9.10 的反检测定制 server 编译项目。从源码编译一个替换了所有 "frida" 标识（字符串、符号、线程名、文件路径）的定制 server。

## 功能概览

- **反检测**：16 个检测向量（进程名、maps 扫描、线程名、memfd、SELinux 标签、D-Bus、端口等）
- **XOM 修复**：解决 Android 10（kernel 4.9 / SELinux Enforcing）上 execute-only 内存导致 zymbiote 注入崩溃的问题
- **本地编译**：macOS（Docker）和 Linux/WSL 均可一键编译

## 本地编译

### macOS（Docker）

```bash
# 前置（一次性）：
brew install colima docker
colima start --dns 2235.5.5                          # 中国网络需要
docker pull docker.m.daocloud.io/library/ubuntu:22.04  # 国内镜像
docker tag docker.m.daocloud.io/library/ubuntu:22.04 ubuntu:22.04

# 编译：
./build-local.sh -v 17.9.10 -n meituan -a android-arm64 -p 6666 --yes
```

`build-local.sh` 自动检测 macOS → 启动 Docker 容器（ubuntu:22.04）→ 运行 `build.py`（clone frida → 打补丁 → 下载 NDK → meson+ninja 编译）。NDK + frida 源码缓存在 `.docker-build-cache/`。

### Linux / WSL

```bash
# 直接用 build.py：
python3 build.py --version 17.9.10 --name meituan --arch android-arm64 --port 6666 --verify

# 或用 build-local.sh（原生 Linux 路径）：
./build-local.sh -v 17.9.10 -n meituan -a android-arm64 -p 6666 --yes

# 或用 WSL 脚本：
wsl -d Ubuntu bash build-wsl.sh

# 只打补丁不编译（检查改动）：
python3 build.py --version 17.9.10 --skip-build
```

### 编译选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-v, --version` | Frida 版本 | 17.7.2 |
| `-n, --name` | 替换 "frida" 的自定义名 | ajeossida |
| `-a, --arch` | 目标架构（逗号分隔） | android-arm64 |
| `-p, --port` | 自定义端口 | 27042 |
| `-e, --extended` | 扩展反检测（向量 9-16） | 关 |
| `--temp-fixes` | 稳定性修复 | 关 |
| `--verify` | 编译后扫描残留 "frida" 字符串 | 开 |
| `--skip-build` | 只打补丁不编译 | 关 |
| `--skip-clone` | 复用已有源码 | 关 |
| `--ndk-path` | 指定已有 NDK 路径 | 自动下载 |
| `-y, --yes` | 非交互模式 | 关 |

## 部署

```bash
# 推到设备
adb push output/meituan-server-17.9.10-android-arm64 /data/dd/meituan-server
adb shell chmod 755 /data/dd/meituan-server
chcon u:object_r:system_data_file:s0 /data/dd/meituan-server 2>/dev/null

# 启动
adb shell /data/dd/meituan-server -l 127.0.0.0:6666 &
adb forward tcp:6666 tcp:6666
frida -H 127.0.0.1:6666 -f com.example.app
```

## XOM 修复（Android 10 / kernel 4.9 / SELinux Enforcing）

### 问题

部分 Android 10 设备（如 MI 8 SE / kernel 4.9 / SELinux Enforcing）的内核**真强制 execute-only 内存**：libstagefright 的 `.text` 页映射为 `--xp`（只可执行、不可读）。zymbiote payload 的第一条自读指令（`LDR x8, [x20, #8]` 读自己的结构体）直接 `SIGSEGV`，spawn 注入崩溃。

对比：MI 8 Lite（kernel 4.4 / SELinux Permissive）的 `--xp` 页**硬件层实际可读**，zymbiote 自读直接过，不崩。

### 修复方案

frida-server 在 `inject_zymbiote` 里、写完 payload+GOT 后、SIGCONT 之前，对 zygote64 的 payload 页做一次**瞬态 ptrace mprotect**（`--xp` → `RX`）。子进程 fork 时继承 RX → 原版 zymbiote 自读过 → 注入正常。

| 特性 | 说明 |
|------|------|
| 只在 `--xp` 页软化 | `needs_softening = !m.readable`；`r-x` 页（如 MI 8 Lite）跳过，不碰 ptrace |
| 跳过 32-bit zygote | 检测 `iov_len`，非 aarch64 直接 detach |
| 跳过待处理 SIGSTOP | 循环 PTRACE_CONT 直到 brk 的 SIGTRAP |
| TracerPid=0 | ptrace detach 后恢复，不留痕 |
| app 从不被 ptrace | 只 ptrace 父 zygote（fork 前） |
| zymbiote.c 不改 | 原版 zymbiote，无 trampoline / /proc/self/mem |

## Frida 源码改动

### my_page.patch（核心补丁）

| 文件 | 改动 | 说明 |
|------|------|------|
| `linjector-glue.c` | 新增 `frida_soften_zygote_page()` | 瞬态 ptrace zygote：写 svc;brk stub → setregs mprotect(RX) → CONT(skip SIGSTOP) → SIGTRAP → restore → DETACH。跳过非 aarch64 |
| `linux-host-session.vala` | `if` 条件去掉 `m.readable` | 扫 maps 时能匹配 `--xp` 页（原版 `m.readable && m.executable` 跳过 --xp） |
| `linux-host-session.vala` | 新增 `needs_softening` 字段 | `= !m.readable`；`--xp` → true（需要软化），`r-x` → false（跳过） |
| `linux-host-session.vala` | 新增 `soften_zygote_page` extern + 条件调用 | 在 `inject_zymbiote` 里、payload+GOT 写完、SIGCONT 前 |
| `frida-gum/gum/gummemory.c` 等 5 文件 | `gum_ensure_code_readable` → 整段 RWX | agent 进程后读/改 execute-only 代码段（用于 hook 打补丁） |
| `zymbiote.c` | **不改** | 原版 zymbiote，流程跟 MI 8 Lite 一致 |

### 构建脚本改动

| 文件 | 改动 | 说明 |
|------|------|------|
| `build-local.sh` | `${CUSTOM_NAME,,}` → `tr` | macOS bash 3.2 兼容 |
| `build-local.sh` | `docker run -it` → `-i` | 非交互模式不挂 |
| `build.py` | `unzip -q` → `unzip -q -o` | NDK 解压不交互提示 |

### 构建阶段

| 阶段 | 说明 |
|------|------|
| Phase 1: 源码替换 | 全局字符串替换（frida → 自定义名）：frida-agent、frida-helper、frida-server、re.frida.* 等 |
| Phase 2: 定向修复 | meson.build、memfd 名、libc hook 禁用、SELinux 标签 |
| Phase 3: 后编译修复 | 重命名 `frida_agent_main` 符号（Vala 编译产物）→ 二次增量编译 |
| Phase 4: 二进制补丁 | 十六进制替换线程名（gmain、gdbus、pool-spawner）+ 残留字符串扫描 |

## 反检测向量

| # | 检测向量 | 检测方法 | 基础 | 扩展 |
|---|---------|---------|------|------|
| 1 | 进程名 `frida-server` | `/proc/*/cmdline` | 重命名 | 重命名 |
| 2 | `libfrida-agent.so` 在 maps | `/proc/self/maps` 扫描 | 重命名 | 重命名 |
| 3 | 线程名 `gum-js-loop`、`gmain`、`gdbus` | `/proc/self/task/*/comm` | 重命名 | 重命名 |
| 4 | memfd 名 `frida-agent-64.so` | `/proc/self/fd/` readlink | `jit-cache` | `jit-cache` |
| 5 | `frida_agent_main` 符号 | `dlsym` / 内存扫描 | 重命名 | 重命名 |
| 6 | SELinux 标签 `frida_file` | SELinux 上下文检查 | 重命名 | 重命名 |
| 7 | libc hooks（exit、signal） | hook 检测 | 禁用 | 禁用 |
| 8 | D-Bus 服务 `re.frida.server` | D-Bus 内省 | 重命名 | 重命名 |
| 9 | 默认端口 27042 | `connect()` 扫描 | — | `--port N` |
| 10 | D-Bus 接口名 | 协议检查 | — | 重命名 |
| 11 | 内部 C 符号 | 内存字符串扫描 | — | 重命名 |
| 12 | GType 名 `FridaServer` | GObject 内省 | — | 重命名 |
| 13 | 临时路径 `.frida`、`frida-` | 文件系统扫描 | — | 重命名 |
| 14 | 二进制残留字符串 | `strings` 扫描 | — | 清扫 |
| 15 | 构建配置宏 | 内存扫描 | — | 重命名 |
| 16 | 资源目录 `libdir/frida` | 路径检查 | — | 重命名 |

## 文件结构

```
build.py                 主构建脚本（clone、打补丁、编译、收集产物）
build-local.sh           本地构建（macOS Docker / Linux 原生）
build-wsl.sh             WSL 构建脚本
patches.py               所有补丁定义（87 补丁 + 17 回滚）
namegen.py               随机名/端口生成器
my_page.patch            XOM 修复补丁（zygote-RX ptrace soften + frida-gum RWX）
wxshadow.patch           wxshadow 隐蔽补丁
test_comprehensive.js    反检测 + Java bridge 验证脚本
```

## 环境要求

| 环境 | 要求 |
|------|------|
| macOS | Docker（Colima）+ `colima start --dns 2235.5.5` |
| Linux / WSL | Ubuntu 22.04+、Python 3.10+、Git/curl/unzip/make、~20GB 磁盘 |
| NDK | Android NDK r29（自动下载，~1.5GB） |

## 版本支持

| Frida | 状态 |
|-------|------|
| 17.9.10 | 完全验证 + XOM 修复 |
| 17.x | 兼容（自动检测 API 差异） |
| 16.x | 兼容 |

## 已知限制

- **arm32 应用**（Chrome）：Frida 上游 bug，非本项目问题
- **D-Bus 接口名**（`re.frida.HostSession17` 等）：基础模式不重命名（协议层，重命名会破坏标准 frida 客户端）

## 致谢

- [Frida](https://frida.re/) by Ole Andre Ravnas
- [ajeossida](https://github.com/hackcatml/ajeossida) by hackcatml — 原始反检测 Frida 概念

## License

MIT
