# Gadget 字符串残留问题分析与修复

## 问题现象

在未开启 `--extended` 的情况下，构建出的 gadget (`.so`) 二进制文件中可以用
`strings` 检出残留的 `frida` 字符串，而同一次构建的 server (executable) 则没有
这个问题。开启 `--extended` 之后通过 binary string sweep 可以掩盖部分残留，但
根本原因并未消除。

---

## 根本原因

### Frida 的构建流水线

Frida 的 `post-process.py` 脚本负责对最终产物执行 `strip` 和 `elf-cleaner`。
server 和 gadget/agent 的流水线不同：

```
server:
  raw_server  →  post_process.py (strip + elf-cleaner)  →  frida-server  ✅ 已 strip

gadget / agent:
  raw_gadget  →  modulate.py (重排 constructor/destructor 顺序)
              →  libfrida-gadget-modulated.so  ⚠️ 尚未 strip
              →  post_process.py (strip + elf-cleaner)
              →  libfrida-gadget.so  ✅ 已 strip
```

`modulate.py` 的作用是通过直接读写 ELF 字节，将 `frida_libc_shim_init`
移到 `.init_array` 第一位、将 `frida_on_load` 移到最后一位（destructor 同理），
以保证注入时的初始化顺序。它不做任何 strip。

### 旧代码的错误

`collect_artifacts` 在查找 gadget 时的搜索优先级是：

```python
# 旧代码
gadget = find_artifact("lib/gadget", [
    f"lib{custom_name}-gadget.so",
    f"lib{custom_name}-gadget-modulated.so",   # ← 排在第 2 位，优先于最终产物
    "libfrida-gadget.so",
    "libfrida-gadget-modulated.so",
])
```

由于构建系统命名方式，`lib{custom_name}-gadget-modulated.so` 在目录中比
`lib{custom_name}-gadget.so` 更容易存在（后者是 custom_target 输出，路径有时
不同），导致实际拿到的是 **modulate 后但尚未 strip 的中间产物**，而不是最终的
stripped 版本。

server 没有 modulate 步骤，`collect_artifacts` 直接拿到的就是经过
`post_process.py` 处理的最终产物，所以没有字符串残留。

---

## 修复方案

### 改动 1：调整 gadget / agent 的搜索优先级

将 `*-modulated.so` 从第 2 位降到第 3 位，优先查找最终的 `post_process` 输出：

```python
# 修复后
gadget = find_artifact("lib/gadget", [
    f"lib{custom_name}-gadget.so",       # post_process 后的最终产物（优先）
    "libfrida-gadget.so",
    f"lib{custom_name}-gadget-modulated.so",   # 降级后备
    "libfrida-gadget-modulated.so",
])
```

agent 同理。

### 改动 2：新增 `strip_binary()` 函数

如果最终只找到了 `modulated` 中间文件（降级后备命中），在执行 binary patches
之前先用 NDK 的 `llvm-strip` 补做 strip：

```python
def strip_binary(binary_path: Path, ndk_path: Path, arch: str):
    # NDK r23+ 路径：toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
    # .so 用 --strip-unneeded，executable 用 --strip-all
```

### 改动 3：`collect_artifacts` 签名加入 `ndk_path`

```python
def collect_artifacts(..., ndk_path: Path | None = None):
```

调用点传入 `ndk_path`：

```python
collect_artifacts(frida_dir, arch, custom_name, version, output_dir, args.extended, ndk_path)
```

---

## 修改的文件

| 文件 | 位置 | 内容 |
|------|------|------|
| `build.py` | `718–747` | 新增 `strip_binary()` 函数 |
| `build.py` | `750–752` | `collect_artifacts` 签名加 `ndk_path` 参数 |
| `build.py` | `800–813` | agent 搜索顺序调整 + 条件 strip |
| `build.py` | `815–831` | gadget 搜索顺序调整 + 条件 strip |
| `build.py` | `1024` | 调用 `collect_artifacts` 时传入 `ndk_path` |

---

## 验证方法

构建完成后用 `--verify` 标志检查输出：

```bash
python3 build.py --version 17.7.2 --name myname --extended --verify
```

或手动用 `strings` 检查：

```bash
strings output/myname-gadget-17.7.2-android-arm64.so | grep -i frida
strings output/myname-server-17.7.2-android-arm64   | grep -i frida
```

修复后两者输出应均为空（在 `--extended` 模式下）。

---

## 延伸说明

`--extended` 的 binary string sweep（`get_binary_string_patches`）在修复之后仍然
有意义：它针对的是编译器静态初始化数据、第三方库内嵌字符串等 strip 无法去除的
**数据段字符串**，与 strip 去除的**调试符号段**是两个不同的来源，二者互补。
