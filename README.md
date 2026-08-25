# phantom-frida

Build anti-detection Frida server from source. Covers 16 detection vectors with ~90 patches.

Extended beyond [ajeossida](https://github.com/hackcatml/ajeossida) with additional stealth techniques: custom port, binary string sweep, internal symbol renaming, temp path obfuscation, and more.

## How it works

Phantom-frida clones Frida source, applies patches in 4 phases (source, targeted, post-build, binary), and compiles a custom server where all identifiable "frida" strings, symbols, thread names, and file paths are replaced with a custom name.

Standard Frida client (`pip install frida-tools`) connects to the patched server normally — the client-server protocol is preserved.

## Quick Start

### GitHub Actions (recommended)

1. Fork this repo
2. Actions > **Build Custom Frida** > Run workflow
3. Choose version, name, architecture, options
4. Download artifacts (~8 min with cache, ~35 min cold build)

### Weekly auto-builds

The **Weekly Stealth Build** workflow runs every Sunday:
- Detects latest Frida version automatically
- Generates a random name and port via `namegen.py`
- Builds with `--extended` for maximum stealth
- Creates a GitHub Release with binary + `build-info.json`

### Local build (macOS via Docker)

```bash
# 前置(一次性):
brew install colima docker
colima start --dns 2235.5.5          # 中国网络需要
docker pull docker.m.daocloud.io/library/ubuntu:22.04
docker tag docker.m.daocloud.io/library/ubuntu:22.04 ubuntu:22.04

# 编译:
./build-local.sh -v 17.9.10 -n meituan -a android-arm64 -p 6666 --yes

# 非交互 + 自定义:
FRIDA_VERSION=17.9.10 CUSTOM_NAME=myserver CUSTOM_PORT=27142 ./build-local.sh --yes
```

`build-local.sh` 自动检测 macOS → Docker (ubuntu:22.04) → build.py。NDK + frida 源码缓存在 `.docker-build-cache/`(首次 ~1.5GB NDK 下载,后续 cache hit)。

### Local build (WSL Ubuntu)

```bash
python3 build.py --version 17.9.10

# Full options:
python3 build.py --version 17.9.10 --name myserver --port 27142 --extended --verify

# Patch only (inspect changes without compiling):
python3 build.py --version 17.9.10 --skip-build
```

### WSL helper script

```bash
wsl -d Ubuntu bash build-wsl.sh

# With options:
FRIDA_VERSION=17.9.10 CUSTOM_NAME=myserver CUSTOM_PORT=27142 EXTENDED=1 \
  wsl -d Ubuntu bash build-wsl.sh
```

## Detection Vectors

| # | Vector | Detection method | Base | Extended |
|---|--------|-----------------|------|----------|
| 1 | Process name `frida-server` | `/proc/*/cmdline`, `ps` | Renamed | Renamed |
| 2 | `libfrida-agent.so` in maps | `/proc/self/maps` scan | Renamed | Renamed |
| 3 | Thread names `gum-js-loop`, `gmain`, `gdbus` | `/proc/self/task/*/comm` | Renamed | Renamed |
| 4 | memfd name `frida-agent-64.so` | `/proc/self/fd/` readlink | `jit-cache` | `jit-cache` |
| 5 | `frida_agent_main` symbol | `dlsym` / memory scan | Renamed | Renamed |
| 6 | SELinux labels `frida_file` | SELinux context check | Renamed | Renamed |
| 7 | libc hooks (exit, signal) | Hook detection | Disabled | Disabled |
| 8 | D-Bus service `re.frida.server` | D-Bus introspection | Renamed | Renamed |
| 9 | Default port 27042 | `connect()` scan | - | `--port N` |
| 10 | D-Bus interfaces | Protocol inspection | - | Renamed |
| 11 | Internal C symbols | Memory string scan | - | Renamed |
| 12 | GType names `FridaServer` | GObject introspection | - | Renamed |
| 13 | Temp paths `.frida`, `frida-` | Filesystem scan | - | Renamed |
| 14 | Binary string residuals | Binary `strings` scan | - | Swept |
| 15 | Build config defines | Memory scan | - | Renamed |
| 16 | Asset directory `libdir/frida` | Path inspection | - | Renamed |

## Options

```
--version, -v    Frida version to build (required)
--name, -n       Custom name replacing 'frida' (default: ajeossida; use random for stealth)
--arch, -a       Target arch (default: android-arm64)
--port, -p       Custom listening port (default: 27042)
--extended, -e   Enable extended anti-detection (vectors 9-16)
--temp-fixes     Stability fixes (perfetto skip, cloak detach)
--verify         Scan output for residual 'frida' strings
--skip-build     Apply patches only, don't compile
--skip-clone     Use existing source in work-dir
--ndk-path       Path to existing Android NDK r29
```

## Deploy

```bash
# Push to device
adb push output/myserver-server-17.7.2-android-arm64 /data/local/tmp/myserver-server
adb shell chmod 755 /data/local/tmp/myserver-server

# Start (default port 27042)
adb shell /data/local/tmp/myserver-server -D &
frida -U -f com.example.app

# Start (custom port)
adb shell /data/local/tmp/myserver-server -D &
adb forward tcp:27142 tcp:27142
frida -H 127.0.0.1:27142 -f com.example.app
```

Each weekly release includes a `build-info.json` with the name, port, version, and architecture.

## XOM Fix (Android 10 / kernel 4.9 / SELinux Enforcing)

On devices with true execute-only memory enforcement (e.g. MI 8 SE / kernel 4.9 / SELinux Enforcing), the zygote's libstagefright `.text` page is mapped `--xp` (execute-only, no read). The zymbiote payload's self-read of its `ZymbioteContext` struct faults with `SIGSEGV SEGV_ACCERR`.

**Fix:** `frida_soften_zygote_page()` in `linjector-glue.c` — transient ptrace on the zygote (after writing payload+GOT, before SIGCONT in `inject_zymbiote`) to mprotect the payload page `--xp → RX`. Forked children inherit RX → original zymbiote self-read works.

- Only on `--xp` pages (`needs_softening = !m.readable`; `r-x` pages like MI 8 Lite are skipped, no ptrace).
- Skips non-aarch64 (32-bit zygote).
- `TracerPid` returns to 0 after detach. App process is never ptraced.
- `zymbiote.c` is **unchanged** (original zymbiote, no trampoline / `/proc/self/mem`).

## Build Phases

1. **Source patches**: Global string replacement across the entire Frida source tree. Renames all `frida-agent`, `frida-helper`, `frida-server`, `re.frida.*` references. Rebuilds Android helper DEX with renamed Java package.

2. **Targeted patches**: Specific fixes for build system files (meson.build), memfd names, libc hook disabling, SELinux labels.

3. **Post-build patches**: After first compilation, renames `frida_agent_main` symbol (generated by Vala compiler, only exists in build output). Requires a second incremental build.

4. **Binary patches**: Hex-level replacements in compiled binaries — thread names (`gmain`, `gdbus`, `pool-spawner`), and optional binary string sweep for residual `frida`/`Frida` strings.

## Architecture

```
build.py                Main build script (clone, patch, compile, collect)
patches.py              All patch definitions (87 patches + 17 rollbacks)
namegen.py              Random name/port generator for stealth builds
build-local.sh           Local build (macOS Docker / Linux native)
build-wsl.sh            WSL helper script
test_comprehensive.js   Anti-detection + Java bridge verification script
.github/workflows/
  build.yml             Manual build workflow
  scheduled-build.yml   Weekly auto-build with releases
```

## Requirements

**GitHub Actions (recommended):** No local setup needed.

**Local build (macOS):** Docker (Colima) + `colima start --dns 2235.5.5` (China network).

**Local build (Linux/WSL):**
- Ubuntu 22.04+ (WSL works)
- Python 3.10+
- Git, curl, unzip, make
- ~20 GB free disk space
- Android NDK r29 (auto-downloaded)

## Version Support

| Frida | Status |
|-------|--------|
| 17.9.10 | Fully verified + XOM fix |
| 17.x | Compatible (auto-detects API differences) |
| 16.x | Compatible (auto-detects API differences) |

## Tested Apps

Verified on arm64 Android 14 device with `--extended`:

| App | Java bridge | Hooks | Anti-detection |
|-----|-------------|-------|----------------|
| Telegram | 28,772 classes | SSL+crypto | All clean |
| Google Play Store | 47,305 classes | Activity hooks | All clean |
| Facebook | 54,064 classes | Basic hooks | All clean |
| Magisk | 27,737 classes | Activity hooks | All clean |

## Known Limitations

- **arm32 apps** (Chrome): Frida upstream bug [#2878](https://github.com/frida/frida/issues/2878) — `invalid instruction` in `_patchCode`. Not a phantom-frida issue.
- **D-Bus interface names** (`re.frida.HostSession17` etc.): Intentionally NOT renamed in base mode. These are the client-server protocol — renaming server-side would break standard `frida` client. Not a detection vector (only visible over USB/TCP channel).

## Credits

- [Frida](https://frida.re/) by Ole Andre Ravnas
- [ajeossida](https://github.com/hackcatml/ajeossida) by hackcatml — original stealth Frida concept
- Detection vector research from the Android security community

## License

MIT
