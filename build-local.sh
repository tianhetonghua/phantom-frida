#!/usr/bin/env bash
# build-local.sh — Self-bootstrapping local build for phantom-frida (Frida 17.16.4 base).
#
# On a bare machine (fresh clone, no cache) this script downloads and installs
# EVERYTHING the build needs into a project-local cache directory:
#
#   .local-env/
#     ndk/android-ndk-r29/          Android NDK r29 (revision 29.0.14206865,
#                                   exactly what build.py's validate_ndk requires)
#     sdk/                          Android SDK subset (build-tools;36.1.0 +
#                                   platforms;android-36 — android.jar & d8)
#     jdk/                          Temurin JDK 17 (only if javac missing)
#     node/                         Node.js 18 (only if node missing)
#
# Already-present system tools are detected and reused: an ANDROID_SDK_ROOT /
# ANDROID_HOME with android.jar + d8, a system NDK at the exact revision, a
# system JDK (any vendor) and a system node are all honoured via --ndk-path or
# environment passthrough. Cache is content-addressed by revision — repeated
# builds reuse everything and download nothing.
#
# Supports Linux (native) and macOS (native). No Docker needed.
#
# Usage:
#   ./build-local.sh                                    # interactive prompts
#   ./build-local.sh --help                             # all options
#   ./build-local.sh -v 17.16.4 -n meituan -a android-arm64 -p 6666 -e -y
#
# Environment variables (override defaults, flags override env vars):
#   FRIDA_VERSION  CUSTOM_NAME  BUILD_ARCH  CUSTOM_PORT  EXTENDED  TEMP_FIXES
#   ANDROID_SDK_ROOT / ANDROID_HOME   existing SDK (skips SDK bootstrap)
#   NDK_PATH                          existing NDK at revision 29.0.14206865
#   MIRROR                            'cn' to use China mirrors for downloads
#
# NOTE on --temp-fixes: the upstream perfetto stability patch does not compile
# against 17.16.4 (inserts `goto skip` into a function whose label was removed
# upstream). Leave TEMP_FIXES off until that is fixed.

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
step()  { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }
die()   { err "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Pinned toolchain (must match build.py's NDK_REVISION / NDK_VERSION) ──────
NDK_VERSION="r29"
NDK_REVISION="29.0.14206865"
# sha1 of the platform zips, computed from the official artifacts.
NDK_SHA1_DARWIN="03d29fbb57e3c05a7d53597dd011d856c1456a4f"
NDK_SHA1_LINUX="87e2bb7e9be5d6a1c6cdf5ec40dd4e0c6d07c30b"
# SDK components (android.jar for javac -bootclasspath, d8 for DEX).
SDK_BUILD_TOOLS="36.1.0"
SDK_PLATFORM="android-36"
CMDLINE_TOOLS_MAC="15641748"    # latest mac build that exists on dl.google.com
CMDLINE_TOOLS_LINUX="16111833"  # latest linux build
NODE_VERSION="18.20.4"
# Temurin JDK 17 stable release (GitHub redirect resolves the exact tarball).
JDK_TAG="jdk-17.0.20.1%2B1"

# ── Defaults (env vars win over hard-coded, flags win over everything) ───────
FRIDA_VERSION="${FRIDA_VERSION:-17.16.4}"
CUSTOM_NAME="${CUSTOM_NAME:-ajeossida}"
BUILD_ARCH="${BUILD_ARCH:-android-arm64}"
CUSTOM_PORT="${CUSTOM_PORT:-}"
EXTENDED="${EXTENDED:-0}"
TEMP_FIXES="${TEMP_FIXES:-0}"

WORK_DIR="${WORK_DIR:-$SCRIPT_DIR/build}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"
ENV_DIR="$SCRIPT_DIR/.local-env"          # everything downloaded lives here

YES=0
SKIP_CLONE=0
SKIP_BUILD=0
VERIFY=1
NDK_PATH="${NDK_PATH:-}"
MIRROR="${MIRROR:-}"

# ── Argument parsing ──────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

  -v, --version VERSION     Frida version (default: $FRIDA_VERSION)
  -n, --name NAME           Custom name replacing 'frida' (default: $CUSTOM_NAME)
  -a, --arch ARCH           Target arch(s), comma-separated (default: $BUILD_ARCH)
                            Choices: android-arm64 android-arm android-x86_64 android-x86
  -p, --port PORT           Custom port (default: 27042 unchanged)
  -e, --extended            Enable extended anti-detection patches
      --temp-fixes          Enable stability fixes (BROKEN on 17.16.4 — see header)
  -w, --work-dir DIR        Working/build directory (default: ./build)
  -o, --output-dir DIR      Output directory (default: ./output)
      --ndk-path PATH       Use existing NDK (must be revision $NDK_REVISION)
      --skip-clone          Reuse existing source in work-dir (reset to clean state)
      --skip-build          Apply patches only, skip compilation
      --no-verify           Skip post-build forbidden-marker scan
      --mirror cn           Use China mirrors (dl.google.com via tencent, npmmirror)
  -y, --yes                 Non-interactive, use defaults / env vars
  -h, --help                Show this help

Everything the build needs is auto-downloaded into .local-env/ on first run
(NDK ~1 GB, SDK ~200 MB, plus JDK/Node only if missing system-wide).
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)    FRIDA_VERSION="$2";  shift 2 ;;
    -n|--name)       CUSTOM_NAME="$2";    shift 2 ;;
    -a|--arch)       BUILD_ARCH="$2";     shift 2 ;;
    -p|--port)       CUSTOM_PORT="$2";    shift 2 ;;
    -e|--extended)   EXTENDED=1;          shift   ;;
    --temp-fixes)    TEMP_FIXES=1;        shift   ;;
    -w|--work-dir)   WORK_DIR="$2";       shift 2 ;;
    -o|--output-dir) OUTPUT_DIR="$2";     shift 2 ;;
    --ndk-path)      NDK_PATH="$2";       shift 2 ;;
    --skip-clone)    SKIP_CLONE=1;        shift   ;;
    --skip-build)    SKIP_BUILD=1;        shift   ;;
    --no-verify)     VERIFY=0;            shift   ;;
    --mirror)        MIRROR="$2";         shift 2 ;;
    -y|--yes)        YES=1;               shift   ;;
    -h|--help)       usage ;;
    *) die "Unknown option: $1  (run with --help)" ;;
  esac
done

# ── Interactive prompts (skipped with --yes) ──────────────────────────────────
ask() {
  local var="$1" prompt="$2" default="$3"
  if [[ $YES -eq 1 ]]; then
    printf -v "$var" '%s' "$default"
    return
  fi
  local input
  read -r -p "$(echo -e "${CYAN}?${RESET} ${prompt} [${default}]: ")" input
  printf -v "$var" '%s' "${input:-$default}"
}

ask_bool() {
  local var="$1" prompt="$2" default="$3"
  if [[ $YES -eq 1 ]]; then
    printf -v "$var" '%s' "$default"
    return
  fi
  local hint
  [[ "$default" == "1" ]] && hint="Y/n" || hint="y/N"
  local input
  read -r -p "$(echo -e "${CYAN}?${RESET} ${prompt} [${hint}]: ")" input
  input="${input:-$default}"
  [[ "$input" =~ ^[Yy1]$ ]] && printf -v "$var" '1' || printf -v "$var" '0'
}

step "phantom-frida local builder (base: upstream 17.16.4)"
echo -e "  Self-bootstrapping: NDK r29 + SDK (android.jar/d8) + JDK + Node auto-install to .local-env/"
echo ""

ask         FRIDA_VERSION  "Frida version"                              "$FRIDA_VERSION"
ask         CUSTOM_NAME    "Custom name (replaces 'frida' everywhere)"  "$CUSTOM_NAME"
ask         BUILD_ARCH     "Target arch(s) (comma-separated)"           "$BUILD_ARCH"
ask         CUSTOM_PORT    "Custom port (empty = keep 27042)"           "$CUSTOM_PORT"
ask_bool    EXTENDED       "Extended anti-detection patches?"           "$EXTENDED"
if [[ "$TEMP_FIXES" == "1" ]]; then
  warn "--temp-fixes requested: the upstream perfetto patch does not compile on"
  warn "17.16.4 (undeclared label 'skip'). The build WILL fail if you proceed."
  ask_bool TEMP_FIXES "Enable anyway?" "0"
fi

# Normalise name (macOS bash 3.2 has no ${VAR,,})
CUSTOM_NAME="$(echo "$CUSTOM_NAME" | tr '[:upper:]' '[:lower:]')"

# Validate arch list
IFS=',' read -ra ARCH_LIST <<< "$BUILD_ARCH"
VALID_ARCHS=("android-arm64" "android-arm" "android-x86_64" "android-x86")
for arch in "${ARCH_LIST[@]}"; do
  arch="${arch// /}"
  ok=0
  for va in "${VALID_ARCHS[@]}"; do [[ "$arch" == "$va" ]] && ok=1; done
  [[ $ok -eq 0 ]] && die "Invalid arch '$arch'. Valid: ${VALID_ARCHS[*]}"
done

PLATFORM="$(uname -s)"
[[ "$PLATFORM" == "Linux" || "$PLATFORM" == "Darwin" ]] || \
  die "Unsupported platform: $PLATFORM (supported: Linux, macOS)"

echo ""
echo -e "${BOLD}Build configuration:${RESET}"
echo -e "  Version  : $FRIDA_VERSION"
echo -e "  Name     : $CUSTOM_NAME"
echo -e "  Arch(s)  : $BUILD_ARCH"
echo -e "  Port     : ${CUSTOM_PORT:-27042 (default)}"
echo -e "  Extended : $EXTENDED"
echo -e "  TempFixes: $TEMP_FIXES"
echo -e "  Work dir : $WORK_DIR"
echo -e "  Output   : $OUTPUT_DIR"
echo -e "  Env cache: $ENV_DIR"
echo ""

# ── Base tool checks (git/curl/unzip/make are expected present) ───────────────
step "Base tools"
for cmd in git python3 curl unzip make; do
  command -v "$cmd" &>/dev/null && ok "$cmd" || die "$cmd not found — install it first (brew/apt)."
done
PYTHON_OK=$(python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' && echo 1 || echo 0)
[[ "$PYTHON_OK" == "1" ]] || die "Python 3.10+ required (build.py contract)."

# ── Download helper with mirror support ───────────────────────────────────────
# NOTE: dl() is called inside command substitutions (resolve_ndk/resolve_sdk),
# so every diagnostic goes to stderr; stdout must stay clean for the path.
dl() { # dl <url> <dest> [expected-sha1]
  local url="$1" dest="$2" sha1="${3:-}"
  if [[ -n "$sha1" && -f "$dest" ]]; then
    if [[ "$(shasum "$dest" | cut -d' ' -f1)" == "$sha1" ]]; then
      ok "cache hit: $(basename "$dest")" >&2
      return
    fi
    rm -f "$dest"
  elif [[ -f "$dest" ]]; then
    ok "cache hit: $(basename "$dest")" >&2
    return
  fi
  mkdir -p "$(dirname "$dest")"
  local actual_url="$url"
  if [[ "$MIRROR" == "cn" ]]; then
    # dl.google.com artifacts are mirrored by tencent with identical paths.
    actual_url="$url"
    case "$url" in
      https://dl.google.com/android/repository/*)
        actual_url="https://mirrors.cloud.tencent.com/AndroidSDK/${url##*/}" ;;
      https://nodejs.org/dist/*)
        actual_url="https://npmmirror.com/mirrors/node/${url#https://nodejs.org/dist/}" ;;
    esac
  fi
  info "Downloading $(basename "$dest") ..." >&2
  curl -fL --retry 3 -sS -o "$dest" "$actual_url" \
    || curl -fL --retry 3 -sS -o "$dest" "$url"   # mirror failed → direct
  if [[ -n "$sha1" ]]; then
    local got
    got="$(shasum "$dest" | cut -d' ' -f1)"
    [[ "$got" == "$sha1" ]] || die "sha1 mismatch for $dest: expected $sha1, got $got"
    ok "sha1 verified: $sha1" >&2
  fi
}

# ── NDK (pinned revision — build.py validate_ndk enforces it) ────────────────
step "Android NDK $NDK_VERSION (revision $NDK_REVISION)"

ndk_rev_ok() { # <ndk-dir>: true when source.properties pins our revision
  local props="$1/source.properties"
  [[ -f "$props" ]] && grep -q "^Pkg.Revision = $NDK_REVISION$" "$props"
}

resolve_ndk() {
  # stdout of this function is consumed by command substitution:
  # log lines must go to stderr.
  # 1. explicit --ndk-path
  if [[ -n "$NDK_PATH" ]]; then
    [[ -d "$NDK_PATH" ]] || die "NDK path not found: $NDK_PATH"
    ndk_rev_ok "$NDK_PATH" || die "NDK at $NDK_PATH is not revision $NDK_REVISION (build.py rejects it)."
    echo "$NDK_PATH"
    return
  fi
  # 2. cached bootstrap
  local cached="$ENV_DIR/ndk/android-ndk-$NDK_VERSION"
  if ndk_rev_ok "$cached"; then
    echo "$cached"
    return
  fi
  # 3. system SDK NDKs (macOS Android Studio installs) with matching revision
  local sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
  if [[ -d "$sdk_root/ndk" ]]; then
    for v in "$sdk_root"/ndk/*/; do
      [[ -d "$v" ]] || continue
      if ndk_rev_ok "${v%/}"; then
        echo "${v%/}"
        return
      fi
    done
  fi
  # 4. download
  local suffix zip sha1
  if [[ "$PLATFORM" == "Darwin" ]]; then
    suffix="darwin"; sha1="$NDK_SHA1_DARWIN"
  else
    suffix="linux"; sha1="$NDK_SHA1_LINUX"
  fi
  zip="$ENV_DIR/archives/android-ndk-$NDK_VERSION-$suffix.zip"
  dl "https://dl.google.com/android/repository/android-ndk-$NDK_VERSION-$suffix.zip" "$zip" "$sha1"
  mkdir -p "$ENV_DIR/ndk"
  info "Extracting NDK (~1 GB, takes a minute)..." >&2
  unzip -q -o "$zip" -d "$ENV_DIR/ndk"
  ndk_rev_ok "$cached" || die "Downloaded NDK has unexpected revision (wanted $NDK_REVISION)."
  echo "$cached"
}

NDK_DIR="$(resolve_ndk | tr -d '\r\n')"
# absolutise: build.py resolves the path relative to its own cwd
case "$NDK_DIR" in
  /*) ;;
  *)  NDK_DIR="$PWD/$NDK_DIR" ;;
esac
ok "NDK ready: $NDK_DIR"

# ── SDK components (android.jar + d8) ─────────────────────────────────────────
step "Android SDK (android.jar + d8)"

sdk_has_components() { # <sdk-root>
  local root="$1"
  compgen -G "$root/platforms/$SDK_PLATFORM/android.jar" >/dev/null 2>&1 || \
  [[ -f "$root/platforms/$SDK_PLATFORM/android.jar" ]] || return 1
  [[ -f "$root/build-tools/$SDK_BUILD_TOOLS/d8" || -f "$root/build-tools/$SDK_BUILD_TOOLS/lib/d8.jar" ]]
}

resolve_sdk() {
  # stdout of this function is consumed by command substitution:
  # log lines must go to stderr.
  # 1. an existing SDK with both components (env var or default location)
  local root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
  if [[ -n "$root" ]] && sdk_has_components "$root"; then
    echo "$root"
    return
  fi
  if [[ -z "$root" ]]; then
    root="$HOME/Library/Android/sdk"
    if [[ "$PLATFORM" == "Darwin" ]] && sdk_has_components "$root"; then
      echo "$root"
      return
    fi
  fi
  # 2. cached bootstrap — validate lazily: build.py picks newest platform and
  #    build-tools dir, so our pinned components satisfy it on any machine.
  local cached="$ENV_DIR/sdk"
  if sdk_has_components "$cached"; then
    echo "$cached"
    return
  fi
  # 3. bootstrap via cmdline-tools + sdkmanager
  local tools_ver zip
  if [[ "$PLATFORM" == "Darwin" ]]; then
    tools_ver="$CMDLINE_TOOLS_MAC"; zip="$ENV_DIR/archives/commandlinetools-mac-${tools_ver}_latest.zip"
  else
    tools_ver="$CMDLINE_TOOLS_LINUX"; zip="$ENV_DIR/archives/commandlinetools-linux-${tools_ver}_latest.zip"
  fi
  dl "https://dl.google.com/android/repository/commandlinetools-$( [[ "$PLATFORM" == "Darwin" ]] && echo mac || echo linux )-${tools_ver}_latest.zip" "$zip"
  local tools_dir="$ENV_DIR/cmdline-tools"
  rm -rf "$tools_dir"
  mkdir -p "$tools_dir"
  unzip -q -o "$zip" -d "$tools_dir"
  # zip layout: cmdline-tools/bin/sdkmanager
  local sdkmanager="$tools_dir/cmdline-tools/bin/sdkmanager"
  [[ -f "$sdkmanager" ]] || die "sdkmanager not found after extraction"
  chmod +x "$sdkmanager"
  info "Installing build-tools;$SDK_BUILD_TOOLS + platforms;$SDK_PLATFORM (~200 MB)..." >&2
  yes | "$sdkmanager" --sdk_root="$ENV_DIR/sdk" "build-tools;$SDK_BUILD_TOOLS" "platforms;$SDK_PLATFORM" >/dev/null 2>&1
  sdk_has_components "$ENV_DIR/sdk" || die "sdkmanager did not install the expected components"
  echo "$ENV_DIR/sdk"
}

SDK_ROOT="$(resolve_sdk | tr -d '\r\n')"
case "$SDK_ROOT" in
  /*) ;;
  *)  SDK_ROOT="$PWD/$SDK_ROOT" ;;
esac
export ANDROID_SDK_ROOT="$SDK_ROOT"
ok "SDK ready: $SDK_ROOT (ANDROID_SDK_ROOT exported)"

# ── JDK 17 (needed for javac/jar — helper DEX rebuild) ───────────────────────
step "JDK (javac + jar)"
if command -v javac &>/dev/null && command -v jar &>/dev/null && command -v java &>/dev/null; then
  ok "system JDK: $(javac -version 2>&1)"
  JAVA_HOME_SET="${JAVA_HOME:-}"
else
  JDK_DIR="$ENV_DIR/jdk/jdk-17"
  if [[ -x "$JDK_DIR/bin/javac" ]]; then
    ok "cached JDK 17: $JDK_DIR"
  else
    warn "No system JDK — downloading Temurin JDK 17 (~180 MB)..."
    JDK_TAR="$ENV_DIR/archives/jdk17.tar.gz"
    case "$PLATFORM" in
      Darwin)
        # Apple Silicon: aarch64; Intel: x64
        ARCH_TAG="x64"
        [[ "$(uname -m)" == "arm64" ]] && ARCH_TAG="aarch64"
        JDK_URL="https://github.com/adoptium/temurin17-binaries/releases/download/$JDK_TAG/OpenJDK17U-jdk_${ARCH_TAG}_mac_hotspot_17.0.20.1_1.tar.gz"
        ;;
      Linux)
        JDK_URL="https://github.com/adoptium/temurin17-binaries/releases/download/$JDK_TAG/OpenJDK17U-jdk_x64_linux_hotspot_17.0.20.1_1.tar.gz"
        ;;
    esac
    dl "$JDK_URL" "$JDK_TAR"
    mkdir -p "$ENV_DIR/jdk"
    rm -rf "$JDK_DIR"
    mkdir -p "$JDK_DIR"
    tar -xzf "$JDK_TAR" -C "$JDK_DIR" --strip-components=1
    [[ -x "$JDK_DIR/bin/javac" ]] || die "JDK extraction failed"
    ok "JDK 17 installed: $JDK_DIR"
  fi
  export JAVA_HOME="$JDK_DIR"
  export PATH="$JDK_DIR/bin:$PATH"
fi

# ── Node.js (build.py requires the `node` executable) ─────────────────────────
step "Node.js"
if command -v node &>/dev/null; then
  ok "system node: $(node --version)"
else
  NODE_DIR="$ENV_DIR/node/node-$NODE_VERSION"
  if [[ -x "$NODE_DIR/bin/node" ]]; then
    ok "cached node: $NODE_DIR"
  else
    warn "No system node — downloading Node $NODE_VERSION (~25 MB)..."
    case "$PLATFORM" in
      Darwin)
        ARCH_TAG="x64"
        [[ "$(uname -m)" == "arm64" ]] && ARCH_TAG="arm64"
        NODE_TAR_EXT="tar.gz"; NODE_FILE="node-v$NODE_VERSION-darwin-$ARCH_TAG"
        ;;
      Linux)
        NODE_FILE="node-v$NODE_VERSION-linux-x64"
        NODE_TAR_EXT="tar.xz"
        ;;
    esac
    NODE_TAR="$ENV_DIR/archives/$NODE_FILE.$NODE_TAR_EXT"
    dl "https://nodejs.org/dist/v$NODE_VERSION/$NODE_FILE.$NODE_TAR_EXT" "$NODE_TAR"
    mkdir -p "$ENV_DIR/node"
    rm -rf "$NODE_DIR"
    mkdir -p "$NODE_DIR"
    if [[ "$NODE_TAR_EXT" == "tar.xz" ]]; then
      tar -xJf "$NODE_TAR" -C "$NODE_DIR" --strip-components=1
    else
      tar -xzf "$NODE_TAR" -C "$NODE_DIR" --strip-components=1
    fi
    [[ -x "$NODE_DIR/bin/node" ]] || die "Node extraction failed"
    ok "Node $NODE_VERSION installed: $NODE_DIR"
  fi
  export PATH="$NODE_DIR/bin:$PATH"
fi

# ── Frida source ───────────────────────────────────────────────────────────────
FRIDA_DIR="$WORK_DIR/frida"

if [[ "$SKIP_CLONE" -eq 1 ]]; then
  step "Frida source (reuse, cache-hit mode)"
  [[ -d "$FRIDA_DIR" ]] || die "--skip-clone: no source at $FRIDA_DIR"
  info "Resetting source to clean state (patches are destructive)..."
  (
    cd "$FRIDA_DIR"
    git checkout -- . 2>/dev/null || true
    git submodule foreach --recursive 'git checkout -- . 2>/dev/null || true'
    git clean -fdx 2>/dev/null || true
    rm -rf build/
  )
  ok "Source reset to clean state"
else
  step "Frida $FRIDA_VERSION source"
  if [[ -d "$FRIDA_DIR" ]]; then
    info "Removing stale source directory..."
    rm -rf "$FRIDA_DIR"
  fi
  info "Cloning Frida $FRIDA_VERSION with submodules (~500 MB)..."
  git clone --recurse-submodules \
            --branch "$FRIDA_VERSION" \
            --depth 1 \
            https://github.com/frida/frida.git \
            "$FRIDA_DIR"
  ok "Frida $FRIDA_VERSION cloned"
fi

# ── Assemble build.py command ─────────────────────────────────────────────────
step "Running build.py"

CMD=(python3 "$SCRIPT_DIR/build.py"
     --version "$FRIDA_VERSION"
     --name "$CUSTOM_NAME"
     --arch "$BUILD_ARCH"
     --skip-clone
     --ndk-path "$NDK_DIR"
     --work-dir "$WORK_DIR"
     --output-dir "$OUTPUT_DIR")

[[ -n "$CUSTOM_PORT" ]]    && CMD+=(--port "$CUSTOM_PORT")
[[ "$EXTENDED"   == "1" ]] && CMD+=(--extended)
[[ "$TEMP_FIXES" == "1" ]] && CMD+=(--temp-fixes)
[[ "$VERIFY"     -eq 1 ]]  && CMD+=(--verify)
[[ "$SKIP_BUILD" -eq 1 ]]  && CMD+=(--skip-build)

info "Command: ${CMD[*]}"
echo ""
"${CMD[@]}"

# ── Artifact summary ──────────────────────────────────────────────────────────
step "Build artifacts"
if [[ -d "$OUTPUT_DIR" ]] && [[ -n "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]]; then
  ls -lh "$OUTPUT_DIR/"
  echo ""
  echo -e "${BOLD}Residual 'frida' string scan (informational):${RESET}"
  for f in "$OUTPUT_DIR"/*; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *.gz ]] && continue
    count=$(strings "$f" 2>/dev/null | grep -c "frida" || true)
    if [[ "$count" -eq 0 ]]; then
      echo -e "  ${GREEN}CLEAN${RESET}  $(basename "$f")"
    else
      echo -e "  ${YELLOW}WARN${RESET}   $(basename "$f"): $count residual 'frida' string(s)"
    fi
  done
else
  warn "No artifacts found in $OUTPUT_DIR"
fi

# ── Deploy hint ───────────────────────────────────────────────────────────────
ARCH_SHORT="${ARCH_LIST[0]//android-/}"
SERVER="$CUSTOM_NAME-server-${FRIDA_VERSION}-android-${ARCH_SHORT}"
echo ""
echo -e "${BOLD}Deploy:${RESET}"
echo "  adb push $OUTPUT_DIR/$SERVER /data/local/tmp/$CUSTOM_NAME-server"
echo "  adb shell chmod 755 /data/local/tmp/$CUSTOM_NAME-server"
echo "  adb shell /data/local/tmp/$CUSTOM_NAME-server &"
if [[ -n "$CUSTOM_PORT" ]]; then
  echo "  frida -H 127.0.0.1:$CUSTOM_PORT -f <package>"
else
  echo "  frida -U -f <package>"
fi
