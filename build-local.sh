#!/usr/bin/env bash
# build-local.sh — Local build script mirroring the GitHub Actions workflow.
#
# Supports Linux (native / WSL / Docker) and macOS (via Docker).
#
# Usage:
#   ./build-local.sh                         # interactive prompts
#   ./build-local.sh --help                  # show all options
#
# Quick examples:
#   ./build-local.sh -v 17.7.2 -n stealth
#   ./build-local.sh -v 17.7.2 -n myfrida -a android-arm64,android-arm -p 28042 --extended
#   FRIDA_VERSION=17.7.2 CUSTOM_NAME=ghost ./build-local.sh --yes   # non-interactive
#
# Environment variable overrides (all have flag equivalents):
#   FRIDA_VERSION   CUSTOM_NAME   BUILD_ARCH   CUSTOM_PORT
#   EXTENDED        TEMP_FIXES    WORK_DIR      OUTPUT_DIR

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
err()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
step()  { echo -e "\n${BOLD}━━━  $*  ━━━${RESET}"; }
die()   { err "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults (env vars win over hard-coded, flags win over everything) ────────
FRIDA_VERSION="${FRIDA_VERSION:-17.7.2}"
CUSTOM_NAME="${CUSTOM_NAME:-ajeossida}"
BUILD_ARCH="${BUILD_ARCH:-android-arm64}"
CUSTOM_PORT="${CUSTOM_PORT:-}"
EXTENDED="${EXTENDED:-0}"
TEMP_FIXES="${TEMP_FIXES:-0}"
WORK_DIR="${WORK_DIR:-$SCRIPT_DIR/build}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"

YES=0          # --yes skips interactive prompts
SKIP_CLONE=0   # --skip-clone reuses existing source (like GHA cache hit)
SKIP_BUILD=0   # --skip-build patches only, no compilation
VERIFY=1       # --no-verify disables post-build string scan
USE_DOCKER=0   # force Docker even on Linux
NDK_PATH=""    # --ndk-path bypasses download

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
      --temp-fixes          Enable stability fixes
  -w, --work-dir DIR        Working/build directory (default: ./build)
  -o, --output-dir DIR      Output directory (default: ./output)
      --ndk-path PATH       Use existing NDK instead of downloading (~1.5 GB)
      --skip-clone          Reuse existing source in work-dir (reset to clean state)
      --skip-build          Apply patches only, skip compilation
      --no-verify           Skip post-build 'frida' string scan
      --docker              Force Docker build (default: auto-detect on macOS)
  -y, --yes                 Non-interactive, use defaults / env vars
  -h, --help                Show this help

Environment variables (override defaults, flags override env vars):
  FRIDA_VERSION  CUSTOM_NAME  BUILD_ARCH  CUSTOM_PORT  EXTENDED  TEMP_FIXES
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
    --docker)        USE_DOCKER=1;        shift   ;;
    -y|--yes)        YES=1;               shift   ;;
    -h|--help)       usage ;;
    *) die "Unknown option: $1  (run with --help)" ;;
  esac
done

# ── Interactive prompts (skipped with --yes) ──────────────────────────────────
ask() {
  # ask VAR "prompt" default
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
  # ask_bool VAR "prompt" default(0|1)
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

step "Custom Frida Local Builder"
echo -e "  Mirrors the GitHub Actions workflow exactly.\n"

ask         FRIDA_VERSION  "Frida version (e.g. 17.7.2)"              "$FRIDA_VERSION"
ask         CUSTOM_NAME    "Custom name (replaces 'frida' everywhere)" "$CUSTOM_NAME"
ask         BUILD_ARCH     "Target arch(s) (comma-separated)"         "$BUILD_ARCH"
ask         CUSTOM_PORT    "Custom port (empty = keep 27042)"          "$CUSTOM_PORT"
ask_bool    EXTENDED       "Extended anti-detection patches?"          "$EXTENDED"
ask_bool    TEMP_FIXES     "Stability fixes (perfetto, cloak detach)?" "$TEMP_FIXES"

# Normalise
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
echo ""

# ── Platform check ────────────────────────────────────────────────────────────
PLATFORM="$(uname -s)"

if [[ "$PLATFORM" == "Darwin" || "$USE_DOCKER" -eq 1 ]]; then
  # ── Docker path (macOS or forced) ──────────────────────────────────────────
  step "Running via Docker (Ubuntu 22.04)"
  command -v docker &>/dev/null || die "Docker not found. Install Docker Desktop first."

  # Pass all resolved settings as env vars into the container
  DOCKER_ENV=(
    -e "FRIDA_VERSION=$FRIDA_VERSION"
    -e "CUSTOM_NAME=$CUSTOM_NAME"
    -e "BUILD_ARCH=$BUILD_ARCH"
    -e "EXTENDED=$EXTENDED"
    -e "TEMP_FIXES=$TEMP_FIXES"
  )
  [[ -n "$CUSTOM_PORT" ]] && DOCKER_ENV+=(-e "CUSTOM_PORT=$CUSTOM_PORT")

  # Mount project directory and persistent build cache
  BUILD_CACHE="$SCRIPT_DIR/.docker-build-cache"
  mkdir -p "$BUILD_CACHE" "$OUTPUT_DIR"
  info "Build cache  : $BUILD_CACHE  (NDK + source cached here)"
  info "Output dir   : $OUTPUT_DIR"

  # Build the inner command
  INNER_CMD="python3 /workspace/build.py --version \$FRIDA_VERSION --name \$CUSTOM_NAME --arch \$BUILD_ARCH --verify"
  [[ -n "$CUSTOM_PORT" ]] && INNER_CMD="$INNER_CMD --port \$CUSTOM_PORT"
  [[ "$EXTENDED"   == "1" ]] && INNER_CMD="$INNER_CMD --extended"
  [[ "$TEMP_FIXES" == "1" ]] && INNER_CMD="$INNER_CMD --temp-fixes"
  INNER_CMD="$INNER_CMD --work-dir /cache --output-dir /output"
  [[ -n "$NDK_PATH" ]] && INNER_CMD="$INNER_CMD --ndk-path $NDK_PATH"
  [[ "$SKIP_CLONE"  -eq 1 ]] && INNER_CMD="$INNER_CMD --skip-clone"
  [[ "$SKIP_BUILD"  -eq 1 ]] && INNER_CMD="$INNER_CMD --skip-build"

  SETUP_CMDS="apt-get update -qq && apt-get install -y -qq build-essential curl git python3 unzip default-jdk > /dev/null 2>&1"

  docker run --rm -i --platform linux/amd64 \
    "${DOCKER_ENV[@]}" \
    -v "$SCRIPT_DIR:/workspace:ro" \
    -v "$BUILD_CACHE:/cache" \
    -v "$OUTPUT_DIR:/output" \
    -w /workspace \
    ubuntu:22.04 \
    bash -c "$SETUP_CMDS && $INNER_CMD"

else
  # ── Native Linux path ───────────────────────────────────────────────────────
  [[ "$PLATFORM" != "Linux" ]] && die "Unsupported platform: $PLATFORM. Use --docker on non-Linux."

  step "System info"
  echo "  CPUs : $(nproc)"
  echo "  RAM  : $(free -h | awk '/^Mem/{print $2}')"
  echo "  Disk : $(df -h "$SCRIPT_DIR" | awk 'NR==2{print $4}') free in project dir"
  python3 --version
  git --version

  step "Checking dependencies"
  MISSING=()
  for cmd in git python3 curl unzip make; do
    if command -v "$cmd" &>/dev/null; then
      ok "$cmd found"
    else
      warn "$cmd NOT found"
      MISSING+=("$cmd")
    fi
  done

  if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing: ${MISSING[*]}"
    if [[ $YES -eq 1 ]]; then
      info "Auto-installing missing dependencies..."
      sudo apt-get update -qq
      sudo apt-get install -y build-essential curl git python3 unzip
    else
      read -r -p "$(echo -e "${CYAN}?${RESET} Install missing packages via apt? [Y/n]: ")" yn
      [[ "${yn:-Y}" =~ ^[Yy]$ ]] || die "Cannot continue without required tools."
      sudo apt-get update -qq
      sudo apt-get install -y build-essential curl git python3 unzip
    fi
  fi

  # ── NDK (mirrors "Cache NDK" + "Download NDK" steps) ─────────────────────
  NDK_VER="r29"
  NDK_DIR="$WORK_DIR/android-ndk-$NDK_VER"
  NDK_ZIP="$WORK_DIR/android-ndk-$NDK_VER-linux.zip"
  NDK_URL="https://dl.google.com/android/repository/android-ndk-${NDK_VER}-linux.zip"

  if [[ -n "$NDK_PATH" ]]; then
    [[ -d "$NDK_PATH" ]] || die "NDK path not found: $NDK_PATH"
    NDK_DIR="$NDK_PATH"
    ok "Using provided NDK: $NDK_DIR"
  else
    step "NDK $NDK_VER"
    mkdir -p "$WORK_DIR"
    if [[ -d "$NDK_DIR" ]]; then
      ok "NDK cache hit: $NDK_DIR"
    else
      if [[ -f "$NDK_ZIP" ]]; then
        ok "NDK zip already downloaded, extracting..."
      else
        info "Downloading NDK $NDK_VER (~1.5 GB)..."
        curl -L --progress-bar -o "$NDK_ZIP" "$NDK_URL"
      fi
      info "Extracting NDK..."
      unzip -q "$NDK_ZIP" -d "$WORK_DIR"
      rm -f "$NDK_ZIP"
      [[ -d "$NDK_DIR" ]] || die "NDK extraction failed — expected $NDK_DIR"
      ok "NDK ready: $NDK_DIR"
    fi
  fi

  # ── Frida source (mirrors "Cache Frida source" + "Clone / Prepare" steps) ─
  FRIDA_DIR="$WORK_DIR/frida"

  if [[ "$SKIP_CLONE" -eq 1 ]]; then
    step "Frida source (reuse, cache-hit mode)"
    [[ -d "$FRIDA_DIR" ]] || die "--skip-clone: no source at $FRIDA_DIR"
    info "Resetting source to clean state (patches are destructive)..."
    cd "$FRIDA_DIR"
    git checkout -- . 2>/dev/null || true
    git submodule foreach --recursive 'git checkout -- . 2>/dev/null || true'
    git clean -fdx 2>/dev/null || true
    rm -rf build/
    cd "$SCRIPT_DIR"
    ok "Source reset to clean state"
  else
    step "Frida $FRIDA_VERSION source"
    if [[ -d "$FRIDA_DIR" ]]; then
      info "Removing stale source directory..."
      rm -rf "$FRIDA_DIR"
    fi
    info "Cloning Frida $FRIDA_VERSION with submodules..."
    git clone --recurse-submodules \
              --branch "$FRIDA_VERSION" \
              --depth 1 \
              https://github.com/frida/frida.git \
              "$FRIDA_DIR"
    ok "Frida $FRIDA_VERSION cloned"
  fi

  # ── Assemble build.py command (mirrors "Build command" step) ─────────────
  step "Running build.py"

  CMD="python3 $SCRIPT_DIR/build.py"
  CMD="$CMD --version $FRIDA_VERSION"
  CMD="$CMD --name $CUSTOM_NAME"
  CMD="$CMD --arch $BUILD_ARCH"
  CMD="$CMD --skip-clone"                  # source already ready
  CMD="$CMD --ndk-path $NDK_DIR"
  CMD="$CMD --work-dir $WORK_DIR"
  CMD="$CMD --output-dir $OUTPUT_DIR"

  [[ -n "$CUSTOM_PORT" ]]  && CMD="$CMD --port $CUSTOM_PORT"
  [[ "$EXTENDED"   == "1" ]] && CMD="$CMD --extended"
  [[ "$TEMP_FIXES" == "1" ]] && CMD="$CMD --temp-fixes"
  [[ "$VERIFY"     -eq 1 ]]  && CMD="$CMD --verify"
  [[ "$SKIP_BUILD" -eq 1 ]]  && CMD="$CMD --skip-build"

  info "Command: $CMD"
  echo ""
  eval "$CMD"
fi

# ── Artifact summary (mirrors "List artifacts" step) ─────────────────────────
step "Build artifacts"
if [[ -d "$OUTPUT_DIR" ]] && [[ -n "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]]; then
  ls -lh "$OUTPUT_DIR/"
  echo ""
  echo -e "${BOLD}Binary verification (residual 'frida' strings):${RESET}"
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
