#!/usr/bin/env python3
"""
Custom Frida Builder — build anti-detection Frida server from source.

Extended beyond ajeossida with additional stealth techniques.
Verified against Frida 17.7.2 source code.

Usage (run in WSL Ubuntu):
    python3 build.py --version 17.7.2
    python3 build.py --version 17.7.2 --name stealth --port 27142
    python3 build.py --version 17.7.2 --arch android-arm64,android-arm --extended
    python3 build.py --version 17.7.2 --skip-build  # only patch, don't compile

Requirements:
    - Ubuntu 22.04+ (WSL works)
    - Python 3.10+
    - Git
    - ~20GB free disk space
    - Internet connection (clones Frida + downloads NDK)
"""

import argparse
import gzip
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

from patches import (
    get_source_patches,
    get_targeted_patches,
    get_binary_patches,
    get_binary_string_patches,
    get_rollback_patches,
    get_port_patches,
    get_transport_patches,
    get_internal_patches,
    get_temp_path_patches,
    get_stability_patches_17,
    MEMFD_PATCHES,
    LIBC_HOOK_PATCHES,
    SELINUX_PATCHES,
    DETECTION_VECTORS,
)

# --- Constants ---

NDK_VERSION = "r29"
NDK_URL = f"https://dl.google.com/android/repository/android-ndk-{NDK_VERSION}-linux.zip"
ALL_ARCHS = ["android-arm64", "android-arm", "android-x86_64", "android-x86"]


def log(msg: str, level: str = "INFO"):
    colors = {
        "INFO": "\033[36m",
        "OK": "\033[32m",
        "WARN": "\033[33m",
        "ERROR": "\033[31m",
        "STEP": "\033[35m",
        "HEADER": "\033[1;37m",
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    print(f"{color}[{level}]{reset} {msg}", flush=True)


def run(cmd: str, cwd: str | None = None, env: dict | None = None,
        check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command with inherited env + overrides."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    log(f"$ {cmd}", "INFO")
    result = subprocess.run(
        cmd, shell=True, cwd=cwd, env=full_env,
        capture_output=False, text=True,
    )
    if check and result.returncode != 0:
        log(f"Command failed with exit code {result.returncode}", "ERROR")
        sys.exit(1)
    return result


def detect_frida_major(version: str) -> int:
    return int(version.split(".")[0])


# ============================================================================
# File operations
# ============================================================================

def replace_in_file(filepath: Path, old: str, new: str) -> int:
    """Replace string in a single file. Returns number of replacements."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, IsADirectoryError, OSError):
        return 0
    if old not in content:
        return 0
    count = content.count(old)
    content = content.replace(old, new)
    filepath.write_text(content, encoding="utf-8")
    return count


def replace_in_tree(root: Path, old: str, new: str,
                    include_build: bool = False) -> int:
    """Recursively replace string in all text files under root."""
    total = 0
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv"}
    if not include_build:
        skip_dirs.add("build")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            # Skip binary files by extension
            if fpath.suffix in {".o", ".a", ".so", ".gz", ".zip", ".png", ".jpg", ".pyc",
                                ".dex", ".jar", ".class", ".elf", ".wasm", ".dylib", ".dll"}:
                continue
            total += replace_in_file(fpath, old, new)

    return total


# ============================================================================
# NDK
# ============================================================================

def ensure_ndk(work_dir: Path) -> Path:
    """Download and extract Android NDK if needed."""
    ndk_dir = work_dir / f"android-ndk-{NDK_VERSION}"
    if ndk_dir.exists():
        log(f"NDK already at {ndk_dir}", "OK")
        return ndk_dir

    ndk_zip = work_dir / f"android-ndk-{NDK_VERSION}-linux.zip"
    if not ndk_zip.exists():
        log(f"Downloading NDK {NDK_VERSION} (~1.5 GB)...", "STEP")
        run(f"curl -L -o {ndk_zip} {NDK_URL}", cwd=str(work_dir))

    log("Extracting NDK...", "STEP")
    run(f"unzip -q -o {ndk_zip}", cwd=str(work_dir))

    if ndk_dir.exists():
        log(f"NDK ready at {ndk_dir}", "OK")
        ndk_zip.unlink(missing_ok=True)
        return ndk_dir
    else:
        log("NDK extraction failed", "ERROR")
        sys.exit(1)


# ============================================================================
# Clone
# ============================================================================

def clone_frida(version: str, work_dir: Path) -> Path:
    """Clone Frida source at the specified version tag."""
    frida_dir = work_dir / "frida"
    if frida_dir.exists():
        log(f"Frida source already at {frida_dir}", "OK")
        return frida_dir

    log(f"Cloning Frida {version} (with submodules)...", "STEP")
    run(
        f"git clone --recurse-submodules --branch {version} --depth 1 "
        f"https://github.com/frida/frida.git {frida_dir}",
        cwd=str(work_dir),
    )
    log(f"Frida {version} cloned", "OK")
    return frida_dir


# ============================================================================
# PHASE 1: Source-level patches (before build)
# ============================================================================

def rename_frida_files(frida_dir: Path, custom_name: str):
    """
    Rename files on disk whose names contain 'frida-helper' or 'frida-agent' etc.
    After global source patches rename references in meson.build/Vala/C files,
    the actual files on disk must also be renamed to match.

    IMPORTANT: Skip build system files (.symbols, .version, .def, .plist, .xcent)
    because rollback patches revert their references to original names.
    Also skip releng/frida_version.py (not renamed by our patches).
    """
    rename_patterns = [
        ("frida-helper", f"{custom_name}-helper"),
        ("frida-agent", f"{custom_name}-agent"),
        ("frida-gadget", f"{custom_name}-gadget"),
        ("frida-server", f"{custom_name}-server"),
    ]

    # Build system file extensions that rollback patches keep with original names
    skip_extensions = {".symbols", ".version", ".def", ".plist", ".xcent"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "build"}
    # Specific files to never rename
    skip_names = {"frida_version.py", "frida-version.py"}
    renamed_count = 0

    for dirpath, dirnames, filenames in os.walk(frida_dir, topdown=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname in skip_names:
                continue
            # Skip build system files (rollback patches keep their original names)
            if Path(fname).suffix in skip_extensions:
                continue
            new_fname = fname
            for old_pat, new_pat in rename_patterns:
                if old_pat in new_fname:
                    new_fname = new_fname.replace(old_pat, new_pat)
            if new_fname != fname:
                old_path = Path(dirpath) / fname
                new_path = Path(dirpath) / new_fname
                if old_path.exists() and not new_path.exists():
                    old_path.rename(new_path)
                    renamed_count += 1

    if renamed_count:
        log(f"  Renamed {renamed_count} files on disk", "OK")


def rebuild_helper_dex(frida_dir: Path, custom_name: str):
    """Rebuild the Android helper DEX with renamed Java package.

    The pre-compiled helper.dex in the repo contains 're.frida.Helper'.
    We need to recompile it with the new package name so that:
    1. The DEX string table doesn't contain 'frida' (binary sweep safe)
    2. The class name matches what the renamed Vala code expects
    """
    helper_dir = frida_dir / "subprojects" / "frida-core" / "src" / "android-helper"
    old_pkg_dir = helper_dir / "re" / "frida"
    new_pkg_dir = helper_dir / "re" / custom_name
    java_file = old_pkg_dir / "Helper.java"

    if not java_file.exists():
        # Package might already be renamed (e.g., from cache)
        java_file = new_pkg_dir / "Helper.java"
        if not java_file.exists():
            log("  Helper.java not found, skipping DEX rebuild", "WARN")
            return

    # Rename directory: re/frida/ -> re/{name}/
    if old_pkg_dir.exists() and not new_pkg_dir.exists():
        old_pkg_dir.rename(new_pkg_dir)
        log(f"  Renamed {old_pkg_dir.name}/ -> {new_pkg_dir.name}/", "OK")

    java_file = new_pkg_dir / "Helper.java"
    if not java_file.exists():
        log("  Helper.java not found after rename", "WARN")
        return

    # The Java source was already patched by replace_in_tree:
    #   "package re.frida;" -> "package re.{name};"
    #   "re.frida.Helper" -> "re.{name}.Helper"
    # Verify:
    content = java_file.read_text(encoding="utf-8")
    if f"package re.{custom_name};" not in content:
        log("  Helper.java package not patched, fixing...", "WARN")
        content = content.replace("package re.frida;", f"package re.{custom_name};")
        java_file.write_text(content, encoding="utf-8")

    # Try to recompile the DEX
    dex_file = helper_dir / "helper.dex"
    build_dir = helper_dir / "build"
    build_dir.mkdir(exist_ok=True)
    java_build = build_dir / "java"
    java_build.mkdir(exist_ok=True)

    # Check if javac is available
    javac_check = subprocess.run(["javac", "-version"], capture_output=True, text=True)
    if javac_check.returncode != 0:
        log("  javac not available, keeping pre-compiled DEX (may contain 'frida' strings)", "WARN")
        return

    # We need android.jar for compilation. Check common locations.
    android_jar = None
    possible_jars = [
        # GitHub Actions / CI
        Path("/usr/local/lib/android/sdk/platforms/android-34/android.jar"),
        Path("/usr/local/lib/android/sdk/platforms/android-33/android.jar"),
        # Try any available platform
    ]
    # Also search in ANDROID_SDK_ROOT if set
    sdk_root = os.environ.get("ANDROID_SDK_ROOT", os.environ.get("ANDROID_HOME", ""))
    if sdk_root:
        platforms_dir = Path(sdk_root) / "platforms"
        if platforms_dir.exists():
            for p in sorted(platforms_dir.iterdir(), reverse=True):
                jar = p / "android.jar"
                if jar.exists():
                    possible_jars.insert(0, jar)

    for jar in possible_jars:
        if jar.exists():
            android_jar = jar
            break

    if android_jar is None:
        # Search more broadly
        result = subprocess.run(
            "find /usr/local/lib/android -name 'android.jar' 2>/dev/null | head -1",
            shell=True, capture_output=True, text=True
        )
        if result.stdout.strip():
            android_jar = Path(result.stdout.strip())

    if android_jar is None:
        log("  android.jar not found, keeping pre-compiled DEX", "WARN")
        return

    log(f"  Recompiling helper DEX (android.jar: {android_jar.name})...", "STEP")

    # Step 1: javac -> .class files
    javac_cmd = (
        f"javac -cp .:{android_jar} -bootclasspath {android_jar} "
        f"-source 1.8 -target 1.8 "
        f"-Xlint:-options "  # suppress bootclasspath warning
        f"{java_file} -d {java_build}"
    )
    result = subprocess.run(javac_cmd, shell=True, cwd=str(helper_dir),
                            capture_output=True, text=True)
    if result.returncode != 0:
        log(f"  javac failed: {result.stderr[:200]}", "WARN")
        log("  Keeping pre-compiled DEX", "WARN")
        return

    # Collect ALL .class files (including inner classes like Helper$1.class)
    class_dir = java_build / "re" / custom_name
    class_files = list(class_dir.glob("*.class"))
    if not class_files:
        log("  No .class files generated", "WARN")
        return
    log(f"  Compiled {len(class_files)} class files (including inner classes)", "OK")

    # Step 2: Package into JAR first (avoids d8 "defined multiple times" error)
    jar_file = build_dir / f"{custom_name}-helper.jar"
    jar_cmd = f"jar cfe {jar_file} re.{custom_name}.Helper -C {java_build} ."
    result = subprocess.run(jar_cmd, shell=True, cwd=str(helper_dir),
                            capture_output=True, text=True)
    if result.returncode != 0:
        log(f"  jar failed: {result.stderr[:200]}", "WARN")
        return

    # Step 3: Convert JAR to DEX using d8
    d8_path = None
    d8_check = subprocess.run(["which", "d8"], capture_output=True, text=True)
    if d8_check.returncode == 0:
        d8_path = "d8"
    else:
        # Try d8 from Android SDK build-tools
        if sdk_root:
            bt_dir = Path(sdk_root) / "build-tools"
            if bt_dir.exists():
                for bt in sorted(bt_dir.iterdir(), reverse=True):
                    candidate = bt / "d8"
                    if candidate.exists():
                        d8_path = str(candidate)
                        break
        if d8_path is None:
            find_result = subprocess.run(
                "find /usr/local/lib/android -name 'd8' -type f 2>/dev/null | head -1",
                shell=True, capture_output=True, text=True
            )
            if find_result.stdout.strip():
                d8_path = find_result.stdout.strip()

    if d8_path is None:
        log("  d8 not found, keeping pre-compiled DEX", "WARN")
        return
    dex_cmd = f"{d8_path} --lib {android_jar} --output {build_dir} {jar_file}"

    result = subprocess.run(dex_cmd, shell=True, cwd=str(helper_dir),
                            capture_output=True, text=True)
    if result.returncode != 0:
        log(f"  d8 failed: {result.stderr[:200]}", "WARN")
        log("  Keeping pre-compiled DEX", "WARN")
        return

    # Step 3: Replace helper.dex with new one
    new_dex = build_dir / "classes.dex"
    if new_dex.exists():
        shutil.copy2(new_dex, dex_file)
        log(f"  Helper DEX rebuilt: {dex_file.stat().st_size} bytes (package: re.{custom_name})", "OK")
    else:
        log("  classes.dex not generated, keeping pre-compiled DEX", "WARN")


def apply_page_patch(frida_dir: Path):
    """Apply page_patch to frida-gum (Android page permission fix)."""
    patch_file = Path(__file__).parent / "my_page.patch"
    if not patch_file.exists():
        log("my_page.patch not found, skipping", "WARN")
        return
    log("Applying my_page.patch to frida-gum...", "STEP")
    run(f"git apply {patch_file}", cwd=str(frida_dir))
    log("my_page.patch applied", "OK")



def apply_source_patches(frida_dir: Path, custom_name: str):
    """Apply global recursive string replacements across the source tree."""
    log("=" * 60, "HEADER")
    log("PHASE 1: Global source patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]

    patches = get_source_patches(custom_name, cap_name)
    for old, new in patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  {old} -> {new} ({count})", "OK")
        else:
            log(f"  {old} -> (not found)", "WARN")

    # Rollback accidental renames of build system files
    log("Rolling back build file renames...", "STEP")
    rollbacks = get_rollback_patches(custom_name)
    for old, new in rollbacks:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  [rollback] {old} ({count})", "INFO")

    # Rename actual files on disk to match source references
    rename_frida_files(frida_dir, custom_name)

    # Rebuild helper DEX with renamed Java package
    rebuild_helper_dex(frida_dir, custom_name)

    log("Global source patches complete", "OK")


def apply_targeted_patches(frida_dir: Path, custom_name: str, frida_major: int):
    """Apply patches to specific files (memfd, libc hooks, SELinux, build system)."""
    log("=" * 60, "HEADER")
    log("PHASE 2: Targeted file patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]
    core_dir = frida_dir / "subprojects" / "frida-core"
    gum_dir = frida_dir / "subprojects" / "frida-gum"

    # --- memfd_create: hide agent name in /proc/pid/fd ---
    memfd_cfg = MEMFD_PATCHES.get(frida_major, MEMFD_PATCHES[17])
    memfd_file = core_dir / memfd_cfg["file"]
    if memfd_file.exists():
        count = replace_in_file(memfd_file, memfd_cfg["old"], memfd_cfg["new"])
        if count:
            log(f"  memfd_create -> 'jit-cache' in {memfd_cfg['file']}", "OK")
        else:
            log(f"  memfd_create: pattern not found in {memfd_cfg['file']}", "WARN")
    else:
        log(f"  memfd file missing: {memfd_cfg['file']}", "WARN")

    # --- Disable exit monitor (prevents detection via hooked exit/_exit/abort) ---
    exit_monitor = core_dir / "lib" / "payload" / "exit-monitor.vala"
    if exit_monitor.exists():
        for old, new in LIBC_HOOK_PATCHES["exit_monitor"]:
            count = replace_in_file(exit_monitor, old, new)
            if count:
                log(f"  exit-monitor: disabled interceptor.attach ({count})", "OK")

    # --- Disable signal/sigaction hooking ---
    exceptor = gum_dir / "gum" / "backend-posix" / "gumexceptor-posix.c"
    if exceptor.exists():
        for old, new in LIBC_HOOK_PATCHES["exceptor"]:
            count = replace_in_file(exceptor, old, new)
            if count:
                log(f"  gumexceptor: disabled hook ({count})", "OK")

    # --- SELinux labels (in linjector.vala for 17.x) ---
    for old, new in SELINUX_PATCHES(custom_name):
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  SELinux: {old} -> {new} ({count})", "OK")

    # --- Build system files ---
    targets = {
        "server_meson": core_dir / "server" / "meson.build",
        "compat_build": core_dir / "compat" / "build.py",
        "core_meson": core_dir / "meson.build",
        "gadget_meson": core_dir / "lib" / "gadget" / "meson.build",
        "agent_meson": core_dir / "lib" / "agent" / "meson.build",
    }

    for target_name, target_file in targets.items():
        if target_file.exists():
            patches = get_targeted_patches(custom_name, cap_name, target_name)
            applied = 0
            for old, new in patches:
                applied += replace_in_file(target_file, old, new)
            if applied:
                log(f"  {target_name}: {applied} patches", "OK")
        else:
            log(f"  {target_name}: file not found", "WARN")

    log("Targeted patches complete", "OK")


def apply_extended_patches(frida_dir: Path, custom_name: str, port: int | None):
    """Apply extended anti-detection patches beyond ajeossida."""
    log("=" * 60, "HEADER")
    log("PHASE 2.5: Extended anti-detection patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]

    # --- Port change ---
    if port and port != 27042:
        port_patches = get_port_patches(port)
        for patch in port_patches:
            for fpath in patch["files"]:
                full_path = frida_dir / fpath
                if full_path.exists():
                    count = replace_in_file(full_path, patch["pattern"], patch["replacement"])
                    if count:
                        log(f"  Port: {patch['description']} in {Path(fpath).name} ({count})", "OK")
        # Also do a global sweep for the port number in less obvious places
        count = replace_in_tree(frida_dir / "subprojects" / "frida-core", "27042", str(port))
        if count:
            log(f"  Port: global sweep found {count} more occurrences", "OK")

    # --- D-Bus interface names ---
    # NOTE: Transport/D-Bus interface renames (re.frida.HostSession etc.) are DISABLED.
    # These interface names are part of the Frida client-server protocol.
    # Renaming them on the server breaks communication with the standard frida client.
    # They are NOT visible to other apps (only over USB/TCP channel), so not a detection vector.
    # The D-Bus service name (re.frida.server) IS renamed by global source patches — that's safe.

    # --- Internal identifiers (C symbols, GType names) ---
    internal_patches = get_internal_patches(custom_name, cap_name)
    for old, new in internal_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Internal: {old} -> {new} ({count})", "OK")

    # --- Temp file paths ---
    temp_patches = get_temp_path_patches(custom_name)
    for old, new in temp_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Temp paths: {old} -> {new} ({count})", "OK")

    log("Extended patches complete", "OK")


def apply_stability_fixes(frida_dir: Path, frida_major: int):
    """Apply optional stability/crash fixes."""
    log("Applying stability fixes...", "STEP")

    core_dir = frida_dir / "subprojects" / "frida-core"

    if frida_major >= 17:
        patches = get_stability_patches_17(frida_dir)
        for patch in patches:
            fpath = frida_dir / patch["file"]
            if fpath.exists():
                count = replace_in_file(fpath, patch["old"], patch["new"])
                if count:
                    log(f"  {patch['description']}", "OK")
                else:
                    log(f"  Pattern not found: {patch['description']}", "WARN")

    # DirListCloaker interceptor detach — safe to disable to prevent crash
    cloak = core_dir / "lib" / "payload" / "cloak.vala"
    if cloak.exists():
        # 17.x: DirListCloaker uses Gum.Interceptor.detach in destructor
        old = "Gum.Interceptor.obtain ().detach (listener);"
        new = "// Gum.Interceptor.obtain ().detach (listener);"
        count = replace_in_file(cloak, old, new)
        if count:
            log(f"  cloak.vala: disabled interceptor detach ({count})", "OK")

    log("Stability fixes complete", "OK")


# ============================================================================
# PHASE 3: Post-build patches (after first compilation)
# ============================================================================

def apply_post_build_patches(frida_dir: Path, custom_name: str):
    """Patch frida_agent_main symbol (generated during first build).

    Must include build/ directory because:
    - agent-glue.c (source) CALLS frida_agent_main
    - meson-generated_agent.c (build output) DEFINES frida_agent_main
    Both must be renamed together, otherwise linker error.
    """
    log("PHASE 3: Post-build patches (frida_agent_main)...", "STEP")
    count = replace_in_tree(frida_dir, "frida_agent_main", f"{custom_name}_agent_main",
                            include_build=True)
    log(f"  frida_agent_main -> {custom_name}_agent_main ({count})", "OK")


# ============================================================================
# PHASE 4: Binary-level patches (after second compilation)
# ============================================================================

def find_dex_regions(data: bytes) -> list[tuple[int, int]]:
    """Find embedded DEX sections in binary data by scanning for DEX magic.
    Returns list of (start, end) byte ranges to protect from modification."""
    regions = []
    dex_magics = [b'dex\n035\x00', b'dex\n037\x00', b'dex\n038\x00', b'dex\n039\x00']
    for magic in dex_magics:
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos == -1:
                break
            # Read header_size and file_size from DEX header
            if pos + 0x28 < len(data):
                file_size = struct.unpack_from('<I', data, pos + 0x20)[0]
                header_size = struct.unpack_from('<I', data, pos + 0x24)[0]
                # Valid DEX: header_size=112 (0x70), file_size > header_size
                if header_size == 112 and file_size > 112 and file_size < 10_000_000:
                    regions.append((pos, pos + file_size))
                    log(f"    [dex] Protected DEX region: 0x{pos:08x}-0x{pos+file_size:08x} ({file_size} bytes)", "INFO")
            idx = pos + 8
    return regions


def replace_bytes_outside_regions(data: bytes, old: bytes, new: bytes,
                                   skip_regions: list[tuple[int, int]]) -> tuple[bytes, int]:
    """Replace byte pattern in data, skipping protected regions.
    Returns (modified_data, replacement_count)."""
    assert len(old) == len(new), "Replacement must be same length"
    result = bytearray(data)
    count = 0
    idx = 0
    while True:
        pos = data.find(old, idx)
        if pos == -1:
            break
        # Check if this position falls inside any protected region
        in_protected = any(start <= pos < end for start, end in skip_regions)
        if not in_protected:
            result[pos:pos + len(new)] = new
            count += 1
        idx = pos + 1
    return bytes(result), count


def apply_binary_patches(binary_path: Path, custom_name: str, extended: bool = False):
    """Apply hex-level patches to compiled binaries.
    DEX-aware: protects embedded DEX sections from string sweep corruption."""
    data = binary_path.read_bytes()
    original_size = len(data)
    patched = False

    # Find embedded DEX regions to protect
    dex_regions = find_dex_regions(data) if extended else []

    # Standard thread name patches (safe — these patterns don't appear in DEX)
    for old_hex, new_hex, description in get_binary_patches():
        old_bytes = bytes.fromhex(old_hex)
        new_bytes = bytes.fromhex(new_hex)
        if old_bytes in data:
            data = data.replace(old_bytes, new_bytes)
            log(f"    {description}", "OK")
            patched = True

    # Extended: sweep for residual "frida" strings in binary
    # MUST skip DEX regions to avoid corrupting embedded helper DEX
    if extended:
        for old_hex, new_hex, description in get_binary_string_patches(custom_name):
            old_bytes = bytes.fromhex(old_hex)
            new_bytes = bytes.fromhex(new_hex)
            if old_bytes in data:
                if dex_regions:
                    data, count = replace_bytes_outside_regions(data, old_bytes, new_bytes, dex_regions)
                else:
                    count = data.count(old_bytes)
                    data = data.replace(old_bytes, new_bytes)
                if count:
                    log(f"    [ext] {description} ({count}x, skipped DEX regions)", "OK")
                    patched = True

    if patched:
        assert len(data) == original_size, "Binary size changed — patches are not same-length!"
        binary_path.write_bytes(data)


# ============================================================================
# Build
# ============================================================================

def configure_arch(frida_dir: Path, arch: str, ndk_path: Path):
    log(f"Configuring for {arch}...", "STEP")
    run(
        f"./configure --host={arch}",
        cwd=str(frida_dir),
        env={"ANDROID_NDK_ROOT": str(ndk_path)},
    )


def build_frida(frida_dir: Path, ndk_path: Path):
    cpus = os.cpu_count() or 4
    log(f"Building ({cpus} threads)...", "STEP")
    run(
        f"make -j{cpus}",
        cwd=str(frida_dir),
        env={"ANDROID_NDK_ROOT": str(ndk_path)},
    )


# ============================================================================
# Collect artifacts
# ============================================================================

def strip_binary(binary_path: Path, ndk_path: Path, arch: str):
    """Strip a compiled binary using NDK llvm-strip.

    Used when collect_artifacts falls back to a *-modulated.so (unstripped
    intermediate), which happens on x86/x86_64 where post_process.py places
    the final artifact at a different path that find_artifact misses.
    """
    # NDK r23+: toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
    strip_bin = ndk_path / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / "llvm-strip"
    if not strip_bin.exists():
        log(f"    llvm-strip not found at {strip_bin}, skipping strip", "WARN")
        return

    flag = "--strip-unneeded" if binary_path.suffix == ".so" else "--strip-all"
    result = subprocess.run(
        [str(strip_bin), flag, str(binary_path)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        log(f"    Stripped {binary_path.name} ({binary_path.stat().st_size:,} bytes after strip)", "OK")
    else:
        log(f"    llvm-strip failed: {result.stderr[:200]}", "WARN")


def collect_artifacts(frida_dir: Path, arch: str, custom_name: str,
                      version: str, output_dir: Path, extended: bool,
                      ndk_path: Path | None = None):
    """Find, binary-patch, and package build artifacts."""
    log(f"Collecting artifacts for {arch}...", "STEP")

    arch_short = arch.replace("android-", "")

    def find_artifact(subdir: str, patterns: list[str]) -> Path | None:
        base = frida_dir / "build" / "subprojects" / "frida-core" / subdir
        for pattern in patterns:
            candidate = base / pattern
            if candidate.exists():
                return candidate
        # List directory for debugging
        if base.exists():
            log(f"    Looking in {base}:", "INFO")
            for f in sorted(base.iterdir()):
                if f.is_file() and f.stat().st_size > 1000:
                    log(f"      {f.name} ({f.stat().st_size:,} bytes)", "INFO")
        return None

    def save_artifact(src: Path, out_name: str):
        # Save compressed
        out_gz = output_dir / f"{out_name}.gz"
        with open(src, "rb") as f_in:
            with gzip.open(out_gz, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        log(f"    -> {out_gz.name} ({out_gz.stat().st_size / 1024 / 1024:.1f} MB)", "OK")

        # Save uncompressed
        out_bin = output_dir / out_name
        shutil.copy2(src, out_bin)
        os.chmod(out_bin, 0o755)

    # --- Server ---
    server = find_artifact("server", [
        f"{custom_name}-server",
        f"{custom_name}-server-raw",
        "frida-server",
        "frida-server-raw",
    ])
    if server:
        log(f"  Server: {server.name}", "OK")
        apply_binary_patches(server, custom_name, extended)
        save_artifact(server, f"{custom_name}-server-{version}-android-{arch_short}")
    else:
        log("  Server: NOT FOUND", "ERROR")

    # --- Agent .so ---
    agent = find_artifact("lib/agent", [
        f"lib{custom_name}-agent.so",
        f"lib{custom_name}-agent-modulated.so",
        f"lib{custom_name}-agent-raw.so",
        "libfrida-agent.so",
        "libfrida-agent-modulated.so",
    ])
    if agent:
        log(f"  Agent: {agent.name}", "OK")
        if "modulated" in agent.name and ndk_path:
            log("    Agent is unstripped modulated intermediate — stripping now", "WARN")
            strip_binary(agent, ndk_path, arch)
        apply_binary_patches(agent, custom_name, extended)

    # --- Gadget .so ---
    gadget = find_artifact("lib/gadget", [
        f"lib{custom_name}-gadget.so",
        f"lib{custom_name}-gadget-modulated.so",
        "libfrida-gadget.so",
        "libfrida-gadget-modulated.so",
    ])
    if gadget:
        log(f"  Gadget: {gadget.name}", "OK")
        if "modulated" in gadget.name and ndk_path:
            log("    Gadget is unstripped modulated intermediate — stripping now", "WARN")
            strip_binary(gadget, ndk_path, arch)
        apply_binary_patches(gadget, custom_name, extended)
        save_artifact(gadget, f"{custom_name}-gadget-{version}-android-{arch_short}.so")


# ============================================================================
# Verification
# ============================================================================

def verify_binary(binary_path: Path):
    """Check compiled binary for residual 'frida' strings."""
    if not binary_path.exists():
        return

    data = binary_path.read_bytes()
    # Search for null-terminated "frida" (case-sensitive)
    frida_bytes = b"frida\x00"
    count = data.count(frida_bytes)
    if count:
        log(f"  WARNING: {binary_path.name} still contains 'frida\\0' x{count}", "WARN")

        # Show context around each occurrence
        idx = 0
        shown = 0
        while shown < 5:
            pos = data.find(frida_bytes, idx)
            if pos == -1:
                break
            # Extract surrounding context
            start = max(0, pos - 20)
            end = min(len(data), pos + 30)
            context = data[start:end]
            # Show printable chars only
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in context)
            log(f"    @ 0x{pos:08x}: ...{printable}...", "WARN")
            idx = pos + 1
            shown += 1
    else:
        log(f"  {binary_path.name}: clean (no 'frida' strings)", "OK")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Build custom anti-detection Frida server from source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build.py --version 17.7.2
  python3 build.py --version 17.7.2 --name stealth --port 27142
  python3 build.py --version 17.7.2 --arch android-arm64,android-arm --extended
  python3 build.py --version 17.7.2 --skip-build  # patch only, no compilation
  python3 build.py --version 17.7.2 --temp-fixes   # add stability patches

Detection vectors covered:
""" + DETECTION_VECTORS,
    )

    parser.add_argument("--version", "-v", required=True,
                        help="Frida version to build (e.g. 17.7.2)")
    parser.add_argument("--arch", "-a", default="android-arm64",
                        help=f"Comma-separated architectures. Options: {', '.join(ALL_ARCHS)}")
    parser.add_argument("--name", "-n", default="ajeossida",
                        help="Custom name replacing 'frida' everywhere (default: ajeossida)")
    parser.add_argument("--port", "-p", type=int, default=None,
                        help="Custom listening port (default: 27042 unchanged)")
    parser.add_argument("--extended", "-e", action="store_true",
                        help="Apply extended anti-detection (D-Bus interfaces, symbols, paths, binary sweep)")
    parser.add_argument("--temp-fixes", action="store_true",
                        help="Apply stability fixes (perfetto skip, cloak detach)")
    parser.add_argument("--work-dir", "-w", default=None,
                        help="Working directory (default: ./build)")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Output directory (default: ./output)")
    parser.add_argument("--ndk-path", default=None,
                        help="Path to existing Android NDK r29 (skip download)")
    parser.add_argument("--skip-clone", action="store_true",
                        help="Use existing source in work-dir")
    parser.add_argument("--skip-build", action="store_true",
                        help="Only apply patches, don't compile")
    parser.add_argument("--verify", action="store_true",
                        help="After build, scan binaries for residual 'frida' strings")

    args = parser.parse_args()

    # Validate
    version = args.version
    frida_major = detect_frida_major(version)
    custom_name = args.name.lower()
    archs = [a.strip() for a in args.arch.split(",")]

    for arch in archs:
        if arch not in ALL_ARCHS:
            log(f"Unknown architecture: {arch}. Valid: {', '.join(ALL_ARCHS)}", "ERROR")
            sys.exit(1)

    if len(custom_name) < 3:
        log("Custom name must be at least 3 characters", "ERROR")
        sys.exit(1)

    # Directories
    script_dir = Path(__file__).parent.resolve()
    work_dir = Path(args.work_dir) if args.work_dir else script_dir / "build"
    output_dir = Path(args.output_dir) if args.output_dir else script_dir / "output"
    work_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Banner
    log("=" * 60, "HEADER")
    log("Custom Frida Builder", "HEADER")
    log("=" * 60, "HEADER")
    log(f"  Version:  Frida {version} (major: {frida_major})", "INFO")
    log(f"  Name:     '{custom_name}'", "INFO")
    log(f"  Archs:    {', '.join(archs)}", "INFO")
    log(f"  Port:     {args.port or '27042 (default)'}", "INFO")
    log(f"  Extended: {args.extended}", "INFO")
    log(f"  Work dir: {work_dir}", "INFO")
    log(f"  Output:   {output_dir}", "INFO")

    # Step 1: NDK
    if args.ndk_path:
        ndk_path = Path(args.ndk_path).resolve()
        if not ndk_path.exists():
            log(f"NDK path does not exist: {ndk_path}", "ERROR")
            sys.exit(1)
    else:
        ndk_path = ensure_ndk(work_dir)
    log(f"  NDK:      {ndk_path}", "INFO")

    # Step 2: Clone
    frida_dir = work_dir / "frida"
    if not args.skip_clone:
        if frida_dir.exists():
            log("Removing existing frida dir...", "WARN")
            shutil.rmtree(frida_dir)
        frida_dir = clone_frida(version, work_dir)
    else:
        if not frida_dir.exists():
            log("--skip-clone requires existing source in work-dir", "ERROR")
            sys.exit(1)
        log(f"Using existing source at {frida_dir}", "OK")

    # Step 2.5: Apply page_patch to frida-gum
    apply_page_patch(frida_dir)

    # Step 3: Source patches
    apply_source_patches(frida_dir, custom_name)
    apply_targeted_patches(frida_dir, custom_name, frida_major)

    # Step 3.5: Extended patches
    if args.extended:
        apply_extended_patches(frida_dir, custom_name, args.port)
    elif args.port:
        # Apply port patch even without --extended
        apply_extended_patches(frida_dir, custom_name, args.port)

    # Step 4: Stability fixes
    if args.temp_fixes:
        apply_stability_fixes(frida_dir, frida_major)

    if args.skip_build:
        log("=" * 60, "HEADER")
        log("Patches applied. Build skipped (--skip-build).", "OK")
        log(f"Source ready at: {frida_dir}", "INFO")
        log("To build manually:", "INFO")
        log(f"  cd {frida_dir}", "INFO")
        log(f"  ANDROID_NDK_ROOT={ndk_path} ./configure --host=android-arm64", "INFO")
        log(f"  ANDROID_NDK_ROOT={ndk_path} make -j$(nproc)", "INFO")
        return

    # Step 5: Build loop
    for arch in archs:
        log("=" * 60, "HEADER")
        log(f"Building for {arch}", "STEP")
        log("=" * 60, "HEADER")

        # Configure
        configure_arch(frida_dir, arch, ndk_path)

        # First build
        log("First build...", "STEP")
        build_frida(frida_dir, ndk_path)

        # Post-build patches (frida_agent_main appears only after first build)
        apply_post_build_patches(frida_dir, custom_name)

        # Second build (incremental — only recompiles files with patched symbol)
        log("Second build (incremental)...", "STEP")
        build_frida(frida_dir, ndk_path)

        # Collect and binary-patch artifacts
        collect_artifacts(frida_dir, arch, custom_name, version, output_dir, args.extended, ndk_path)

    # Step 6: Verification
    if args.verify:
        log("=" * 60, "HEADER")
        log("Verification: scanning for residual 'frida' strings...", "STEP")
        for f in sorted(output_dir.iterdir()):
            if f.is_file() and not f.name.endswith(".gz"):
                verify_binary(f)

    # Done
    log("=" * 60, "HEADER")
    log("BUILD COMPLETE", "OK")
    log(f"Artifacts in: {output_dir}", "OK")
    for f in sorted(output_dir.iterdir()):
        size_mb = f.stat().st_size / (1024 * 1024)
        log(f"  {f.name} ({size_mb:.1f} MB)", "OK")

    # Usage hint
    log("", "INFO")
    log("To deploy:", "STEP")
    arch_short = archs[0].replace("android-", "")
    server_name = f"{custom_name}-server-{version}-android-{arch_short}"
    log(f"  adb push output/{server_name} /data/local/tmp/{custom_name}-server", "INFO")
    log(f"  adb shell chmod 755 /data/local/tmp/{custom_name}-server", "INFO")
    log(f"  adb shell /data/local/tmp/{custom_name}-server &", "INFO")
    if args.port:
        log(f"  frida -H 127.0.0.1:{args.port} -f <package>", "INFO")
    else:
        log(f"  frida -U -f <package>", "INFO")


if __name__ == "__main__":
    main()
