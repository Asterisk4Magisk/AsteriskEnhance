# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: GPL-3.0

"""Build the Android module with the supplied SDK and NDK."""

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64": "x86_64-linux-android",
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "armv7a-linux-androideabi",
    "x86": "i686-linux-android",
}


def ndk_toolchain(ndk):
    host = platform.system()
    host_tag = {
        "Windows": "windows-x86_64",
        "Linux": "linux-x86_64",
        "Darwin": "darwin-x86_64",
    }.get(host)
    if host_tag is None:
        raise RuntimeError(f"No Android NDK host toolchain is defined for {host}")
    directory = ndk / "toolchains/llvm/prebuilt" / host_tag / "bin"
    if not directory.is_dir():
        raise FileNotFoundError(f"Android NDK host toolchain is missing: {directory}")
    return directory


def build_tool(directory, name):
    suffix = ".exe" if platform.system() == "Windows" else ""
    executable = directory / (name + suffix)
    if not executable.is_file():
        raise FileNotFoundError(f"Required build tool is missing: {executable}")
    return executable


def build_identity(args, abi):
    digest = hashlib.sha256()
    for directory in ("native", "third_party"):
        for source in sorted((ROOT / directory).rglob("*")):
            if source.is_file():
                digest.update(source.relative_to(ROOT).as_posix().encode() + b"\0")
                digest.update(source.read_bytes().replace(b"\r\n", b"\n"))
    for name in ("tools/build.py", "module/module.prop"):
        digest.update((ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
    digest.update(f"abi={abi};sdk={args.min_sdk};ndk=".encode())
    digest.update((args.ndk / "source.properties").read_bytes())
    return digest.hexdigest()


def build_libraries(args, abi, environment):
    toolchain = ndk_toolchain(args.ndk)
    compiler = build_tool(toolchain, "clang++")
    c_compiler = build_tool(toolchain, "clang")
    aidl_compiler = build_tool(args.sdk / "build-tools/37.0.0", "aidl")
    output = args.work_directory / "release" / abi
    output.mkdir(parents=True, exist_ok=True)
    library = output / "libasterisk_enhance.so"
    properties = dict(
        line.split("=", 1)
        for line in (ROOT / "module/module.prop").read_text().splitlines()
        if "=" in line
    )
    version = properties["version"]
    import re

    if (
        not re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", version)
        or not properties["versionCode"].isdigit()
    ):
        raise ValueError("Invalid runtime module version")
    identity = build_identity(args, abi)
    (output / "ae_build_identity.h").write_text(
        "#define AE_MODULE_VERSION_CODE "
        + json.dumps(properties["versionCode"])
        + "\n"
        + "#define AE_MODULE_VERSION "
        + json.dumps(version)
        + "\n"
        + "#define AE_MODULE_BUILD_ID "
        + json.dumps(identity)
        + "\n",
        newline="\n",
    )
    (output / "runtime-identity.prop").write_text("buildId=" + identity + "\n", newline="\n")
    target = TARGETS[abi] + str(args.min_sdk)
    core_objects = []
    for source in sorted((ROOT / "native/common").glob("*.c")):
        obj = output / (source.stem + ".o")
        subprocess.run(
            [
                str(c_compiler),
                f"--target={target}",
                "-std=c17",
                "-O2",
                "-fPIC",
                "-fvisibility=hidden",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
                str(source),
                "-o",
                str(obj),
            ],
            env=environment,
            check=True,
        )
        core_objects.append(str(obj))
    for source in ("platform_cache_list", "platform_legacy27"):
        platform_object = output / (source + ".o")
        subprocess.run(
            [
                str(compiler),
                f"--target={target}",
                "-std=c++17",
                "-O2",
                "-fPIC",
                "-fvisibility=hidden",
                "-fno-exceptions",
                "-fno-rtti",
                "-D_LIBCPP_ABI_NAMESPACE=__1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
                str(ROOT / "native/netd" / (source + ".cpp")),
                "-o",
                str(platform_object),
            ],
            env=environment,
            check=True,
        )
        core_objects.append(str(platform_object))
    module_sources = [
        str(p)
        for p in sorted((ROOT / "native/netd").glob("*.cpp"))
        if p.name not in ("binder_bridge.cpp", "platform_cache_list.cpp", "platform_legacy27.cpp")
    ]
    module_sources.extend(str(p) for p in sorted((ROOT / "native/broker").glob("*.cpp")))
    command = [
        str(compiler),
        f"--target={target}",
        "-std=c++17",
        "-O2",
        "-shared",
        "-fPIC",
        "-fvisibility=hidden",
        "-fno-exceptions",
        "-fno-rtti",
        "-static-libstdc++",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pthread",
        "-I",
        str(output),
        "-I",
        str(ROOT / "third_party/zygisk-next"),
        *module_sources,
        *core_objects,
        "-llog",
        "-ldl",
        "-o",
        str(library),
    ]
    subprocess.run(command, env=environment, check=True)
    aidl = ROOT / "third_party/aosp-dnsresolver-v1"
    generated = output / "aidl"
    (generated / "src").mkdir(parents=True, exist_ok=True)
    (generated / "include").mkdir(parents=True, exist_ok=True)
    definitions = [
        aidl / "android/net/IDnsResolver.aidl",
        aidl / "android/net/ResolverParamsParcel.aidl",
        aidl / "android/net/metrics/INetdEventListener.aidl",
    ]
    frozen_hash = (aidl / ".hash").read_text().strip()
    subprocess.run(
        [
            str(aidl_compiler),
            "--lang=ndk",
            "--structured",
            "--version=1",
            f"--hash={frozen_hash}",
            "--min_sdk_version=29",
            "-I",
            str(aidl),
            "-o",
            str(generated / "src"),
            "-h",
            str(generated / "include"),
            *[str(p) for p in definitions],
        ],
        env=environment,
        check=True,
    )
    bridge = output / "libae_resolver29.so"
    bridge_target = TARGETS[abi] + str(max(29, args.min_sdk))
    subprocess.run(
        [
            str(compiler),
            f"--target={bridge_target}",
            "-std=c++17",
            "-O2",
            "-shared",
            "-fPIC",
            "-fvisibility=hidden",
            "-fno-exceptions",
            "-fno-rtti",
            "-static-libstdc++",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(generated / "include"),
            "-I",
            str(ROOT / "third_party/binder-ndk-cpp"),
            str(ROOT / "native/netd/binder_bridge.cpp"),
            *[str(p) for p in sorted((generated / "src").rglob("*.cpp"))],
            "-lbinder_ndk",
            "-ldl",
            "-llog",
            "-o",
            str(bridge),
        ],
        env=environment,
        check=True,
    )
    return library, bridge


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--abi", choices=["all", *TARGETS], default="all")
    parser.add_argument("--abis", nargs="+", choices=list(TARGETS))
    parser.add_argument("--min-sdk", type=int, default=26)
    parser.add_argument("--work-directory", type=Path, default=ROOT / "build")
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--skip-package", action="store_true")
    parser.add_argument("--sdk", type=Path, required=True)
    args = parser.parse_args()
    environment = os.environ.copy()
    if args.min_sdk < 26:
        parser.error("The enhancement module requires API26+")
    abis = args.abis or (list(TARGETS) if args.abi == "all" else [args.abi])
    libraries = {abi: build_libraries(args, abi, environment) for abi in abis}
    if args.output_directory:
        for abi, files in libraries.items():
            directory = args.output_directory / abi
            directory.mkdir(parents=True, exist_ok=True)
            for library in files:
                shutil.copyfile(library, directory / library.name)
            shutil.copyfile(
                files[0].parent / "runtime-identity.prop", directory / "runtime-identity.prop"
            )
    if args.skip_package:
        print(args.output_directory or args.work_directory)
        return
    destination = ROOT / "dist"
    destination.mkdir(exist_ok=True)
    name = "asterisk-enhance"
    if args.abi != "all":
        name += "-" + args.abi
    archive = destination / (name + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
        for path in sorted((ROOT / "module").rglob("*")):
            if path.is_file():
                entry = path.relative_to(ROOT / "module").as_posix()
                if entry in ("customize.sh", "module.prop", "zn_modules.txt", "sepolicy.rule"):
                    data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                    package.writestr(entry, data)
                else:
                    package.write(path, entry)
        for abi, files in libraries.items():
            package.write(
                files[0].parent / "runtime-identity.prop", f"lib/{abi}/runtime-identity.prop"
            )
            for library in files:
                package.write(library, f"lib/{abi}/{library.name}")
    print(archive)


if __name__ == "__main__":
    main()
