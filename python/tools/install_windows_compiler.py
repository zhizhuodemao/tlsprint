"""Install a checked LLVM-MinGW archive on a GitHub Windows runner."""

import hashlib
import os
from pathlib import Path
import platform
import tempfile
import urllib.request
import zipfile

RELEASE = "20260826"
ARCHIVES = {
    "AMD64": (
        "x86_64",
        "ae601f4e0f72bbdf441ad2df8bb16f037e2e9251559ea6b37b4057aef39c06c3",
    ),
    "ARM64": (
        "aarch64",
        "dbce5a314c44cf44d02ab0d0e6bce948955b46429274df25544f9cfea4986f7b",
    ),
}


def main():
    arch, expected = ARCHIVES[platform.machine().upper()]
    filename = f"llvm-mingw-{RELEASE}-ucrt-{arch}"
    destination = Path(os.environ["RUNNER_TEMP"]) / "tlsprint-toolchain"
    url = f"https://github.com/mstorsjo/llvm-mingw/releases/download/{RELEASE}/{filename}.zip"
    with tempfile.TemporaryDirectory() as temp:
        archive = Path(temp) / "compiler.zip"
        urllib.request.urlretrieve(url, archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise RuntimeError("LLVM-MinGW archive checksum mismatch")
        with zipfile.ZipFile(archive) as source:
            source.extractall(destination)
    binaries = destination / filename / "bin"
    compiler = binaries / f"{arch}-w64-mingw32-clang.exe"
    if not compiler.is_file():
        raise RuntimeError(f"Compiler missing from archive: {compiler}")
    with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as target:
        target.write(str(binaries) + "\n")
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as target:
        target.write(f"CC={compiler}\n")
    print(f"Installed LLVM-MinGW {RELEASE} for {arch}")


if __name__ == "__main__":
    main()
