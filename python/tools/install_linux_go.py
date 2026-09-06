"""Install the pinned Go toolchain inside a manylinux/musllinux build container."""

import hashlib
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request

VERSION = "1.24.13"
ARCHIVES = {
    "x86_64": (
        "amd64",
        "1fc94b57134d51669c72173ad5d49fd62afb0f1db9bf3f798fd98ee423f8d730",
    ),
    "aarch64": (
        "arm64",
        "74d97be1cc3a474129590c67ebf748a96e72d9f3a2b6fef3ed3275de591d49b3",
    ),
}


def main():
    arch, expected = ARCHIVES[platform.machine()]
    destination = Path("/opt/tlsprint-toolchain")
    destination.mkdir(parents=True, exist_ok=True)
    url = f"https://go.dev/dl/go{VERSION}.linux-{arch}.tar.gz"
    with tempfile.TemporaryDirectory() as temp:
        archive = Path(temp) / "go.tar.gz"
        urllib.request.urlretrieve(url, archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise RuntimeError("Go archive checksum mismatch")
        with tarfile.open(archive) as source:
            source.extractall(destination, filter="data")
    print(f"Installed Go {VERSION} for linux/{arch}")


if __name__ == "__main__":
    main()
