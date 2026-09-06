"""Build a platform wheel, freezing the existing Go modules into each sdist."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

HERE = Path(__file__).resolve().parent
CORE_DIRS = ("client", "utls", "http2", "iana", "preset", "hello", "ja3", "ja4")


def freeze_core(destination):
    source = HERE / "native" / "core"
    if source.exists():
        shutil.copytree(source, destination, dirs_exist_ok=True)
        return
    source = HERE.parent
    if not (source / "profile.go").exists():
        raise RuntimeError("Go core sources are missing from this source distribution")
    for folder in ("", *CORE_DIRS):
        for path in (source / folder).rglob("*") if folder else source.iterdir():
            if not path.is_file():
                continue
            rel = path.relative_to(source)
            if any(p in {"examples", "testdata"} for p in rel.parts):
                continue
            if path.name.endswith("_test.go"):
                continue
            if path.suffix not in {".go", ".json"} and path.name not in {
                "go.mod",
                "go.sum",
                "LICENSE",
                "NOTICE",
                "README.md",
            }:
                continue
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def stage_native(destination):
    shutil.copytree(HERE / "native", destination, dirs_exist_ok=True)
    if not (destination / "core").exists():
        freeze_core(destination / "core")
    module = destination / "go.mod"
    module.write_text(module.read_text().replace("=> ../..", "=> ./core"))


class BuildPy(build_py):
    def run(self):
        super().run()
        if not shutil.which("go"):
            raise RuntimeError(
                "Building tlsprint-python from source requires Go >= 1.24 and a C compiler. "
                "Install a compatible prebuilt wheel to avoid build tools."
            )
        suffix = (
            ".dll"
            if sys.platform == "win32"
            else ".dylib"
            if sys.platform == "darwin"
            else ".so"
        )
        output = Path(self.build_lib).resolve() / "tlsprint" / ("_libtlsprint" + suffix)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="tlsprint-build-") as temp:
            native = Path(temp) / "native"
            stage_native(native)
            env = dict(os.environ, CGO_ENABLED="1", GOWORK="off")
            if sys.platform == "darwin":
                env.setdefault("MACOSX_DEPLOYMENT_TARGET", "11.0")
                minimum = "-mmacosx-version-min=" + env["MACOSX_DEPLOYMENT_TARGET"]
                # Include the target in cgo's flags so its cached objects use
                # the same minimum OS as the final shared library.
                for flag in ("CGO_CFLAGS", "CGO_LDFLAGS"):
                    env[flag] = env.get(flag, "-O2 -g") + " " + minimum
            subprocess.run(
                [
                    "go",
                    "build",
                    "-mod=readonly",
                    "-trimpath",
                    "-buildmode=c-shared",
                    "-ldflags=-s -w",
                    "-o",
                    str(output),
                    ".",
                ],
                cwd=native,
                env=env,
                check=True,
            )
        output.with_suffix(".h").unlink(missing_ok=True)


class Sdist(sdist):
    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        native = Path(base_dir) / "native"
        # setuptools may hard-link files; replace go.mod before rewriting it.
        module = native / "go.mod"
        content = module.read_text().replace("=> ../..", "=> ./core")
        module.unlink()
        module.write_text(content)
        freeze_core(native / "core")


class Wheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        _, _, platform = super().get_tag()
        return "py3", "none", platform


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


setup(
    distclass=BinaryDistribution,
    cmdclass={"build_py": BuildPy, "sdist": Sdist, "bdist_wheel": Wheel},
)
