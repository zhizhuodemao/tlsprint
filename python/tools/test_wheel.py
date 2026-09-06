"""Run the installed wheel's integration tests with build tools off PATH."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    package = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="tlsprint-wheel-test-") as temp:
        root = Path(temp)
        server = root / ("testserver.exe" if sys.platform == "win32" else "testserver")
        subprocess.run(
            ["go", "build", "-mod=readonly", "-o", str(server), "./testserver"],
            cwd=package / "native",
            env=dict(os.environ, CGO_ENABLED="0", GOWORK="off"),
            check=True,
        )
        empty_path = root / "no-build-tools"
        empty_path.mkdir()
        env = dict(os.environ, PATH=str(empty_path), TLSPRINT_TEST_SERVER=str(server))
        # Do not allow a caller's PYTHONPATH to shadow the wheel under test.
        env.pop("PYTHONPATH", None)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(package / "tests"),
                "-v",
            ],
            cwd=root,
            env=env,
            check=True,
        )


if __name__ == "__main__":
    main()
