import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

import tlsprint


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = os.environ.get("TLSPRINT_TEST_SERVER")
        if not executable:
            raise RuntimeError(
                "Build native/testserver and set TLSPRINT_TEST_SERVER to its path"
            )
        cls.server = subprocess.Popen(
            [executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )
        cls.addClassCleanup(cls.stop_server)
        cls.urls = json.loads(cls.server.stdout.readline())
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.ca = Path(cls.temp.name) / "ca.pem"
        cls.ca.write_text(cls.urls["ca"])

    @classmethod
    def stop_server(cls):
        try:
            cls.server.communicate("\n", timeout=10)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.communicate()

    def test_all_presets_and_aliases(self):
        values = tlsprint.list_presets()
        self.assertEqual(len(values), 47)
        self.assertEqual(len({p["product"] for p in values}), 13)
        for value in values:
            self.assertEqual(tlsprint.get_preset(value["key"]), value)
            with tlsprint.Session(impersonate=value["key"]) as session:
                self.assertEqual(session.impersonate, value["key"])
        self.assertEqual(tlsprint.get_preset("chrome-142")["version"], "142")
        self.assertEqual(
            tlsprint.get_preset("chrome_142"), tlsprint.get_preset("chrome-142")
        )
        self.assertTrue(
            all(p["product"] == "chrome" for p in tlsprint.list_presets("chrome"))
        )
        # Compare the complete embedded registry to the checked-in source.
        root = Path(__file__).resolve().parents[1]
        source = root.parent / "preset/data/registry.json"
        if not source.exists():
            source = root / "native/core/preset/data/registry.json"
        expected = json.loads(source.read_text())["presets"]
        self.assertEqual({p["key"] for p in values}, {p["key"] for p in expected})
        for p in expected:
            actual = tlsprint.get_preset(p["key"])
            self.assertEqual(actual["tls"]["cipher_suites"], p["tls"]["cipher_suites"])
            self.assertEqual(actual["tls"]["extensions"], p["tls"]["extensions"])

    def test_query_headers_binary_and_forms(self):
        payload = bytes(range(256)) * 1024
        with tlsprint.Session(headers={"X-Test": "session"}) as session:
            response = session.post(
                self.urls["http"] + "/echo?old=yes",
                data=payload,
                params={"a": ["one", "two"], "unicode": "中文"},
                headers={"x-test": "request"},
            )
            data = response.json()
            self.assertEqual(base64.b64decode(data["body"]), payload)
            self.assertEqual(
                data["query"],
                {"old": ["yes"], "a": ["one", "two"], "unicode": ["中文"]},
            )
            self.assertEqual(data["headers"]["X-Test"], ["request"])
            data = session.post(self.urls["http"], data={"a": ["1", "2"]}).json()
            self.assertEqual(base64.b64decode(data["body"]), b"a=1&a=2")
            self.assertEqual(data["headers"]["X-Test"], ["session"])
            for value in ({"hello": "中文"}, None):
                data = session.post(self.urls["http"], json=value).json()
                self.assertEqual(json.loads(base64.b64decode(data["body"])), value)

    def test_response_and_compression(self):
        self.assertEqual(
            tlsprint.get(self.urls["http"] + "/binary").content, b"\x00\xff\x80\x00A"
        )
        response = tlsprint.get(self.urls["http"] + "/gzip")
        self.assertEqual(response.json(), {"message": "compressed"})
        self.assertEqual(response.headers["CONTENT-ENCODING"], "gzip")
        self.assertIn("compressed", response.text)
        self.assertGreater(response.elapsed.total_seconds(), 0)
        response = tlsprint.get(self.urls["http"] + "/status")
        self.assertFalse(response.ok)
        with self.assertRaises(tlsprint.HTTPError) as error:
            response.raise_for_status()
        self.assertIs(error.exception.response, response)

    def test_cookies_redirects_and_pooling(self):
        with tlsprint.Session() as session:
            response = session.get(self.urls["http"] + "/cookies")
            self.assertEqual(len(response.headers.get_list("set-cookie")), 2)
            initial = response.json()["remote"]
            response = session.get(self.urls["http"] + "/redirect")
            self.assertTrue(response.url.endswith("/echo"))
            self.assertEqual(response.json()["remote"], initial)
            self.assertIn("session=fixture", response.json()["headers"]["Cookie"][0])
        response = tlsprint.get(self.urls["http"] + "/redirect", allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        with tlsprint.Session(cookies=False) as session:
            session.get(self.urls["http"] + "/cookies")
            self.assertNotIn("Cookie", session.get(self.urls["http"]).json()["headers"])

    def test_tls_verification_and_protocols(self):
        with self.assertRaises(tlsprint.SSLError):
            tlsprint.get(self.urls["h2"])
        for name, protocol in (("h2", "HTTP/2.0"), ("h1", "HTTP/1.1")):
            with tlsprint.Session(verify=self.ca) as session:
                response = session.get(self.urls[name])
                self.assertEqual(response.http_version, protocol)
                self.assertEqual(
                    session.get(self.urls[name]).json()["remote"],
                    response.json()["remote"],
                )
        self.assertEqual(
            tlsprint.get(self.urls["h2"], verify=False, http_version="h1").http_version,
            "HTTP/1.1",
        )

    def test_timeouts_and_concurrency(self):
        with tlsprint.Session(timeout=0.02) as session:
            with self.assertRaises(tlsprint.Timeout):
                session.get(self.urls["http"] + "/slow?ms=200")
            self.assertEqual(
                session.get(self.urls["http"] + "/slow?ms=80", timeout=2).status_code,
                200,
            )
            self.assertEqual(
                session.get(
                    self.urls["http"] + "/slow?ms=80", timeout=None
                ).status_code,
                200,
            )
        with tlsprint.Session(verify=self.ca) as session:
            with ThreadPoolExecutor(max_workers=8) as pool:
                values = list(
                    pool.map(
                        lambda i: session.post(self.urls["h2"], json={"i": i}).json(),
                        range(40),
                    )
                )
            self.assertEqual(
                [json.loads(base64.b64decode(v["body"]))["i"] for v in values],
                list(range(40)),
            )

    def test_close_cancels_and_prevents_reuse(self):
        session = tlsprint.Session()
        with ThreadPoolExecutor() as pool:
            future = pool.submit(session.get, self.urls["http"] + "/slow?ms=5000")
            time.sleep(0.05)
            start = time.monotonic()
            session.close()
            self.assertLess(time.monotonic() - start, 2)
            with self.assertRaises((tlsprint.Cancelled, tlsprint.SessionClosed)):
                future.result(timeout=2)
        session.close()
        with self.assertRaises(tlsprint.SessionClosed):
            session.get(self.urls["http"])

    def test_proxy_and_proxy_timeout(self):
        before = tlsprint.get(self.urls["http"] + "/proxy-count").json()
        for target in ("http", "h2"):
            response = tlsprint.get(
                self.urls[target], proxy=self.urls["proxy"], verify=self.ca
            )
            self.assertEqual(response.status_code, 200)
        # A redirect from HTTPS to HTTP must continue to use the proxy.
        tlsprint.get(
            self.urls["h2"] + "/redirect",
            params={"to": self.urls["http"]},
            proxy=self.urls["proxy"],
            verify=self.ca,
        )
        after = tlsprint.get(self.urls["http"] + "/proxy-count").json()
        self.assertEqual(after - before, 4)
        start = time.monotonic()
        with self.assertRaises(tlsprint.Timeout):
            tlsprint.get(self.urls["h2"], proxy=self.urls["stall_proxy"], timeout=0.05)
        self.assertLess(time.monotonic() - start, 2)

    def test_wire_fingerprint(self):
        names = (
            "TLS_CHROME_141",
            "TLS_FIREFOX_145",
            "TLS_SAFARI_26_0_1_MACOS_18_3",
            "TLS_CURL_8_16_0",
            "TLS_EDGE_150_MACOS_10_15_7",
        )
        for name in names:
            with self.subTest(name=name):
                preset = tlsprint.get_preset(name)
                # localhost sends SNI for the fingerprint comparison. The
                # httptest certificate covers loopback IPs, not localhost;
                # certificate validation is exercised separately above.
                actual = tlsprint.get(
                    self.urls["capture"],
                    impersonate=name,
                    verify=False,
                    http_version="h2",
                ).json()
                tls = preset["tls"]

                def ids(values):
                    return "-".join(
                        str(v)
                        for v in values
                        if not (v & 0x0F0F == 0x0A0A and v >> 8 == v & 255)
                    )

                expected = ",".join(
                    (
                        str(tls["legacy_version"]),
                        ids(tls["cipher_suites"]),
                        ids(v for v in tls["extensions"] if v not in (41, 42)),
                        ids(tls["supported_groups"]),
                        ids(base64.b64decode(tls.get("ec_point_formats", ""))),
                    )
                )
                self.assertEqual(actual["ja3"], expected)
                self.assertEqual(actual["settings"], preset["http2"]["settings"])
                self.assertEqual(actual["window"], preset["http2"]["window_update"])
                self.assertEqual(
                    actual["pseudo"], preset["http2"]["pseudo_header_order"]
                )
                order = preset["headers"].get("order", [])
                self.assertEqual(
                    [h for h in actual["headers"] if h in order],
                    [h for h in order if h in actual["headers"]],
                )

    def test_invalid_arguments(self):
        for options in (
            {"impersonate": "missing"},
            {"proxy": "socks5://localhost:8080"},
            {"timeout": -1},
            {"timeout": float("nan")},
            {"verify": ""},
            {"http_version": "h3"},
        ):
            with (
                self.subTest(options=options),
                self.assertRaises(tlsprint.InvalidArgument),
            ):
                tlsprint.Session(**options)
        with tlsprint.Session() as session:
            with self.assertRaises(tlsprint.InvalidArgument):
                session.get("file:///tmp/nope")
            with self.assertRaises(tlsprint.InvalidArgument):
                session.post(self.urls["http"], data=b"x", json={})


if __name__ == "__main__":
    unittest.main()
