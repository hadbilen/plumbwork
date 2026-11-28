#!/usr/bin/env python3
"""Hermetic tests for ADR-0018 Feature 2: skills/ui-refinery/scripts/check_ui_matrix.py."""

from __future__ import annotations

import builtins
import contextlib
import http.server
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401  # must precede repository imports per ADR-0010

SCRIPT_PATH = REPO_ROOT / "skills" / "ui-refinery" / "scripts" / "check_ui_matrix.py"


def _load_matrix_module():
    spec = importlib.util.spec_from_file_location("_test_check_ui_matrix", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_test_check_ui_matrix"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestAdr0018UiMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_matrix_module()

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="plumbwork_adr0018_matrix_")
        self.root = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_script_has_executable_bit_on_posix(self) -> None:
        if os.name != "nt":
            mode = stat.S_IMODE(SCRIPT_PATH.stat().st_mode)
            self.assertTrue(bool(mode & 0o111), f"Expected executable mode on {SCRIPT_PATH}, got {oct(mode)}")

    def test_all_11_checks_clean_vs_seeded_broken_and_weak_snapshots_and_desktop_gating(self) -> None:
        clean_snap = {
            "viewport": "mobile-390x844",
            "touch": True,
            "viewportWidth": 390,
            "viewportHeight": 844,
            "scrollWidth": 390,
            "textLen": 140,
            "visibleMediaCount": 0,  # text-only must NOT be blank (tests `and` vs `or`)
            "viewportMeta": "width=device-width, initial-scale=1",
            "interactiveControls": [
                {"id": 1, "sel": "button#ok", "x": 16, "y": 100, "width": 120, "height": 48, "ancestorIds": []},
                # 10% overlap (< 15% threshold) must NOT flag overlap
                {"id": 2, "sel": "button#near", "x": 124, "y": 100, "width": 120, "height": 48, "ancestorIds": []},
                # Child input inside parent label must NOT count as overlap
                {"id": 3, "sel": "label#wrap", "x": 16, "y": 200, "width": 200, "height": 48, "ancestorIds": []},
                {"id": 4, "sel": "input#field", "x": 20, "y": 204, "width": 180, "height": 40, "ancestorIds": [3]},
            ],
        }
        media_only_snap = {
            "viewport": "desktop-canvas",
            "touch": False,
            "viewportWidth": 1440,
            "viewportHeight": 900,
            "scrollWidth": 1440,
            "textLen": 0,
            "visibleMediaCount": 1,  # media-only must NOT be blank
            "viewportMeta": None,    # touch=False must ignore missing viewportMeta
            "tinyTap": [{"sel": "button.small", "width": 20, "height": 20}],  # touch=False must ignore tinyTap
        }
        clean_rep = self.mod.evaluate_matrix_report([clean_snap, media_only_snap], fail_on="weak")
        self.assertTrue(clean_rep["ok"], clean_rep)
        self.assertEqual(clean_rep["counts"], {"broken": 0, "weak": 0})

        # Seeded snapshots triggering all 11 checks + ARIA role="button" truncation + distinct missing vs malformed viewportMeta
        seeded_snaps = [
            {
                "viewport": "mobile-blank",
                "touch": True,
                "viewportWidth": 390,
                "viewportHeight": 844,
                "scrollWidth": 390,
                "textLen": 0,
                "visibleMediaCount": 0,
                "viewportMeta": None,
            },
            {
                "viewport": "mobile-defects",
                "touch": True,
                "viewportWidth": 390,
                "viewportHeight": 844,
                "scrollWidth": 450,
                "textLen": 80,
                "visibleMediaCount": 1,
                "viewportMeta": "initial-scale=1",
                "offscreen": [{"sel": ".hero-card", "over": 24, "side": "right"}],
                "truncated": [
                    {"sel": "div.cta", "tag": "div", "role": "button", "by": 18},
                    {"sel": "span.caption", "tag": "span", "role": "", "by": 12},
                ],
                "spill": [
                    {"sel": "p.wide", "by": 10},
                    {"sel": "p.tight", "by": 3},
                ],
                "brokenImages": [{"sel": "img#logo", "src": "/missing.png"}],
                "consoleErrors": ["TypeError: undefined is not a function"],
                "tinyTap": [{"sel": "a.icon", "width": 24, "height": 24}],
                "tinyText": [{"sel": "small.note", "fontSize": 9.5}],
                "interactiveControls": [
                    {"id": 10, "sel": "button#a", "x": 10, "y": 10, "width": 60, "height": 44, "ancestorIds": []},
                    {"id": 11, "sel": "button#b", "x": 40, "y": 10, "width": 60, "height": 44, "ancestorIds": []},
                ],
            },
        ]
        rep = self.mod.evaluate_matrix_report(seeded_snaps, fail_on="broken")
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["counts"], {"broken": 7, "weak": 7})
        found_checks = {item["check"] for item in rep["findings"]}
        self.assertEqual(found_checks, set(self.mod.CHECK_NAMES))

        vp_meta_findings = [f for f in rep["findings"] if f["check"] == "viewportMeta"]
        self.assertEqual(len(vp_meta_findings), 2)
        self.assertTrue(any("Missing" in f["detail"] for f in vp_meta_findings))
        self.assertTrue(any("device-width" in f["detail"] for f in vp_meta_findings))

        snap_file = self.root / "snap.json"
        snap_file.write_text(json.dumps({"viewports": seeded_snaps}), encoding="utf-8")
        proc_bad = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--from-json", str(snap_file), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_bad.returncode, 1, proc_bad.stdout + proc_bad.stderr)
        self.assertEqual(json.loads(proc_bad.stdout)["counts"], {"broken": 7, "weak": 7})

        weak_only = dict(clean_snap)
        weak_only["tinyText"] = [{"sel": "small.fine", "fontSize": 10}]
        weak_file = self.root / "weak.json"
        weak_file.write_text(json.dumps([weak_only]), encoding="utf-8")
        self.assertEqual(self.mod.main(["--from-json", str(weak_file), "--fail-on", "broken"]), 0)
        self.assertEqual(self.mod.main(["--from-json", str(weak_file), "--fail-on", "weak"]), 1)

    def test_ssrf_guard_pinned_redirect_and_route_interceptor(self) -> None:
        url, is_lb, _ = self.mod.validate_url("http://127.0.0.1:5173/app")
        self.assertTrue(is_lb)
        self.assertEqual(url, "http://127.0.0.1:5173/app")

        with self.assertRaises(self.mod.MatrixError) as cm:
            self.mod.validate_url("https://example.com/")
        self.assertEqual(cm.exception.code, "SSRF_BLOCKED")

        # Exact porter/net.py parity: block IPv4-compatible, IPv4-translated, Teredo, 6to4, site-local, 6to4-relay, CGNAT, port 0, malformed ports
        for bad in (
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://user:pass@93.184.216.34/",
            "http://93.184.216.34:0/",
            "http://93.184.216.34:99999/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://192.88.99.1/",
            "http://0.0.0.0/",
            "http://[::127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:0:127.0.0.1]/",
            "http://[fe80::1]/",
            "http://[fec0::1]/",
            "http://[fc00::1]/",
            "http://[2001:0000:7f00:0001:0000:0000:fefe:fefe]/",
            "http://[2002:0101:0101::1]/",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(self.mod.MatrixError) as exc_ctx:
                    self.mod.validate_url(bad, allow_remote=True, forbid_loopback=True)
                self.assertEqual(exc_ctx.exception.code, "SSRF_BLOCKED")

        # DNS rebinding returning any private IP fails closed
        def fake_rebind_resolver(_h: str, _p: int):
            return [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("169.254.169.254", 443))]

        with self.assertRaises(self.mod.MatrixError) as exc_dns:
            self.mod.validate_url("https://rebind.example/", allow_remote=True, resolver=fake_rebind_resolver)
        self.assertEqual(exc_dns.exception.code, "SSRF_BLOCKED")

        # Route interceptor: remote mode uses pinned fetcher (route.fulfill) and NEVER route.continue_; local mode with allow_remote=True still blocks external URLs
        aborted = []
        continued = []
        fulfilled = []

        class _FakeRoute:
            def __init__(self, req_url: str) -> None:
                self.request = type("Req", (), {"url": req_url, "method": "GET", "headers": {}, "post_data_buffer": None})()

            def abort(self, reason: str = "") -> None:
                aborted.append((self.request.url, reason))

            def continue_(self) -> None:
                continued.append(self.request.url)

            def fulfill(self, **kwargs) -> None:
                fulfilled.append((self.request.url, kwargs["status"], kwargs["body"]))

        def _fake_fetcher(req_url: str, **_kw):
            if "169.254.169.254" in req_url or "127.0.0.1" in req_url:
                raise self.mod.MatrixError("SSRF_BLOCKED", "blocked")
            return 200, {"Content-Type": "text/plain"}, b"ok"

        remote_ic = self.mod.make_route_interceptor(
            allow_remote=True, target_is_loopback=False, remote_fetcher=_fake_fetcher
        )
        remote_ic(_FakeRoute("https://example.com/app.js"))
        remote_ic(_FakeRoute("http://127.0.0.1:8080/internal"))
        remote_ic(_FakeRoute("http://169.254.169.254/latest/meta-data/"))
        remote_ic(_FakeRoute("http://127.0.0.1:99999/malformed"))
        self.assertEqual(continued, [])
        self.assertEqual(fulfilled, [("https://example.com/app.js", 200, b"ok")])
        self.assertEqual(len(aborted), 3)
        self.assertTrue(all(r == "blockedbyclient" for _, r in aborted))

        # Local target with allow_remote=True must STILL abort external URLs and enforce session prefix + strict 127.0.0.1
        aborted.clear()
        continued.clear()
        local_ic = self.mod.make_route_interceptor(
            allow_remote=True,
            target_is_loopback=True,
            expected_loopback_port=54321,
            strict_ipv4_loopback=True,
            required_path_prefix="/tok123/",
        )
        local_ic(_FakeRoute("http://127.0.0.1:54321/tok123/index.html"))
        local_ic(_FakeRoute("http://localhost:54321/tok123/index.html"))
        local_ic(_FakeRoute("http://127.0.0.1:54321/wrong/index.html"))
        local_ic(_FakeRoute("https://example.com/exfil.js"))
        self.assertEqual(continued, ["http://127.0.0.1:54321/tok123/index.html"])
        self.assertEqual(len(aborted), 3)

        # Pinned fetcher blocks 302 redirect targeting 169.254.169.254!
        class _RedirectHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args):  # noqa: A002
                return

            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.end_headers()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            # Mock validate_url to allow hop 0 onto our local test server, then enforce real validate_url on redirect hop 1!
            real_validate = self.mod.validate_url

            def _allow_hop0(u: str, **kw):
                if u.startswith("http://public.test:"):
                    return u, False, ["127.0.0.1"]
                return real_validate(u, **kw)

            with mock.patch.object(self.mod, "validate_url", side_effect=_allow_hop0):
                with self.assertRaises(self.mod.MatrixError) as redir_err:
                    self.mod.fetch_pinned_remote(f"http://public.test:{port}/start")
                self.assertEqual(redir_err.exception.code, "SSRF_BLOCKED")
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(timeout=2.0)

    def test_hardened_local_html_server_blocks_dotfiles_dir_listing_host_prefix_symlinks_and_fifo(self) -> None:
        html = self.root / "index.html"
        html.write_text("<!doctype html><html><body><h1>Hi</h1></body></html>\n", encoding="utf-8")
        (self.root / ".env").write_text("SECRET=1\n", encoding="utf-8")
        sub = self.root / "sub"
        sub.mkdir()
        (sub / ".env").write_text("NESTED=1\n", encoding="utf-8")
        outside = self.root.parent / f"{self.root.name}_secret.txt"
        outside.write_text("TOP_SECRET\n", encoding="utf-8")
        symlink_ok = False
        if hasattr(os, "symlink"):
            try:
                os.symlink(outside, self.root / "leak.txt")
                symlink_ok = True
            except (OSError, NotImplementedError):
                symlink_ok = False
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "pipe.txt")

        try:
            with self.mod._HardenedLocalHtmlServer(html) as (entry_url, port, prefix):
                with urllib.request.urlopen(entry_url, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn(b"<h1>Hi</h1>", resp.read())

                # Wrong Host header rejected (403)
                req_bad_host = urllib.request.Request(entry_url, headers={"Host": f"evil.local:{port}"})
                with self.assertRaises(urllib.error.HTTPError) as herr_host:
                    urllib.request.urlopen(req_bad_host, timeout=5)
                self.assertEqual(herr_host.exception.code, 403)
                herr_host.exception.close()

                # Missing prefix, dotfiles, nested dotfile, %2e%2e traversal, backslash, dirs, symlink, FIFO -> 403
                blocked = [
                    "/index.html",
                    f"{prefix}.env",
                    f"{prefix}sub/.env",
                    f"{prefix}%2e%2e/secret.txt",
                    f"{prefix}sub%5cindex.html",
                    prefix,
                    f"{prefix}sub",
                ]
                if symlink_ok:
                    blocked.append(f"{prefix}leak.txt")
                if hasattr(os, "mkfifo"):
                    blocked.append(f"{prefix}pipe.txt")
                for rel in blocked:
                    with self.subTest(rel=rel):
                        with self.assertRaises(urllib.error.HTTPError) as http_err:
                            urllib.request.urlopen(f"http://127.0.0.1:{port}{rel}", timeout=5)
                        self.assertEqual(http_err.exception.code, 403)
                        http_err.exception.close()
        finally:
            outside.unlink(missing_ok=True)

    def test_cli_from_json_edge_cases_parse_viewports_missing_playwright_and_stubbed_driver(self) -> None:
        # parse_viewports positive & negative
        vps = self.mod.parse_viewports("390x844:touch,1440x900:desktop")
        self.assertEqual(len(vps), 2)
        self.assertTrue(vps[0]["touch"])
        self.assertFalse(vps[1]["touch"])
        with self.assertRaises(self.mod.MatrixError):
            self.mod.parse_viewports("50x50")

        # --from-json edge cases: empty list, scalar JSON, non-dict elements -> exit 2 TARGET_INVALID
        for label, body in (("empty", "[]"), ("empty_wrap", '{"viewports": []}'), ("scalar", "123"), ("bad_item", '["x"]')):
            with self.subTest(label=label):
                p = self.root / f"{label}.json"
                p.write_text(body, encoding="utf-8")
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = self.mod.main(["--from-json", str(p), "--json"])
                self.assertEqual(rc, 2)
                self.assertEqual(json.loads(buf.getvalue())["error_code"], "TARGET_INVALID")

        # main() with missing Playwright -> exit 2 JSON PLAYWRIGHT_MISSING (mentions check_ui_slop.py & plumb-guard ui-slop)
        html = self.root / "index.html"
        html.write_text("<!doctype html><html><body><p>Hello</p></body></html>\n", encoding="utf-8")
        real_import = builtins.__import__

        def _block_playwright(name, *args, **kwargs):
            if name == "playwright" or name.startswith("playwright."):
                raise ImportError("No module named 'playwright'")
            return real_import(name, *args, **kwargs)

        buf = io.StringIO()
        with mock.patch.object(builtins, "__import__", side_effect=_block_playwright), contextlib.redirect_stdout(buf):
            rc = self.mod.main([str(html), "--json"])
        self.assertEqual(rc, 2)
        err_obj = json.loads(buf.getvalue())
        self.assertEqual(err_obj["error_code"], "PLAYWRIGHT_MISSING")
        self.assertIn("check_ui_slop.py", err_obj["error"])
        self.assertIn("plumb-guard ui-slop", err_obj["error"])

        # Stubbed playwright.sync_api verifies context.route, route_web_socket, service_workers="block", and TimeoutError -> exit 2
        recorded = {"context_kwargs": None, "routed": [], "ws_routed": False, "goto_url": None}

        class _FakeTimeoutError(Exception):
            pass

        class _FakePage:
            def on(self, _ev, _cb):
                pass

            def goto(self, url, **_kw):
                recorded["goto_url"] = url
                if recorded.get("raise_timeout"):
                    raise _FakeTimeoutError("nav timed out")

            def wait_for_timeout(self, _ms):
                pass

            def evaluate(self, _js, _args):
                return {
                    "viewportWidth": 390,
                    "viewportHeight": 844,
                    "scrollWidth": 390,
                    "textLen": 10,
                    "visibleMediaCount": 0,
                    "viewportMeta": "width=device-width",
                }

        class _FakeContext:
            def route(self, pat, _cb):
                recorded["routed"].append(pat)

            def route_web_socket(self, _pat, _cb):
                recorded["ws_routed"] = True

            def new_page(self):
                return _FakePage()

            def close(self):
                pass

        class _FakeBrowser:
            def new_context(self, **kw):
                recorded["context_kwargs"] = kw
                return _FakeContext()

            def close(self):
                pass

        class _FakePW:
            def __enter__(self):
                return type("P", (), {"chromium": type("C", (), {"launch": lambda *_a, **_k: _FakeBrowser()})()})()

            def __exit__(self, *_a):
                pass

        fake_pw_pkg = types.ModuleType("playwright")
        fake_sync_mod = types.ModuleType("playwright.sync_api")
        fake_sync_mod.sync_playwright = lambda: _FakePW()  # type: ignore[attr-defined]

        with mock.patch.dict(sys.modules, {"playwright": fake_pw_pkg, "playwright.sync_api": fake_sync_mod}):
            buf_ok = io.StringIO()
            with contextlib.redirect_stdout(buf_ok):
                rc_ok = self.mod.main([str(html), "--viewports", "390x844:touch", "--json"])
            self.assertEqual(rc_ok, 0, buf_ok.getvalue())
            self.assertEqual(recorded["routed"], ["**/*"])
            self.assertTrue(recorded["ws_routed"])
            self.assertEqual(recorded["context_kwargs"]["service_workers"], "block")
            self.assertTrue(recorded["goto_url"].startswith("http://127.0.0.1:"))

            # Timeout inside Playwright converts cleanly to exit 2 + NAVIGATION_TIMEOUT
            recorded["raise_timeout"] = True
            buf_to = io.StringIO()
            with contextlib.redirect_stdout(buf_to):
                rc_to = self.mod.main([str(html), "--viewports", "390x844:touch", "--json"])
            self.assertEqual(rc_to, 2)
            self.assertEqual(json.loads(buf_to.getvalue())["error_code"], "NAVIGATION_TIMEOUT")


if __name__ == "__main__":
    unittest.main()
