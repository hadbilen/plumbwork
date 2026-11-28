#!/usr/bin/env python3
"""
skills/ui-refinery/scripts/check_ui_matrix.py — Optional Playwright Multi-Viewport DOM Matrix Checker
Part of Plumbwork (https://github.com/tozhax/plumbwork)
Zero mandatory dependencies: pure Python stdlib evaluator; live browser capture requires optional
Python `playwright` (`playwright.sync_api`). Never auto-installs packages (`GEMINI.md` Rule 12).

Check taxonomy inspired by DeadInternetStudios/100x-engineer-skill (MIT License), implemented from
scratch in Python with strict SSRF routing guards, pinned-socket remote fetching (re-validating
every HTTP 3xx redirect hop), and a session-token-hardened ephemeral local HTML server.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
import ssl
import stat
import sys
import threading
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

CHECK_NAMES: Tuple[str, ...] = (
    "blank",
    "overflowX",
    "offscreen",
    "truncated",
    "spill",
    "brokenImage",
    "consoleErrors",
    "tinyTap",
    "tinyText",
    "overlap",
    "viewportMeta",
)
_CHECK_NAMES_SET = frozenset(CHECK_NAMES)

PRIMARY_TRUNCATION_TAGS = frozenset({"h1", "h2", "h3", "button", "a", "nav"})
PRIMARY_TRUNCATION_ROLES = frozenset({"button", "tab", "link", "heading"})

DEFAULT_VIEWPORTS: Tuple[Dict[str, Any], ...] = (
    {"name": "mobile-390x844", "width": 390, "height": 844, "touch": True},
    {"name": "mobile-landscape-844x390", "width": 844, "height": 390, "touch": True},
    {"name": "tablet-768x1024", "width": 768, "height": 1024, "touch": True},
    {"name": "laptop-1024x768", "width": 1024, "height": 768, "touch": False},
    {"name": "desktop-1440x900", "width": 1440, "height": 900, "touch": False},
)

DEFAULT_MIN_TAP = 44
DEFAULT_MIN_FONT = 12
DEFAULT_OVERLAP_RATIO = 0.15
DEFAULT_TIMEOUT_MS = 15000
DEFAULT_SETTLE_MS = 300
MAX_SERVED_FILE_BYTES = 25 * 1024 * 1024  # 25 MiB
MAX_REMOTE_REDIRECTS = 5

# Exact standalone parity with porter/net.py blocked ranges (no harness runtime import needed).
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 relay anycast
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/96"),           # IPv4-compatible IPv6 (deprecated)
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::ffff:0:0:0/96"), # IPv4-translated IPv6
    ipaddress.ip_network("64:ff9b::/96"),    # NAT64
    ipaddress.ip_network("64:ff9b:1::/48"),  # Local NAT64
    ipaddress.ip_network("2001::/32"),       # Teredo (blocked outright)
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("2002::/16"),       # 6to4 (blocked outright)
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fec0::/10"),       # Deprecated site-local
    ipaddress.ip_network("ff00::/8"),
)

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
})

JS_COLLECT_SNAPSHOT = r"""
({ touch, minTap, minFont }) => {
  const vw = document.documentElement.clientWidth || window.innerWidth;
  const vh = document.documentElement.clientHeight || window.innerHeight;
  const scrollWidth = Math.max(
    document.documentElement.scrollWidth || 0,
    document.body ? document.body.scrollWidth || 0 : 0
  );
  const bodyText = (document.body ? document.body.innerText || "" : "").trim();
  const isVisible = (el) => {
    const s = window.getComputedStyle(el);
    if (!s || s.display === "none" || s.visibility === "hidden" || parseFloat(s.opacity || "1") === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const selOf = (el) => {
    if (!el || !el.tagName) return "";
    const id = el.id ? "#" + el.id : "";
    const cls = typeof el.className === "string" && el.className.trim()
      ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".")
      : "";
    return (el.tagName.toLowerCase() + id + cls).slice(0, 80);
  };

  let visibleMediaCount = 0;
  const brokenImages = [];
  for (const el of document.querySelectorAll("img, svg, canvas, video")) {
    if (isVisible(el)) visibleMediaCount += 1;
    if (el.tagName.toLowerCase() === "img" && el.complete && el.naturalWidth === 0) {
      brokenImages.push({ sel: selOf(el), src: (el.currentSrc || el.src || "").slice(-80) });
    }
  }

  const allEls = Array.from(document.querySelectorAll("body *")).slice(0, 1000);
  const offscreen = [];
  const truncated = [];
  const spill = [];
  const tinyTap = [];
  const tinyText = [];
  const interactiveControls = [];
  const idMap = new WeakMap();
  let nextId = 1;
  const getId = (el) => {
    if (!idMap.has(el)) idMap.set(el, nextId++);
    return idMap.get(el);
  };

  const interactiveSel = 'a[href], button, input:not([type="hidden"]), select, textarea, [role="button"], [role="tab"], [role="link"]';
  const interactiveSet = new Set(document.querySelectorAll(interactiveSel));

  for (const el of allEls) {
    if (!isVisible(el)) continue;
    const r = el.getBoundingClientRect();
    const s = window.getComputedStyle(el);
    const tag = el.tagName.toLowerCase();
    const role = (el.getAttribute("role") || "").toLowerCase();
    const sel = selOf(el);
    const txt = (el.innerText || "").trim().slice(0, 60);

    if (r.right > vw + 2) offscreen.push({ sel, over: Math.round(r.right - vw), side: "right", text: txt });
    else if (r.left < -2) offscreen.push({ sel, over: Math.round(-r.left), side: "left", text: txt });

    if (el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0) {
      const ovx = s.overflowX;
      if (ovx === "hidden" || ovx === "clip") {
        truncated.push({ sel, tag, role, by: Math.round(el.scrollWidth - el.clientWidth), text: txt });
      } else if (ovx === "visible" && txt.length > 0) {
        spill.push({ sel, by: Math.round(el.scrollWidth - el.clientWidth), text: txt });
      }
    }

    const fontSize = parseFloat(s.fontSize || "0");
    const hasDirectText = Array.from(el.childNodes).some((n) => n.nodeType === 3 && (n.textContent || "").trim().length > 0);
    if (hasDirectText && fontSize > 0 && fontSize < minFont) {
      tinyText.push({ sel, fontSize: Math.round(fontSize * 10) / 10, text: txt });
    }

    if (interactiveSet.has(el)) {
      if (touch && (r.width < minTap || r.height < minTap)) {
        tinyTap.push({ sel, width: Math.round(r.width), height: Math.round(r.height), text: txt });
      }
      if (interactiveControls.length < 250) {
        const ancestors = [];
        let cur = el.parentElement;
        while (cur) {
          if (idMap.has(cur)) ancestors.push(idMap.get(cur));
          cur = cur.parentElement;
        }
        interactiveControls.push({
          id: getId(el),
          sel,
          x: r.left,
          y: r.top,
          width: r.width,
          height: r.height,
          ancestorIds: ancestors,
        });
      }
    }
  }

  const vpMetaEl = document.querySelector('meta[name="viewport"]');
  const viewportMeta = vpMetaEl ? (vpMetaEl.getAttribute("content") || "") : null;

  return {
    viewportWidth: vw,
    viewportHeight: vh,
    scrollWidth,
    textLen: bodyText.length,
    visibleMediaCount,
    viewportMeta,
    offscreen: offscreen.slice(0, 20),
    truncated: truncated.slice(0, 20),
    spill: spill.slice(0, 20),
    brokenImages: brokenImages.slice(0, 20),
    tinyTap: tinyTap.slice(0, 20),
    tinyText: tinyText.slice(0, 20),
    interactiveControls,
  };
}
"""


class MatrixError(Exception):
    """Structured exit-2 operational error with machine-readable error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class MatrixFinding:
    viewport: str
    check: str
    severity: str  # "broken" | "weak"
    selector: str
    detail: str

    def __post_init__(self) -> None:
        if self.check not in _CHECK_NAMES_SET:
            raise ValueError(f"Unknown UI matrix check name: {self.check!r}")


def _read_regular_file_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Opens a regular non-symlink file with `O_NOFOLLOW | O_NONBLOCK` and enforces `max_bytes`."""
    if os.path.islink(path):
        raise MatrixError("TARGET_INVALID", f"Refusing symlinked {label}: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(os.fspath(path), flags)
    except FileNotFoundError as exc:
        raise MatrixError("TARGET_INVALID", f"{label} not found: {path}") from exc
    except OSError as exc:
        raise MatrixError("TARGET_INVALID", f"Cannot safely open {label} ({path}): {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise MatrixError("TARGET_INVALID", f"Refusing non-regular {label} (directory/FIFO/device): {path}")
        if st.st_size > max_bytes:
            raise MatrixError("TARGET_INVALID", f"{label} exceeds {max_bytes} bytes: {path}")
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise MatrixError("TARGET_INVALID", f"{label} exceeded {max_bytes} bytes while reading: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise MatrixError("TARGET_INVALID", f"Failed reading {label} ({path}): {exc}") from exc
    finally:
        os.close(fd)


def is_public_ip(addr: Any) -> bool:
    """
    Returns True only when `addr` is globally routable (matching `porter/net.py:_address_allowed`).
    Checks `_EXTRA_BLOCKED_NETWORKS` before IPv6 unwrapping so 6to4 (`2002::/16`), Teredo (`2001::/32`),
    IPv4-compatible (`::/96`), IPv4-translated (`::ffff:0:0:0/96`), and site-local (`fec0::/10`) are
    rejected outright, while IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is validated via its inner IPv4.
    """
    ip = addr if isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(addr))
    for net in _EXTRA_BLOCKED_NETWORKS:
        if ip.version == net.version and ip in net:
            return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_public_ip(ip.ipv4_mapped)
    return bool(ip.is_global and not ip.is_multicast)


def is_loopback_host(host: str) -> bool:
    return (host or "").strip().lower().rstrip(".") in _LOOPBACK_HOSTS


def validate_url(
    url: str,
    *,
    allow_remote: bool = False,
    forbid_loopback: bool = False,
    expected_loopback_port: Optional[int] = None,
    strict_ipv4_loopback: bool = False,
    required_path_prefix: Optional[str] = None,
    resolver: Optional[Callable[[str, int], Iterable[Any]]] = None,
) -> Tuple[str, bool, List[str]]:
    """
    Validates a URL against scheme and SSRF policy.
    Returns `(normalized_url, is_loopback, resolved_ips)` or raises `MatrixError("SSRF_BLOCKED", ...)`.
    """
    try:
        parsed = urllib.parse.urlparse((url or "").strip())
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        explicit_port = parsed.port
    except ValueError as exc:
        raise MatrixError("SSRF_BLOCKED", f"Malformed URL rejected ({url!r}): {exc}") from exc

    if scheme not in ("http", "https"):
        raise MatrixError("SSRF_BLOCKED", f"Disallowed URL scheme {scheme!r}; only http/https are permitted.")
    if parsed.username or parsed.password:
        raise MatrixError("SSRF_BLOCKED", "URLs with embedded credentials are prohibited.")
    if not host:
        raise MatrixError("SSRF_BLOCKED", f"URL has no host: {url!r}")
    if explicit_port is not None and explicit_port == 0:
        raise MatrixError("SSRF_BLOCKED", "Port 0 is prohibited.")
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)

    if is_loopback_host(host):
        if forbid_loopback:
            raise MatrixError("SSRF_BLOCKED", f"Loopback subresource blocked during remote audit: {url!r}")
        if strict_ipv4_loopback and (scheme != "http" or host != "127.0.0.1"):
            raise MatrixError(
                "SSRF_BLOCKED",
                f"Local HTML audit restricts requests strictly to http://127.0.0.1; refused {scheme}://{host}.",
            )
        if expected_loopback_port is not None and port != expected_loopback_port:
            raise MatrixError(
                "SSRF_BLOCKED",
                f"Local HTML audit restricts requests to loopback port {expected_loopback_port}; refused port {port}.",
            )
        if required_path_prefix is not None and not (parsed.path or "").startswith(required_path_prefix):
            raise MatrixError("SSRF_BLOCKED", "Local HTML request missing required per-session path token.")
        return url, True, [host]

    if not allow_remote:
        raise MatrixError(
            "SSRF_BLOCKED",
            f"Non-loopback host {host!r} is blocked by default; pass --allow-remote to inspect public hosts.",
        )

    try:
        lit_ip = ipaddress.ip_address(host)
    except ValueError:
        lit_ip = None

    if lit_ip is not None:
        if not is_public_ip(lit_ip):
            raise MatrixError("SSRF_BLOCKED", f"Non-public IP address blocked: {lit_ip}")
        return url, False, [str(lit_ip)]

    resolve_fn = resolver or (lambda h, p: socket.getaddrinfo(h, p, type=socket.SOCK_STREAM))
    try:
        infos = list(resolve_fn(host, port))
    except OSError as exc:
        raise MatrixError("SSRF_BLOCKED", f"DNS resolution failed for {host!r}: {exc}") from exc
    if not infos:
        raise MatrixError("SSRF_BLOCKED", f"DNS returned no addresses for {host!r}")
    resolved_ips: List[str] = []
    for info in infos:
        sockaddr = info[4]
        raw_ip = str(sockaddr[0]).split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise MatrixError("SSRF_BLOCKED", f"Invalid resolved IP {raw_ip!r} for {host!r}") from exc
        if not is_public_ip(ip_obj):
            raise MatrixError("SSRF_BLOCKED", f"Host {host!r} resolved to non-public IP {ip_obj}")
        ip_str = str(ip_obj)
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)
    return url, False, resolved_ips


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, *, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, *, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw_sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            raw_sock.close()
            raise


def fetch_pinned_remote(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout_sec: float = 15.0,
    max_redirects: int = MAX_REMOTE_REDIRECTS,
    resolver: Optional[Callable[[str, int], Iterable[Any]]] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    """
    Fetches a public HTTP/HTTPS URL over a DNS-pinned socket, re-validating every HTTP 3xx
    redirect hop against `validate_url(..., allow_remote=True, forbid_loopback=True)`.
    """
    cur_url = url
    cur_method = (method or "GET").upper()
    cur_body = body
    req_headers = {
        k: v for k, v in (headers or {}).items()
        if k.lower() not in _HOP_BY_HOP_HEADERS and k.lower() != "host"
    }

    for _hop in range(max_redirects + 1):
        _, _, ips = validate_url(cur_url, allow_remote=True, forbid_loopback=True, resolver=resolver)
        parsed = urllib.parse.urlparse(cur_url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
        path_q = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        pinned_ip = ips[0]

        conn: http.client.HTTPConnection
        if scheme == "https":
            conn = _PinnedHTTPSConnection(host, port, pinned_ip=pinned_ip, timeout=timeout_sec)
        else:
            conn = _PinnedHTTPConnection(host, port, pinned_ip=pinned_ip, timeout=timeout_sec)

        try:
            conn.request(cur_method, path_q, body=cur_body, headers=req_headers)
            resp = conn.getresponse()
            status = int(resp.status)
            resp_headers = {k: v for k, v in resp.getheaders() if k.lower() not in _HOP_BY_HOP_HEADERS}
            if status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                resp.read(4096)
                if not loc:
                    return status, resp_headers, b""
                cur_url = urllib.parse.urljoin(cur_url, loc)
                if status in (301, 302, 303):
                    cur_method = "GET"
                    cur_body = None
                continue

            chunks: List[bytes] = []
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SERVED_FILE_BYTES:
                    raise MatrixError("SSRF_BLOCKED", f"Remote response exceeded {MAX_SERVED_FILE_BYTES} bytes: {cur_url}")
                chunks.append(chunk)
            return status, resp_headers, b"".join(chunks)
        except MatrixError:
            raise
        except OSError as exc:
            raise MatrixError("BROWSER_ERROR", f"Pinned fetch failed for {cur_url!r}: {exc}") from exc
        finally:
            conn.close()

    raise MatrixError("SSRF_BLOCKED", f"Too many HTTP redirects (> {max_redirects}) for {url!r}")


def _safe_resolve_local_path(base_dir: Path, req_path: str, *, session_prefix: str = "") -> Optional[List[str]]:
    """
    Validates a local server URL path: requires `session_prefix` when set, refuses dotfiles,
    `..`, backslashes, and NULs, and returns safe relative path segments.
    """
    raw_path = req_path.split("?", 1)[0].split("#", 1)[0]
    if session_prefix:
        if not raw_path.startswith(session_prefix):
            return None
        raw_path = raw_path[len(session_prefix):]
    raw = urllib.parse.unquote(raw_path)
    rel = raw.lstrip("/")
    if not rel or "\x00" in rel or "\\" in rel:
        return None
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return None
    cur = base_dir
    for part in parts:
        if part in (".", "..") or part.startswith(".") or "\\" in part:
            return None
        cur = cur / part
        if os.path.islink(cur):
            return None
    try:
        cur.resolve().relative_to(base_dir.resolve())
    except ValueError:
        return None
    return parts


def _open_local_leaf_dirfd(base_dir: Path, parts: Sequence[str]) -> Tuple[int, str]:
    """Traverses `base_dir` step-by-step using `dir_fd` (`O_DIRECTORY | O_NOFOLLOW`) and opens leaf `O_NOFOLLOW | O_NONBLOCK`."""
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)

    if os.name == "nt" or not getattr(os, "O_DIRECTORY", 0):
        target = base_dir
        for part in parts:
            target = target / part
            if os.path.islink(target):
                raise PermissionError("Symlink component rejected")
        return os.open(os.fspath(target), file_flags), parts[-1]

    cur_fd = os.open(os.fspath(base_dir), dir_flags)
    try:
        for seg in parts[:-1]:
            nxt_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
        leaf_fd = os.open(parts[-1], file_flags, dir_fd=cur_fd)
        return leaf_fd, parts[-1]
    finally:
        os.close(cur_fd)


class _HardenedLocalHtmlServer:
    """
    Ephemeral 127.0.0.1:0 HTTP server for local HTML files:
    per-session URL prefix token, strict Host check, dir_fd no-follow traversal,
    no directory listings, no dotfiles, bounded cumulative reads, O_NONBLOCK FIFO guard.
    """

    def __init__(self, html_file: Path) -> None:
        if os.path.islink(html_file):
            raise MatrixError("TARGET_INVALID", f"Refusing symlinked target HTML file: {html_file}")
        if not html_file.exists():
            raise MatrixError("TARGET_INVALID", f"Target HTML file not found: {html_file}")
        st = os.lstat(html_file)
        if not stat.S_ISREG(st.st_mode):
            raise MatrixError("TARGET_INVALID", f"Target path is not a regular file: {html_file}")
        self.html_file = html_file.resolve()
        self.base_dir = self.html_file.parent
        self.session_token = secrets.token_urlsafe(24)
        self.session_prefix = f"/{self.session_token}/"
        self._server: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: int = 0

    def __enter__(self) -> Tuple[str, int, str]:
        base_dir = self.base_dir
        session_prefix = self.session_prefix
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _serve(self, *, head_only: bool) -> None:
                expected_host = f"127.0.0.1:{outer.port}"
                req_host = (self.headers.get("Host") or "").strip()
                if req_host != expected_host:
                    self.send_error(403, "Invalid Host header")
                    return
                parts = _safe_resolve_local_path(base_dir, self.path, session_prefix=session_prefix)
                if parts is None:
                    self.send_error(403, "Forbidden")
                    return
                try:
                    fd, leaf_name = _open_local_leaf_dirfd(base_dir, parts)
                except FileNotFoundError:
                    self.send_error(404, "Not Found")
                    return
                except OSError:
                    self.send_error(403, "Forbidden")
                    return
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        self.send_error(403, "Directory listing disabled")
                        return
                    if st.st_size > MAX_SERVED_FILE_BYTES:
                        self.send_error(413, "File too large")
                        return
                    data = b""
                    if not head_only:
                        chunks: List[bytes] = []
                        total = 0
                        while True:
                            chunk = os.read(fd, 65536)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > MAX_SERVED_FILE_BYTES:
                                self.send_error(413, "File too large")
                                return
                            chunks.append(chunk)
                        data = b"".join(chunks)
                    content_length = st.st_size if head_only else len(data)
                except OSError:
                    self.send_error(500, "Read failed")
                    return
                finally:
                    os.close(fd)
                ctype, _ = mimetypes.guess_type(leaf_name)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", ctype or "application/octet-stream")
                    self.send_header("Content-Length", str(content_length))
                    self.end_headers()
                    if not head_only:
                        self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

            def do_GET(self) -> None:  # noqa: N802
                self._serve(head_only=False)

            def do_HEAD(self) -> None:  # noqa: N802
                self._serve(head_only=True)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        entry_url = f"http://127.0.0.1:{self.port}{self.session_prefix}{urllib.parse.quote(self.html_file.name)}"
        return entry_url, self.port, self.session_prefix

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def parse_viewports(raw: Optional[str]) -> List[Dict[str, Any]]:
    if not raw:
        return [dict(v) for v in DEFAULT_VIEWPORTS]
    out: List[Dict[str, Any]] = []
    for tok in raw.split(","):
        item = tok.strip()
        if not item:
            continue
        m = re.fullmatch(r"(\d{2,5})x(\d{2,5})(?::(touch|desktop))?", item, flags=re.IGNORECASE)
        if not m:
            raise MatrixError("TARGET_INVALID", f"Invalid viewport spec {item!r}; expected WxH[:touch|desktop].")
        w, h = int(m.group(1)), int(m.group(2))
        if w < 100 or h < 100:
            raise MatrixError("TARGET_INVALID", f"Viewport dimensions too small: {w}x{h}")
        mode = (m.group(3) or "").lower()
        touch = (mode == "touch") if mode else (w <= 900)
        out.append({"name": f"vp-{w}x{h}", "width": w, "height": h, "touch": touch})
    if not out:
        raise MatrixError("TARGET_INVALID", "At least one viewport is required.")
    return out


def compute_control_overlaps(
    controls: Sequence[Dict[str, Any]],
    *,
    min_ratio: float = DEFAULT_OVERLAP_RATIO,
) -> List[Dict[str, Any]]:
    """
    Computes interactive control overlap pairs where `interArea / min(areaA, areaB) >= min_ratio`,
    excluding ancestor/descendant relationships and zero-area boxes.
    """
    overlaps: List[Dict[str, Any]] = []
    n = len(controls)
    for i in range(n):
        a = controls[i]
        aw, ah = float(a.get("width", 0)), float(a.get("height", 0))
        if aw <= 0 or ah <= 0:
            continue
        ax1, ay1 = float(a.get("x", 0)), float(a.get("y", 0))
        ax2, ay2 = ax1 + aw, ay1 + ah
        a_id = a.get("id")
        a_anc = set(a.get("ancestorIds") or ())
        area_a = aw * ah
        for j in range(i + 1, n):
            b = controls[j]
            bw, bh = float(b.get("width", 0)), float(b.get("height", 0))
            if bw <= 0 or bh <= 0:
                continue
            b_id = b.get("id")
            b_anc = set(b.get("ancestorIds") or ())
            if (a_id is not None and a_id in b_anc) or (b_id is not None and b_id in a_anc):
                continue
            bx1, by1 = float(b.get("x", 0)), float(b.get("y", 0))
            bx2, by2 = bx1 + bw, by1 + bh
            iw = min(ax2, bx2) - max(ax1, bx1)
            ih = min(ay2, by2) - max(ay1, by1)
            if iw <= 0 or ih <= 0:
                continue
            inter = iw * ih
            denom = min(area_a, bw * bh)
            if denom <= 0:
                continue
            ratio = inter / denom
            if ratio >= min_ratio:
                overlaps.append(
                    {
                        "selA": str(a.get("sel", "")),
                        "selB": str(b.get("sel", "")),
                        "ratio": round(ratio, 3),
                    }
                )
    return overlaps


def evaluate_viewport_snapshot(
    snapshot: Dict[str, Any],
    *,
    min_tap: int = DEFAULT_MIN_TAP,
    min_font: int = DEFAULT_MIN_FONT,
) -> List[MatrixFinding]:
    """Evaluates a single viewport DOM snapshot across all 11 deterministic check categories."""
    if not isinstance(snapshot, dict):
        raise MatrixError("TARGET_INVALID", "Each viewport snapshot must be a JSON object.")
    vp_name = str(snapshot.get("viewport") or f"{snapshot.get('viewportWidth', 0)}x{snapshot.get('viewportHeight', 0)}")
    touch = bool(snapshot.get("touch", False))
    findings: List[MatrixFinding] = []

    # 1. blank (broken)
    text_len = int(snapshot.get("textLen", 0))
    media_cnt = int(snapshot.get("visibleMediaCount", 0))
    if text_len == 0 and media_cnt == 0:
        findings.append(MatrixFinding(vp_name, "blank", "broken", "body", "Page rendered zero visible text or media."))

    # 2. overflowX (broken)
    vw = int(snapshot.get("viewportWidth", 0))
    sw = int(snapshot.get("scrollWidth", 0))
    if vw > 0 and sw > vw + 1:
        findings.append(
            MatrixFinding(vp_name, "overflowX", "broken", "html", f"Page scrollWidth {sw}px exceeds viewport {vw}px (+{sw - vw}px).")
        )

    # 3. offscreen (broken)
    for item in snapshot.get("offscreen") or ():
        over = int(item.get("over", 0))
        if over >= 2:
            findings.append(
                MatrixFinding(
                    vp_name,
                    "offscreen",
                    "broken",
                    str(item.get("sel", "")),
                    f"Clipped {over}px past {item.get('side', 'viewport')} edge.",
                )
            )

    # 4. truncated (broken on primary heading/button/nav, weak otherwise)
    for item in snapshot.get("truncated") or ():
        tag = str(item.get("tag", "")).lower()
        role = str(item.get("role", "")).lower()
        sev = "broken" if (tag in PRIMARY_TRUNCATION_TAGS or role in PRIMARY_TRUNCATION_ROLES) else "weak"
        findings.append(
            MatrixFinding(
                vp_name,
                "truncated",
                sev,
                str(item.get("sel", "")),
                f"Text clipped horizontally by {int(item.get('by', 0))}px under hidden overflow.",
            )
        )

    # 5. spill (broken >= 6px, weak 1..5px)
    for item in snapshot.get("spill") or ():
        by = int(item.get("by", 0))
        if by >= 1:
            sev = "broken" if by >= 6 else "weak"
            findings.append(
                MatrixFinding(vp_name, "spill", sev, str(item.get("sel", "")), f"Text spills outside container by {by}px.")
            )

    # 6. brokenImage (broken)
    for item in snapshot.get("brokenImages") or ():
        findings.append(
            MatrixFinding(
                vp_name,
                "brokenImage",
                "broken",
                str(item.get("sel", "img")),
                f"Image failed to load ({item.get('src', '')}).",
            )
        )

    # 7. consoleErrors (broken)
    for err in snapshot.get("consoleErrors") or ():
        findings.append(MatrixFinding(vp_name, "consoleErrors", "broken", "console", str(err)[:200]))

    # 8. tinyTap (weak, touch only)
    if touch:
        for item in snapshot.get("tinyTap") or ():
            w = int(item.get("width", 0))
            h = int(item.get("height", 0))
            if w < min_tap or h < min_tap:
                findings.append(
                    MatrixFinding(
                        vp_name,
                        "tinyTap",
                        "weak",
                        str(item.get("sel", "")),
                        f"Touch target {w}x{h}px is below {min_tap}x{min_tap}px minimum.",
                    )
                )

    # 9. tinyText (weak)
    for item in snapshot.get("tinyText") or ():
        fs = float(item.get("fontSize", 0))
        if 0 < fs < min_font:
            findings.append(
                MatrixFinding(
                    vp_name,
                    "tinyText",
                    "weak",
                    str(item.get("sel", "")),
                    f"Font size {fs}px is below {min_font}px minimum.",
                )
            )

    # 10. overlap (weak)
    overlaps = list(snapshot.get("overlaps") or ())
    if not overlaps and snapshot.get("interactiveControls"):
        overlaps = compute_control_overlaps(snapshot["interactiveControls"])
    for item in overlaps:
        ratio = float(item.get("ratio", 0))
        if ratio >= DEFAULT_OVERLAP_RATIO:
            findings.append(
                MatrixFinding(
                    vp_name,
                    "overlap",
                    "weak",
                    str(item.get("selA", "")),
                    f"Overlaps {item.get('selB', '')} by {round(ratio * 100)}%.",
                )
            )

    # 11. viewportMeta (weak, touch only)
    if touch:
        vp_meta = snapshot.get("viewportMeta")
        if vp_meta is None:
            findings.append(
                MatrixFinding(vp_name, "viewportMeta", "weak", "head", "Missing <meta name='viewport'> tag.")
            )
        elif not re.search(r"width\s*=\s*device-width", str(vp_meta), flags=re.IGNORECASE):
            findings.append(
                MatrixFinding(
                    vp_name,
                    "viewportMeta",
                    "weak",
                    "head",
                    f"Viewport meta lacks width=device-width ({vp_meta!r}).",
                )
            )

    return findings


def evaluate_matrix_report(
    snapshots: Sequence[Dict[str, Any]],
    *,
    fail_on: str = "broken",
    min_tap: int = DEFAULT_MIN_TAP,
    min_font: int = DEFAULT_MIN_FONT,
) -> Dict[str, Any]:
    if not snapshots:
        raise MatrixError("TARGET_INVALID", "Snapshot input contains 0 viewports; refusing empty pass.")
    all_findings: List[MatrixFinding] = []
    for snap in snapshots:
        all_findings.extend(evaluate_viewport_snapshot(snap, min_tap=min_tap, min_font=min_font))

    broken = sum(1 for f in all_findings if f.severity == "broken")
    weak = sum(1 for f in all_findings if f.severity == "weak")
    passed = (broken == 0 and weak == 0) if fail_on == "weak" else (broken == 0)

    return {
        "ok": passed,
        "fail_on": fail_on,
        "viewports_checked": len(snapshots),
        "counts": {"broken": broken, "weak": weak},
        "findings": [asdict(f) for f in all_findings],
    }


def make_route_interceptor(
    *,
    allow_remote: bool,
    target_is_loopback: bool,
    expected_loopback_port: Optional[int] = None,
    strict_ipv4_loopback: bool = False,
    required_path_prefix: Optional[str] = None,
    timeout_sec: float = 15.0,
    resolver: Optional[Callable[[str, int], Iterable[Any]]] = None,
    remote_fetcher: Optional[Callable[..., Tuple[int, Dict[str, str], bytes]]] = None,
) -> Callable[[Any], None]:
    """
    Builds a Playwright `context.route('**/*', ...)` handler enforcing fail-closed SSRF policy.
    Remote requests (`allow_remote and not target_is_loopback`) are fulfilled via pinned-socket
    Python fetches with per-hop 3xx redirect validation (never `route.continue_()`).
    """
    fetcher = remote_fetcher or fetch_pinned_remote

    def _handle_route(route: Any) -> None:
        try:
            req = route.request
            req_url = str(getattr(req, "url", "") or "")
            if allow_remote and not target_is_loopback:
                method = str(getattr(req, "method", "GET") or "GET")
                raw_headers = getattr(req, "headers", None)
                hdrs = dict(raw_headers) if isinstance(raw_headers, dict) else {}
                post_data = getattr(req, "post_data_buffer", None)
                status, resp_hdrs, resp_body = fetcher(
                    req_url,
                    method=method,
                    headers=hdrs,
                    body=post_data if isinstance(post_data, (bytes, bytearray)) else None,
                    timeout_sec=timeout_sec,
                    resolver=resolver,
                )
                route.fulfill(status=status, headers=resp_hdrs, body=resp_body)
                return

            validate_url(
                req_url,
                allow_remote=False,
                forbid_loopback=False,
                expected_loopback_port=expected_loopback_port,
                strict_ipv4_loopback=strict_ipv4_loopback,
                required_path_prefix=required_path_prefix,
                resolver=resolver,
            )
            route.continue_()
        except Exception:
            try:
                route.abort("blockedbyclient")
            except Exception:
                pass

    return _handle_route


def capture_playwright_matrix(
    target: str,
    *,
    viewports: Sequence[Dict[str, Any]],
    allow_remote: bool = False,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    settle_ms: int = DEFAULT_SETTLE_MS,
    min_tap: int = DEFAULT_MIN_TAP,
    min_font: int = DEFAULT_MIN_FONT,
) -> List[Dict[str, Any]]:
    """Captures DOM snapshots across viewports using optional Python `playwright.sync_api`."""
    is_url = bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", target.strip()))
    local_file: Optional[Path] = None
    target_is_loopback = True

    if is_url:
        _, target_is_loopback, _ = validate_url(target, allow_remote=allow_remote)
    else:
        local_file = Path(target)
        if os.path.islink(local_file) or not local_file.exists() or not stat.S_ISREG(os.lstat(local_file).st_mode):
            raise MatrixError("TARGET_INVALID", f"Local HTML target must be an existing regular non-symlink file: {target}")

    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError as exc:
        raise MatrixError(
            "PLAYWRIGHT_MISSING",
            "Optional Python Playwright runtime is not installed. Live DOM viewport checks were skipped "
            "(declare live viewport rendering under `Not verified`, and run `check_ui_slop.py` or optional "
            "`plumb-guard ui-slop` for static checks). To enable live checks, install a pinned version "
            "explicitly in your project environment: "
            "`python3 -m pip install 'playwright==1.52.0' && python3 -m playwright install chromium`.",
        ) from exc

    def _run_against(
        entry_url: str,
        *,
        expected_port: Optional[int],
        strict_ipv4: bool,
        required_prefix: Optional[str],
    ) -> List[Dict[str, Any]]:
        snapshots: List[Dict[str, Any]] = []
        interceptor = make_route_interceptor(
            allow_remote=allow_remote,
            target_is_loopback=target_is_loopback,
            expected_loopback_port=expected_port,
            strict_ipv4_loopback=strict_ipv4,
            required_path_prefix=required_prefix,
            timeout_sec=max(1.0, float(timeout_ms) / 1000.0),
        )
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
                )
                try:
                    for vp in viewports:
                        context = browser.new_context(
                            viewport={"width": int(vp["width"]), "height": int(vp["height"])},
                            has_touch=bool(vp["touch"]),
                            is_mobile=bool(vp["touch"]),
                            service_workers="block",
                        )
                        try:
                            context.route("**/*", interceptor)
                            if hasattr(context, "route_web_socket"):
                                context.route_web_socket("**/*", lambda ws: ws.close())
                            page = context.new_page()
                            console_errors: List[str] = []
                            page.on("pageerror", lambda err: console_errors.append(f"pageerror: {err}"))
                            page.on(
                                "console",
                                lambda msg: console_errors.append(f"console.error: {msg.text}")
                                if getattr(msg, "type", "") == "error"
                                else None,
                            )
                            page.goto(entry_url, wait_until="load", timeout=timeout_ms)
                            if settle_ms > 0:
                                page.wait_for_timeout(settle_ms)
                            snap = page.evaluate(
                                JS_COLLECT_SNAPSHOT,
                                {"touch": bool(vp["touch"]), "minTap": min_tap, "minFont": min_font},
                            )
                            snap["viewport"] = vp["name"]
                            snap["touch"] = bool(vp["touch"])
                            snap["consoleErrors"] = console_errors[:20]
                            snapshots.append(snap)
                        finally:
                            context.close()
                finally:
                    browser.close()
        except MatrixError:
            raise
        except Exception as exc:
            err_name = type(exc).__name__
            code = "NAVIGATION_TIMEOUT" if "Timeout" in err_name else "BROWSER_ERROR"
            raise MatrixError(code, f"Playwright execution failed ({err_name}): {exc}") from exc
        return snapshots

    if local_file is not None:
        with _HardenedLocalHtmlServer(local_file) as (entry_url, port, prefix):
            return _run_against(entry_url, expected_port=port, strict_ipv4=True, required_prefix=prefix)
    return _run_against(target, expected_port=None, strict_ipv4=False, required_prefix=None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_ui_matrix",
        description="Optional Playwright multi-viewport DOM/layout matrix evaluator (11 checks, stdlib core).",
        allow_abbrev=False,
    )
    parser.add_argument("target", nargs="?", help="Local HTML file or loopback URL (use --allow-remote for public http/https)")
    parser.add_argument("--from-json", help="Evaluate pre-captured viewport snapshot JSON instead of launching Playwright")
    parser.add_argument("--viewports", help="Comma-separated WxH[:touch|desktop] list (default: 5 mobile/tablet/desktop sizes)")
    parser.add_argument("--allow-remote", action="store_true", help="Allow public http/https targets (private/metadata IPs stay blocked)")
    parser.add_argument("--fail-on", choices=["broken", "weak"], default="broken", help="Minimum severity causing exit 1 (default: broken)")
    parser.add_argument("--min-tap", type=int, default=DEFAULT_MIN_TAP, help="Minimum touch target px (default: 44)")
    parser.add_argument("--min-font", type=int, default=DEFAULT_MIN_FONT, help="Minimum readable font px (default: 12)")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS, help="Per-viewport load timeout ms (default: 15000)")
    parser.add_argument("--settle-ms", type=int, default=DEFAULT_SETTLE_MS, help="Post-load layout settle wait ms (default: 300)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")
    args = parser.parse_args(argv)

    try:
        if args.from_json:
            raw_bytes = _read_regular_file_bounded(Path(args.from_json), max_bytes=MAX_SERVED_FILE_BYTES, label="snapshot JSON")
            payload = json.loads(raw_bytes.decode("utf-8", errors="strict"))
            if isinstance(payload, list):
                snapshots = payload
            elif isinstance(payload, dict):
                snapshots = payload["viewports"] if "viewports" in payload else [payload]
            else:
                raise MatrixError("TARGET_INVALID", "Snapshot JSON must be a JSON object or list of viewport snapshots.")
            if not isinstance(snapshots, list) or not snapshots or not all(isinstance(s, dict) for s in snapshots):
                raise MatrixError("TARGET_INVALID", "Snapshot JSON must contain a non-empty list of viewport objects.")
        else:
            if not args.target:
                raise MatrixError("TARGET_INVALID", "Specify a local HTML file, URL, or --from-json <path>.")
            viewports = parse_viewports(args.viewports)
            snapshots = capture_playwright_matrix(
                args.target,
                viewports=viewports,
                allow_remote=bool(args.allow_remote),
                timeout_ms=args.timeout_ms,
                settle_ms=args.settle_ms,
                min_tap=args.min_tap,
                min_font=args.min_font,
            )
        report = evaluate_matrix_report(
            snapshots,
            fail_on=args.fail_on,
            min_tap=args.min_tap,
            min_font=args.min_font,
        )
    except MatrixError as exc:
        if args.as_json:
            print(json.dumps({"ok": False, "error_code": exc.code, "error": exc.message}, indent=2))
        else:
            print(f"[{exc.code}] {exc.message}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if args.as_json:
            print(json.dumps({"ok": False, "error_code": "TARGET_INVALID", "error": str(exc)}, indent=2))
        else:
            print(f"[TARGET_INVALID] {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        status = "PASS" if report["ok"] else "FAIL"
        print(
            f"[UI-MATRIX:{status}] {report['viewports_checked']} viewport(s) checked — "
            f"broken={report['counts']['broken']}, weak={report['counts']['weak']}"
        )
        for item in report["findings"]:
            print(f"  [{item['severity'].upper():6s}] ({item['viewport']}) {item['check']} {item['selector']}: {item['detail']}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
